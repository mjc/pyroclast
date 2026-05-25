use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};
use pyroclast::symbols::{Addr2lineResolver, SymbolCache, SymbolRequest, SymbolResolver};

#[test]
fn resolves_each_unique_symbol_address_once() {
    let resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
        },
        "app::main".to_string(),
    )]);
    let mut cache = SymbolCache::new(&resolver);

    let first = cache
        .resolve(&SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
        })
        .expect("first symbol");
    let second = cache
        .resolve(&SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
        })
        .expect("second symbol");

    assert_eq!(first.as_deref(), Some("app::main"));
    assert_eq!(second.as_deref(), Some("app::main"));
    assert_eq!(
        resolver.batch_calls(),
        vec![vec![SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
        }]]
    );
}

#[test]
fn batches_only_uncached_symbol_addresses() {
    let resolver = RecordingResolver::with_symbols([
        (
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
            },
            "app::main".to_string(),
        ),
        (
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
            },
            "app::work".to_string(),
        ),
    ]);
    let mut cache = SymbolCache::new(&resolver);
    cache
        .resolve_many(&[SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
        }])
        .expect("prime cache");

    let symbols = cache
        .resolve_many(&[
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
            },
        ])
        .expect("symbols");

    assert_eq!(
        symbols,
        vec![
            Some("app::main".to_string()),
            Some("app::work".to_string()),
            Some("app::work".to_string()),
        ]
    );
    assert_eq!(
        resolver.batch_calls(),
        vec![
            vec![SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
            }],
            vec![SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
            }],
        ]
    );
}

#[test]
fn addr2line_resolver_batches_requests_by_binary() {
    let runner = Addr2lineRunner::new(b"app::main\n/bin/app.rs:10\napp::work\n/bin/app.rs:20\n");
    let resolver = Addr2lineResolver::new(&runner);

    let symbols = resolver
        .resolve_batch(&[
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
            },
        ])
        .expect("symbols");

    assert_eq!(
        symbols,
        vec![Some("app::main".to_string()), Some("app::work".to_string())]
    );
    assert_eq!(runner.commands().len(), 1);
    assert_eq!(
        runner.commands()[0].stdin.as_deref(),
        Some(&b"0x10\n0x20\n"[..])
    );
}

#[test]
fn addr2line_resolver_treats_failed_batches_as_unresolved() {
    let runner = Addr2lineRunner::failed();
    let resolver = Addr2lineResolver::new(&runner);

    let symbols = resolver
        .resolve_batch(&[
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
            },
        ])
        .expect("failed addr2line should degrade");

    assert_eq!(symbols, vec![None, None]);
    assert_eq!(runner.commands().len(), 1);
}

#[derive(Default)]
struct RecordingResolver {
    symbols: BTreeMap<SymbolRequest, String>,
    calls: RefCell<Vec<Vec<SymbolRequest>>>,
}

impl RecordingResolver {
    fn with_symbols<const N: usize>(symbols: [(SymbolRequest, String); N]) -> Self {
        Self {
            symbols: symbols.into(),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn batch_calls(&self) -> Vec<Vec<SymbolRequest>> {
        self.calls.borrow().clone()
    }
}

impl SymbolResolver for RecordingResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        self.calls.borrow_mut().push(requests.to_vec());
        Ok(requests
            .iter()
            .map(|request| self.symbols.get(request).cloned())
            .collect())
    }
}

struct Addr2lineRunner {
    status_code: Option<i32>,
    stdout: Vec<u8>,
    commands: Mutex<Vec<CommandSpec>>,
}

impl Addr2lineRunner {
    fn new(stdout: &[u8]) -> Self {
        Self {
            status_code: Some(0),
            stdout: stdout.to_vec(),
            commands: Mutex::new(Vec::new()),
        }
    }

    fn failed() -> Self {
        Self {
            status_code: Some(1),
            stdout: Vec::new(),
            commands: Mutex::new(Vec::new()),
        }
    }

    fn commands(&self) -> Vec<CommandSpec> {
        self.commands.lock().unwrap().clone()
    }
}

impl CommandRunner for Addr2lineRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        Ok(CommandOutput {
            status_code: self.status_code,
            stdout: self.stdout.clone(),
            stderr: Vec::new(),
        })
    }
}
