use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

use pyroclast::symbols::{SymbolCache, SymbolRequest, SymbolResolver};

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
