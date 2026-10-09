use std::hint::black_box;
use std::process::ExitCode;

#[inline(never)]
fn cpu(mut value: u64, rounds: usize) -> u64 {
    for _ in 0..rounds {
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        value = value.wrapping_mul(0x2545_f491_4f6c_dd1d);
    }
    black_box(value)
}

#[inline(never)]
fn allocations(rounds: usize) -> u64 {
    let retained: Vec<_> = (0_u8..128).map(|value| vec![value; 65536]).collect();
    let mut checksum = 0_u64;
    for round in 0..rounds {
        let value = u8::try_from(round % 256).unwrap();
        let bytes = vec![value; 64 + round % 2048];
        black_box(&bytes);
        checksum += u64::from(bytes[0]) + u64::from(bytes[bytes.len() - 1]);
    }
    black_box(&retained);
    checksum
}

fn run() -> Result<u64, &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: workload {cpu|threads|alloc} POSITIVE_ROUNDS");
    }
    let rounds: usize = args[1].parse().map_err(|_| "invalid rounds")?;
    if rounds == 0 {
        return Err("rounds must be positive");
    }
    match args[0].as_str() {
        "cpu" => Ok(cpu(1, rounds)),
        "threads" => {
            let workers: Vec<_> = (1_u64..=4)
                .map(|seed| std::thread::spawn(move || cpu(seed, rounds)))
                .collect();
            workers.into_iter().try_fold(0_u64, |sum, worker| {
                worker
                    .join()
                    .map(|value| sum.wrapping_add(value))
                    .map_err(|_| "worker panicked")
            })
        }
        "alloc" => Ok(allocations(rounds)),
        _ => Err("unknown mode"),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(checksum) => {
            println!("{checksum}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
