// Oracle workload: mixes inlined helpers, recursion, allocation, and libc
// calls so perf records stacks with inline frames, deep user stacks, and
// shared-library frames.

use std::hint::black_box;

#[inline(always)]
fn mix(value: u64) -> u64 {
    value
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .rotate_left(31)
        .wrapping_add(0x517c_c1b7_2722_0a95)
}

#[inline(always)]
fn mix_twice(value: u64) -> u64 {
    mix(mix(value))
}

fn recurse(depth: u32, seed: u64) -> u64 {
    if depth == 0 {
        let mut acc = seed;
        for index in 0..512 {
            acc = mix_twice(acc ^ index);
        }
        acc
    } else {
        recurse(depth - 1, mix(seed)).wrapping_add(depth.into())
    }
}

fn churn_allocations(rounds: usize) -> u64 {
    let mut acc = 0u64;
    for round in 0..rounds {
        let mut values: Vec<u64> = (0..2048).map(|i| mix(i ^ round as u64)).collect();
        values.sort_unstable();
        let text = format!("round-{round}-{}", values[values.len() / 2]);
        acc = acc.wrapping_add(text.len() as u64).wrapping_add(values[0]);
        black_box(&values);
    }
    acc
}

fn main() {
    let mut total = 0u64;
    for round in 0..200u64 {
        total = total.wrapping_add(recurse(24, round));
        total = total.wrapping_add(churn_allocations(8));
    }
    println!("{total}");
}
