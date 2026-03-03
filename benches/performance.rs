use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use signhash::{hash_file, HasherOptions};
use std::hint::black_box;
use std::io::Write;
use tempfile::NamedTempFile;

fn benchmark_hash_algorithms(c: &mut Criterion) {
    let algorithms = ["256", "512", "blake3"];
    let sizes = [
        ("1KB", 1024),
        ("64KB", 64 * 1024),
        ("1MB", 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
    ];

    for algorithm in algorithms {
        for (size_name, size) in sizes {
            let mut group = c.benchmark_group(format!("hash_{algorithm}_{size_name}"));
            group.throughput(Throughput::Bytes(size as u64));

            group.bench_function("file_hash", |b| {
                let data = vec![0u8; size];
                let mut temp_file = NamedTempFile::new().unwrap();
                temp_file.write_all(&data).unwrap();
                temp_file.flush().unwrap();

                let hasher = HasherOptions::new(algorithm);

                b.iter(|| {
                    let result = hash_file(&hasher, temp_file.path().as_os_str());
                    black_box(result)
                });
            });

            group.finish();
        }
    }
}

fn benchmark_parallel_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_hashing");

    // Create multiple test files
    let file_count = 100;
    let file_size = 64 * 1024; // 64KB each
    let temp_files: Vec<_> = (0..file_count)
        .map(|_| {
            let data = vec![42u8; file_size];
            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(&data).unwrap();
            temp_file.flush().unwrap();
            temp_file
        })
        .collect();

    group.throughput(Throughput::Bytes((file_count * file_size) as u64));

    for thread_count in [1, 2, 4, 8] {
        group.bench_function(format!("threads_{thread_count}"), |b| {
            let hasher = HasherOptions::new("blake3");

            b.iter(|| {
                use rayon::prelude::*;

                // Configure thread pool for this benchmark run
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(thread_count)
                    .build()
                    .unwrap();

                let results: Vec<_> = pool.install(|| {
                    temp_files
                        .par_iter()
                        .map(|file| hash_file(&hasher, file.path().as_os_str()))
                        .collect()
                });
                black_box(results)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_hash_algorithms,
    benchmark_parallel_hashing
);
criterion_main!(benches);
