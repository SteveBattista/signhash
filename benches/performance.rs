use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use signhash::{HasherOptions, hash_file};
use std::hint::black_box;
use std::io::Write;
use std::time::Duration;
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
            group.measurement_time(Duration::from_secs(120));

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


criterion_group!(
    benches,
    benchmark_hash_algorithms,
);
criterion_main!(benches);
