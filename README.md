# Description

![Gemini](https://img.shields.io/badge/Built%20with-Gemini%20AI-blue?logo=google&logoColor=white)

![SignHash Icon](./Gemini_Generated_Image_d93h3cd93h3cd93h.png)

**Version:** 1.0.0  
**Manifest Format:** 0.8.0

sign_hash - Takes a directory, hashes files and signs them with Ed25519 signatures.  
check_hash - Takes manifest and public key from a running of sign_hash and looks at a directory to both check to see if the files changed and also checks if manifest was tampered.

## Features

- **Multiple Hash Algorithms:** SHA1, SHA256, SHA384, SHA512, SHA512_256, and BLAKE3
- **Multi-threaded:** Parallel file hashing for improved performance
- **Ed25519 Signatures:** Cryptographic signing of manifest entries
- **Progress Indicators:** Real-time progress bars during operations
- **Symlink Detection:** Identifies and handles symbolic links
- **Comprehensive Verification:** Checks file size, modification time, type, hash, and signature

## Why Does This Exist

One of the things that always bothered me is that people provide a list of hashes for a series of files. There is no guarantee that the file of hashes were tampered. With this project one can send the file of hashes, named a manifest and if they keep the public key from being changed, one can check if the manifest has been tampered. The program does not write out a private key on purpose. This prevents someone from tampering with the file after it has been created. As an added security feature, the file uses its length, its hash and signs this hash, making adjusting the file without rehashing and resigning with the private key detectable.

## What do you need to keep secret (confidential)

Manifest file needs to be kept encrypted if:

1. If knowledge is leaked when an adversary can see the names or the existence of files in the directory hashed.
2. An adversary can determine if one file in the manifest matches another file in any of the manifests by matching hashes. (See road-map for version 2)
3. A determined adversary can create hashes of their own of estimated files. Then they can use this database (e.g. a rainbow table) to determine the content. (See road map for version 2)

Public key:

1. You do not need to keep this secret.

## What do you need to keep from tamper (integrity)

Manifest file needs to be kept from tamper if:

1. An adversary can cause a denial of service attack if they continuously tamper with the manifest. Users would know that it is tampered and know which lines were tampered but if you suspend processing until a correct manifest, you can be stopped

Signature file needs to be kept from tamper:

1. An adversary who tampers the signature file but not the manifest, can cause a denial of service condition.
2. An adversary who tampers with the signature file and the manifest can spoof the manifest. This means you can not trust the the manifest has been tampered. If the adversary can also tamper the data that you check, you can not trust that the data has adversary changed.

N.B. Some of the thoughts on how to keep this from tamper are:

1. Writing this to multiple locations that would require an adversary to compromise a majority of them.
2. Reading the signature over the phone (64 hexadecimal numbers)
3. Placing the key in an un-editable database like a public block-chain.

## How To Use

Use the flag -h for command line flags

### sign_hash

`./sign_hash -d ./place -o manifest234`

Take sub-directory named place and all sub directories in it and create a signed hash manifest for them named manifest234

`./sign_hash -d ./place -o manifest234 -a blake3 -p 8`

Use blake3 hashing algorithm with 8 threads

`./sign_hash -d ./place -o manifest234 -i header.txt`

Include custom header file in the manifest

Available options:

- `-a, --hash`: Hash algorithm (SHA1/128, SHA256/256, SHA384/384, SHA512/512, SHA512_256/512_256, blake3). Default: SHA256
- `-s, --signing`: Signing algorithm (ED25519). Default: ED25519
- `-u, --public`: Public key file location. Default: Signpub.txt
- `-o, --output`: Manifest output file. Default: STDIO
- `-p, --pool`: Thread pool size. Default: CPU cores
- `-i, --include`: Header file to include
- `-d, --directory`: Directory to hash. Default: current directory

### check_hash

`./check_hash -i manifest234 -o checkfile234 -m`

Take manifest234 and check to see if it has been tampered. Write results to file named checkfile234

`./check_hash -d ./place -i manifest234 -o checkfile234`

Take sub-directory named place and see if the hashes and files match the files listed in manifest234. Take manifest234 and check to see if it has been tampered. Write results to file named checkfile234

`./check_hash -d ./place -i manifest234 -v`

Verbose mode - print all checks including successful ones

Available options:

- `-u, --public`: Public key file location. Default: Signpub.txt
- `-i, --input`: Manifest file location. Default: Manifest.txt
- `-o, --output`: Output file location. Default: STDIO
- `-p, --pool`: Thread pool size. Default: CPU cores
- `-d, --directory`: Directory to check. Default: current directory
- `-v, --verbose`: Print matches as well as failures
- `-m, --manifestonly`: Check manifest validity only, ignore -d option

## Known Issues/Behaviors/Limitations

### Architecture

The programs use a multi-threaded architecture with worker threads for hashing and a writer thread for output. Thread pool size can be configured or defaults to the number of CPU cores (detected via num_threads crate which respects cgroups and CPU affinity).

### Symbolic Links

Not following symbolic links:

Program will not follow infinite loops based on hard links (in Linux). Could add a flag to follow sym-links but this could result in a infinite loop so it is not part of the system. The program detects symbolic links and marks them in the manifest.

Discussion on nonces:

Nonce length is 128 bytes. This means that after 2^64 number of files, there could be a collision. The program ensures that when creating a manifest file that every file has a unique nonce. It will provide an error message when a collision occurred during construction and pick another random nonce. At orders of magnitude higher than 2^64, one might have delays in picking a nonce. If you are looking at creating a manifest with greater than 2^128 files, the creation program will fail (good luck finishing in your lifetime anyway). When checking the manifest, it checks for duplicated nonces. This makes it very hard to guess the private key from a large manifest. If across all of your manifests you had a line that matched the name, date of last changed, length, nonce which was signed with the same private key, one could substitute one of these lines for the other allowing an attacker to change a file to the one captured in the other manifest. The odds of this are 1/ 2^384 (so low to be impractical with a lifetime of human computing power).

Don't know limits of hashing:

When working on a live Linux system /proc/kcore can be very large (e.g. 128TB). Need to see if it can hash a file that big!

## Recent Changes (v1.0.0)

- Added BLAKE3 hashing algorithm support with Rayon parallelization
- Simplified codebase with helper functions for better maintainability
- Switched from num_cpus to num_threads for better container support
- Improved progress indicators with indicatif library
- Enhanced command-line interface with clap 4.x
- Comprehensive code documentation
- **Extensive test suite:** 220+ comprehensive tests covering all core functionality

## Testing

The project includes a comprehensive test suite with 220+ tests covering:

### Cryptographic Operations (139 tests)

- **Hash Algorithms (38 tests):** BLAKE3, SHA1, SHA256, SHA384, SHA512, SHA512_256
  - File hashing with all algorithms
  - Streaming hasher interface
  - Edge cases: empty files, large files (1MB+), Unicode content
  
- **Ed25519 Cryptography (42 tests):**
  - Key pair generation and management (22 tests)
  - YAML serialization/deserialization
  - Deterministic signing (20 tests)
  - Signature verification with valid/invalid signatures
  - Edge cases: empty data, special characters

- **Manifest Operations (46 tests):**
  - Parsing manifest files (26 tests)
  - Creating manifest entries (20 tests)
  - Field validation and error handling

- **Nonce Generation (19 tests):**
  - Random generation with cryptographic strength
  - Uniqueness and collision detection
  - Statistical randomness validation

- **File Verification (14 tests):**
  - Integrity checks: size, timestamp, hash, signature
  - Symlink and directory handling
  - Tamper detection

### Infrastructure Tests (80+ tests)

- **I/O Operations (18 tests):** File writing, header dumping, streaming
- **Channel Communication (19 tests):** Message passing, progress tracking
- **Integration Tests (15 tests):** End-to-end workflows, tampering detection
- **Helper Functions:** Test utilities and file operations

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test hash_helper_tests
cargo test --test verification_tests

# Run with output
cargo test -- --nocapture
```

All cryptographic tests use real implementations (ring, blake3) rather than mocks, ensuring accurate validation of Ed25519 operations and hash algorithms.

## Development Status

- ✅ Core functionality complete and tested
- ✅ 220+ comprehensive tests covering all features
- ✅ All hash algorithms validated (BLAKE3, SHA family)
- ✅ Ed25519 signing/verification fully tested
- ✅ Manifest parsing and creation verified
- ⚠️ Module refactoring needed for public API access

## Possible Road-map (v2.0)

1. Move the nonce into the hash with a keyed hash (HMAC). This would ensure that when files matched they would not have the same hash. Also, it would make rainbow table guessing infeasible. This would remove some of the reasons why you would have to keep the manifest confidential
2. Add post-quantum cryptographic algorithm option in addition to Ed25519. If we used two signatures and one of them failed due to the advent of quantum computing, the second would ensure integrity
3. Add option to store private key in secure enclave or hardware security module
4. Support for streaming verification without loading entire manifest into memory
