# Test Suite for SignHash

This directory contains comprehensive test coverage for the SignHash project.

## Test Organization

Tests are organized into separate files by functionality:

### 1. `hash_helper_tests.rs`

Tests for the hash_helper module covering:

- Algorithm parsing and selection
- Hash computation (BLAKE3, SHA variants)
- Streaming vs one-shot hashing
- File hashing with memmap
- Hash consistency and correctness

### 2. `key_management_tests.rs`

Tests for Ed25519 key management:

- Key pair generation
- Key serialization to YAML
- Key deserialization from YAML
- Round-trip key storage/retrieval
- Key validation

### 3. `signing_tests.rs`

Tests for cryptographic signing:

- Ed25519 signature generation
- Signature verification
- Signature determinism
- Invalid signature detection

### 4. `manifest_parsing_tests.rs`

Tests for manifest file parsing:

- Parsing manifest lines
- Extracting file metadata
- Reading manifest files
- Handling malformed data

### 5. `manifest_creation_tests.rs`

Tests for manifest creation:

- Creating manifest entries
- Writing manifest headers
- Computing manifest statistics
- Signing manifests

### 6. `verification_tests.rs`

Tests for file verification:

- Checking files against manifests
- Detecting modifications
- Verifying signatures
- Handling missing files
- Manifest-only verification mode

### 7. `nonce_tests.rs`

Tests for nonce generation:

- Generating unique nonces
- Detecting duplicate nonces
- Nonce randomness
- Collision avoidance

### 8. `helper_utils_tests.rs`

Tests for utility functions:

- File collection
- Progress bar creation
- Thread pool size calculation

### 9. `io_tests.rs`

Tests for I/O operations:

- File writing
- Header reading
- Streaming digest computation

### 10. `channel_tests.rs`

Tests for channel communication:

- Message passing between threads
- Channel error handling
- Progress updates via channels

### 11. `integration_tests.rs`

End-to-end integration tests:

- Complete sign and verify workflows
- Tampering detection
- Multi-file scenarios
- Different hash algorithms

## Running Tests

Run all tests:

```bash
cargo test
```

Run specific test file:

```bash
cargo test --test hash_helper_tests
```

Run specific test:

```bash
cargo test test_algorithm_from_str_blake3
```

Run with output:

```bash
cargo test -- --nocapture
```

Run in parallel:

```bash
cargo test -- --test-threads=4
```

## Test Implementation Status

Currently, the test files contain placeholder test functions that define the test structure and intentions. To implement the tests:

1. The hash_helper and main_helper modules need to be refactored into a library crate
2. Test helper utilities need to be created
3. Each test function needs implementation with assertions

## Contributing Tests

When adding new tests:

1. Place them in the appropriate test file
2. Use descriptive test names
3. Add doc comments explaining what is being tested
4. Use assertions to verify behavior
5. Clean up test resources (files, directories) after test completion

## Test Coverage Goals

- Unit tests: Cover all public functions
- Integration tests: Cover main user workflows
- Edge cases: Handle error conditions and boundary cases
- Performance tests: Verify multi-threading efficiency
