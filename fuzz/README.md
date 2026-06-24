# Fuzzing with cargo-fuzz

## Setup

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Initialize fuzzing (already done - see fuzz/Cargo.toml)
```

## Running Fuzzers

```bash
# Run message parsing fuzzer
cargo fuzz run message_parse

# Run with specific timeout (seconds)
cargo fuzz run message_parse --timeout=60

# Run with multiple jobs (parallel)
cargo fuzz run message_parse -j4

# Run until crash or interrupted
cargo fuzz run message_parse
```

## Fuzzing Targets

### message_parse

Fuzzes deserialization of:
- Key exchange messages
- Network envelopes
- PSI protocol inputs

Catches:
- Panics on malformed input
- Infinite loops in parsers
- Memory exhaustion

## Interpreting Results

When a crash is found, cargo-fuzz will output:

```
Found crater: fuzz/artifacts/message_parse/crash-<hash>
```

To reproduce the crash:

```bash
# Reproduce specific crash
cargo fuzz run message_parse fuzz/artifacts/message_parse/crash-<hash>
```

## Minimizing Test Cases

```bash
# Minimize crash input
cargo fuzz cmin message_parse
```

## Coverage

```bash
# Show coverage
cargo fuzz coverage message_parse

# View in browser
open -a open coverage/target/x86_64-unknown-linux-gnu/release/message_parse/coverage.html
```

## Adding New Targets

1. Create new file in `fuzz/fuzz_targets/`
2. Add binary to `fuzz/Cargo.toml`
3. Run with `cargo fuzz run <target_name>`

Example new target:

```rust
// fuzz/fuzz_targets/double_ratchet.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowgram_crypto::double_ratchet::DoubleRatchet;

fuzz_target!(|data: &[u8]| {
    // Fuzz ratchet state transitions
    let mut ratchet = DoubleRatchet::default();
    // Try to process arbitrary data as ratchet messages
    let _ = ratchet.process_message_bytes(data);
});
```

## Regression Corpus

Maintain a corpus of interesting inputs:

```bash
# Add new test case to corpus
cp interesting_input fuzz/corpus/message_parse/

# Run fuzzer starting from corpus
cargo fuzz run message_parse
```

## Continuous Fuzzing

For continuous fuzzing, consider:

1. **OSS-Fuzz**: Submit project to Google's OSS-Fuzz
2. **CI Integration**: Run short fuzz sessions in CI
3. **Dedicated Hardware**: Run 24/7 on spare machines

## Known Issues

List any known fuzzing findings here:

- [ ] Issue #1: Description of finding
- [ ] Issue #2: Description of finding