Run the parser boundary with nightly Rust and `cargo-fuzz`:

```sh
cargo +nightly fuzz run parse -- -max_total_time=60
```

The target checks arbitrary UTF-8 imports, model validation, exact export/import
round trips and range coverage. It makes no network requests and never executes
configuration hooks. Corpus keys are public test fixtures, not real credentials.
Keep minimized regressions in `corpus/parse/`.
