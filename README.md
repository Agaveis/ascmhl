# ascmhl

Read and validate [ASC Media Hash List](https://github.com/ascmitc/mhl) (MHL) manifests from Rust.

An `ascmhl/` folder travels with footage from the camera card through every copy. Each generation inside it records a content hash for every file. This crate opens the latest generation under a source directory, recomputes the hashes against the files that are there, and tells you whether they match.

## What it does

- Finds `ascmhl/` directly under the directory you pass, picks the highest-numbered `.mhl` file, and parses ASC MHL v2 (`<path>`) and v1 (`<file>`) entries.
- Recomputes **SHA-256, SHA-1 and MD5**, the fixed-width hex algorithms, and compares them to the manifest, ignoring case.
- Reports a manifest that carries only **xxh64, xxh3 or c4** as detected and unvalidated, with the reason, instead of passing it.
- Returns per-file detail: how many files matched, and a list of mismatches, missing files, and entries without a usable hash.

## What it does not do

- It never writes or generates an MHL. Read only.
- It never blocks or deletes anything. A mismatch is a result, not an error; your code decides what happens next.
- It does not implement the xxHash or C4 algorithms.

## Example

```rust
use std::path::Path;

fn main() -> Result<(), ascmhl::Error> {
    match ascmhl::detect_and_validate(Path::new("/media/card-001"))? {
        None => println!("no ascmhl/ folder here"),
        Some(outcome) if outcome.validated => println!(
            "generation {} validated with {}: {} of {} files matched",
            outcome.generation, outcome.algorithm, outcome.files_matched, outcome.files_in_manifest
        ),
        Some(outcome) => {
            println!("generation {} not validated ({})", outcome.generation, outcome.algorithm);
            for problem in &outcome.mismatches {
                println!("  {problem}");
            }
        }
    }
    Ok(())
}
```

`detect_and_validate` returns `Ok(None)` when there is no `ascmhl/` folder, `Ok(Some(outcome))` otherwise, and an `Err` only when the folder, a manifest or a listed file could not be read. `AscMhlOutcome::to_sidecar()` gives the compact `AscMhlValidation` record (generation, algorithm, counts, all matched) for storing next to your own records; it derives `serde::Serialize` and `Deserialize`.

## Where it comes from

This is the ASC MHL check from the [Hiberden](https://hiberden.app) archive engine, published on its own so other tools can use it. Hiberden runs it on every folder it archives and records the outcome; the engine itself is not part of this crate.

## License

MIT. See [LICENSE](LICENSE).

Built by [AgaveIS](https://agaveis.com) for [Hiberden](https://hiberden.app).
