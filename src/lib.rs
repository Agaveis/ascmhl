//! Read and validate [ASC MHL](https://github.com/ascmitc/mhl) (Media Hash
//! List) manifests.
//!
//! Post houses and DITs ship an `ascmhl/` folder alongside footage: a chain of
//! generation manifests that record each file's content hash. This crate finds
//! that folder directly under a source directory, parses the latest generation,
//! and recomputes the hashes against the files on disk. It reports; it never
//! acts:
//!
//! - **No `ascmhl/` directory: `Ok(None)`.** Nothing to report, so nothing is.
//! - **Mismatch: reported, never an error.** A divergence lands in the outcome's
//!   `mismatches` with `validated == false`. The caller decides what to do.
//! - **Read only.** This crate never writes or generates an MHL.
//!
//! Validation covers the fixed-width hex algorithms recomputed here: **SHA-256,
//! SHA-1 and MD5**. A manifest that carries only xxh64, xxh3 or c4 is **detected
//! and reported as unvalidated** with a plain reason, never passed.
//!
//! Extracted from the Hiberden archive engine, which runs this check on every
//! folder it archives and records the outcome. See <https://hiberden.app>.
//!
//! ```no_run
//! use std::path::Path;
//!
//! match ascmhl::detect_and_validate(Path::new("/media/card-001"))? {
//!     None => println!("no ascmhl/ folder"),
//!     Some(outcome) if outcome.validated => println!(
//!         "generation {} validated with {}",
//!         outcome.generation, outcome.algorithm
//!     ),
//!     Some(outcome) => println!("not validated: {:?}", outcome.mismatches),
//! }
//! # Ok::<(), ascmhl::Error>(())
//! ```

#![forbid(unsafe_code)]

mod error;

pub use error::{Error, Result};

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Read buffer for streaming a file through a digest.
const HASH_BUF_BYTES: usize = 2 * 1024 * 1024;

/// Lowercase hex of a digest.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Algorithms this crate can recompute to validate an MHL (standard lowercase
/// hex digests). Others (xxh64/xxh3/c4) are recognized but not recomputed here.
const SUPPORTED: &[&str] = &["sha256", "sha1", "md5"];
/// Hash element names recognized in an MHL `<hash>` block (a superset of
/// [`SUPPORTED`]); anything else inside a hash block is ignored.
const KNOWN_ALGOS: &[&str] = &["sha256", "sha1", "md5", "xxh64", "xxh3", "c4"];

/// The compact validation record a caller stores next to its own records when
/// an `ascmhl/` directory was found and processed: "validated against generation
/// N". Hiberden writes it into the archive's sidecar, hence [`AscMhlOutcome::to_sidecar`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AscMhlValidation {
    /// The generation number of the manifest that was read (highest present).
    pub generation: u32,
    /// The hash algorithm used to validate (e.g. `sha256`), or an
    /// `unsupported:<algo>` / `unparsed` marker when validation could not run.
    pub algorithm: String,
    pub files_in_manifest: usize,
    pub files_matched: usize,
    /// True only when every manifest file was present and matched.
    pub all_matched: bool,
}

/// The rich outcome of a detect+validate run, carrying per-file mismatch detail
/// for the caller's log line. Maps to the compact [`AscMhlValidation`].
#[derive(Debug, Clone)]
pub struct AscMhlOutcome {
    pub generation: u32,
    pub algorithm: String,
    pub files_in_manifest: usize,
    pub files_matched: usize,
    /// Human-readable per-file problems (mismatch, missing, no usable hash).
    pub mismatches: Vec<String>,
    /// True only when hashes were actually recomputed and every file matched.
    pub validated: bool,
}

impl AscMhlOutcome {
    /// The compact record a caller stores (named for its first home, an archive
    /// sidecar).
    pub fn to_sidecar(&self) -> AscMhlValidation {
        AscMhlValidation {
            generation: self.generation,
            algorithm: self.algorithm.clone(),
            files_in_manifest: self.files_in_manifest,
            files_matched: self.files_matched,
            all_matched: self.validated,
        }
    }
}

/// One file record parsed from an MHL manifest.
#[derive(Debug, Default, Clone)]
struct MhlEntry {
    path: String,
    /// `(algorithm, hex_value)` pairs declared for this file.
    hashes: Vec<(String, String)>,
}

/// Detect an `ascmhl/` directory directly under `source_dir`, parse its
/// latest-generation manifest, and validate its hashes against the files on
/// disk. Returns:
///
/// - `Ok(None)` when there is no `ascmhl/` directory (the silent, transparent
///   no-op; the caller records nothing).
/// - `Ok(Some(outcome))` otherwise, INCLUDING on mismatch or when the MHL's
///   algorithm cannot be recomputed here. A caller typically logs any non-clean
///   outcome and proceeds; nothing here blocks anything.
///
/// Never writes to the source directory. Never generates an MHL.
pub fn detect_and_validate(source_dir: &Path) -> Result<Option<AscMhlOutcome>> {
    let dir = source_dir.join("ascmhl");
    if !dir.is_dir() {
        return Ok(None); // transparent: no ASC MHL here
    }

    let Some((generation, mhl_path)) = latest_generation(&dir)? else {
        return Ok(Some(unvalidated(
            0,
            "none",
            0,
            "ascmhl/ is present but contains no .mhl manifest",
        )));
    };

    let xml = std::fs::read_to_string(&mhl_path).map_err(|e| Error::io_at(&mhl_path, e))?;
    let entries = match parse_mhl(&xml) {
        Ok(e) => e,
        Err(e) => {
            return Ok(Some(unvalidated(
                generation,
                "unparsed",
                0,
                &format!("could not parse MHL generation {generation}: {e}"),
            )))
        }
    };

    // Pick a validation algorithm: the first SUPPORTED algorithm present anywhere
    // in the manifest. If the MHL carries only unsupported algorithms, record the
    // detection but do not claim a validation we cannot perform.
    let algo = entries
        .iter()
        .flat_map(|e| e.hashes.iter().map(|(a, _)| a.as_str()))
        .find(|a| SUPPORTED.contains(a))
        .map(str::to_string);
    let Some(algo) = algo else {
        let found = entries
            .iter()
            .flat_map(|e| e.hashes.iter().map(|(a, _)| a.clone()))
            .next()
            .unwrap_or_else(|| "unknown".to_string());
        return Ok(Some(AscMhlOutcome {
            generation,
            algorithm: format!("unsupported:{found}"),
            files_in_manifest: entries.len(),
            files_matched: 0,
            mismatches: vec![format!(
                "MHL uses {found}, which this build does not recompute (supported: sha256, sha1, md5)"
            )],
            validated: false,
        }));
    };

    // Validate each manifest file's hash against the file on disk.
    let mut files_matched = 0;
    let mut mismatches = Vec::new();
    for e in &entries {
        let Some((_, expected)) = e.hashes.iter().find(|(a, _)| *a == algo) else {
            mismatches.push(format!("{}: no {algo} hash in the manifest entry", e.path));
            continue;
        };
        let file = source_dir.join(&e.path);
        match hash_file(&file, &algo) {
            Ok(got) if got.eq_ignore_ascii_case(expected) => files_matched += 1,
            Ok(got) => mismatches.push(format!("{}: expected {expected}, computed {got}", e.path)),
            Err(_) => mismatches.push(format!("{}: file missing or unreadable", e.path)),
        }
    }

    let validated = mismatches.is_empty() && !entries.is_empty();
    Ok(Some(AscMhlOutcome {
        generation,
        algorithm: algo,
        files_in_manifest: entries.len(),
        files_matched,
        mismatches,
        validated,
    }))
}

fn unvalidated(generation: u32, algo: &str, files: usize, reason: &str) -> AscMhlOutcome {
    AscMhlOutcome {
        generation,
        algorithm: algo.to_string(),
        files_in_manifest: files,
        files_matched: 0,
        mismatches: vec![reason.to_string()],
        validated: false,
    }
}

/// The `.mhl` file in `dir` with the highest generation (the leading number of
/// its name, e.g. `0003_...mhl`). Ties (or unnumbered names) break by file name
/// for determinism. `None` when there is no `.mhl` file.
fn latest_generation(dir: &Path) -> Result<Option<(u32, PathBuf)>> {
    let mut candidates: Vec<(u32, String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| Error::io_at(dir, e))? {
        let entry = entry.map_err(|e| Error::io_at(dir, e))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("mhl") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let gen = leading_number(&name).unwrap_or(0);
        candidates.push((gen, name, path));
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(candidates.pop().map(|(gen, _, path)| (gen, path)))
}

/// Leading ASCII-digit run of `s` parsed as a generation, if any.
fn leading_number(s: &str) -> Option<u32> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Parse an MHL manifest into `(path, [(algo, hex)])` records. Handles ASC MHL
/// v2 (`<path>`) and v1 (`<file>`) path elements and a default XML namespace.
/// A flat state machine: leaf elements inside a `<hash>` block are captured;
/// everything outside a hash block is ignored.
fn parse_mhl(xml: &str) -> std::result::Result<Vec<MhlEntry>, String> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    let mut entries: Vec<MhlEntry> = Vec::new();
    let mut cur: Option<MhlEntry> = None;
    let mut field: Option<String> = None;
    let mut text = String::new();

    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) => {
                let name = local_name(e.name().as_ref());
                if name == "hash" {
                    cur = Some(MhlEntry::default());
                } else {
                    field = Some(name);
                    text.clear();
                }
            }
            Event::Text(e) => {
                if field.is_some() {
                    text.push_str(&e.unescape().map_err(|x| x.to_string())?);
                }
            }
            Event::End(e) => {
                let name = local_name(e.name().as_ref());
                if name == "hash" {
                    if let Some(entry) = cur.take() {
                        if !entry.path.is_empty() {
                            entries.push(entry);
                        }
                    }
                } else if field.take().is_some() {
                    if let Some(entry) = cur.as_mut() {
                        let val = text.trim().to_string();
                        match name.as_str() {
                            "path" | "file" => entry.path = val,
                            a if KNOWN_ALGOS.contains(&a) => {
                                entry.hashes.push((a.to_string(), val))
                            }
                            _ => {}
                        }
                    }
                    text.clear();
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(entries)
}

/// Strip any namespace prefix from a raw element name (`ns:path` -> `path`).
fn local_name(name: &[u8]) -> String {
    let s = String::from_utf8_lossy(name);
    s.rsplit(':').next().unwrap_or(&s).to_string()
}

/// Compute a file's hash with the named algorithm, lowercase hex.
fn hash_file(path: &Path, algo: &str) -> Result<String> {
    match algo {
        "sha256" => digest_file::<sha2::Sha256>(path),
        "sha1" => digest_file::<sha1::Sha1>(path),
        "md5" => digest_file::<md5::Md5>(path),
        other => Err(Error::Invalid(format!(
            "unsupported MHL hash algorithm {other}"
        ))),
    }
}

/// Stream a file through a RustCrypto digest, returning lowercase hex.
fn digest_file<D: Digest>(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| Error::io_at(path, e))?;
    let mut hasher = D::new();
    let mut buf = vec![0u8; HASH_BUF_BYTES];
    loop {
        let n = f.read(&mut buf).map_err(|e| Error::io_at(path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Write a media file under `root` and return its md5 hex (what an MHL records).
    fn put_file(root: &Path, rel: &str, data: &[u8]) -> String {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, data).unwrap();
        let mut h = md5::Md5::new();
        h.update(data);
        hex_lower(&h.finalize())
    }

    /// Write an `ascmhl/NNNN_name.mhl` (v2-shaped) listing `(rel, md5)` entries.
    fn put_mhl(root: &Path, generation: u32, files: &[(&str, &str)]) {
        let dir = root.join("ascmhl");
        std::fs::create_dir_all(&dir).unwrap();
        let mut xml = String::from(
            "<?xml version=\"1.0\"?>\n<hashlist version=\"2.0\" xmlns=\"urn:ASC:MHL:v2.0\">\n<hashes>\n",
        );
        for (rel, md5) in files {
            xml.push_str(&format!(
                "<hash><path size=\"1\">{rel}</path><md5>{md5}</md5></hash>\n"
            ));
        }
        xml.push_str("</hashes>\n</hashlist>\n");
        std::fs::write(dir.join(format!("{generation:04}_take.mhl")), xml).unwrap();
    }

    #[test]
    fn no_ascmhl_directory_is_a_silent_no_op() {
        let root = tempdir().unwrap();
        std::fs::write(root.path().join("clip.mov"), b"footage").unwrap();
        assert!(
            detect_and_validate(root.path()).unwrap().is_none(),
            "absence of ascmhl/ yields no record at all"
        );
    }

    #[test]
    fn matching_mhl_validates_and_records_the_generation() {
        let root = tempdir().unwrap();
        let m1 = put_file(root.path(), "a.mov", b"alpha-footage");
        let m2 = put_file(root.path(), "sub/b.wav", b"bravo-audio");
        put_mhl(root.path(), 1, &[("a.mov", &m1), ("sub/b.wav", &m2)]);

        let out = detect_and_validate(root.path())
            .unwrap()
            .expect("ascmhl present");
        assert_eq!(out.generation, 1);
        assert_eq!(out.algorithm, "md5");
        assert_eq!(out.files_in_manifest, 2);
        assert_eq!(out.files_matched, 2);
        assert!(out.validated, "all hashes matched: {:?}", out.mismatches);

        let sc = out.to_sidecar();
        assert!(sc.all_matched);
        assert_eq!(sc.generation, 1);
    }

    #[test]
    fn latest_generation_wins_when_several_are_present() {
        let root = tempdir().unwrap();
        let m1 = put_file(root.path(), "a.mov", b"alpha");
        put_mhl(root.path(), 1, &[("a.mov", &m1)]);
        // A newer generation whose recorded hash is deliberately WRONG, to prove
        // the latest generation (not the first) is the one validated.
        put_mhl(
            root.path(),
            2,
            &[("a.mov", "00000000000000000000000000000000")],
        );

        let out = detect_and_validate(root.path()).unwrap().unwrap();
        assert_eq!(out.generation, 2, "the highest generation is read");
        assert!(
            !out.validated,
            "the newer generation's wrong hash is caught"
        );
        assert_eq!(out.files_matched, 0);
        assert_eq!(out.mismatches.len(), 1);
    }

    #[test]
    fn mismatch_is_recorded_but_never_an_error() {
        let root = tempdir().unwrap();
        let _ = put_file(root.path(), "a.mov", b"the real bytes");
        // MHL claims a different md5 than the file actually has.
        put_mhl(
            root.path(),
            1,
            &[("a.mov", "ffffffffffffffffffffffffffffffff")],
        );
        let out = detect_and_validate(root.path()).unwrap().unwrap();
        assert!(!out.validated);
        assert_eq!(out.files_matched, 0);
        assert!(out.mismatches[0].contains("a.mov"));
    }

    #[test]
    fn unsupported_algorithm_is_detected_not_silently_passed() {
        let root = tempdir().unwrap();
        std::fs::write(root.path().join("a.mov"), b"footage").unwrap();
        let dir = root.path().join("ascmhl");
        std::fs::create_dir_all(&dir).unwrap();
        // An xxh64-only MHL: recognized, but this build cannot recompute it.
        let xml = "<hashlist version=\"2.0\"><hashes><hash><path>a.mov</path>\
                   <xxh64>0123456789abcdef</xxh64></hash></hashes></hashlist>";
        std::fs::write(dir.join("0001_take.mhl"), xml).unwrap();

        let out = detect_and_validate(root.path()).unwrap().unwrap();
        assert!(out.algorithm.starts_with("unsupported:xxh64"));
        assert!(
            !out.validated,
            "never claims a validation it cannot perform"
        );
        assert!(out.mismatches[0].contains("xxh64"));
    }

    #[test]
    fn missing_file_named_in_the_manifest_is_flagged() {
        let root = tempdir().unwrap();
        // Manifest references a file that is not on disk.
        put_mhl(
            root.path(),
            1,
            &[("ghost.mov", "ffffffffffffffffffffffffffffffff")],
        );
        let out = detect_and_validate(root.path()).unwrap().unwrap();
        assert!(!out.validated);
        assert!(out.mismatches[0].contains("missing or unreadable"));
    }
}
