//! PHP webshell detection.
//!
//! Two halves that share one list of flagged files:
//!
//! - [`PhpShellScanner`] reads PHP files under web roots — host paths and the
//!   docroots of PHP containers — and flags those whose content scores as a
//!   webshell. A file names no attacker, so this alerts and never bans.
//! - [`PhpShellAccessDetector`] watches access logs for requests to flagged
//!   files and for POSTs to PHP files in upload directories. Those lines carry
//!   the client address, so they feed the IP ban engine.

mod access;
pub mod signatures;

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::UNIX_EPOCH;

use anyhow::Result;
use chrono::Utc;
use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::database::connection::DbPool;
use crate::sniff::analyzer::AnomalySeverity;

use self::signatures::{SignatureSet, Weight};
use super::{DetectorFamily, DetectorFinding};

pub use self::access::{PhpShellAccessDetector, ACCESS_DETECTOR_ID};

pub const FILE_DETECTOR_ID: &str = "php.shell-file";

/// Score at which a file is reported. One strong signal, or a medium plus a
/// weak one; a PHP file in an upload directory alone (medium) is not enough,
/// because plugins drop `<?php // Silence is golden` index files there.
const FLAG_THRESHOLD: u32 = 3;
/// A strong signal plus corroboration (an upload directory, a second strong one).
const CRITICAL_THRESHOLD: u32 = 5;
/// A run of base64/hex this long on one line is a packed payload, not code.
const ENCODED_BLOB_MIN_LEN: usize = 1000;
const MAX_FILES_PER_ROOT: usize = 200_000;

const PHP_EXTENSIONS: &[&str] = &[
    "php", "phtml", "phar", "php3", "php4", "php5", "php7", "php8", "pht", "phps",
];

/// Path segments under which no PHP should be executed.
const UPLOAD_DIR_SEGMENTS: &[&str] = &["uploads", "upload", "tmp", "temp", "files", "images"];

/// Where PHP images and compose files put the document root.
pub const DOCROOT_PREFIXES: &[&str] = &["/var/www", "/usr/share/nginx/html", "/srv", "/app"];

/// Container name or image fragments that mark a PHP workload.
pub const DEFAULT_CONTAINER_PATTERNS: &[&str] = &[
    "php",
    "wordpress",
    "drupal",
    "joomla",
    "laravel",
    "magento",
    "apache",
    "httpd",
];

pub const DEFAULT_SKIP_DIRS: &[&str] = &["vendor", "node_modules", ".git"];
pub const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// A directory to scan, and how to name its files in alerts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRoot {
    /// Where Stackdog reads the files (may sit under the host-root mount).
    pub fs_path: PathBuf,
    /// The path as the workload sees it, e.g. `/var/www/html`.
    pub logical_path: String,
    /// Who owns it: `host` or a container name.
    pub owner: String,
}

#[derive(Debug, Clone)]
pub struct PhpShellOptions {
    pub max_file_bytes: u64,
    pub skip_dirs: Vec<String>,
    pub signatures_path: Option<String>,
}

impl Default for PhpShellOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            skip_dirs: DEFAULT_SKIP_DIRS
                .iter()
                .map(|dir| dir.to_string())
                .collect(),
            signatures_path: None,
        }
    }
}

/// What a running container exposes to the scanner.
#[derive(Debug, Clone, Default)]
pub struct ContainerFilesystem {
    pub id: String,
    pub name: String,
    pub image: String,
    /// `(source on the host, destination in the container)`.
    pub mounts: Vec<(String, String)>,
    /// overlay2 `MergedDir`: the container's root filesystem on the host.
    pub merged_dir: Option<String>,
}

/// A file the scanner flagged, as the access detector needs to know it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlaggedFile {
    /// Path as the workload sees it, lowercased: `/var/www/html/up/x.php`.
    pub logical_path: String,
    pub in_upload_dir: bool,
}

pub type FlaggedFiles = Arc<RwLock<Vec<FlaggedFile>>>;

#[derive(Debug, Clone)]
struct CachedScan {
    size_bytes: u64,
    modified_at: i64,
    score: u32,
    logical_path: String,
    in_upload_dir: bool,
}

#[derive(Debug, Default)]
pub struct PhpShellScanner {
    flagged: FlaggedFiles,
    signatures: Mutex<Option<(Option<String>, Arc<SignatureSet>)>>,
}

impl PhpShellScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Shared handle the access detector reads.
    pub fn flagged_files(&self) -> FlaggedFiles {
        Arc::clone(&self.flagged)
    }

    /// Scan `roots`, report files that are new or changed since the last pass
    /// and score as a webshell, and refresh the flagged list.
    pub fn detect(
        &self,
        pool: &DbPool,
        roots: &[ScanRoot],
        options: &PhpShellOptions,
    ) -> Result<Vec<DetectorFinding>> {
        if roots.is_empty() {
            self.set_flagged(Vec::new());
            return Ok(Vec::new());
        }

        let signatures = self.signature_set(options);
        let cached = load_cache(pool)?;
        let mut current: HashMap<String, CachedScan> = HashMap::new();
        let mut findings = Vec::new();
        let conn = pool.get()?;

        for root in roots {
            let mut candidates = Vec::new();
            collect_candidates(root, &root.fs_path, options, &mut candidates);
            if candidates.len() > MAX_FILES_PER_ROOT {
                log::warn!(
                    "PHP shell scan: {} has {} candidate files, scanning the first {}",
                    root.fs_path.display(),
                    candidates.len(),
                    MAX_FILES_PER_ROOT
                );
                candidates.truncate(MAX_FILES_PER_ROOT);
            }

            for (path, metadata) in candidates {
                let key = path.to_string_lossy().into_owned();
                let size_bytes = metadata.len();
                let modified_at = modified_secs(&metadata);

                if let Some(hit) = cached.get(&key) {
                    if hit.size_bytes == size_bytes && hit.modified_at == modified_at {
                        current.insert(key, hit.clone());
                        continue;
                    }
                }

                let Some(content) = read_bounded(&path, options.max_file_bytes) else {
                    continue;
                };
                let logical_path = logical_path(root, &path);
                let in_upload_dir = in_upload_dir_under(root, &path);
                let verdict = score_file(&signatures, &path, &content, in_upload_dir);
                let sha256 = format!("{:x}", Sha256::digest(&content));

                conn.execute(
                    "INSERT INTO php_shell_scans (
                        path, owner, logical_path, size_bytes, modified_at, sha256,
                        score, rules, in_upload_dir, scanned_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                     ON CONFLICT(path) DO UPDATE SET
                        owner = excluded.owner,
                        logical_path = excluded.logical_path,
                        size_bytes = excluded.size_bytes,
                        modified_at = excluded.modified_at,
                        sha256 = excluded.sha256,
                        score = excluded.score,
                        rules = excluded.rules,
                        in_upload_dir = excluded.in_upload_dir,
                        scanned_at = excluded.scanned_at",
                    params![
                        &key,
                        &root.owner,
                        &logical_path,
                        size_bytes as i64,
                        modified_at,
                        &sha256,
                        verdict.score as i64,
                        verdict.rules.join(","),
                        in_upload_dir as i64,
                        Utc::now().to_rfc3339(),
                    ],
                )?;

                if verdict.score >= FLAG_THRESHOLD {
                    findings.push(file_finding(root, &logical_path, &sha256, &verdict));
                }

                current.insert(
                    key,
                    CachedScan {
                        size_bytes,
                        modified_at,
                        score: verdict.score,
                        logical_path,
                        in_upload_dir,
                    },
                );
            }
        }

        // A file that is gone, or a root that is no longer scanned, leaves the
        // cache: if it comes back it is scanned — and reported — again.
        for path in cached.keys() {
            if !current.contains_key(path) {
                conn.execute("DELETE FROM php_shell_scans WHERE path = ?1", params![path])?;
            }
        }

        self.set_flagged(
            current
                .values()
                .filter(|scan| scan.score >= FLAG_THRESHOLD)
                .map(|scan| FlaggedFile {
                    logical_path: scan.logical_path.to_ascii_lowercase(),
                    in_upload_dir: scan.in_upload_dir,
                })
                .collect(),
        );

        findings.sort_by(|left, right| left.sample_line.cmp(&right.sample_line));
        Ok(findings)
    }

    fn set_flagged(&self, files: Vec<FlaggedFile>) {
        if let Ok(mut flagged) = self.flagged.write() {
            *flagged = files;
        }
    }

    fn signature_set(&self, options: &PhpShellOptions) -> Arc<SignatureSet> {
        let mut slot = self
            .signatures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some((path, set)) = slot.as_ref() {
            if path == &options.signatures_path {
                return Arc::clone(set);
            }
        }

        let set = match options.signatures_path.as_deref() {
            Some(path) => SignatureSet::with_file(path).unwrap_or_else(|err| {
                log::warn!("{:#}; using built-in PHP shell signatures only", err);
                SignatureSet::builtin()
            }),
            None => SignatureSet::builtin(),
        };
        let set = Arc::new(set);
        *slot = Some((options.signatures_path.clone(), Arc::clone(&set)));
        set
    }
}

struct Verdict {
    score: u32,
    rules: Vec<String>,
}

fn score_file(signatures: &SignatureSet, path: &Path, content: &[u8], upload_dir: bool) -> Verdict {
    let text = String::from_utf8_lossy(content);
    let mut score = 0;
    let mut rules = Vec::new();

    for signature in signatures.matches(&text) {
        score += signature.weight.points();
        rules.push(signature.id.clone());
    }

    if upload_dir {
        if has_php_extension(path) {
            score += Weight::Medium.points();
            rules.push("php-in-upload-dir".into());
        } else if contains_php_open_tag(&text) {
            // An "image" in an upload directory that carries PHP is a polyglot
            // waiting for an include(). Weak on its own: config files and docs
            // mention "<?php" in comments; a real polyglot also carries code.
            score += Weight::Weak.points();
            rules.push("php-in-non-php-file".into());
        }
    }

    if has_encoded_blob(&text) {
        score += Weight::Weak.points();
        rules.push("encoded-blob".into());
    }

    Verdict { score, rules }
}

fn file_finding(
    root: &ScanRoot,
    logical_path: &str,
    sha256: &str,
    verdict: &Verdict,
) -> DetectorFinding {
    DetectorFinding {
        detector_id: FILE_DETECTOR_ID.into(),
        family: DetectorFamily::Web,
        description: format!(
            "PHP shell indicators in {} on {} (score {}: {}; sha256 {})",
            logical_path,
            root.owner,
            verdict.score,
            verdict.rules.join(", "),
            &sha256[..16.min(sha256.len())]
        ),
        severity: if verdict.score >= CRITICAL_THRESHOLD {
            AnomalySeverity::Critical
        } else {
            AnomalySeverity::High
        },
        confidence: (60 + verdict.score * 5).min(97) as u8,
        sample_line: format!("{}:{}", root.owner, logical_path),
    }
}

fn load_cache(pool: &DbPool) -> Result<HashMap<String, CachedScan>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT path, size_bytes, modified_at, score, logical_path, in_upload_dir
         FROM php_shell_scans",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            CachedScan {
                size_bytes: row.get::<_, i64>(1)? as u64,
                modified_at: row.get(2)?,
                score: row.get::<_, i64>(3)? as u32,
                logical_path: row.get(4)?,
                in_upload_dir: row.get::<_, i64>(5)? != 0,
            },
        ))
    })?;

    let mut cache = HashMap::new();
    for row in rows {
        let (path, scan) = row?;
        cache.insert(path, scan);
    }
    Ok(cache)
}

/// Walk `dir` for files worth reading: PHP by extension anywhere, and any
/// file inside an upload directory. Unreadable entries are skipped — a web
/// root routinely holds files Stackdog may not open, and one of them must not
/// stop the scan of the rest.
fn collect_candidates(
    root: &ScanRoot,
    dir: &Path,
    options: &PhpShellOptions,
    out: &mut Vec<(PathBuf, fs::Metadata)>,
) {
    let metadata = match fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(err) => {
            log::debug!("PHP shell scan: skipping {}: {}", dir.display(), err);
            return;
        }
    };

    if metadata.file_type().is_symlink() {
        return;
    }

    if metadata.is_file() {
        if has_php_extension(dir) || in_upload_dir_under(root, dir) {
            out.push((dir.to_path_buf(), metadata));
        }
        return;
    }

    if !metadata.is_dir() || out.len() > MAX_FILES_PER_ROOT {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            log::debug!("PHP shell scan: cannot read {}: {}", dir.display(), err);
            return;
        }
    };

    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    paths.sort();

    for path in paths {
        let skipped = path
            .file_name()
            .map(|name| options.skip_dirs.iter().any(|skip| name == skip.as_str()))
            .unwrap_or(false);
        if skipped && path.is_dir() {
            continue;
        }
        collect_candidates(root, &path, options, out);
    }
}

fn read_bounded(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            log::debug!("PHP shell scan: cannot open {}: {}", path.display(), err);
            return None;
        }
    };
    let mut content = Vec::new();
    file.take(max_bytes).read_to_end(&mut content).ok()?;
    Some(content)
}

fn modified_secs(metadata: &fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn logical_path(root: &ScanRoot, path: &Path) -> String {
    let relative = path.strip_prefix(&root.fs_path).unwrap_or(path);
    let base = root.logical_path.trim_end_matches('/');
    let relative = relative.to_string_lossy();
    if relative.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base, relative.trim_start_matches('/'))
    }
}

fn has_php_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| PHP_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Upload directory, judged inside the root only. Where the root itself sits
/// says nothing: a site deployed under `/srv/files/` or a temp checkout would
/// otherwise make every file in it an "upload". The root's own name does
/// count, for a volume mounted straight at `.../wp-content/uploads`.
fn in_upload_dir_under(root: &ScanRoot, path: &Path) -> bool {
    let relative = path.strip_prefix(&root.fs_path).unwrap_or(path);
    let root_name = root
        .logical_path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    in_upload_dir(&format!("/{}/{}", root_name, relative.to_string_lossy()))
}

pub(crate) fn in_upload_dir(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower
        .split('/')
        .rev()
        .skip(1) // the file name itself
        .any(|segment| UPLOAD_DIR_SEGMENTS.contains(&segment))
}

fn contains_php_open_tag(text: &str) -> bool {
    text.to_ascii_lowercase().contains("<?php")
}

fn has_encoded_blob(text: &str) -> bool {
    let mut run = 0;
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=') {
            run += 1;
            if run >= ENCODED_BLOB_MIN_LEN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Join a host path onto the host-root mount (`/host` when Stackdog runs in a
/// container with `/:/host:ro`; empty when it runs on the host).
pub fn under_host_root(host_root: Option<&str>, path: &str) -> PathBuf {
    match host_root
        .map(|root| root.trim_end_matches('/'))
        .filter(|root| !root.is_empty())
    {
        Some(root) => PathBuf::from(format!("{}/{}", root, path.trim_start_matches('/'))),
        None => PathBuf::from(path),
    }
}

/// Roots for paths configured on the host.
pub fn host_roots(paths: &[String], host_root: Option<&str>) -> Vec<ScanRoot> {
    paths
        .iter()
        .map(|path| path.trim())
        .filter(|path| !path.is_empty())
        .map(|path| ScanRoot {
            fs_path: under_host_root(host_root, path),
            logical_path: path.to_string(),
            owner: "host".into(),
        })
        .collect()
}

/// Docroots of PHP containers.
///
/// A container counts as PHP when its name or image matches `patterns`, or
/// when something is mounted at a docroot. Mounted docroots are read at their
/// host source; docroots baked into the image are read through the overlay
/// `MergedDir`. Both live on the host, so both go through `host_root`.
pub fn container_roots(
    containers: &[ContainerFilesystem],
    patterns: &[String],
    host_root: Option<&str>,
) -> Vec<ScanRoot> {
    let mut roots = Vec::new();

    for container in containers {
        let docroot_mounts: Vec<&(String, String)> = container
            .mounts
            .iter()
            .filter(|(_, destination)| is_docroot(destination))
            .collect();

        let identity = format!("{} {}", container.name, container.image).to_ascii_lowercase();
        let looks_php = patterns
            .iter()
            .any(|pattern| identity.contains(pattern.as_str()));
        if !looks_php && docroot_mounts.is_empty() {
            continue;
        }

        for (source, destination) in &docroot_mounts {
            roots.push(ScanRoot {
                fs_path: under_host_root(host_root, source),
                logical_path: destination.clone(),
                owner: container.name.clone(),
            });
        }

        if !looks_php {
            continue;
        }
        let Some(merged) = container.merged_dir.as_deref() else {
            continue;
        };
        for prefix in DOCROOT_PREFIXES {
            // Covered by a mount already: the overlay shows nothing there.
            if docroot_mounts
                .iter()
                .any(|(_, destination)| path_within(prefix, destination))
            {
                continue;
            }
            let fs_path = under_host_root(host_root, &format!("{}{}", merged, prefix));
            if fs_path.is_dir() {
                roots.push(ScanRoot {
                    fs_path,
                    logical_path: (*prefix).to_string(),
                    owner: container.name.clone(),
                });
            }
        }
    }

    roots
}

fn is_docroot(destination: &str) -> bool {
    DOCROOT_PREFIXES
        .iter()
        .any(|prefix| path_within(destination, prefix))
}

/// `path` is `base` or below it.
fn path_within(path: &str, base: &str) -> bool {
    let base = base.trim_end_matches('/');
    path == base || path.starts_with(&format!("{}/", base))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::{create_pool, init_database};

    const SHELL: &str = "<?php @eval($_POST['x']); ?>";

    fn pool() -> DbPool {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        pool
    }

    fn root(dir: &Path) -> ScanRoot {
        ScanRoot {
            fs_path: dir.to_path_buf(),
            logical_path: "/var/www/html".into(),
            owner: "host".into(),
        }
    }

    #[test]
    fn test_flags_dropped_shell_and_reports_it_once() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("wp-content/uploads/2026")).unwrap();
        fs::write(dir.path().join("wp-content/uploads/2026/x.php"), SHELL).unwrap();
        fs::write(
            dir.path().join("index.php"),
            "<?php require 'wp-blog-header.php';",
        )
        .unwrap();

        let pool = pool();
        let scanner = PhpShellScanner::new();
        let roots = vec![root(dir.path())];
        let options = PhpShellOptions::default();

        let findings = scanner.detect(&pool, &roots, &options).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector_id, FILE_DETECTOR_ID);
        assert!(findings[0]
            .description
            .contains("/var/www/html/wp-content/uploads/2026/x.php"));
        assert_eq!(findings[0].severity, AnomalySeverity::Critical);

        // Unchanged on the next pass: no second alert, still flagged.
        assert!(scanner.detect(&pool, &roots, &options).unwrap().is_empty());
        let flagged = scanner.flagged_files();
        let flagged = flagged.read().unwrap();
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].in_upload_dir);
    }

    #[test]
    fn test_changed_file_is_rescanned() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("helper.php");
        fs::write(&file, "<?php echo 'ok';").unwrap();

        let pool = pool();
        let scanner = PhpShellScanner::new();
        let roots = vec![root(dir.path())];
        let options = PhpShellOptions::default();
        assert!(scanner.detect(&pool, &roots, &options).unwrap().is_empty());

        fs::write(&file, format!("<?php echo 'ok'; {}", SHELL)).unwrap();
        let findings = scanner.detect(&pool, &roots, &options).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_benign_php_is_not_flagged() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("wp-content/uploads")).unwrap();
        fs::write(
            dir.path().join("wp-content/uploads/index.php"),
            "<?php // Silence is golden.",
        )
        .unwrap();
        fs::write(
            dir.path().join("wp-config.php"),
            "<?php define('AUTH_KEY', 'x'); $data = base64_decode($opt); error_reporting(0);",
        )
        .unwrap();

        let findings = PhpShellScanner::new()
            .detect(&pool(), &[root(dir.path())], &PhpShellOptions::default())
            .unwrap();
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn test_php_hidden_in_image_upload() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("uploads")).unwrap();
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(b"<?php system($_GET['c']); ?>");
        fs::write(dir.path().join("uploads/avatar.gif"), gif).unwrap();

        let findings = PhpShellScanner::new()
            .detect(&pool(), &[root(dir.path())], &PhpShellOptions::default())
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("php-in-non-php-file"));
    }

    #[test]
    fn test_skip_dirs_are_not_scanned() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vendor/acme")).unwrap();
        fs::write(dir.path().join("vendor/acme/shell.php"), SHELL).unwrap();

        let findings = PhpShellScanner::new()
            .detect(&pool(), &[root(dir.path())], &PhpShellOptions::default())
            .unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_removed_shell_leaves_flagged_list() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.php");
        fs::write(&file, SHELL).unwrap();

        let pool = pool();
        let scanner = PhpShellScanner::new();
        let roots = vec![root(dir.path())];
        let options = PhpShellOptions::default();
        assert_eq!(scanner.detect(&pool, &roots, &options).unwrap().len(), 1);

        fs::remove_file(&file).unwrap();
        scanner.detect(&pool, &roots, &options).unwrap();
        assert!(scanner.flagged_files().read().unwrap().is_empty());
    }

    #[test]
    fn test_upload_dir_is_judged_inside_the_root() {
        let site = ScanRoot {
            fs_path: PathBuf::from("/srv/files/site"),
            logical_path: "/srv/files/site".into(),
            owner: "host".into(),
        };
        assert!(!in_upload_dir_under(
            &site,
            Path::new("/srv/files/site/index.php")
        ));
        assert!(in_upload_dir_under(
            &site,
            Path::new("/srv/files/site/uploads/x.php")
        ));

        let uploads_volume = ScanRoot {
            fs_path: PathBuf::from("/host/var/lib/docker/volumes/up/_data"),
            logical_path: "/var/www/html/wp-content/uploads".into(),
            owner: "blog".into(),
        };
        assert!(in_upload_dir_under(
            &uploads_volume,
            Path::new("/host/var/lib/docker/volumes/up/_data/2026/x.php")
        ));
    }

    #[test]
    fn test_in_upload_dir_ignores_file_name() {
        assert!(in_upload_dir("/var/www/html/wp-content/uploads/x.php"));
        assert!(!in_upload_dir("/var/www/html/uploads.php"));
        assert!(!in_upload_dir("/var/www/html/index.php"));
    }

    #[test]
    fn test_host_roots_go_under_host_root() {
        let roots = host_roots(&["/var/www".into()], Some("/host"));
        assert_eq!(roots[0].fs_path, PathBuf::from("/host/var/www"));
        assert_eq!(roots[0].logical_path, "/var/www");

        let roots = host_roots(&["/var/www".into()], None);
        assert_eq!(roots[0].fs_path, PathBuf::from("/var/www"));
    }

    #[test]
    fn test_container_roots_from_mounts_and_name() {
        let patterns: Vec<String> = DEFAULT_CONTAINER_PATTERNS
            .iter()
            .map(|p| p.to_string())
            .collect();
        let containers = vec![
            ContainerFilesystem {
                name: "blog".into(),
                image: "wordpress:6".into(),
                mounts: vec![("/srv/blog".into(), "/var/www/html".into())],
                ..Default::default()
            },
            ContainerFilesystem {
                name: "custom-app".into(),
                image: "acme/site".into(),
                mounts: vec![("/data/site".into(), "/var/www".into())],
                ..Default::default()
            },
            ContainerFilesystem {
                name: "postgres".into(),
                image: "postgres:16".into(),
                mounts: vec![("/var/lib/pg".into(), "/var/lib/postgresql/data".into())],
                ..Default::default()
            },
        ];

        let roots = container_roots(&containers, &patterns, Some("/host"));
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].fs_path, PathBuf::from("/host/srv/blog"));
        assert_eq!(roots[0].logical_path, "/var/www/html");
        assert_eq!(roots[0].owner, "blog");
        assert_eq!(roots[1].owner, "custom-app");
    }

    #[test]
    fn test_container_roots_read_image_docroot_through_merged_dir() {
        let host = tempfile::tempdir().unwrap();
        fs::create_dir_all(
            host.path()
                .join("var/lib/docker/overlay2/abc/merged/var/www/html"),
        )
        .unwrap();

        let containers = vec![ContainerFilesystem {
            name: "php-site".into(),
            image: "php:8.3-apache".into(),
            merged_dir: Some("/var/lib/docker/overlay2/abc/merged".into()),
            ..Default::default()
        }];
        let patterns = vec!["php".to_string()];

        let roots = container_roots(&containers, &patterns, host.path().to_str());
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].logical_path, "/var/www");
        assert!(roots[0].fs_path.ends_with("merged/var/www"));
    }

    /// False-positive check against real code, vendor directories included:
    /// `STACKDOG_PHPSHELL_CORPUS=/path/to/wordpress cargo test --lib -- --ignored php_shell_corpus`
    #[test]
    #[ignore]
    fn test_php_shell_corpus_has_no_findings() {
        let Ok(corpus) = std::env::var("STACKDOG_PHPSHELL_CORPUS") else {
            return;
        };
        let options = PhpShellOptions {
            skip_dirs: Vec::new(),
            ..PhpShellOptions::default()
        };
        let roots: Vec<ScanRoot> = corpus
            .split(',')
            .map(|path| ScanRoot {
                fs_path: PathBuf::from(path),
                logical_path: path.to_string(),
                owner: "corpus".into(),
            })
            .collect();

        let findings = PhpShellScanner::new()
            .detect(&pool(), &roots, &options)
            .unwrap();
        for finding in &findings {
            eprintln!("{}", finding.description);
        }
        assert!(findings.is_empty(), "{} files flagged", findings.len());
    }
}
