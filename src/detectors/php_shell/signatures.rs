//! PHP webshell content signatures.
//!
//! No single keyword marks a webshell: WordPress core calls `base64_decode`,
//! Composer calls `proc_open`, and test suites call `assert`. What marks one is
//! user input reaching code execution, or code that hides what it executes.
//! Signatures carry a weight and a file is flagged on the sum.
//!
//! Extra signatures load from a JSON file (`STACKDOG_PHPSHELL_SIGNATURES`) so
//! a new shell family can be covered without a rebuild:
//!
//! ```json
//! [{"id": "acme-shell", "description": "ACME shell marker",
//!   "pattern": "acme_shell_v\\d", "weight": "strong"}]
//! ```

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Weight {
    Strong,
    Medium,
    Weak,
}

impl Weight {
    pub fn points(self) -> u32 {
        match self {
            Weight::Strong => 3,
            Weight::Medium => 2,
            Weight::Weak => 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub id: String,
    pub description: String,
    pub pattern: Regex,
    pub weight: Weight,
}

#[derive(Debug, Deserialize)]
struct SignatureSpec {
    id: String,
    description: String,
    pattern: String,
    weight: Weight,
}

const BUILTIN: &[(&str, &str, &str, Weight)] = &[
    (
        "superglobal-exec",
        "request input passed straight to a code or command execution function",
        r"\b(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|create_function)\s*\(\s*@?\s*(\$_(get|post|request|cookie|server|files)\b|stripslashes\s*\(\s*\$_|base64_decode\s*\(\s*\$_)",
        Weight::Strong,
    ),
    (
        "eval-decode-chain",
        "eval of decoded or deobfuscated data",
        r"\b(eval|assert)\s*\(\s*@?\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uudecode)\s*\(",
        Weight::Strong,
    ),
    (
        "superglobal-callable",
        "request input called as a function",
        r"\$_(get|post|request|cookie)\s*\[[^\]]{1,40}\]\s*\(",
        Weight::Strong,
    ),
    (
        "preg-replace-eval",
        "preg_replace with the /e modifier (executes the replacement)",
        r#"preg_replace\s*\(\s*['"]/[^'"]*/[a-df-z]*e[a-z]*['"]"#,
        Weight::Strong,
    ),
    (
        "backtick-superglobal",
        "shell backticks around request input",
        r"`[^`\n]{0,80}\$_(get|post|request|cookie)",
        Weight::Strong,
    ),
    (
        "known-family",
        "marker of a known webshell family",
        r"(c99shell|c99_buff_prepare|r57shell|wso_version|\bfilesman\b|b374k|p0wny|indoxploit|alfa_data|alfashell|weevely|\bphpspy\b|mini shell|anonsec shell)",
        Weight::Strong,
    ),
    (
        "nested-decode",
        "decode functions nested inside each other",
        r"\b(base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(",
        Weight::Medium,
    ),
    (
        "write-request-input",
        "request input written to a file",
        r"\b(file_put_contents|fwrite|fputs)\s*\([^;]{0,120}\$_(get|post|request|cookie)",
        Weight::Medium,
    ),
    (
        "silenced-errors",
        "error reporting switched off",
        r"\berror_reporting\s*\(\s*0\s*\)",
        Weight::Weak,
    ),
    (
        "no-time-limit",
        "execution time limit removed",
        r"\bset_time_limit\s*\(\s*0\s*\)",
        Weight::Weak,
    ),
    (
        "command-with-variable",
        "shell command built from a variable",
        r"\b(system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$",
        Weight::Weak,
    ),
];

#[derive(Debug, Clone)]
pub struct SignatureSet {
    signatures: Vec<Signature>,
}

impl SignatureSet {
    pub fn builtin() -> Self {
        let signatures = BUILTIN
            .iter()
            .map(|(id, description, pattern, weight)| Signature {
                id: (*id).to_string(),
                description: (*description).to_string(),
                pattern: compile(pattern).expect("built-in PHP shell signature compiles"),
                weight: *weight,
            })
            .collect();
        Self { signatures }
    }

    /// Built-ins plus the signatures in `path`.
    pub fn with_file(path: &str) -> Result<Self> {
        let mut set = Self::builtin();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read PHP shell signatures {}", path))?;
        let specs: Vec<SignatureSpec> = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse PHP shell signatures {}", path))?;

        for spec in specs {
            let pattern = compile(&spec.pattern)
                .with_context(|| format!("Invalid pattern in PHP shell signature {}", spec.id))?;
            set.signatures.push(Signature {
                id: spec.id,
                description: spec.description,
                pattern,
                weight: spec.weight,
            });
        }

        Ok(set)
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Signatures that match `content`, each counted once.
    pub fn matches<'a>(&'a self, content: &str) -> Vec<&'a Signature> {
        self.signatures
            .iter()
            .filter(|signature| signature.pattern.is_match(content))
            .collect()
    }
}

fn compile(pattern: &str) -> Result<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .build()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(set: &SignatureSet, content: &str) -> Vec<String> {
        set.matches(content)
            .into_iter()
            .map(|signature| signature.id.clone())
            .collect()
    }

    #[test]
    fn test_builtin_signatures_compile() {
        assert_eq!(SignatureSet::builtin().len(), BUILTIN.len());
    }

    #[test]
    fn test_china_chopper_one_liner() {
        let set = SignatureSet::builtin();
        assert!(ids(&set, r#"<?php @eval($_POST['x']);?>"#).contains(&"superglobal-exec".into()));
    }

    #[test]
    fn test_variable_function_shell() {
        let set = SignatureSet::builtin();
        assert!(ids(&set, r#"<?php $_GET['f']($_GET['c']); ?>"#)
            .contains(&"superglobal-callable".into()));
    }

    #[test]
    fn test_obfuscated_eval() {
        let set = SignatureSet::builtin();
        let found = ids(
            &set,
            r#"<?php eval(gzinflate(base64_decode('SGVsbG8='))); ?>"#,
        );
        assert!(found.contains(&"eval-decode-chain".into()));
        assert!(found.contains(&"nested-decode".into()));
    }

    #[test]
    fn test_preg_replace_e_modifier_but_not_other_modifiers() {
        let set = SignatureSet::builtin();
        assert!(ids(&set, r#"preg_replace("/.*/e", $_POST['c'], '');"#)
            .contains(&"preg-replace-eval".into()));
        assert!(!ids(&set, r#"preg_replace('/\s+/u', ' ', $title);"#)
            .contains(&"preg-replace-eval".into()));
    }

    #[test]
    fn test_ordinary_php_matches_nothing_strong() {
        let set = SignatureSet::builtin();
        let ordinary = r#"<?php
            $data = base64_decode($row['payload']);
            $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
            $stmt->execute([$_GET['id']]);
            assert($count > 0);
            echo htmlspecialchars($_POST['name']);
        "#;
        assert!(set
            .matches(ordinary)
            .iter()
            .all(|signature| signature.weight != Weight::Strong));
    }

    #[test]
    fn test_signature_file_extends_builtins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signatures.json");
        std::fs::write(
            &path,
            r#"[{"id":"acme","description":"ACME marker","pattern":"acme_shell_v\\d","weight":"strong"}]"#,
        )
        .unwrap();

        let set = SignatureSet::with_file(path.to_str().unwrap()).unwrap();
        assert_eq!(set.len(), BUILTIN.len() + 1);
        assert_eq!(ids(&set, "// ACME_SHELL_V2"), vec!["acme".to_string()]);
    }

    #[test]
    fn test_invalid_signature_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signatures.json");
        std::fs::write(
            &path,
            r#"[{"id":"bad","description":"x","pattern":"(","weight":"strong"}]"#,
        )
        .unwrap();
        assert!(SignatureSet::with_file(path.to_str().unwrap()).is_err());
    }
}
