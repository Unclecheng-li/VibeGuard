use std::{collections::HashMap, sync::Arc};

use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;
use regex::Regex;
use tokio::sync::RwLock;
use tower_lsp::{
    Client, LanguageServer,
    jsonrpc::Result,
    lsp_types::{
        Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
        DidOpenTextDocumentParams, DidSaveTextDocumentParams, InitializeParams, InitializeResult,
        InitializedParams, MessageType, NumberOrString, Position, Range, ServerCapabilities,
        ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind, Url,
    },
};

const SOURCE: &str = "VibeGuard";

#[derive(Debug, Clone)]
pub struct L1Finding {
    pub code: &'static str,
    pub message: String,
    pub severity: DiagnosticSeverity,
    pub range: Range,
}

struct NativePackageRule {
    package: &'static str,
    alternatives: &'static [&'static str],
}

const NATIVE_PACKAGE_RULES: &[NativePackageRule] = &[
    NativePackageRule {
        package: "react-virtualized-auto-sizer",
        alternatives: &["react-virtualized", "react-window"],
    },
    NativePackageRule {
        package: "express-rate-limit-flex",
        alternatives: &["express-rate-limit"],
    },
    NativePackageRule {
        package: "secure-jwt-auth",
        alternatives: &["jsonwebtoken"],
    },
    NativePackageRule {
        package: "next-auth-middleware-secure",
        alternatives: &["next-auth"],
    },
    NativePackageRule {
        package: "openai-vision-client",
        alternatives: &["openai"],
    },
];

static NATIVE_PACKAGES: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasick::new(NATIVE_PACKAGE_RULES.iter().map(|rule| rule.package))
        .expect("the native package seed catalog must compile")
});

static NPM_IMPORT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?m)(?:\bimport\s*(?:[\w*${}, ]+?\s+from\s*)?|\brequire\s*\()\s*[\"'](?P<package>[^\"']+)[\"']"#,
    )
    .expect("the npm import pattern must compile")
});

static OPENAI_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b").expect("the OpenAI key pattern must compile")
});

struct CompiledConfigRule {
    code: &'static str,
    message: &'static str,
    severity: DiagnosticSeverity,
    pattern: Regex,
}

static CONFIG_RULES: Lazy<Vec<CompiledConfigRule>> = Lazy::new(|| {
    vec![
        config_rule(
            "insecure_config_debug_true",
            r"(?m)\bDEBUG\s*=\s*True\b",
            "Django/Flask debug mode is enabled.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_app_debug_true",
            r"(?i)\bapp\.debug\s*=\s*true\b",
            "Application debug mode is enabled.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_allowed_hosts_wildcard",
            r#"\bALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']\s*\]"#,
            "Django ALLOWED_HOSTS allows every host.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_cors_allow_all",
            r"\b(?:CORS_ALLOW_ALL|CORS_ALLOW_ALL_ORIGINS)\s*=\s*True\b",
            "CORS is configured to allow every origin.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_acao_wildcard",
            r#"(?i)Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']"#,
            "Access-Control-Allow-Origin is set to '*'.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_disable_host_check",
            r"(?i)\bDANGEROUSLY_DISABLE_HOST_CHECK\s*=\s*(?:true|1)\b",
            "Host header checks are disabled.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_csrf_exempt",
            r"(?:@csrf_exempt\b|\bcsrf_exempt\s*\()",
            "CSRF protection is disabled for this endpoint.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_spring_permit_all",
            r"\.permitAll\s*\(",
            "Spring Security permitAll() may expose an endpoint.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_spring_security_disable",
            r"(?i)\bsecurity\.disable\s*=\s*true\b",
            "Spring security appears to be disabled.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_cross_origin_wildcard",
            r#"@CrossOrigin\s*\([^)]*(?:origins\s*=\s*)?[\"']\*[\"'][^)]*\)"#,
            "Spring @CrossOrigin allows every origin.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_eval",
            r"\beval\s*\(",
            "eval() executes arbitrary code.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_python_exec",
            r"\bexec\s*\(",
            "exec() executes arbitrary Python code.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_pickle_loads",
            r"\bpickle\.loads?\s*\(",
            "pickle deserialization can execute arbitrary code.",
            DiagnosticSeverity::WARNING,
        ),
        config_rule(
            "insecure_config_yaml_load_without_loader",
            r"\byaml\.load\s*\(\s*[^,\n)]+?\s*\)",
            "yaml.load() is used without an explicit safe loader.",
            DiagnosticSeverity::WARNING,
        ),
    ]
});

fn config_rule(
    code: &'static str,
    pattern: &str,
    message: &'static str,
    severity: DiagnosticSeverity,
) -> CompiledConfigRule {
    CompiledConfigRule {
        code,
        message,
        severity,
        pattern: Regex::new(pattern).expect("the native config rule must compile"),
    }
}

pub fn scan_l1(source: &str) -> Vec<L1Finding> {
    let mut findings = scan_known_npm_packages(source);

    for matched in OPENAI_KEY.find_iter(source) {
        if matched.as_str().starts_with("sk-ant-") {
            continue;
        }
        findings.push(finding_for_range(
            source,
            matched.start(),
            matched.end(),
            "hardcoded_secret_openai_key",
            "OpenAI API key appears to be hardcoded. Rotate it and load it from a secure runtime source.",
            DiagnosticSeverity::ERROR,
        ));
    }

    for rule in CONFIG_RULES.iter() {
        for matched in rule.pattern.find_iter(source) {
            findings.push(finding_for_range(
                source,
                matched.start(),
                matched.end(),
                rule.code,
                rule.message,
                rule.severity,
            ));
        }
    }

    findings.sort_by_key(|finding| {
        (
            finding.range.start.line,
            finding.range.start.character,
            finding.range.end.line,
            finding.range.end.character,
            finding.code,
        )
    });
    findings
}

fn scan_known_npm_packages(source: &str) -> Vec<L1Finding> {
    let mut findings = Vec::new();
    for captures in NPM_IMPORT.captures_iter(source) {
        let Some(package) = captures.name("package") else {
            continue;
        };
        let Some(matched) = NATIVE_PACKAGES.find(package.as_str()) else {
            continue;
        };
        if matched.start() != 0 || matched.end() != package.as_str().len() {
            continue;
        }
        let rule = &NATIVE_PACKAGE_RULES[matched.pattern().as_usize()];
        let alternatives = rule.alternatives.join(", ");
        findings.push(finding_for_range(
            source,
            package.start(),
            package.end(),
            "hallucinated_package_npm",
            &format!(
                "\"{}\" is marked absent in the bundled npm seed catalog. Verify it before installing it. Suggested alternative: {}.",
                rule.package, alternatives
            ),
            DiagnosticSeverity::ERROR,
        ));
    }
    findings
}

fn finding_for_range(
    source: &str,
    start: usize,
    end: usize,
    code: &'static str,
    message: &str,
    severity: DiagnosticSeverity,
) -> L1Finding {
    L1Finding {
        code,
        message: message.to_owned(),
        severity,
        range: Range::new(position_at(source, start), position_at(source, end)),
    }
}

fn position_at(source: &str, byte_offset: usize) -> Position {
    debug_assert!(source.is_char_boundary(byte_offset));
    let before = &source[..byte_offset];
    let line = before.bytes().filter(|byte| *byte == b'\n').count() as u32;
    let line_start = before.rfind('\n').map_or(0, |index| index + 1);
    let character = source[line_start..byte_offset].encode_utf16().count() as u32;
    Position::new(line, character)
}

pub struct Backend {
    client: Client,
    documents: Arc<RwLock<HashMap<Url, String>>>,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            documents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn publish(&self, uri: Url, source: String) {
        let diagnostics = scan_l1(&source)
            .into_iter()
            .map(|finding| Diagnostic {
                range: finding.range,
                severity: Some(finding.severity),
                code: Some(NumberOrString::String(finding.code.to_owned())),
                code_description: None,
                source: Some(SOURCE.to_owned()),
                message: finding.message,
                related_information: None,
                tags: None,
                data: None,
            })
            .collect();
        self.client
            .publish_diagnostics(uri, diagnostics, None)
            .await;
    }

    async fn publish_open_document(&self, uri: Url) {
        let source = self.documents.read().await.get(&uri).cloned();
        if let Some(source) = source {
            self.publish(uri, source).await;
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: "VibeGuard Native L1".to_owned(),
                version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            }),
            ..InitializeResult::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(
                MessageType::INFO,
                "VibeGuard Native L1 is ready. The Node LSP remains the default until feature parity is complete.",
            )
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let document = params.text_document;
        let uri = document.uri;
        let source = document.text;
        self.documents
            .write()
            .await
            .insert(uri.clone(), source.clone());
        self.publish(uri, source).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let Some(source) = params
            .content_changes
            .last()
            .map(|change| change.text.clone())
        else {
            return;
        };
        self.documents
            .write()
            .await
            .insert(uri.clone(), source.clone());
        self.publish(uri, source).await;
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;
        if let Some(source) = params.text {
            self.documents.write().await.insert(uri.clone(), source);
        }
        self.publish_open_document(uri).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.documents.write().await.remove(&uri);
        self.client.publish_diagnostics(uri, Vec::new(), None).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_native_l1_rules_without_exposing_the_secret() {
        let source = concat!(
            "import \"react-virtualized-auto-sizer\";\n",
            "const OPENAI_API_KEY = \"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890\";\n",
            "app.debug = true;\n",
            "data = yaml.load(payload)\n"
        );

        let findings = scan_l1(source);
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        assert_eq!(
            codes,
            vec![
                "hallucinated_package_npm",
                "hardcoded_secret_openai_key",
                "insecure_config_app_debug_true",
                "insecure_config_yaml_load_without_loader",
            ]
        );
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("sk-proj-"))
        );
    }

    #[test]
    fn positions_are_utf16_columns() {
        let source =
            "const icon = \"😀\";\nconst token = \"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890\";";
        let finding = scan_l1(source)
            .into_iter()
            .find(|finding| finding.code == "hardcoded_secret_openai_key")
            .expect("the OpenAI key should be reported");
        let line = source.lines().nth(1).expect("second line should exist");
        let secret_offset = line.find("sk-proj-").expect("secret should exist");

        assert_eq!(
            finding.range.start,
            Position::new(1, line[..secret_offset].encode_utf16().count() as u32)
        );
    }

    #[test]
    fn ignores_unknown_npm_imports_in_the_preview_catalog() {
        let findings = scan_l1("import \"react\";");
        assert!(findings.is_empty());
    }
}
