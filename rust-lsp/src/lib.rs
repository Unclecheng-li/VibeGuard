use std::{
    collections::HashMap,
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use aho_corasick::AhoCorasick;
use flate2::read::GzDecoder;
use globset::GlobBuilder;
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_lsp::{
    Client, LanguageServer,
    jsonrpc::Result,
    lsp_types::{
        CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams, Command, Diagnostic,
        DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
        DidOpenTextDocumentParams, DidSaveTextDocumentParams, ExecuteCommandOptions,
        ExecuteCommandParams, InitializeParams, InitializeResult, InitializedParams, MessageType,
        NumberOrString, Position, Range, ServerCapabilities, ServerInfo,
        TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Url, WorkspaceEdit,
    },
};

const SOURCE: &str = "VibeGuard";
const NATIVE_IGNORE_COMMAND: &str = "vibeguard.native.ignoreFinding";

#[derive(Debug, Clone)]
pub struct L1Finding {
    pub code: &'static str,
    pub message: String,
    pub severity: DiagnosticSeverity,
    pub range: Range,
    fixes: Vec<L1QuickFix>,
    package: Option<PackageEvidence>,
}

#[derive(Debug, Clone)]
struct L1QuickFix {
    title: String,
    replacement: String,
    is_preferred: bool,
}

#[derive(Debug, Clone)]
struct PackageEvidence {
    registry: PackageRegistry,
    package: String,
}

#[derive(Debug, Clone, Default)]
struct NativePackageIndex {
    registries: HashMap<PackageRegistry, NativeIndexRegistry>,
    sqlite: Option<Arc<NativeSqlitePackageIndex>>,
}

#[derive(Debug, Clone)]
struct NativeIndexRegistry {
    coverage: NativeIndexCoverage,
    packages: std::collections::HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeIndexCoverage {
    Partial,
    Full,
}

#[derive(Debug)]
struct NativeSqlitePackageIndex {
    registries: HashMap<PackageRegistry, NativeIndexCoverage>,
    connection: std::sync::Mutex<Connection>,
}

#[derive(Debug, Deserialize)]
struct SharedPackageIndexFile {
    #[serde(default)]
    registries: HashMap<String, SharedPackageIndexRegistry>,
}

#[derive(Debug, Deserialize)]
struct SharedPackageIndexRegistry {
    #[serde(default)]
    coverage: String,
    #[serde(default)]
    packages: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NativeIgnoreRules {
    #[serde(default)]
    ignore: Vec<NativeIgnoreRule>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NativeIgnoreRule {
    #[serde(default)]
    rule: Option<String>,
    #[serde(default)]
    rules: Option<Vec<String>>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    registry: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NativeIgnoreScope {
    Line,
    File,
    Global,
    Package,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NativeIgnoreCommand {
    uri: String,
    code: String,
    range: Range,
    scope: NativeIgnoreScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PackageRegistry {
    Npm,
    Pypi,
    Cargo,
    GoMod,
    Maven,
}

impl PackageRegistry {
    fn config_identifier(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Cargo => "cargo",
            Self::GoMod => "gomod",
            Self::Maven => "maven",
        }
    }

    fn from_config_identifier(value: &str) -> Option<Self> {
        match value {
            "npm" => Some(Self::Npm),
            "pypi" => Some(Self::Pypi),
            "cargo" => Some(Self::Cargo),
            "gomod" => Some(Self::GoMod),
            "maven" => Some(Self::Maven),
            _ => None,
        }
    }

    fn identifier(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "PyPI",
            Self::Cargo => "Cargo",
            Self::GoMod => "Go module",
            Self::Maven => "Maven",
        }
    }

    fn finding_code(self) -> &'static str {
        match self {
            Self::Npm => "hallucinated_package_npm",
            Self::Pypi => "hallucinated_package_pypi",
            Self::Cargo => "hallucinated_package_cargo",
            Self::GoMod => "hallucinated_package_gomod",
            Self::Maven => "hallucinated_package_maven",
        }
    }
}

struct NativePackageRule {
    registry: PackageRegistry,
    package: &'static str,
    alternatives: &'static [&'static str],
}

const NATIVE_PACKAGE_RULES: &[NativePackageRule] = &[
    NativePackageRule {
        registry: PackageRegistry::Npm,
        package: "react-virtualized-auto-sizer",
        alternatives: &["react-virtualized", "react-window"],
    },
    NativePackageRule {
        registry: PackageRegistry::Npm,
        package: "express-rate-limit-flex",
        alternatives: &["express-rate-limit"],
    },
    NativePackageRule {
        registry: PackageRegistry::Npm,
        package: "secure-jwt-auth",
        alternatives: &["jsonwebtoken"],
    },
    NativePackageRule {
        registry: PackageRegistry::Npm,
        package: "next-auth-middleware-secure",
        alternatives: &["next-auth"],
    },
    NativePackageRule {
        registry: PackageRegistry::Npm,
        package: "openai-vision-client",
        alternatives: &["openai"],
    },
    NativePackageRule {
        registry: PackageRegistry::Pypi,
        package: "torch-vision-utils",
        alternatives: &["torchvision", "torch"],
    },
    NativePackageRule {
        registry: PackageRegistry::Pypi,
        package: "fastapi-limiter-middleware",
        alternatives: &["slowapi", "fastapi-limiter"],
    },
    NativePackageRule {
        registry: PackageRegistry::Pypi,
        package: "django-secure-auth",
        alternatives: &["django-allauth", "django"],
    },
    NativePackageRule {
        registry: PackageRegistry::Pypi,
        package: "openai-secret-manager",
        alternatives: &["openai", "python-dotenv"],
    },
    NativePackageRule {
        registry: PackageRegistry::Pypi,
        package: "pandas-ai-utils",
        alternatives: &["pandas"],
    },
    NativePackageRule {
        registry: PackageRegistry::Cargo,
        package: "actix-web-secure-middleware",
        alternatives: &["actix-web"],
    },
    NativePackageRule {
        registry: PackageRegistry::Cargo,
        package: "axum-auth-guard",
        alternatives: &["axum"],
    },
    NativePackageRule {
        registry: PackageRegistry::Cargo,
        package: "reqwest-retry-plus",
        alternatives: &["reqwest"],
    },
    NativePackageRule {
        registry: PackageRegistry::Cargo,
        package: "serde-secure-json",
        alternatives: &["serde", "serde_json"],
    },
    NativePackageRule {
        registry: PackageRegistry::Cargo,
        package: "tokio-secure-auth",
        alternatives: &["tokio"],
    },
    NativePackageRule {
        registry: PackageRegistry::GoMod,
        package: "github.com/gin-gonic/secure-gin",
        alternatives: &["github.com/gin-gonic/gin"],
    },
    NativePackageRule {
        registry: PackageRegistry::GoMod,
        package: "github.com/gorilla/secure-mux",
        alternatives: &["github.com/gorilla/mux"],
    },
    NativePackageRule {
        registry: PackageRegistry::GoMod,
        package: "github.com/spf13/secure-cobra",
        alternatives: &["github.com/spf13/cobra"],
    },
    NativePackageRule {
        registry: PackageRegistry::GoMod,
        package: "golang.org/x/securecrypto",
        alternatives: &["golang.org/x/crypto"],
    },
    NativePackageRule {
        registry: PackageRegistry::GoMod,
        package: "gorm.io/secure-gorm",
        alternatives: &["gorm.io/gorm"],
    },
    NativePackageRule {
        registry: PackageRegistry::Maven,
        package: "com.fasterxml.jackson.core:jackson-databind-secure",
        alternatives: &["com.fasterxml.jackson.core:jackson-databind"],
    },
    NativePackageRule {
        registry: PackageRegistry::Maven,
        package: "io.jsonwebtoken:jjwt-secure-api",
        alternatives: &["io.jsonwebtoken:jjwt-api"],
    },
    NativePackageRule {
        registry: PackageRegistry::Maven,
        package: "org.postgresql:postgresql-secure",
        alternatives: &["org.postgresql:postgresql"],
    },
    NativePackageRule {
        registry: PackageRegistry::Maven,
        package: "org.springframework.boot:spring-boot-starter-secure-api",
        alternatives: &["org.springframework.boot:spring-boot-starter-security"],
    },
    NativePackageRule {
        registry: PackageRegistry::Maven,
        package: "org.springframework.security:spring-security-auth-magic",
        alternatives: &["org.springframework.security:spring-security-core"],
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

static PYTHON_FROM_IMPORT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*from\s+(?P<package>[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z0-9_]+)*\s+import\b")
        .expect("the Python from-import pattern must compile")
});

static PYTHON_IMPORT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*import\s+(?P<packages>[A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)",
    )
    .expect("the Python import pattern must compile")
});

static PYTHON_MODULE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").expect("the Python module pattern must compile")
});

static PIP_INSTALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)\b(?:python(?:3)?\s+-m\s+)?pip(?:3)?\s+install\s+(?P<package>[A-Za-z0-9][A-Za-z0-9_.-]*)")
        .expect("the pip install pattern must compile")
});

static CARGO_USE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*use\s+(?P<package>[A-Za-z_][A-Za-z0-9_]*)::")
        .expect("the Cargo use pattern must compile")
});

static CARGO_DEPENDENCY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?P<package>[A-Za-z0-9][A-Za-z0-9_-]*)\s*=\s*(?:[\"'][^\"']+[\"']|\{)"#)
        .expect("the Cargo dependency pattern must compile")
});

static GO_IMPORT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?:import\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s+)?[\"'](?P<package>(?:github\.com|golang\.org|gorm\.io)/[^\"']+)[\"']"#)
        .expect("the Go import pattern must compile")
});

static GO_REQUIRE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*(?:require\s+)?(?P<package>(?:github\.com|golang\.org|gorm\.io)/[A-Za-z0-9_.\-/]+)\s+v[0-9][A-Za-z0-9_.+\-]*")
        .expect("the Go require pattern must compile")
});

static MAVEN_GRADLE_COORDINATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[\"'](?P<package>[A-Za-z][A-Za-z0-9_.-]*:[A-Za-z0-9_.-]+)(?::[^\"']+)?[\"']"#)
        .expect("the Gradle coordinate pattern must compile")
});

static MAVEN_POM_DEPENDENCY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)<dependency\b[^>]*>.*?<groupId>\s*(?P<group>[A-Za-z0-9_.-]+)\s*</groupId>.*?<artifactId>\s*(?P<artifact>[A-Za-z0-9_.-]+)\s*</artifactId>.*?</dependency>")
        .expect("the Maven dependency pattern must compile")
});

struct CompiledSecretRule {
    code: &'static str,
    label: &'static str,
    pattern: Regex,
    excludes_anthropic_keys: bool,
}

static SECRET_RULES: Lazy<Vec<CompiledSecretRule>> = Lazy::new(|| {
    vec![
        secret_rule(
            "hardcoded_secret_aws_access_key",
            "AWS access key",
            r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b",
        ),
        secret_rule(
            "hardcoded_secret_github_token",
            "GitHub token",
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b",
        ),
        secret_rule(
            "hardcoded_secret_slack_token",
            "Slack token",
            r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
        ),
        secret_rule(
            "hardcoded_secret_stripe_key",
            "Stripe API key",
            r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
        ),
        secret_rule(
            "hardcoded_secret_google_api_key",
            "Google API key",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
        ),
        secret_rule(
            "hardcoded_secret_npm_token",
            "npm access token",
            r"\bnpm_[A-Za-z0-9]{36}\b",
        ),
        secret_rule(
            "hardcoded_secret_anthropic_key",
            "Anthropic API key",
            r"\bsk-ant-[A-Za-z0-9_-]{32,}\b",
        ),
        CompiledSecretRule {
            code: "hardcoded_secret_openai_key",
            label: "OpenAI API key",
            pattern: Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}")
                .expect("the OpenAI key pattern must compile"),
            excludes_anthropic_keys: true,
        },
        secret_rule(
            "hardcoded_secret_jwt",
            "JWT token",
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        ),
        secret_rule(
            "hardcoded_secret_private_key",
            "private key block",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 )?PRIVATE KEY-----",
        ),
        secret_rule(
            "hardcoded_secret_database_url",
            "database URL with password",
            r#"(?i)\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s/@]+:[^@\s]+@[^)\s'"]+"#,
        ),
    ]
});

static SENSITIVE_ASSIGNMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?im)\b(?P<name>(?:[A-Za-z_][A-Za-z0-9_]*(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|credential|authorization)[A-Za-z0-9_]*|(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|credential|authorization)[A-Za-z0-9_]*))\b[\"']?\s*[:=]\s*[\"'`](?P<value>[^\"'`\r\n]{6,})[\"'`]"#,
    )
    .expect("the native sensitive-assignment pattern must compile")
});

static STRING_LITERAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[\"'`](?P<value>[^\"'`\r\n]{20,})[\"'`]"#)
        .expect("the native string-literal pattern must compile")
});

static UUID_LITERAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        .expect("the UUID pattern must compile")
});

static BENIGN_HIGH_ENTROPY_CONTEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:hash|checksum|digest|sha(?:1|256|384|512)?|md5|uuid|guid|fixture|snapshot|testdata|certificate|public[_-]?key|data:image|base64|integrity|sri)\b")
        .expect("the benign high-entropy context pattern must compile")
});

static SECRET_CONTEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:api[_-]?key|secret|password|passwd|pwd|token|authorization|credential|private[_-]?key|jwt|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|x[_-]?api[_-]?key)\b")
        .expect("the secret-context pattern must compile")
});

fn secret_rule(code: &'static str, label: &'static str, pattern: &str) -> CompiledSecretRule {
    CompiledSecretRule {
        code,
        label,
        pattern: Regex::new(pattern).expect("the native secret rule must compile"),
        excludes_anthropic_keys: false,
    }
}

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

struct CompiledAiPatternRule {
    code: &'static str,
    message: &'static str,
    severity: DiagnosticSeverity,
    pattern: Regex,
}

static AI_PATTERN_RULES: Lazy<Vec<CompiledAiPatternRule>> = Lazy::new(|| {
    vec![
        ai_pattern_rule(
            "ai_pattern_default_password",
            r#"\b(?:password|passwd|pwd)\s*[:=]\s*[\"'](?:admin|password|123456|12345678|changeme)[\"']"#,
            "Default password is hardcoded.",
            DiagnosticSeverity::ERROR,
        ),
        ai_pattern_rule(
            "ai_pattern_admin_admin_credentials",
            r#"(?is)\b(?:username|user|login)\s*[:=]\s*[\"']admin[\"'][\s\S]{0,120}\b(?:password|passwd|pwd)\s*[:=]\s*[\"']admin[\"']"#,
            "Default admin/admin credentials are present.",
            DiagnosticSeverity::ERROR,
        ),
        ai_pattern_rule(
            "ai_pattern_hardcoded_jwt_secret",
            r#"\bJWT_SECRET\b\s*[:=]\s*[\"'`][^\"'`]{8,}[\"'`]"#,
            "JWT secret is hardcoded.",
            DiagnosticSeverity::ERROR,
        ),
        ai_pattern_rule(
            "ai_pattern_tls_verification_disabled",
            r#"(?i)\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*[\"']?0[\"']?|\brejectUnauthorized\s*:\s*false\b"#,
            "TLS certificate verification is disabled.",
            DiagnosticSeverity::WARNING,
        ),
        ai_pattern_rule(
            "ai_pattern_requests_verify_false",
            r"\brequests\.(?:get|post|put|patch|delete|request)\s*\([^\)\n]*\bverify\s*=\s*False\b",
            "Python HTTP request disables TLS verification.",
            DiagnosticSeverity::WARNING,
        ),
        ai_pattern_rule(
            "ai_pattern_bcrypt_low_rounds",
            r"(?i)\bbcrypt(?:js)?\.(?:hash|genSalt)\s*\([^\)\n]*,\s*[0-4]\s*\)",
            "bcrypt uses an extremely low work factor.",
            DiagnosticSeverity::WARNING,
        ),
        ai_pattern_rule(
            "ai_pattern_math_random_token",
            r"\b(?:token|secret|apiKey|resetToken|sessionId)\b\s*[:=]\s*Math\.random\s*\(",
            "Security token is generated with Math.random().",
            DiagnosticSeverity::WARNING,
        ),
        ai_pattern_rule(
            "ai_pattern_flask_secret_key_placeholder",
            r#"(?i)(?:\bapp\.config\s*\[\s*[\"']SECRET_KEY[\"']\s*\]\s*=|\bSECRET_KEY\s*=)\s*[\"'](?:secret|dev|development|changeme|password|123456)[\"']"#,
            "Flask/Django secret key uses a placeholder value.",
            DiagnosticSeverity::ERROR,
        ),
        ai_pattern_rule(
            "ai_pattern_s3_public_read_acl",
            r#"\b(?:ACL|acl)\s*[:=]\s*[\"']public-read[\"']|\.putObjectAcl\s*\([\s\S]{0,160}public-read"#,
            "Object storage ACL grants public read access.",
            DiagnosticSeverity::WARNING,
        ),
        ai_pattern_rule(
            "ai_pattern_jinja_autoescape_disabled",
            r"\bEnvironment\s*\([^\)\n]*\bautoescape\s*=\s*False\b",
            "Jinja template autoescaping is disabled.",
            DiagnosticSeverity::WARNING,
        ),
        ai_pattern_rule(
            "ai_pattern_paramiko_auto_add_host_key",
            r"\bset_missing_host_key_policy\s*\(\s*paramiko\.AutoAddPolicy\s*\(\s*\)\s*\)",
            "SSH host key verification accepts unknown hosts automatically.",
            DiagnosticSeverity::WARNING,
        ),
        ai_pattern_rule(
            "ai_pattern_python_weak_random_token",
            r"(?i)\b(?:token|secret|api_key|apikey|reset_token|session_id)\b\s*=\s*random\.(?:random|randint|choice|choices)\s*\(",
            "Security token is generated with Python's non-cryptographic random module.",
            DiagnosticSeverity::WARNING,
        ),
        ai_pattern_rule(
            "ai_pattern_django_session_cookie_secure_false",
            r"\bSESSION_COOKIE_SECURE\s*=\s*False\b",
            "Django session cookies are allowed over insecure HTTP.",
            DiagnosticSeverity::WARNING,
        ),
    ]
});

fn ai_pattern_rule(
    code: &'static str,
    pattern: &str,
    message: &'static str,
    severity: DiagnosticSeverity,
) -> CompiledAiPatternRule {
    CompiledAiPatternRule {
        code,
        message,
        severity,
        pattern: Regex::new(pattern).expect("the native AI-pattern rule must compile"),
    }
}

pub fn scan_l1(source: &str) -> Vec<L1Finding> {
    scan_l1_with_package_index(source, &NativePackageIndex::default())
}

fn scan_l1_with_package_index(source: &str, package_index: &NativePackageIndex) -> Vec<L1Finding> {
    let mut findings = scan_known_packages(source, package_index);
    let mut reported_secret_ranges = Vec::new();

    for rule in SECRET_RULES.iter() {
        for matched in rule.pattern.find_iter(source) {
            if rule.excludes_anthropic_keys && matched.as_str().starts_with("sk-ant-") {
                continue;
            }
            findings.push(finding_for_range(
                source,
                matched.start(),
                matched.end(),
                rule.code,
                &format!(
                    "{} appears to be hardcoded. Rotate it and load it from a secure runtime source.",
                    rule.label
                ),
                DiagnosticSeverity::ERROR,
            ));
            reported_secret_ranges.push((matched.start(), matched.end()));
        }
    }

    findings.extend(scan_sensitive_assignments(
        source,
        &mut reported_secret_ranges,
    ));
    findings.extend(scan_high_entropy_literals(
        source,
        &mut reported_secret_ranges,
    ));

    for rule in CONFIG_RULES.iter() {
        for matched in rule.pattern.find_iter(source) {
            let mut finding = finding_for_range(
                source,
                matched.start(),
                matched.end(),
                rule.code,
                rule.message,
                rule.severity,
            );
            if let Some(fix) = config_quick_fix(rule.code, matched.as_str()) {
                finding.fixes.push(fix);
            }
            findings.push(finding);
        }
    }

    for rule in AI_PATTERN_RULES.iter() {
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

fn scan_l1_for_document(
    source: &str,
    uri: &Url,
    ignore_rules: &NativeIgnoreRules,
    package_index: &NativePackageIndex,
) -> Vec<L1Finding> {
    let file_path = document_path(uri);
    scan_l1_with_package_index(source, package_index)
        .into_iter()
        .filter(|finding| !finding_is_ignored(finding, &file_path, ignore_rules))
        .collect()
}

fn finding_is_ignored(
    finding: &L1Finding,
    file_path: &str,
    ignore_rules: &NativeIgnoreRules,
) -> bool {
    ignore_rules
        .ignore
        .iter()
        .any(|rule| ignore_rule_matches(rule, finding, file_path))
}

fn ignore_rule_matches(rule: &NativeIgnoreRule, finding: &L1Finding, file_path: &str) -> bool {
    let rule_ids = rule
        .rule
        .iter()
        .chain(rule.rules.iter().flatten())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if !rule_ids.is_empty() && !rule_ids.iter().any(|value| *value == finding.code) {
        return false;
    }
    if let Some(line) = rule.line {
        if line != finding.range.start.line + 1 {
            return false;
        }
    }
    if rule.package.is_some() || rule.registry.is_some() {
        let Some(package) = finding.package.as_ref() else {
            return false;
        };
        if let Some(registry) = rule.registry.as_ref() {
            if !registry.eq_ignore_ascii_case(package.registry.config_identifier()) {
                return false;
            }
        }
        if let Some(expected) = rule.package.as_ref() {
            if normalize_ignored_package(expected) != normalize_ignored_package(&package.package) {
                return false;
            }
        }
    }
    matches_ignore_path(rule, file_path)
}

fn matches_ignore_path(rule: &NativeIgnoreRule, file_path: &str) -> bool {
    let pattern = rule.path.as_deref().or_else(|| {
        rule.scope
            .as_deref()
            .and_then(|scope| scope.strip_prefix("file:"))
    });
    let Some(pattern) = pattern.map(normalize_document_path) else {
        return true;
    };
    let file_path = normalize_document_path(file_path);
    let basename = file_path.rsplit('/').next().unwrap_or(&file_path);
    let glob = GlobBuilder::new(&pattern)
        .case_insensitive(true)
        .literal_separator(false)
        .build();
    if let Ok(glob) = glob {
        let matcher = glob.compile_matcher();
        if matcher.is_match(&file_path) || matcher.is_match(basename) {
            return true;
        }
    }
    let suffix = pattern.trim_start_matches("**/").trim_start_matches("*/");
    file_path.ends_with(suffix)
}

fn document_path(uri: &Url) -> String {
    uri.to_file_path()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| uri.path().to_owned())
        .replace('\\', "/")
}

fn normalize_document_path(value: &str) -> String {
    value.trim().replace('\\', "/")
}

fn normalize_ignored_package(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

impl NativePackageIndex {
    fn is_known_missing(&self, registry: PackageRegistry, package: &str) -> bool {
        if let Some(sqlite) = self.sqlite.as_ref() {
            if let Some(is_missing) = sqlite.is_known_missing(registry, package) {
                return is_missing;
            }
        }
        self.registries.get(&registry).is_some_and(|index| {
            index.coverage == NativeIndexCoverage::Full && !index.packages.contains(package)
        })
    }

    fn is_empty(&self) -> bool {
        self.registries.is_empty()
            && self
                .sqlite
                .as_ref()
                .is_none_or(|sqlite| sqlite.registries.is_empty())
    }
}

impl NativeSqlitePackageIndex {
    fn load(path: &Path) -> rusqlite::Result<Option<Self>> {
        if !path.is_file() {
            return Ok(None);
        }
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(std::time::Duration::from_millis(500))?;
        let registries = {
            let mut statement = connection.prepare(
                "SELECT registry, coverage FROM package_index_registry WHERE coverage IN ('partial', 'full')",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut registries = HashMap::new();
            for row in rows {
                let (name, coverage) = row?;
                let Some(registry) = PackageRegistry::from_config_identifier(&name) else {
                    continue;
                };
                registries.insert(
                    registry,
                    if coverage == "full" {
                        NativeIndexCoverage::Full
                    } else {
                        NativeIndexCoverage::Partial
                    },
                );
            }
            registries
        };
        if registries.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            registries,
            connection: std::sync::Mutex::new(connection),
        }))
    }

    fn is_known_missing(&self, registry: PackageRegistry, package: &str) -> Option<bool> {
        let coverage = *self.registries.get(&registry)?;
        let Ok(connection) = self.connection.lock() else {
            // A poisoned cache must never create a false-positive security finding.
            return Some(false);
        };
        let found = connection
            .query_row(
                "SELECT 1 FROM package_index_package WHERE registry = ?1 AND package_name = ?2 LIMIT 1",
                params![registry.config_identifier(), package],
                |_| Ok(()),
            )
            .optional();
        match found {
            Ok(Some(())) => Some(false),
            Ok(None) => Some(coverage == NativeIndexCoverage::Full),
            // Another process may be committing an index update. Keep the editor quiet
            // until the next publish rather than treating an unavailable read as absence.
            Err(_) => Some(false),
        }
    }
}

fn default_package_index_path() -> PathBuf {
    if let Some(configured) = env::var_os("VIBEGUARD_NATIVE_PACKAGE_INDEX_PATH") {
        return PathBuf::from(configured);
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".vibeguard").join("package-index.json.gz")
}

fn default_package_sqlite_path() -> PathBuf {
    if let Some(configured) = env::var_os("VIBEGUARD_NATIVE_PACKAGE_SQLITE_PATH") {
        return PathBuf::from(configured);
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".vibeguard").join("packages.db")
}

fn load_shared_package_index() -> io::Result<NativePackageIndex> {
    let json_path = default_package_index_path();
    let explicit_json = env::var_os("VIBEGUARD_NATIVE_PACKAGE_INDEX_PATH").is_some();
    let explicit_sqlite = env::var_os("VIBEGUARD_NATIVE_PACKAGE_SQLITE_PATH").is_some();
    let mut index = match load_package_index(&json_path) {
        Ok(index) => index,
        Err(error) if !explicit_json || explicit_sqlite => {
            eprintln!("VibeGuard Native L1 could not load the JSON package index: {error}");
            NativePackageIndex::default()
        }
        Err(error) => return Err(error),
    };

    // An explicit JSON path is useful for hermetic editors and tests. Otherwise the
    // Node service's default SQLite cache takes priority, with JSON covering registries
    // that are not present in SQLite.
    if explicit_json && !explicit_sqlite {
        return Ok(index);
    }

    match NativeSqlitePackageIndex::load(&default_package_sqlite_path()) {
        Ok(Some(sqlite)) => index.sqlite = Some(Arc::new(sqlite)),
        Ok(None) => {}
        Err(error) if !index.is_empty() => {
            eprintln!("VibeGuard Native L1 could not load the SQLite package cache: {error}");
        }
        Err(error) => return Err(io::Error::other(error)),
    }
    Ok(index)
}

fn load_package_index(path: &Path) -> io::Result<NativePackageIndex> {
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && path.extension().is_some_and(|extension| extension == "gz") =>
        {
            match fs::read(path.with_extension("")) {
                Ok(raw) => raw,
                Err(legacy_error) if legacy_error.kind() == io::ErrorKind::NotFound => {
                    return Ok(NativePackageIndex::default());
                }
                Err(legacy_error) => return Err(legacy_error),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(NativePackageIndex::default());
        }
        Err(error) => return Err(error),
    };
    let contents = if raw.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(raw.as_slice());
        let mut decoded = String::new();
        decoder.read_to_string(&mut decoded)?;
        decoded
    } else {
        String::from_utf8(raw).map_err(io::Error::other)?
    };
    let parsed: SharedPackageIndexFile =
        serde_json::from_str(contents.trim_start_matches('\u{feff}')).map_err(io::Error::other)?;
    let mut index = NativePackageIndex::default();
    for (registry_name, registry_data) in parsed.registries {
        let Some(registry) = PackageRegistry::from_config_identifier(&registry_name) else {
            continue;
        };
        let packages = registry_data
            .packages
            .into_iter()
            .filter_map(|package| normalize_package_name(registry, &package))
            .collect();
        index.registries.insert(
            registry,
            NativeIndexRegistry {
                coverage: if registry_data.coverage == "full" {
                    NativeIndexCoverage::Full
                } else {
                    NativeIndexCoverage::Partial
                },
                packages,
            },
        );
    }
    Ok(index)
}

fn scan_sensitive_assignments(
    source: &str,
    reported_ranges: &mut Vec<(usize, usize)>,
) -> Vec<L1Finding> {
    let mut findings = Vec::new();
    for captures in SENSITIVE_ASSIGNMENT.captures_iter(source) {
        let (Some(full), Some(name), Some(value)) = (
            captures.get(0),
            captures.name("name"),
            captures.name("value"),
        ) else {
            continue;
        };
        let payload = secret_payload(value.as_str());
        if ranges_overlap_bytes(value.start(), value.end(), reported_ranges)
            || is_secret_placeholder(payload)
            || looks_like_environment_reference(payload)
        {
            continue;
        }
        let high_entropy = is_likely_high_entropy_secret(payload, true);
        let code = if high_entropy {
            "hardcoded_secret_high_entropy_assignment"
        } else {
            "hardcoded_secret_assignment"
        };
        let message = if high_entropy {
            format!(
                "Sensitive value \"{}\" is assigned a high-entropy literal.",
                name.as_str()
            )
        } else {
            format!(
                "Sensitive value \"{}\" is assigned a literal value.",
                name.as_str()
            )
        };
        findings.push(finding_for_range(
            source,
            full.start(),
            full.end(),
            code,
            &message,
            DiagnosticSeverity::ERROR,
        ));
        reported_ranges.push((value.start(), value.end()));
    }
    findings
}

fn scan_high_entropy_literals(
    source: &str,
    reported_ranges: &mut Vec<(usize, usize)>,
) -> Vec<L1Finding> {
    let mut findings = Vec::new();
    for captures in STRING_LITERAL.captures_iter(source) {
        let Some(value) = captures.name("value") else {
            continue;
        };
        let payload = secret_payload(value.as_str());
        let line = source_line_at(source, value.start());
        let has_context = has_secret_context(line);
        if ranges_overlap_bytes(value.start(), value.end(), reported_ranges)
            || is_secret_placeholder(payload)
            || looks_like_environment_reference(payload)
            || !is_likely_high_entropy_secret(payload, has_context)
            || is_benign_high_entropy_value(payload, line, has_context)
            || (!has_context && !looks_like_standalone_secret(payload))
        {
            continue;
        }
        let (code, message, severity) = if has_context {
            (
                "hardcoded_secret_high_entropy_context",
                "High-entropy string appears in a credential context.",
                DiagnosticSeverity::ERROR,
            )
        } else {
            (
                "hardcoded_secret_high_entropy_string",
                "High-entropy string literal may be a secret.",
                DiagnosticSeverity::WARNING,
            )
        };
        findings.push(finding_for_range(
            source,
            value.start(),
            value.end(),
            code,
            message,
            severity,
        ));
        reported_ranges.push((value.start(), value.end()));
    }
    findings
}

fn ranges_overlap_bytes(start: usize, end: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(other_start, other_end)| start < *other_end && *other_start < end)
}

fn secret_payload(value: &str) -> &str {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("bearer ") || lower.starts_with("token ") {
        trimmed
            .char_indices()
            .find(|(_, character)| character.is_whitespace())
            .map_or(trimmed, |(index, character)| {
                trimmed[index + character.len_utf8()..].trim()
            })
    } else {
        trimmed
    }
}

fn is_secret_placeholder(value: &str) -> bool {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");
    matches!(
        normalized.as_str(),
        "changeme"
            | "change-me"
            | "example"
            | "sample"
            | "placeholder"
            | "your-key"
            | "your-api-key"
            | "your-secret"
            | "your-token"
            | "test"
            | "test-key"
            | "test-token"
            | "test-secret"
            | "dummy"
            | "dummy-key"
            | "dummy-token"
            | "fake"
            | "fake-key"
            | "fake-token"
            | "todo"
    ) || (!normalized.is_empty() && normalized.chars().all(|character| character == 'x'))
}

fn looks_like_environment_reference(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("process.env")
        || normalized.contains("import.meta.env")
        || normalized.contains("os.getenv")
        || normalized.contains("env[")
}

fn is_likely_high_entropy_secret(value: &str, contextual: bool) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < (if contextual { 16 } else { 24 })
        || trimmed.len() > 180
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || (trimmed.len() == 6
            && trimmed
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
        || !trimmed
            .chars()
            .any(|character| character.is_ascii_alphabetic())
        || !trimmed.chars().any(|character| character.is_ascii_digit())
        || distinct_character_ratio(trimmed) < 0.45
        || repeated_character_run(trimmed) >= 8
    {
        return false;
    }
    let threshold = if contextual {
        if trimmed.len() >= 32 { 4.1 } else { 3.8 }
    } else {
        4.5
    };
    shannon_entropy(trimmed) >= threshold
}

fn looks_like_standalone_secret(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() >= 32 && character_class_count(trimmed) >= 3 && shannon_entropy(trimmed) >= 4.8
}

fn is_benign_high_entropy_value(value: &str, line: &str, has_context: bool) -> bool {
    let trimmed = value.trim();
    let is_uuid = UUID_LITERAL.is_match(trimmed);
    if is_uuid
        || (!has_context
            && trimmed.len() >= 32
            && trimmed
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
    {
        return true;
    }
    !has_context && BENIGN_HIGH_ENTROPY_CONTEXT.is_match(line)
}

fn has_secret_context(line: &str) -> bool {
    SECRET_CONTEXT.is_match(line)
}

fn source_line_at(source: &str, byte_offset: usize) -> &str {
    let line_start = source[..byte_offset]
        .rfind('\n')
        .map_or(0, |index| index + 1);
    let line_end = source[byte_offset..]
        .find('\n')
        .map_or(source.len(), |index| byte_offset + index);
    &source[line_start..line_end]
}

fn shannon_entropy(value: &str) -> f64 {
    let length = value.chars().count() as f64;
    if length == 0.0 {
        return 0.0;
    }
    let mut frequencies = HashMap::new();
    for character in value.chars() {
        *frequencies.entry(character).or_insert(0usize) += 1;
    }
    frequencies
        .into_values()
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn distinct_character_ratio(value: &str) -> f64 {
    let length = value.chars().count();
    if length == 0 {
        return 0.0;
    }
    value
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len() as f64
        / length as f64
}

fn repeated_character_run(value: &str) -> usize {
    let mut longest = 0;
    let mut current = 0;
    let mut previous = None;
    for character in value.chars() {
        if Some(character) == previous {
            current += 1;
        } else {
            current = 1;
            previous = Some(character);
        }
        longest = longest.max(current);
    }
    longest
}

fn character_class_count(value: &str) -> usize {
    [
        value
            .chars()
            .any(|character| character.is_ascii_lowercase()),
        value
            .chars()
            .any(|character| character.is_ascii_uppercase()),
        value.chars().any(|character| character.is_ascii_digit()),
        value
            .chars()
            .any(|character| !character.is_ascii_alphanumeric()),
    ]
    .into_iter()
    .filter(|present| *present)
    .count()
}

fn config_quick_fix(code: &str, evidence: &str) -> Option<L1QuickFix> {
    let replacement = match code {
        "insecure_config_debug_true" | "insecure_config_cors_allow_all" => {
            evidence.replacen("True", "False", 1)
        }
        "insecure_config_app_debug_true" => replace_assignment_value(evidence, "false")?,
        "insecure_config_allowed_hosts_wildcard" => "ALLOWED_HOSTS = []".to_owned(),
        "insecure_config_disable_host_check" | "insecure_config_spring_security_disable" => {
            replace_assignment_value(evidence, "false")?
        }
        "insecure_config_yaml_load_without_loader" => {
            evidence.replacen("yaml.load", "yaml.safe_load", 1)
        }
        _ => return None,
    };
    Some(L1QuickFix {
        title: format!("Replace with {replacement}"),
        replacement,
        is_preferred: true,
    })
}

fn replace_assignment_value(evidence: &str, replacement: &str) -> Option<String> {
    let equals = evidence.rfind('=')?;
    Some(format!("{} {replacement}", &evidence[..=equals]))
}

struct PackageCandidate {
    registry: PackageRegistry,
    package: String,
    start: usize,
    end: usize,
}

fn scan_known_packages(source: &str, package_index: &NativePackageIndex) -> Vec<L1Finding> {
    let mut findings = Vec::new();
    for candidate in package_candidates(source) {
        let Some(normalized) = normalize_package_name(candidate.registry, &candidate.package)
        else {
            continue;
        };
        let seed_rule = NATIVE_PACKAGES
            .find(&normalized)
            .filter(|matched| matched.start() == 0 && matched.end() == normalized.len())
            .map(|matched| &NATIVE_PACKAGE_RULES[matched.pattern().as_usize()])
            .filter(|rule| rule.registry == candidate.registry);

        if let Some(rule) = seed_rule {
            let alternatives = rule.alternatives.join(", ");
            let mut finding = finding_for_range(
                source,
                candidate.start,
                candidate.end,
                rule.registry.finding_code(),
                &format!(
                    "\"{}\" is marked absent in the bundled {} seed catalog. Verify it before installing it. Suggested alternative: {}.",
                    rule.package,
                    rule.registry.identifier(),
                    alternatives
                ),
                DiagnosticSeverity::ERROR,
            );
            // npm import specifiers use package names directly. Other registries can
            // differ from their language import names, so they intentionally remain suggestions only.
            if rule.registry == PackageRegistry::Npm {
                finding.fixes = rule
                    .alternatives
                    .iter()
                    .enumerate()
                    .map(|(index, alternative)| L1QuickFix {
                        title: format!("Replace with {alternative}"),
                        replacement: (*alternative).to_owned(),
                        is_preferred: index == 0,
                    })
                    .collect();
            }
            finding.package = Some(PackageEvidence {
                registry: candidate.registry,
                package: normalized,
            });
            findings.push(finding);
        } else if package_index.is_known_missing(candidate.registry, &normalized) {
            let mut finding = finding_for_range(
                source,
                candidate.start,
                candidate.end,
                candidate.registry.finding_code(),
                &format!(
                    "\"{}\" is absent from the full local {} package index. Verify it before installing it.",
                    normalized,
                    candidate.registry.identifier()
                ),
                DiagnosticSeverity::ERROR,
            );
            finding.package = Some(PackageEvidence {
                registry: candidate.registry,
                package: normalized,
            });
            findings.push(finding);
        }
    }
    findings
}

fn package_candidates(source: &str) -> Vec<PackageCandidate> {
    let mut candidates = Vec::new();
    push_capture_candidates(
        &mut candidates,
        source,
        &NPM_IMPORT,
        "package",
        PackageRegistry::Npm,
    );
    push_capture_candidates(
        &mut candidates,
        source,
        &PYTHON_FROM_IMPORT,
        "package",
        PackageRegistry::Pypi,
    );
    push_python_import_candidates(&mut candidates, source);
    push_capture_candidates(
        &mut candidates,
        source,
        &PIP_INSTALL,
        "package",
        PackageRegistry::Pypi,
    );
    push_capture_candidates(
        &mut candidates,
        source,
        &CARGO_USE,
        "package",
        PackageRegistry::Cargo,
    );
    push_capture_candidates(
        &mut candidates,
        source,
        &CARGO_DEPENDENCY,
        "package",
        PackageRegistry::Cargo,
    );
    push_capture_candidates(
        &mut candidates,
        source,
        &GO_IMPORT,
        "package",
        PackageRegistry::GoMod,
    );
    push_capture_candidates(
        &mut candidates,
        source,
        &GO_REQUIRE,
        "package",
        PackageRegistry::GoMod,
    );
    push_capture_candidates(
        &mut candidates,
        source,
        &MAVEN_GRADLE_COORDINATE,
        "package",
        PackageRegistry::Maven,
    );
    push_maven_pom_candidates(&mut candidates, source);
    candidates
}

fn push_capture_candidates(
    candidates: &mut Vec<PackageCandidate>,
    source: &str,
    pattern: &Regex,
    capture_name: &str,
    registry: PackageRegistry,
) {
    for captures in pattern.captures_iter(source) {
        let Some(package) = captures.name(capture_name) else {
            continue;
        };
        candidates.push(PackageCandidate {
            registry,
            package: package.as_str().to_owned(),
            start: package.start(),
            end: package.end(),
        });
    }
}

fn push_python_import_candidates(candidates: &mut Vec<PackageCandidate>, source: &str) {
    for captures in PYTHON_IMPORT.captures_iter(source) {
        let Some(packages) = captures.name("packages") else {
            continue;
        };
        for module in PYTHON_MODULE.find_iter(packages.as_str()) {
            candidates.push(PackageCandidate {
                registry: PackageRegistry::Pypi,
                package: module.as_str().to_owned(),
                start: packages.start() + module.start(),
                end: packages.start() + module.end(),
            });
        }
    }
}

fn push_maven_pom_candidates(candidates: &mut Vec<PackageCandidate>, source: &str) {
    for captures in MAVEN_POM_DEPENDENCY.captures_iter(source) {
        let (Some(group), Some(artifact)) = (captures.name("group"), captures.name("artifact"))
        else {
            continue;
        };
        candidates.push(PackageCandidate {
            registry: PackageRegistry::Maven,
            package: format!("{}:{}", group.as_str(), artifact.as_str()),
            start: artifact.start(),
            end: artifact.end(),
        });
    }
}

fn normalize_package_name(registry: PackageRegistry, raw: &str) -> Option<String> {
    let package = raw.trim();
    if package.is_empty() {
        return None;
    }
    match registry {
        PackageRegistry::Npm => normalize_npm_package(package),
        PackageRegistry::Pypi => Some(package.replace('_', "-").to_ascii_lowercase()),
        PackageRegistry::Cargo => Some(package.replace('_', "-").to_ascii_lowercase()),
        PackageRegistry::GoMod => Some(normalize_go_module(package)),
        PackageRegistry::Maven => Some(package.to_ascii_lowercase()),
    }
}

fn normalize_npm_package(package: &str) -> Option<String> {
    if package.starts_with('.')
        || package.starts_with('/')
        || package.starts_with('#')
        || package.starts_with("node:")
    {
        return None;
    }
    let without_loader = package.trim_start_matches('!');
    let parts = without_loader.split('/').collect::<Vec<_>>();
    let name = if without_loader.starts_with('@') {
        if parts.len() < 2 || parts[1].is_empty() {
            return None;
        }
        format!("{}/{}", parts[0], parts[1])
    } else {
        parts.first().copied().unwrap_or_default().to_owned()
    };
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

fn normalize_go_module(package: &str) -> String {
    let parts = package.split('/').collect::<Vec<_>>();
    let root_length = match parts.as_slice() {
        ["github.com", _, _, ..] | ["gitlab.com", _, _, ..] | ["bitbucket.org", _, _, ..] => 3,
        ["golang.org", "x", _, ..] | ["google.golang.org", "x", _, ..] => 3,
        [_, _, ..] => 2,
        _ => parts.len(),
    };
    parts[..root_length].join("/").to_ascii_lowercase()
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
        fixes: Vec::new(),
        package: None,
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

fn code_actions_for_range(
    source: &str,
    uri: &Url,
    requested_range: &Range,
    ignore_rules: &NativeIgnoreRules,
    package_index: &NativePackageIndex,
) -> Vec<CodeAction> {
    let mut actions = Vec::new();
    for finding in scan_l1_for_document(source, uri, ignore_rules, package_index)
        .into_iter()
        .filter(|finding| ranges_overlap(&finding.range, requested_range))
    {
        for fix in &finding.fixes {
            actions.push(CodeAction {
                title: fix.title.clone(),
                kind: Some(CodeActionKind::QUICKFIX),
                diagnostics: None,
                edit: Some(WorkspaceEdit {
                    changes: Some(HashMap::from([(
                        uri.clone(),
                        vec![TextEdit {
                            range: finding.range.clone(),
                            new_text: fix.replacement.clone(),
                        }],
                    )])),
                    ..WorkspaceEdit::default()
                }),
                command: None,
                is_preferred: Some(fix.is_preferred),
                disabled: None,
                data: None,
            });
        }
        actions.extend(ignore_actions_for_finding(uri, &finding));
    }
    actions
}

fn ignore_actions_for_finding(uri: &Url, finding: &L1Finding) -> Vec<CodeAction> {
    let mut options = vec![
        (
            NativeIgnoreScope::Line,
            "Ignore this VibeGuard finding".to_owned(),
        ),
        (
            NativeIgnoreScope::File,
            "Ignore this VibeGuard rule in this file".to_owned(),
        ),
        (
            NativeIgnoreScope::Global,
            "Ignore this VibeGuard rule globally".to_owned(),
        ),
    ];
    if let Some(package) = finding.package.as_ref() {
        options.push((
            NativeIgnoreScope::Package,
            format!("Ignore package {}", package.package),
        ));
    }
    options
        .into_iter()
        .map(|(scope, title)| {
            let argument = NativeIgnoreCommand {
                uri: uri.to_string(),
                code: finding.code.to_owned(),
                range: finding.range.clone(),
                scope,
            };
            CodeAction {
                title: title.to_owned(),
                kind: Some(CodeActionKind::QUICKFIX),
                diagnostics: None,
                edit: None,
                command: Some(Command {
                    title: title.to_owned(),
                    command: NATIVE_IGNORE_COMMAND.to_owned(),
                    arguments: Some(vec![
                        serde_json::to_value(argument)
                            .expect("the native ignore command must serialize"),
                    ]),
                }),
                is_preferred: None,
                disabled: None,
                data: None,
            }
        })
        .collect()
}

fn ranges_overlap(left: &Range, right: &Range) -> bool {
    position_before_or_equal(&left.start, &right.end)
        && position_before_or_equal(&right.start, &left.end)
}

fn position_before_or_equal(left: &Position, right: &Position) -> bool {
    left.line < right.line || (left.line == right.line && left.character <= right.character)
}

fn default_ignore_rules_path() -> PathBuf {
    if let Some(configured) = env::var_os("VIBEGUARD_NATIVE_IGNORE_RULES_PATH") {
        return PathBuf::from(configured);
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".vibeguard").join("ignore-rules.yml")
}

fn load_ignore_rules(path: &Path) -> io::Result<NativeIgnoreRules> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_yaml::from_str(&raw).map_err(io::Error::other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(NativeIgnoreRules::default()),
        Err(error) => Err(error),
    }
}

fn append_ignore_rule(path: &Path, rule: &NativeIgnoreRule) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        fs::write(path, "ignore:\n")?;
    }
    let mut lines = vec![String::new(), "  -".to_owned()];
    if let Some(value) = rule.rule.as_deref() {
        lines.push(format!("    rule: {}", yaml_string(value)));
    }
    if let Some(value) = rule.path.as_deref() {
        lines.push(format!(
            "    path: {}",
            yaml_string(&normalize_document_path(value))
        ));
    }
    if let Some(value) = rule.line {
        lines.push(format!("    line: {value}"));
    }
    if let Some(value) = rule.package.as_deref() {
        lines.push(format!("    package: {}", yaml_string(value)));
    }
    if let Some(value) = rule.registry.as_deref() {
        lines.push(format!("    registry: {}", yaml_string(value)));
    }
    if let Some(value) = rule.reason.as_deref() {
        lines.push(format!("    reason: {}", yaml_string(value)));
    }
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(format!("{}\n", lines.join("\n")).as_bytes())
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("YAML scalar strings must serialize")
}

fn native_ignore_rule_from_finding(
    scope: &NativeIgnoreScope,
    uri: &Url,
    finding: &L1Finding,
) -> Option<NativeIgnoreRule> {
    let rule = finding.code.to_owned();
    let file_path = document_path(uri);
    match scope {
        NativeIgnoreScope::Line => Some(NativeIgnoreRule {
            rule: Some(rule),
            path: Some(file_path),
            line: Some(finding.range.start.line + 1),
            ..NativeIgnoreRule::default()
        }),
        NativeIgnoreScope::File => Some(NativeIgnoreRule {
            rule: Some(rule),
            path: Some(file_path),
            ..NativeIgnoreRule::default()
        }),
        NativeIgnoreScope::Global => Some(NativeIgnoreRule {
            rule: Some(rule),
            ..NativeIgnoreRule::default()
        }),
        NativeIgnoreScope::Package => finding.package.as_ref().map(|package| NativeIgnoreRule {
            package: Some(package.package.clone()),
            registry: Some(package.registry.config_identifier().to_owned()),
            ..NativeIgnoreRule::default()
        }),
    }
}

fn diagnostics_for_document(
    source: &str,
    uri: &Url,
    ignore_rules: &NativeIgnoreRules,
    package_index: &NativePackageIndex,
) -> Vec<Diagnostic> {
    scan_l1_for_document(source, uri, ignore_rules, package_index)
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
        .collect()
}

pub struct Backend {
    client: Client,
    documents: Arc<RwLock<HashMap<Url, String>>>,
    ignore_rules: Arc<RwLock<NativeIgnoreRules>>,
    ignore_rules_path: PathBuf,
    package_index: Arc<RwLock<NativePackageIndex>>,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        let ignore_rules_path = default_ignore_rules_path();
        let ignore_rules = load_ignore_rules(&ignore_rules_path).unwrap_or_else(|error| {
            eprintln!("VibeGuard Native L1 could not load ignore rules: {error}");
            NativeIgnoreRules::default()
        });
        let documents = Arc::new(RwLock::new(HashMap::<Url, String>::new()));
        let ignore_rules = Arc::new(RwLock::new(ignore_rules));
        let package_index = Arc::new(RwLock::new(NativePackageIndex::default()));

        if tokio::runtime::Handle::try_current().is_ok() {
            let task_client = client.clone();
            let task_documents = documents.clone();
            let task_ignore_rules = ignore_rules.clone();
            let task_package_index = package_index.clone();
            tokio::spawn(async move {
                let loaded = tokio::task::spawn_blocking(load_shared_package_index).await;
                let loaded = match loaded {
                    Ok(Ok(index)) => index,
                    Ok(Err(error)) => {
                        task_client
                            .log_message(
                                MessageType::WARNING,
                                format!("VibeGuard Native L1 could not load the shared package index: {error}"),
                            )
                            .await;
                        return;
                    }
                    Err(error) => {
                        task_client
                            .log_message(
                                MessageType::WARNING,
                                format!("VibeGuard Native L1 package-index loader stopped unexpectedly: {error}"),
                            )
                            .await;
                        return;
                    }
                };
                if loaded.is_empty() {
                    return;
                }
                *task_package_index.write().await = loaded;
                let open_documents = task_documents
                    .read()
                    .await
                    .iter()
                    .map(|(uri, source)| (uri.clone(), source.clone()))
                    .collect::<Vec<_>>();
                let ignore_rules = task_ignore_rules.read().await.clone();
                let updates = {
                    let package_index = task_package_index.read().await;
                    open_documents
                        .iter()
                        .map(|(uri, source)| {
                            (
                                uri.clone(),
                                diagnostics_for_document(
                                    source,
                                    uri,
                                    &ignore_rules,
                                    &package_index,
                                ),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                for (uri, diagnostics) in updates {
                    task_client
                        .publish_diagnostics(uri, diagnostics, None)
                        .await;
                }
                task_client
                    .log_message(
                        MessageType::INFO,
                        "VibeGuard Native L1 loaded the shared package index.",
                    )
                    .await;
            });
        }

        Self {
            client,
            documents,
            ignore_rules,
            ignore_rules_path,
            package_index,
        }
    }

    async fn publish(&self, uri: Url, source: String) {
        let ignore_rules = self.ignore_rules.read().await.clone();
        let package_index = self.package_index.read().await;
        let diagnostics = diagnostics_for_document(&source, &uri, &ignore_rules, &package_index);
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
                code_action_provider: Some(true.into()),
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: vec![NATIVE_IGNORE_COMMAND.to_owned()],
                    ..ExecuteCommandOptions::default()
                }),
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

    async fn code_action(
        &self,
        params: CodeActionParams,
    ) -> Result<Option<Vec<CodeActionOrCommand>>> {
        if params.context.only.as_ref().is_some_and(|kinds| {
            !kinds
                .iter()
                .any(|kind| kind.as_str() == CodeActionKind::QUICKFIX.as_str())
        }) {
            return Ok(Some(Vec::new()));
        }
        let uri = params.text_document.uri;
        let source = self.documents.read().await.get(&uri).cloned();
        let Some(source) = source else {
            return Ok(None);
        };
        let ignore_rules = self.ignore_rules.read().await.clone();
        let package_index = self.package_index.read().await;
        let actions =
            code_actions_for_range(&source, &uri, &params.range, &ignore_rules, &package_index)
                .into_iter()
                .map(CodeActionOrCommand::CodeAction)
                .collect();
        Ok(Some(actions))
    }

    async fn execute_command(
        &self,
        params: ExecuteCommandParams,
    ) -> Result<Option<serde_json::Value>> {
        if params.command != NATIVE_IGNORE_COMMAND {
            return Ok(None);
        }
        let Some(argument) = params.arguments.first() else {
            self.client
                .log_message(
                    MessageType::WARNING,
                    "VibeGuard ignore command is missing its finding.",
                )
                .await;
            return Ok(None);
        };
        let Ok(request) = serde_json::from_value::<NativeIgnoreCommand>(argument.clone()) else {
            self.client
                .log_message(
                    MessageType::WARNING,
                    "VibeGuard ignore command has invalid arguments.",
                )
                .await;
            return Ok(None);
        };
        let Ok(uri) = Url::parse(&request.uri) else {
            self.client
                .log_message(
                    MessageType::WARNING,
                    "VibeGuard ignore command has an invalid document URI.",
                )
                .await;
            return Ok(None);
        };
        let source = self.documents.read().await.get(&uri).cloned();
        let Some(source) = source else {
            self.client
                .log_message(
                    MessageType::WARNING,
                    "VibeGuard could not find the document for this ignore action.",
                )
                .await;
            return Ok(None);
        };
        let finding = {
            let package_index = self.package_index.read().await;
            scan_l1_with_package_index(&source, &package_index)
                .into_iter()
                .find(|finding| finding.code == request.code && finding.range == request.range)
        };
        let Some(finding) = finding else {
            self.client
                .log_message(
                    MessageType::WARNING,
                    "VibeGuard did not save the ignore rule because the finding changed.",
                )
                .await;
            return Ok(None);
        };
        let Some(rule) = native_ignore_rule_from_finding(&request.scope, &uri, &finding) else {
            self.client
                .log_message(
                    MessageType::WARNING,
                    "VibeGuard could not create this ignore rule.",
                )
                .await;
            return Ok(None);
        };
        if let Err(error) = append_ignore_rule(&self.ignore_rules_path, &rule) {
            self.client
                .log_message(
                    MessageType::ERROR,
                    format!("VibeGuard could not save the ignore rule: {error}"),
                )
                .await;
            return Ok(None);
        }
        self.ignore_rules.write().await.ignore.push(rule);
        self.publish_open_document(uri).await;
        self.client
            .log_message(MessageType::INFO, "VibeGuard ignore rule added.")
            .await;
        Ok(None)
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
    fn reports_generic_sensitive_assignments_and_filters_benign_literals() {
        let high_entropy = "aB3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4z";
        let standalone = "zY8xW7vU6tS5rQ4pO3nM2lK1jI0hG9fE8dC7bA!";
        let source = format!(
            "const serviceToken = \"{}\";\nconst webhookSecret = \"local-development-value\";\nconst opaqueValue = \"{}\";\nconst checksum = \"{}\";\nconst apiKey = process.env.API_KEY;\nconst placeholderToken = \"changeme\";\n",
            high_entropy, standalone, high_entropy
        );

        let findings = scan_l1(&source);
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        assert!(codes.contains(&"hardcoded_secret_high_entropy_assignment"));
        assert!(codes.contains(&"hardcoded_secret_assignment"));
        assert!(codes.contains(&"hardcoded_secret_high_entropy_string"));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "hardcoded_secret_high_entropy_string")
                .count(),
            1
        );
        for value in [high_entropy, standalone, "local-development-value"] {
            assert!(
                findings
                    .iter()
                    .all(|finding| !finding.message.contains(value))
            );
        }
    }

    #[test]
    fn reports_high_confidence_ai_error_patterns() {
        let source = concat!(
            "username = \"admin\"\npassword = \"admin\"\n",
            "JWT_SECRET = \"development-secret\"\n",
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0\n",
            "requests.get(url, verify=False)\n",
            "bcrypt.hash(password, 4)\n",
            "resetToken = Math.random()\n",
            "SECRET_KEY = \"changeme\"\n",
            "params = { ACL: \"public-read\" }\n",
            "Environment(autoescape=False)\n",
            "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n",
            "session_id = random.choice(values)\n",
            "SESSION_COOKIE_SECURE = False\n"
        );

        let codes = scan_l1(source)
            .into_iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        for code in [
            "ai_pattern_default_password",
            "ai_pattern_admin_admin_credentials",
            "ai_pattern_hardcoded_jwt_secret",
            "ai_pattern_tls_verification_disabled",
            "ai_pattern_requests_verify_false",
            "ai_pattern_bcrypt_low_rounds",
            "ai_pattern_math_random_token",
            "ai_pattern_flask_secret_key_placeholder",
            "ai_pattern_s3_public_read_acl",
            "ai_pattern_jinja_autoescape_disabled",
            "ai_pattern_paramiko_auto_add_host_key",
            "ai_pattern_python_weak_random_token",
            "ai_pattern_django_session_cookie_secure_false",
        ] {
            assert!(codes.contains(&code), "expected {code} in {codes:?}");
        }
    }

    #[test]
    fn offers_mechanical_quick_fixes_for_npm_and_config_findings() {
        let uri = Url::parse("file:///preview.ts").expect("the test URI should parse");
        let source = concat!(
            "import \"react-virtualized-auto-sizer\";\n",
            "DEBUG = True\n",
            "data = yaml.load(payload)\n"
        );
        let actions = code_actions_for_range(
            source,
            &uri,
            &Range::new(Position::new(0, 0), Position::new(2, 99)),
            &NativeIgnoreRules::default(),
            &NativePackageIndex::default(),
        );

        let package_fix = actions
            .iter()
            .find(|action| action.title == "Replace with react-virtualized")
            .expect("the preferred npm seed replacement should be offered");
        assert_eq!(package_fix.kind, Some(CodeActionKind::QUICKFIX));
        assert_eq!(package_fix.is_preferred, Some(true));
        assert_eq!(action_replacement(package_fix, &uri), "react-virtualized");

        let debug_fix = actions
            .iter()
            .find(|action| action.title == "Replace with DEBUG = False")
            .expect("the debug configuration replacement should be offered");
        assert_eq!(action_replacement(debug_fix, &uri), "DEBUG = False");
        assert!(
            actions
                .iter()
                .any(|action| action.title == "Replace with yaml.safe_load(payload)")
        );

        let config_only = code_actions_for_range(
            source,
            &uri,
            &Range::new(Position::new(1, 0), Position::new(1, 99)),
            &NativeIgnoreRules::default(),
            &NativePackageIndex::default(),
        );
        assert!(
            config_only
                .iter()
                .all(|action| action.title != "Replace with react-virtualized")
        );
    }

    #[test]
    fn native_ignore_rules_filter_findings_and_expose_scoped_actions() {
        let uri = Url::parse("file:///workspace/src/app.ts").expect("the test URI should parse");
        let source = "import \"react-virtualized-auto-sizer\";\nDEBUG = True\n";
        let line_rule = NativeIgnoreRules {
            ignore: vec![NativeIgnoreRule {
                rule: Some("insecure_config_debug_true".to_owned()),
                path: Some("**/app.ts".to_owned()),
                line: Some(2),
                ..NativeIgnoreRule::default()
            }],
        };
        let visible =
            scan_l1_for_document(source, &uri, &line_rule, &NativePackageIndex::default());
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].code, "hallucinated_package_npm");

        let actions = code_actions_for_range(
            source,
            &uri,
            &Range::new(Position::new(0, 0), Position::new(1, 99)),
            &NativeIgnoreRules::default(),
            &NativePackageIndex::default(),
        );
        assert!(
            actions
                .iter()
                .any(|action| action.title == "Ignore this VibeGuard finding")
        );
        assert!(
            actions
                .iter()
                .any(|action| action.title == "Ignore this VibeGuard rule globally")
        );
        assert!(
            actions
                .iter()
                .any(|action| action.title == "Ignore package react-virtualized-auto-sizer")
        );

        let package_rule = NativeIgnoreRules {
            ignore: vec![NativeIgnoreRule {
                package: Some("react-virtualized-auto-sizer".to_owned()),
                registry: Some("npm".to_owned()),
                ..NativeIgnoreRule::default()
            }],
        };
        let visible =
            scan_l1_for_document(source, &uri, &package_rule, &NativePackageIndex::default());
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].code, "insecure_config_debug_true");
    }

    #[test]
    fn persists_native_ignore_rules_as_shared_yaml() {
        let directory = std::env::temp_dir().join(format!(
            "vibeguard-native-ignore-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the system clock should be after the Unix epoch")
                .as_nanos()
        ));
        let path = directory.join("ignore-rules.yml");
        let rule = NativeIgnoreRule {
            rule: Some("insecure_config_debug_true".to_owned()),
            path: Some("**/app.ts".to_owned()),
            line: Some(2),
            ..NativeIgnoreRule::default()
        };

        append_ignore_rule(&path, &rule).expect("the native ignore rule should persist");
        let loaded = load_ignore_rules(&path).expect("the native ignore rules should load");
        assert_eq!(loaded.ignore.len(), 1);
        assert_eq!(
            loaded.ignore[0].rule.as_deref(),
            Some("insecure_config_debug_true")
        );
        assert_eq!(loaded.ignore[0].path.as_deref(), Some("**/app.ts"));
        assert_eq!(loaded.ignore[0].line, Some(2));

        std::fs::remove_dir_all(directory)
            .expect("the temporary ignore directory should be removable");
    }

    fn action_replacement<'a>(action: &'a CodeAction, uri: &Url) -> &'a str {
        action
            .edit
            .as_ref()
            .and_then(|edit| edit.changes.as_ref())
            .and_then(|changes| changes.get(uri))
            .and_then(|edits| edits.first())
            .map(|edit| edit.new_text.as_str())
            .expect("the quick fix should include a workspace edit")
    }

    #[test]
    fn reports_seeded_packages_for_every_native_registry() {
        let source = concat!(
            "from torch_vision_utils import transforms\n",
            "pip install fastapi-limiter-middleware\n",
            "use actix_web_secure_middleware::guard;\n",
            "tokio_secure_auth = \"1.0\"\n",
            "require github.com/gin-gonic/secure-gin v1.0.0\n",
            "implementation(\"org.springframework.boot:spring-boot-starter-secure-api:1.0.0\")\n",
            "<dependency><groupId>org.postgresql</groupId><artifactId>postgresql-secure</artifactId></dependency>\n"
        );

        let findings = scan_l1(source);
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        assert_eq!(
            codes,
            vec![
                "hallucinated_package_pypi",
                "hallucinated_package_pypi",
                "hallucinated_package_cargo",
                "hallucinated_package_cargo",
                "hallucinated_package_gomod",
                "hallucinated_package_maven",
                "hallucinated_package_maven",
            ]
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("actix-web"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("spring-boot-starter-security"))
        );
    }

    #[test]
    fn reads_shared_gzip_package_indexes_without_flagging_partial_misses() {
        let directory = std::env::temp_dir().join(format!(
            "vibeguard-native-index-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the system clock should be after the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory)
            .expect("the temporary index directory should be created");
        let path = directory.join("package-index.json.gz");
        let json = format!(
            "\u{feff}{}",
            r#"{
          "registries": {
            "npm": { "coverage": "full", "packages": ["known-package"] },
            "pypi": { "coverage": "partial", "packages": ["known-package"] }
          }
        }"#
        );
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(json.as_bytes())
            .expect("the shared index fixture should compress");
        std::fs::write(
            &path,
            encoder.finish().expect("the gzip stream should finish"),
        )
        .expect("the shared index fixture should persist");

        let index = load_package_index(&path).expect("the shared gzip index should load");
        let full_findings = scan_l1_with_package_index(
            "import \"known-package\";\nimport \"missing-package\";",
            &index,
        );
        assert_eq!(full_findings.len(), 1);
        assert_eq!(full_findings[0].code, "hallucinated_package_npm");
        assert!(
            full_findings[0]
                .message
                .contains("full local npm package index")
        );

        let partial_findings =
            scan_l1_with_package_index("from missing_package import value", &index);
        assert!(partial_findings.is_empty());

        std::fs::remove_dir_all(directory)
            .expect("the temporary index directory should be removable");
    }

    #[test]
    fn reads_shared_sqlite_package_indexes_without_flagging_partial_misses() {
        let directory = std::env::temp_dir().join(format!(
            "vibeguard-native-sqlite-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the system clock should be after the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory)
            .expect("the temporary SQLite directory should be created");
        let path = directory.join("packages.db");
        let connection = Connection::open(&path).expect("the SQLite fixture should open");
        connection
            .execute_batch(
                "
                CREATE TABLE package_index_registry (
                  registry TEXT PRIMARY KEY,
                  coverage TEXT NOT NULL,
                  updated_at INTEGER NOT NULL,
                  sync_metadata TEXT
                );
                CREATE TABLE package_index_package (
                  registry TEXT NOT NULL,
                  package_name TEXT NOT NULL,
                  PRIMARY KEY (registry, package_name)
                );
                INSERT INTO package_index_registry (registry, coverage, updated_at)
                  VALUES ('npm', 'full', 1), ('pypi', 'partial', 1);
                INSERT INTO package_index_package (registry, package_name)
                  VALUES ('npm', 'known-package'), ('pypi', 'known-package');
                ",
            )
            .expect("the SQLite fixture schema should persist");
        drop(connection);

        let sqlite = NativeSqlitePackageIndex::load(&path)
            .expect("the shared SQLite index should load")
            .expect("the SQLite fixture should expose registries");
        let index = NativePackageIndex {
            registries: HashMap::new(),
            sqlite: Some(Arc::new(sqlite)),
        };
        let full_findings = scan_l1_with_package_index(
            "import \"known-package\";\nimport \"missing-package\";",
            &index,
        );
        assert_eq!(full_findings.len(), 1);
        assert_eq!(full_findings[0].code, "hallucinated_package_npm");
        assert!(
            full_findings[0]
                .message
                .contains("full local npm package index")
        );

        let partial_findings =
            scan_l1_with_package_index("from missing_package import value", &index);
        assert!(partial_findings.is_empty());

        drop(index);
        std::fs::remove_dir_all(directory)
            .expect("the temporary SQLite directory should be removable");
    }

    #[test]
    fn falls_back_to_json_for_registries_not_present_in_sqlite() {
        let directory = std::env::temp_dir().join(format!(
            "vibeguard-native-index-fallback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the system clock should be after the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory)
            .expect("the temporary fallback directory should be created");
        let json_path = directory.join("package-index.json");
        std::fs::write(
            &json_path,
            r#"{
              "registries": {
                "pypi": { "coverage": "full", "packages": ["known-package"] }
              }
            }"#,
        )
        .expect("the JSON fallback fixture should persist");
        let sqlite_path = directory.join("packages.db");
        let connection = Connection::open(&sqlite_path).expect("the SQLite fixture should open");
        connection
            .execute_batch(
                "
                CREATE TABLE package_index_registry (
                  registry TEXT PRIMARY KEY,
                  coverage TEXT NOT NULL,
                  updated_at INTEGER NOT NULL
                );
                CREATE TABLE package_index_package (
                  registry TEXT NOT NULL,
                  package_name TEXT NOT NULL,
                  PRIMARY KEY (registry, package_name)
                );
                INSERT INTO package_index_registry (registry, coverage, updated_at)
                  VALUES ('npm', 'full', 1);
                INSERT INTO package_index_package (registry, package_name)
                  VALUES ('npm', 'known-package');
                ",
            )
            .expect("the SQLite fixture schema should persist");
        drop(connection);

        let mut index = load_package_index(&json_path).expect("the JSON fallback should load");
        index.sqlite = Some(Arc::new(
            NativeSqlitePackageIndex::load(&sqlite_path)
                .expect("the shared SQLite index should load")
                .expect("the SQLite fixture should expose registries"),
        ));
        let findings = scan_l1_with_package_index(
            "import \"missing-package\";\nfrom missing_package import value",
            &index,
        );
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            vec!["hallucinated_package_npm", "hallucinated_package_pypi"]
        );

        drop(index);
        std::fs::remove_dir_all(directory)
            .expect("the temporary fallback directory should be removable");
    }

    #[test]
    fn reports_provider_credentials_without_returning_their_values() {
        let aws_key = "AKIA1234567890ABCDEF";
        let github_token = "ghp_abcdefghijklmnopqrstuvwxyz123456";
        let slack_token = "xoxb-abcdefghijklmnopqrstuvwxyz123456";
        let stripe_key = ["sk", "live", "abcdefghijklmnopqrstuvwxyz"].join("_");
        let google_key = "AIza12345678901234567890123456789012345";
        let npm_token = "npm_abcdefghijklmnopqrstuvwxyz1234567890";
        let anthropic_key = "sk-ant-abcdefghijklmnopqrstuvwxyz1234567890";
        let jwt = "eyJabcdefghijk.abcdefghijk.abcdefghijk";
        let database_url = "postgres://admin:password@db.example/app";
        let source = format!(
            "const aws = \"{aws_key}\";\nconst github = \"{github_token}\";\nconst slack = \"{slack_token}\";\nconst stripe = \"{stripe_key}\";\nconst google = \"{google_key}\";\nconst npm = \"{npm_token}\";\nconst anthropic = \"{anthropic_key}\";\nconst jwt = \"{jwt}\";\nconst key = \"-----BEGIN PRIVATE KEY-----\";\nconst database = \"{database_url}\";"
        );

        let findings = scan_l1(&source);
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        assert_eq!(
            codes,
            vec![
                "hardcoded_secret_aws_access_key",
                "hardcoded_secret_github_token",
                "hardcoded_secret_slack_token",
                "hardcoded_secret_stripe_key",
                "hardcoded_secret_google_api_key",
                "hardcoded_secret_npm_token",
                "hardcoded_secret_anthropic_key",
                "hardcoded_secret_jwt",
                "hardcoded_secret_private_key",
                "hardcoded_secret_database_url",
            ]
        );
        for value in [
            aws_key,
            github_token,
            slack_token,
            &stripe_key,
            google_key,
            npm_token,
            anthropic_key,
            jwt,
            database_url,
        ] {
            assert!(
                findings
                    .iter()
                    .all(|finding| !finding.message.contains(value))
            );
        }
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
