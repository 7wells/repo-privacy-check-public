#!/usr/bin/env node

// File purpose: Detect high-confidence privacy and secret risks in current trees and Git history.
// Inputs: CLI arguments or GitHub Action inputs plus files and Git objects under the target path.
// Outputs: Metadata-only console findings and an optional redacted JSON report.
// Side effects: Writes a report only when an explicit report path is provided.
// Security and privacy: Never expose matched values, snippets, environment values, or full local paths.
// Maintenance invariants: Preserve separate current/history modes and keep output redaction test-covered.

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

// Skip generated and local-only directories by default to avoid noisy findings and reading local artifacts.
const DEFAULT_IGNORED_DIRECTORIES = new Set([
  ".cache",
  ".git",
  ".next",
  ".nyc_output",
  ".pytest_cache",
  ".ruff_cache",
  ".tox",
  ".turbo",
  ".venv",
  "build",
  "coverage",
  "dist",
  "logs",
  "node_modules",
  "temp",
  "tmp",
  "venv",
  "__pycache__",
]);

const IGNORED_FILE_NAMES = new Set([
  ".DS_Store",
  "Thumbs.db",
  "npm-debug.log",
  "yarn-debug.log",
  "yarn-error.log",
  "pnpm-debug.log",
]);

const privateKeyFileNames = new Set([
  "id_rsa",
  "id_ed25519",
  "id_ed25519_sk",
  "id_ecdsa",
  "id_ecdsa_sk",
  "id_dsa",
]);
const allowedEnvFiles = new Set([".env.example", ".env.sample", ".env.template"]);
const envFileNamePattern = /^\.env(?:$|[._-]|rc(?:$|[._-]))/i;
const blockedCredentialFileNames = new Set([".git-credentials", ".netrc", "_netrc"]);
const blockedCredentialPathPatterns = [
  /(?:^|\/)\.aws\/credentials$/i,
  /(?:^|\/)\.config\/gh\/hosts\.yml$/i,
  /(?:^|\/)\.docker\/config\.json$/i,
  /(?:^|\/)\.kube\/config$/i,
];
const gitConfigFilePattern = /(?:^|\/)(?:\.gitconfig(?:\.local)?|(?:\.config\/)?git\/config)$/i;
const documentationFilePattern = /\.(?:adoc|asciidoc|md|mdx|rst|txt)$/i;
const localGitIdentityPattern = /^\s*(?:name|email)\s*=\s*["']?(?!example|sample|template|placeholder|your[ _-]|github-actions(?:\[bot\])?|\$\{|$)\S/i;
const MAX_TEXT_FILE_BYTES = 10 * 1024 * 1024;
const BINARY_SAMPLE_BYTES = 8000;
const GENERIC_HOME_USERS_FILE = path.resolve(__dirname, "../config/generic-home-users.txt");
const MAX_GENERIC_HOME_USER_FILE_BYTES = 1024;
const MAX_GENERIC_HOME_USER_ENTRIES = 16;
const genericHomeUserNamePattern = /^[a-z][a-z0-9_-]{0,31}$/;
const sensitiveUrlQueryKeyPattern = /^(?:access[_-]?token|address|api[_-]?key|auth(?:entication|orization)?|bearer|client[_-]?secret|credentials?|domain|email|host(?:name)?|ip|key|latitude|location|longitude|password|passwd|phone|private|private[_-]?key|secret|token|user(?:name)?)$/i;
let genericHomeUserNamesCache = null;

const placeholderValuePattern = /^(?:<|\$|example(?:\b|[ _-])|sample(?:\b|[ _-])|template(?:\b|[ _-])|placeholder(?:\b|[ _-])|changeme\b|your(?:\b|[ _-])|github-actions(?:\[bot\])?\b|false\b|true\b|null\b)/i;
const sensitiveDevEnvKeyPattern = /(?:HOST|HOSTNAME|DOMAIN|IP|ADDRESS|USER|USERNAME|EMAIL|NAME|PATH|DIR|DIRECTORY|ROOT|HOME|URL|URI|ENDPOINT|TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL)$/i;
const literalCredentialKeyPattern = /^(?:ACCESS_TOKEN|API_KEY|AUTH_TOKEN|AWS_SECRET_ACCESS_KEY|CLIENT_SECRET|CREDENTIALS?|DATABASE_URL|PASSWORD|PASSWD|PRIVATE_KEY|PRIVATE_TOKEN|REFRESH_TOKEN|SECRET|SECRET_KEY|TOKEN|[A-Z][A-Z0-9_]*(?:_ACCESS_TOKEN|_API_KEY|_AUTH_TOKEN|_CLIENT_SECRET|_PASSWORD|_PASSWD|_PRIVATE_KEY|_PRIVATE_TOKEN|_REFRESH_TOKEN|_SECRET|_SECRET_KEY|_TOKEN))$/;
const indirectCredentialValuePattern = /^(?:\$|\{\{|<|example|sample|template|placeholder|changeme|your|process\.env|os\.environ|Deno\.env|import\.meta\.env|env\.|secrets?\.|config\.|vault\.)/i;

function parseGenericHomeUserNames(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0 || buffer.length > MAX_GENERIC_HOME_USER_FILE_BYTES) {
    throw new Error("Invalid generic home-user allowlist.");
  }

  for (const byte of buffer) {
    const allowedByte =
      byte === 0x0a ||
      byte === 0x2d ||
      byte === 0x5f ||
      (byte >= 0x30 && byte <= 0x39) ||
      (byte >= 0x61 && byte <= 0x7a);
    if (!allowedByte) {
      throw new Error("Invalid generic home-user allowlist.");
    }
  }

  const text = buffer.toString("ascii");
  const withoutTrailingNewline = text.endsWith("\n") ? text.slice(0, -1) : text;
  const entries = withoutTrailingNewline.split("\n");

  if (
    entries.length === 0 ||
    entries.length > MAX_GENERIC_HOME_USER_ENTRIES ||
    entries.some((entry) => !genericHomeUserNamePattern.test(entry)) ||
    new Set(entries).size !== entries.length
  ) {
    throw new Error("Invalid generic home-user allowlist.");
  }

  return new Set(entries);
}

function loadGenericHomeUserNames() {
  const stat = fs.lstatSync(GENERIC_HOME_USERS_FILE);
  if (!stat.isFile() || stat.size > MAX_GENERIC_HOME_USER_FILE_BYTES) {
    throw new Error("Invalid generic home-user allowlist.");
  }
  return parseGenericHomeUserNames(fs.readFileSync(GENERIC_HOME_USERS_FILE));
}

function getGenericHomeUserNames() {
  if (genericHomeUserNamesCache === null) {
    genericHomeUserNamesCache = loadGenericHomeUserNames();
  }
  return genericHomeUserNamesCache;
}

function matchesLiteralCredentialAssignment(line) {
  const assignmentPattern = /\b([A-Z][A-Z0-9_]*)\b["']?\s*[:=]\s*["']?([^\s"'#]{8,})/g;

  for (const match of line.matchAll(assignmentPattern)) {
    const key = match[1];
    const value = match[2];
    if (
      !literalCredentialKeyPattern.test(key) ||
      placeholderValuePattern.test(value) ||
      indirectCredentialValuePattern.test(value)
    ) {
      continue;
    }

    if (!/[()]/.test(value)) {
      return true;
    }
  }

  return false;
}

function matchesGitConfigIdentity(line) {
  const match = /\bgit\s+config(?:\s+--(?:global|local|system))?\s+user\.(?:name|email)\b(.*)$/i.exec(line);
  if (!match) {
    return false;
  }

  const remainder = match[1].trim();
  if (!remainder || /^(?:[)\]}'"`]|\d?>|<|\||;|&&|#)/.test(remainder)) {
    return false;
  }

  return !placeholderValuePattern.test(remainder.replace(/^["']/, ""));
}

function matchesDevEnvLocalValue(line) {
  const assignmentPattern = /\b(DEV_ENV_[A-Z0-9_]*)\s*(?::?=|:)\s*["']?([^"'\s#;}]*)/gi;

  for (const match of line.matchAll(assignmentPattern)) {
    const prefix = line.slice(0, match.index);
    if (prefix.endsWith("${")) {
      continue;
    }

    const key = match[1];
    const value = match[2];
    if (!value || placeholderValuePattern.test(value) || value.includes("$")) {
      continue;
    }

    const looksLikeLocalValue =
      sensitiveDevEnvKeyPattern.test(key) ||
      /^(?:\/|~\/|[A-Za-z]:\\)/.test(value) ||
      /@/.test(value) ||
      /^(?:(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$/.test(value) ||
      /\.(?:internal|lan|local)(?::\d+)?(?:\/|$)/i.test(value);

    if (looksLikeLocalValue) {
      return true;
    }
  }

  return false;
}

function matchesHomeDirectoryPath(line) {
  const genericHomeUserNames = getGenericHomeUserNames();
  const patterns = [
    /(?:^|[\s"'=:])\/home\/([^/\s"'`]+)/g,
    /(?:^|[\s"'=:])\/Users\/([^/\s"'`]+)/g,
    /(?:^|[\s"'=:])[A-Za-z]:\\Users\\([^\\\s"'`]+)/g,
  ];

  for (const pattern of patterns) {
    for (const match of line.matchAll(pattern)) {
      if (match[1] !== "<USER>" && !genericHomeUserNames.has(match[1])) {
        return true;
      }
    }
  }

  return false;
}

function parseIpv4Address(hostname) {
  const parts = hostname.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) {
    return null;
  }

  const octets = parts.map(Number);
  return octets.every((octet) => octet >= 0 && octet <= 255) ? octets : null;
}

function isPrivateNetworkHostname(rawHostname) {
  const hostname = rawHostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");

  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname === "::1") {
    return false;
  }

  const ipv4 = parseIpv4Address(hostname);
  if (ipv4) {
    const [first, second] = ipv4;
    return (
      first === 10 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 169 && second === 254)
    );
  }

  const mappedIpv4 = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(hostname);
  if (mappedIpv4) {
    const high = Number.parseInt(mappedIpv4[1], 16);
    const low = Number.parseInt(mappedIpv4[2], 16);
    const mappedHostname = [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");
    return isPrivateNetworkHostname(mappedHostname);
  }

  if (hostname.includes(":")) {
    const firstHextet = Number.parseInt(hostname.split(":", 1)[0] || "0", 16);
    if (Number.isNaN(firstHextet)) {
      return false;
    }

    const isUniqueLocal = (firstHextet & 0xfe00) === 0xfc00;
    const isLinkLocal = (firstHextet & 0xffc0) === 0xfe80;
    return isUniqueLocal || isLinkLocal;
  }

  return /\.(?:internal|lan|local)$/i.test(hostname);
}

function matchesPrivateNetworkUrl(line) {
  const urlPattern = /\bhttps?:\/\/[^\s"'<>]+/gi;

  for (const match of line.matchAll(urlPattern)) {
    try {
      if (isPrivateNetworkHostname(new URL(match[0]).hostname)) {
        return true;
      }
    } catch {
      // Other rules may still inspect malformed URL-like values.
    }
  }

  return false;
}

function matchesSensitiveUrlQuery(line) {
  const urlPattern = /\bhttps?:\/\/[^\s"'<>`]+/gi;

  for (const match of line.matchAll(urlPattern)) {
    try {
      const parsedUrl = new URL(match[0]);
      for (const [key, value] of parsedUrl.searchParams) {
        if (!sensitiveUrlQueryKeyPattern.test(key)) {
          continue;
        }

        const trimmedValue = value.trim();
        const isIndirectValue =
          !trimmedValue ||
          placeholderValuePattern.test(trimmedValue) ||
          indirectCredentialValuePattern.test(trimmedValue) ||
          /\$\{[^}]+\}|\{\{[^}]+\}\}|<[^>]+>|%[A-Z][A-Z0-9_]*%/.test(trimmedValue);

        if (!isIndirectValue) {
          return true;
        }
      }
    } catch {
      // Other rules may still inspect malformed URL-like values.
    }
  }

  return false;
}

class UsageError extends Error {}
class HelpRequested extends Error {}

const contentRules = [
  {
    ruleId: "private-key-header",
    category: "private-key",
    pattern: /^-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----\s*$/,
  },
  {
    ruleId: "github-token",
    category: "token",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  },
  {
    ruleId: "slack-token",
    category: "token",
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{20,}\b/,
  },
  {
    ruleId: "aws-access-key-id",
    category: "cloud-credential",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  },
  {
    ruleId: "npm-token",
    category: "token",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/,
  },
  {
    ruleId: "pypi-token",
    category: "token",
    pattern: /\bpypi-[A-Za-z0-9_-]{50,}\b/,
  },
  {
    ruleId: "gitlab-token",
    category: "token",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    ruleId: "google-api-key",
    category: "cloud-credential",
    pattern: /\bAIza[A-Za-z0-9_-]{35}\b/,
  },
  {
    ruleId: "stripe-live-secret-key",
    category: "payment-credential",
    pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/,
  },
  {
    ruleId: "sendgrid-api-key",
    category: "cloud-credential",
    pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}\b/,
  },
  {
    ruleId: "literal-credential-assignment",
    category: "credential",
    matches: matchesLiteralCredentialAssignment,
  },
  {
    ruleId: "credential-url",
    category: "credential",
    pattern: /\bhttps?:\/\/[^\s:@/"']+:[^\s@/"']+@[^\s/"']+/,
  },
  {
    ruleId: "authorization-bearer-value",
    category: "credential",
    pattern: /\bauthorization\s*[:=]\s*["']?bearer\s+(?!\$\{\{|\$[A-Z_]|example|sample|template|placeholder|changeme)[A-Za-z0-9._~+/-]{16,}/i,
  },
  {
    ruleId: "git-config-identity",
    category: "git-identity",
    matches: matchesGitConfigIdentity,
  },
  {
    ruleId: "private-network-url",
    category: "private-url",
    matches: matchesPrivateNetworkUrl,
  },
  {
    ruleId: "home-directory-path",
    category: "local-path",
    matches: matchesHomeDirectoryPath,
  },
  {
    ruleId: "url-with-query",
    category: "url-query",
    matches: matchesSensitiveUrlQuery,
  },
  {
    ruleId: "dev-env-local-value",
    category: "local-env",
    matches: matchesDevEnvLocalValue,
  },
  {
    ruleId: "shell-xtrace",
    category: "unsafe-logging",
    history: false,
    pattern: /^\s*set\s+.*-[a-zA-Z]*x[a-zA-Z]*\b/,
  },
  {
    ruleId: "shell-env-dump",
    category: "unsafe-logging",
    history: false,
    pattern: /^\s*(?:printenv(?:\s|$)|env\s*(?:(?:-0|--null)\s*)?(?:[#;&|<>]|$))/,
  },
  {
    ruleId: "shell-git-diff-dump",
    category: "unsafe-logging",
    history: false,
    matches: (line) =>
      /^\s*git\s+diff(?:\s|$)/.test(line) &&
      !/(?:^|\s)--(?:quiet|no-patch)(?:[=\s]|$)/.test(line),
  },
  {
    ruleId: "shell-grep-match-output",
    category: "unsafe-logging",
    history: false,
    matches: (line) => {
      if (!/^\s*grep\s+/.test(line)) {
        return false;
      }

      const hasNonPrintingLongOption = /(?:^|\s)--(?:files-with-matches|quiet)(?:[=\s]|$)/.test(line);
      const hasNonPrintingShortOption = /(?:^|\s)-[A-Za-z]*[lq][A-Za-z]*(?:\s|$)/.test(line);
      return !hasNonPrintingLongOption && !hasNonPrintingShortOption;
    },
  },
  {
    ruleId: "shell-sensitive-file-dump",
    category: "unsafe-logging",
    history: false,
    pattern: /^\s*(?:cat|head|tail)\b[^#;&|]*(?:\.codex\/|\.env(?:[._-]|rc(?:[._-]|\b)|\s|$)|\.git-credentials\b|\.netrc\b|id_(?:dsa|ecdsa(?:_sk)?|ed25519(?:_sk)?|rsa)\b|\.(?:key|p12|pem|pfx|ppk)\b)/i,
  },
  {
    ruleId: "shell-secret-variable-output",
    category: "unsafe-logging",
    history: false,
    pattern: /^\s*(?:echo|printf)\b[^#]*(?:\$\{?[A-Za-z0-9_]*(?:API_KEY|PASSWORD|PASSWD|PRIVATE_KEY|SECRET|TOKEN)[A-Za-z0-9_]*\}?)/i,
  },
  {
    ruleId: "runtime-env-dump",
    category: "unsafe-logging",
    history: false,
    pattern: /\b(?:console\.(?:error|log)\s*\(\s*(?:JSON\.stringify\s*\(\s*)?(?:Deno\.env|process\.env)|print\s*\(\s*(?:dict\s*\(\s*)?os\.environ)/,
  },
];

const sensitivePathRuleIds = new Set([
  "authorization-bearer-value",
  "aws-access-key-id",
  "credential-url",
  "dev-env-local-value",
  "github-token",
  "git-config-identity",
  "gitlab-token",
  "google-api-key",
  "home-directory-path",
  "npm-token",
  "literal-credential-assignment",
  "private-key-header",
  "private-network-url",
  "pypi-token",
  "sendgrid-api-key",
  "slack-token",
  "stripe-live-secret-key",
  "url-with-query",
]);

function parseArgs(argv) {
  const options = {
    includeIgnored: false,
    mode: "current",
    reportPath: null,
    targetPath: process.cwd(),
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--include-ignored") {
      options.includeIgnored = true;
      continue;
    }

    if (arg === "--mode") {
      options.mode = argv[index + 1] || "";
      index += 1;
      continue;
    }

    if (arg.startsWith("--mode=")) {
      options.mode = arg.slice("--mode=".length);
      continue;
    }

    if (arg === "--report") {
      options.reportPath = argv[index + 1] || "";
      index += 1;
      continue;
    }

    if (arg.startsWith("--report=")) {
      options.reportPath = arg.slice("--report=".length);
      continue;
    }

    if (arg === "--help" || arg === "-h") {
      throw new HelpRequested();
    }

    if (arg.startsWith("-")) {
      failUsage("Unknown option.");
    }

    options.targetPath = arg;
  }

  if (!["current", "history"].includes(options.mode)) {
    failUsage("Mode must be 'current' or 'history'.");
  }

  return {
    ...options,
    targetPath: path.resolve(options.targetPath),
    reportPath: options.reportPath ? path.resolve(options.reportPath) : null,
  };
}

function printHelp() {
  return "Usage: privacy-check [--mode current|history] [--include-ignored] [--report path] [target-path]";
}

function failUsage(message) {
  throw new UsageError(message);
}

function toDisplayPath(targetPath, filePath) {
  const relativePath = path.relative(targetPath, filePath) || ".";
  const normalized = relativePath.split(path.sep).join("/");
  return normalized.startsWith("..") ? "[outside-target]" : normalized;
}

function normalizeGitPath(filePath) {
  return filePath.replace(/\\/g, "/");
}

function sanitizeFindingPath(filePath) {
  const normalized = normalizeGitPath(filePath);

  const containsControlCharacters = /[\u0000-\u001f\u007f]/.test(normalized);
  const containsEmailAddress = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(normalized);
  const containsCredentialAssignment = /(?:^|[/_.-])(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)[=:][^/]+/i.test(
    normalized,
  );
  const containsQueryValue = /\?[^/]*=/.test(normalized);
  const containsWindowsHomePath = /[A-Za-z]:\\Users\\/i.test(filePath);

  if (
    containsControlCharacters ||
    containsEmailAddress ||
    containsCredentialAssignment ||
    containsQueryValue ||
    containsWindowsHomePath
  ) {
    return "[redacted-path]";
  }

  for (const rule of contentRules) {
    if (
      sensitivePathRuleIds.has(rule.ruleId) &&
      (rule.pattern?.test(normalized) || rule.matches?.(normalized))
    ) {
      return "[redacted-path]";
    }
  }

  return normalized;
}

function addFinding(findings, ruleId, filePath, lineNumber, category, source) {
  // Findings must stay metadata-only. Never add matched content, env values, or absolute target paths here.
  findings.push({
    ruleId,
    file: sanitizeFindingPath(filePath),
    line: lineNumber || null,
    category,
    source,
  });
}

function isIgnoredPath(relativePath, includeIgnored) {
  if (includeIgnored) {
    return false;
  }

  const parts = normalizeGitPath(relativePath).split("/");
  return parts.some((part) => DEFAULT_IGNORED_DIRECTORIES.has(part)) || IGNORED_FILE_NAMES.has(parts[parts.length - 1]);
}

function checkPathRules(findings, relativePath, dirent, source) {
  const fileName = dirent.name;
  const lowerFileName = fileName.toLowerCase();
  const pathParts = normalizeGitPath(relativePath).split("/");

  const codexPathIndex = pathParts.indexOf(".codex");
  const isCodexDirectoryPath =
    codexPathIndex >= 0 && (codexPathIndex < pathParts.length - 1 || dirent.isDirectory());
  if (isCodexDirectoryPath) {
    const codexDirectoryPath = pathParts.slice(0, codexPathIndex + 1).join("/");
    addFinding(findings, "blocked-codex-directory", codexDirectoryPath, null, "local-credential", source);
    return;
  }

  if (pathParts.includes(".ssh")) {
    const ruleId = dirent.isDirectory() ? "blocked-ssh-directory" : "blocked-ssh-path";
    addFinding(findings, ruleId, relativePath, null, "local-credential", source);
    if (dirent.isDirectory()) {
      return;
    }
  }

  if (!dirent.isFile() && !dirent.isSymbolicLink?.()) {
    return;
  }

  if (privateKeyFileNames.has(lowerFileName)) {
    addFinding(findings, "blocked-private-ssh-key-filename", relativePath, null, "private-key", source);
  }

  if (blockedCredentialFileNames.has(lowerFileName)) {
    addFinding(findings, "blocked-credential-file", relativePath, null, "credential", source);
  }

  if (blockedCredentialPathPatterns.some((pattern) => pattern.test(normalizeGitPath(relativePath)))) {
    addFinding(findings, "blocked-credential-path", relativePath, null, "credential", source);
  }

  if (lowerFileName.endsWith(".pem") || lowerFileName.endsWith(".ppk") || lowerFileName.endsWith(".key")) {
    addFinding(findings, "blocked-private-key-extension", relativePath, null, "private-key", source);
  }

  if (
    lowerFileName.endsWith(".jks") ||
    lowerFileName.endsWith(".keystore") ||
    lowerFileName.endsWith(".p12") ||
    lowerFileName.endsWith(".pfx")
  ) {
    addFinding(findings, "blocked-key-store-extension", relativePath, null, "private-key", source);
  }

  if (envFileNamePattern.test(lowerFileName) && !allowedEnvFiles.has(lowerFileName)) {
    addFinding(findings, "blocked-env-file", relativePath, null, "env-file", source);
  }

  if (lowerFileName.endsWith(".log")) {
    addFinding(findings, "blocked-log-file", relativePath, null, "log-file", source);
  }
}

function isProbablyBinary(buffer) {
  const sampleLength = Math.min(buffer.length, BINARY_SAMPLE_BYTES);
  for (let index = 0; index < sampleLength; index += 1) {
    if (buffer[index] === 0) {
      return true;
    }
  }
  return false;
}

function checkContentRules(findings, relativePath, content, source) {
  const lines = content.split(/\r?\n/);
  const isDocumentationFile = documentationFilePattern.test(relativePath);
  const isGitConfigFile = gitConfigFilePattern.test(relativePath);
  let isGitUserSection = false;

  for (let index = 0; index < lines.length; index += 1) {
    if (isGitConfigFile) {
      const section = /^\s*\[([^\]]+)\]\s*(?:[#;].*)?$/.exec(lines[index]);
      if (section) {
        isGitUserSection = /^user(?:\s|$)/i.test(section[1].trim());
      } else if (isGitUserSection && localGitIdentityPattern.test(lines[index])) {
        addFinding(findings, "git-config-identity", relativePath, index + 1, "git-identity", source);
      }
    }

    for (const rule of contentRules) {
      if (source === "history" && rule.history === false) {
        continue;
      }

      if (isDocumentationFile && rule.category === "unsafe-logging") {
        continue;
      }

      if (rule.pattern?.test(lines[index]) || rule.matches?.(lines[index])) {
        addFinding(findings, rule.ruleId, relativePath, index + 1, rule.category, source);
      }
    }
  }
}

function classifyTextBuffer(buffer) {
  if (isProbablyBinary(buffer)) {
    return { kind: "binary" };
  }

  if (buffer.length > MAX_TEXT_FILE_BYTES) {
    return { kind: "too-large" };
  }

  return { kind: "text", content: buffer.toString("utf8") };
}

function readTextFile(filePath) {
  let descriptor;

  try {
    descriptor = fs.openSync(filePath, "r");
    const stat = fs.fstatSync(descriptor);
    const sample = Buffer.alloc(Math.min(stat.size, BINARY_SAMPLE_BYTES));
    fs.readSync(descriptor, sample, 0, sample.length, 0);

    if (isProbablyBinary(sample)) {
      return { kind: "binary" };
    }

    if (stat.size > MAX_TEXT_FILE_BYTES) {
      return { kind: "too-large" };
    }

    const buffer = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < buffer.length) {
      const bytesRead = fs.readSync(descriptor, buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) {
        break;
      }
      offset += bytesRead;
    }

    return classifyTextBuffer(offset === buffer.length ? buffer : buffer.subarray(0, offset));
  } catch {
    return { kind: "error" };
  } finally {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Closing a read-only descriptor does not affect the completed scan result.
      }
    }
  }
}

function walkCurrentTree(targetPath, includeIgnored) {
  const findings = [];
  const trackedCodexDirectories = listTrackedCodexDirectories(targetPath);

  function walk(directoryPath) {
    let entries;

    try {
      entries = fs.readdirSync(directoryPath, { withFileTypes: true });
    } catch {
      addFinding(findings, "unreadable-directory", toDisplayPath(targetPath, directoryPath), null, "scan-error", "current");
      return;
    }

    for (const entry of entries) {
      const entryPath = path.join(directoryPath, entry.name);
      const relativePath = toDisplayPath(targetPath, entryPath);

      if (isIgnoredPath(relativePath, includeIgnored)) {
        continue;
      }

      if (
        entry.isDirectory() &&
        entry.name === ".codex" &&
        trackedCodexDirectories !== null &&
        !trackedCodexDirectories.has(normalizeGitPath(relativePath))
      ) {
        continue;
      }

      checkPathRules(findings, relativePath, entry, "current");

      if (entry.isDirectory()) {
        if (entry.name !== ".ssh" && entry.name !== ".codex") {
          walk(entryPath);
        }
        continue;
      }

      if (entry.isFile()) {
        const result = readTextFile(entryPath);
        if (result.kind === "text") {
          checkContentRules(findings, relativePath, result.content, "current");
        } else if (result.kind === "error") {
          addFinding(findings, "unreadable-file", relativePath, null, "scan-error", "current");
        } else if (result.kind === "too-large") {
          addFinding(findings, "oversized-text-file", relativePath, null, "scan-error", "current");
        }
      } else if (entry.isSymbolicLink()) {
        try {
          checkContentRules(findings, relativePath, fs.readlinkSync(entryPath), "current");
        } catch {
          addFinding(findings, "unreadable-symbolic-link", relativePath, null, "scan-error", "current");
        }
      }
    }
  }

  walk(targetPath);
  return findings;
}

function git(targetPath, args, encoding = "utf8") {
  // Suppress Git stderr so unexpected repository errors cannot echo private local paths into logs.
  return execFileSync("git", args, {
    cwd: targetPath,
    encoding,
    maxBuffer: 1024 * 1024 * 50,
    stdio: ["ignore", "pipe", "ignore"],
  });
}

function listTrackedCodexDirectories(targetPath) {
  try {
    const output = git(targetPath, ["ls-files", "--cached", "-z", "--"], "buffer");
    const directories = new Set();

    for (const filePath of output.toString("utf8").split("\0").filter(Boolean)) {
      const pathParts = normalizeGitPath(filePath).split("/");
      const codexPathIndex = pathParts.indexOf(".codex");
      if (codexPathIndex >= 0 && codexPathIndex < pathParts.length - 1) {
        directories.add(pathParts.slice(0, codexPathIndex + 1).join("/"));
      }
    }

    return directories;
  } catch {
    return null;
  }
}

function listHistoryCommits(targetPath) {
  try {
    return git(targetPath, ["rev-list", "--all"]).trim().split(/\r?\n/).filter(Boolean);
  } catch {
    failUsage("History mode requires a readable Git repository.");
  }
}

function listCommitEntries(targetPath, commit) {
  const output = git(targetPath, ["ls-tree", "-r", "-z", "--full-tree", commit], "buffer");
  const entries = [];

  for (const record of output.toString("utf8").split("\0").filter(Boolean)) {
    const separator = record.indexOf("\t");
    if (separator < 0) {
      continue;
    }

    const metadata = record.slice(0, separator).split(" ");
    if (metadata.length !== 3) {
      continue;
    }

    const [mode, type, object] = metadata;
    entries.push({
      mode,
      type,
      object,
      filePath: record.slice(separator + 1),
    });
  }

  return entries;
}

function readHistoryBlob(targetPath, object) {
  try {
    return classifyTextBuffer(git(targetPath, ["cat-file", "blob", object], "buffer"));
  } catch {
    return { kind: "error" };
  }
}

function direntLike(filePath) {
  return {
    name: path.basename(filePath),
    isDirectory: () => false,
    isFile: () => true,
    isSymbolicLink: () => false,
  };
}

function scanHistory(targetPath, includeIgnored) {
  const findings = [];
  const seenFindings = new Set();
  const seenPaths = new Set();
  const seenBlobPaths = new Set();

  for (const commit of listHistoryCommits(targetPath)) {
    for (const entry of listCommitEntries(targetPath, commit)) {
      const relativePath = normalizeGitPath(entry.filePath);
      const historyPathParts = relativePath.split("/");
      const codexPathIndex = historyPathParts.indexOf(".codex");
      const isCodexDirectoryPath = codexPathIndex >= 0 && codexPathIndex < historyPathParts.length - 1;

      if (isIgnoredPath(relativePath, includeIgnored)) {
        continue;
      }

      const beforeCount = findings.length;

      if (!seenPaths.has(relativePath)) {
        seenPaths.add(relativePath);
        checkPathRules(findings, relativePath, direntLike(relativePath), "history");
      }

      if (!isCodexDirectoryPath && entry.type === "blob") {
        const blobPathKey = `${entry.object}\0${relativePath}`;
        if (!seenBlobPaths.has(blobPathKey)) {
          seenBlobPaths.add(blobPathKey);
          const result = readHistoryBlob(targetPath, entry.object);
          if (result.kind === "text") {
            checkContentRules(findings, relativePath, result.content, "history");
          } else if (result.kind === "error") {
            addFinding(findings, "unreadable-history-file", relativePath, null, "scan-error", "history");
          } else if (result.kind === "too-large") {
            addFinding(findings, "oversized-text-file", relativePath, null, "scan-error", "history");
          }
        }
      }

      // History scans can see the same finding across many commits; report each location once.
      const newFindings = findings.splice(beforeCount);
      for (const finding of newFindings) {
        const key = `${finding.ruleId}:${finding.file}:${finding.line || ""}`;
        if (!seenFindings.has(key)) {
          seenFindings.add(key);
          findings.push(finding);
        }
      }
    }
  }

  return findings;
}

function writeReport(reportPath, findings, mode) {
  if (!reportPath) {
    return;
  }

  if (fs.existsSync(reportPath) && fs.lstatSync(reportPath).isSymbolicLink()) {
    throw new Error("Refusing to write a report through a symbolic link.");
  }

  // Reports intentionally mirror redacted console findings and do not include snippets or raw matches.
  const report = {
    generatedBy: "repo-privacy-check",
    mode,
    findingCount: findings.length,
    findings,
  };

  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  if (process.platform !== "win32") {
    fs.chmodSync(reportPath, 0o600);
  }
}

function printFindings(findings, writeError) {
  writeError("Privacy check failed. Findings:");
  for (const finding of findings) {
    const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
    writeError(`- ${finding.ruleId} ${location} category=${finding.category}`);
  }
}

function actionInput(environment, name, fallback = "") {
  const canonicalName = `INPUT_${name.toUpperCase()}`;
  const underscoreName = canonicalName.replace(/-/g, "_");
  return environment[canonicalName] ?? environment[underscoreName] ?? fallback;
}

function actionArgsFromEnvironment(environment) {
  const mode = actionInput(environment, "scan-mode", "current");
  const includeIgnored = actionInput(environment, "include-ignored", "false").toLowerCase();
  const reportPath = actionInput(environment, "report-path");
  const targetPath = actionInput(environment, "target-path", ".");
  const args = ["--mode", mode];

  if (!["true", "false"].includes(includeIgnored)) {
    failUsage("Action input 'include-ignored' must be 'true' or 'false'.");
  }

  if (includeIgnored === "true") {
    args.push("--include-ignored");
  }

  if (reportPath) {
    args.push("--report", reportPath);
  }

  args.push(targetPath);
  return args;
}

function runCli(argv, io = {}) {
  const writeOutput = io.stdout || ((message) => console.log(message));
  const writeError = io.stderr || ((message) => console.error(message));
  let options;

  try {
    options = parseArgs(argv);
  } catch (error) {
    if (error instanceof HelpRequested) {
      writeOutput(printHelp());
      return 0;
    }
    if (error instanceof UsageError) {
      writeError(error.message);
      return 2;
    }
    throw error;
  }

  try {
    getGenericHomeUserNames();

    if (!fs.existsSync(options.targetPath)) {
      writeError("Target path does not exist.");
      return 2;
    }

    if (!fs.statSync(options.targetPath).isDirectory()) {
      writeError("Target must be a directory.");
      return 2;
    }

    const findings =
      options.mode === "history"
        ? scanHistory(options.targetPath, options.includeIgnored)
        : walkCurrentTree(options.targetPath, options.includeIgnored);

    writeReport(options.reportPath, findings, options.mode);

    if (findings.length > 0) {
      printFindings(findings, writeError);
      return 1;
    }

    writeOutput(`Privacy check completed successfully. mode=${options.mode} findings=0`);
    return 0;
  } catch (error) {
    if (error instanceof UsageError) {
      writeError(error.message);
    } else {
      writeError("Privacy check could not complete safely.");
    }
    return 2;
  }
}

if (require.main === module) {
  let args;

  try {
    args = process.env.GITHUB_ACTIONS === "true" ? actionArgsFromEnvironment(process.env) : process.argv.slice(2);
  } catch (error) {
    if (error instanceof UsageError) {
      console.error(error.message);
    } else {
      console.error("Privacy check could not complete safely.");
    }
    process.exit(2);
  }

  process.exit(runCli(args));
}

module.exports = {
  actionArgsFromEnvironment,
  runCli,
  testInternals: {
    checkPathRules,
    matchesHomeDirectoryPath,
    matchesSensitiveUrlQuery,
    parseGenericHomeUserNames,
    sanitizeFindingPath,
  },
};
