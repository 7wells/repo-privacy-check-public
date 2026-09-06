// File purpose: Validate scanner rules, CLI behavior, Action metadata, and output redaction.
// Inputs: Synthetic temporary repositories, files, environment maps, and workflow metadata.
// Outputs: Node test assertions over exit status and metadata-only findings.
// Security and privacy: Secret-like fixtures are synthetic and must never be copied from real systems.

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, test } = require("node:test");

const { actionArgsFromEnvironment, runCli, testInternals } = require("../scripts/privacy-check.js");

const temporaryRepositories = new Set();

function makeTempRepo() {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), "repo-privacy-check-"));
  temporaryRepositories.add(target);
  return target;
}

after(() => {
  for (const target of temporaryRepositories) {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

function runScanner(args) {
  const stdout = [];
  const stderr = [];
  const status = runCli(args, {
    stdout: (message) => stdout.push(message),
    stderr: (message) => stderr.push(message),
  });

  return {
    status,
    stdout: stdout.join("\n"),
    stderr: stderr.join("\n"),
  };
}

function combinedOutput(result) {
  return `${result.stdout}\n${result.stderr}`;
}

function assertRedacted(output, sensitiveValue, message = "sensitive value must be redacted") {
  assert.equal(output.includes(sensitiveValue), false, message);
}

test("action metadata avoids unquoted colon-space values", () => {
  const actionMetadata = fs.readFileSync(path.resolve(__dirname, "../action.yml"), "utf8");
  const unsafePlainScalar = /^\s*description:\s+[^"'\n][^\n]*:\s+/m;

  assert.doesNotMatch(actionMetadata, unsafePlainScalar);
  assert.match(actionMetadata, /^\s*using:\s+node24\s*$/m);
  assert.match(actionMetadata, /^\s*main:\s+scripts\/privacy-check\.js\s*$/m);
});

test("reusable workflow invokes the reviewed public action without a second Git checkout", () => {
  const workflow = fs.readFileSync(path.resolve(__dirname, "../.github/workflows/privacy-check.yml"), "utf8");
  const reviewedScannerSha = "5f6554d0b214786da6898d7376d2f71bc1295467";
  const checkoutUses = workflow.match(/^\s*uses:\s+actions\/checkout@/gm) ?? [];

  assert.equal(checkoutUses.length, 1);
  assert.match(workflow, new RegExp(`uses: 7wells/repo-privacy-check-public@${reviewedScannerSha}\\b`));
  assert.doesNotMatch(workflow, /^\s*repository:\s*/m);
  assert.doesNotMatch(workflow, /^\s*uses:\s+\.\/privacy-check-action\s*$/m);
});

test("redacts secret-like content from stdout, stderr, and reports", () => {
  const target = makeTempRepo();
  const reportPath = path.join(target, "privacy-report.json");
  const rawSecret = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");
  const rawPath = ["", "Users", "private-user", "work", "client-repo"].join("/");

  fs.writeFileSync(path.join(target, "leak.txt"), `token=${rawSecret}\npath=${rawPath}\n`);

  const result = runScanner(["--report", reportPath, target]);
  const output = combinedOutput(result);
  const report = fs.readFileSync(reportPath, "utf8");

  assert.equal(result.status, 1);
  assert.match(output, /github-token leak\.txt:1 category=token/);
  assert.match(output, /home-directory-path leak\.txt:2 category=local-path/);
  assertRedacted(output, rawSecret);
  assertRedacted(output, rawPath);
  assertRedacted(report, rawSecret);
  assertRedacted(report, rawPath);
  assert.equal(fs.statSync(reportPath).mode & 0o777, 0o600);
});

test("does not print absolute target paths for missing targets", () => {
  const missingTarget = path.join(os.tmpdir(), "repo-privacy-check-missing-private-path");
  const result = runScanner([missingTarget]);
  const output = combinedOutput(result);

  assert.equal(result.status, 2);
  assert.match(output, /Target path does not exist\./);
  assertRedacted(output, missingTarget);
});

test("skips local generated and ignored-style directories by default", () => {
  const target = makeTempRepo();
  const rawSecret = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

  fs.mkdirSync(path.join(target, ".venv"), { recursive: true });
  fs.writeFileSync(path.join(target, ".venv", "leak.txt"), rawSecret);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 0);
  assertRedacted(output, rawSecret);
});

test("can include ignored-style directories when explicitly requested", () => {
  const target = makeTempRepo();
  const rawSecret = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

  fs.mkdirSync(path.join(target, ".venv"), { recursive: true });
  fs.writeFileSync(path.join(target, ".venv", "leak.txt"), rawSecret);

  const result = runScanner(["--include-ignored", target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /github-token \.venv\/leak\.txt:1 category=token/);
  assertRedacted(output, rawSecret);
});

test("skips untracked files excluded by Git ignore rules", () => {
  const target = makeTempRepo();
  const rawSecret = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

  execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
  fs.writeFileSync(path.join(target, ".gitignore"), "private-cache/\n");
  fs.mkdirSync(path.join(target, "private-cache"));
  fs.writeFileSync(path.join(target, "private-cache", "ignored.txt"), rawSecret);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 0);
  assertRedacted(output, rawSecret);
});

test("scans untracked files not excluded by Git ignore rules", () => {
  const target = makeTempRepo();
  const rawSecret = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

  execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
  fs.writeFileSync(path.join(target, "candidate.txt"), rawSecret);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /github-token candidate\.txt:1 category=token/);
  assertRedacted(output, rawSecret);
});

test("scans tracked files even when a later Git rule ignores their path", () => {
  const target = makeTempRepo();
  const rawSecret = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

  execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
  fs.mkdirSync(path.join(target, "tracked-cache"));
  fs.writeFileSync(path.join(target, "tracked-cache", "tracked.txt"), rawSecret);
  execFileSync("git", ["add", "--", "tracked-cache/tracked.txt"], { cwd: target, stdio: "ignore" });
  fs.writeFileSync(path.join(target, ".gitignore"), "tracked-cache/\n");

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /github-token tracked-cache\/tracked\.txt:1 category=token/);
  assertRedacted(output, rawSecret);
});

test("maps GitHub Action inputs to CLI arguments without evaluating values", () => {
  const args = actionArgsFromEnvironment({
    "INPUT_INCLUDE-IGNORED": "true",
    "INPUT_REPORT-PATH": "privacy-report.json",
    "INPUT_SCAN-MODE": "history",
    "INPUT_TARGET-PATH": "target directory",
  });

  assert.deepEqual(args, [
    "--mode",
    "history",
    "--include-ignored",
    "--report",
    "privacy-report.json",
    "target directory",
  ]);
});

test("rejects invalid boolean GitHub Action inputs", () => {
  assert.throws(
    () => actionArgsFromEnvironment({ "INPUT_INCLUDE-IGNORED": "yes" }),
    /must be 'true' or 'false'/,
  );
});

test("detects additional high-confidence credentials without printing values", () => {
  const target = makeTempRepo();
  const reportPath = path.join(target, "privacy-report.json");
  const values = [
    ["npm-token", ["npm", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"].join("_")],
    ["pypi-token", ["pypi", "AgEIcHlwaS5vcmcCJGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNDU2"].join("-")],
    ["gitlab-token", ["glpat", "abcdefghijklmnopqrstuvwx"].join("-")],
    ["google-api-key", ["AIza", "A".repeat(35)].join("")],
    ["stripe-live-secret-key", ["sk", "live", "A".repeat(24)].join("_")],
    ["sendgrid-api-key", ["SG", "A".repeat(16), "B".repeat(24)].join(".")],
    ["literal-credential-assignment", ["CLIENT_SECRET", "A".repeat(24)].join("=")],
    ["literal-credential-assignment", ["SERVICE_TOKEN", "B".repeat(24)].join("=")],
    ["literal-credential-assignment", ["DEPLOYMENT_SECRET", "C".repeat(24)].join("=")],
    ["literal-credential-assignment", ["DB_PASSWORD", "D".repeat(24)].join("=")],
    ["literal-credential-assignment", ["CREDENTIALS", "E".repeat(24)].join("=")],
    ["literal-credential-assignment", [`"SERVICE_SECRET": "`, "F".repeat(24), `"`].join("")],
    ["credential-url", ["https://user", "password@private.example/repo"].join(":")],
    ["authorization-bearer-value", ["Authorization: Bearer", "abcdefghijklmnopqrstuvwx"].join(" ")],
  ];

  fs.writeFileSync(
    path.join(target, "credentials.txt"),
    `${values.map(([, value]) => value).join("\n")}\n`,
  );

  const result = runScanner(["--report", reportPath, target]);
  const output = combinedOutput(result);
  const report = fs.readFileSync(reportPath, "utf8");

  assert.equal(result.status, 1);
  for (const [ruleId, value] of values) {
    assert.match(output, new RegExp(ruleId));
    assertRedacted(output, value);
    assertRedacted(report, value);
  }
});

test("detects private network URLs and literal Git identities", () => {
  const target = makeTempRepo();
  const privateUrl = ["http:/", "192.168.10.20", "status"].join("/");
  const gitIdentity = ["git", "config", "--global", "user.email", "private-user@example.invalid"].join(" ");

  fs.writeFileSync(path.join(target, "local-config.txt"), `${privateUrl}\n${gitIdentity}\n`);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /private-network-url local-config\.txt:1 category=private-url/);
  assert.match(output, /git-config-identity local-config\.txt:2 category=git-identity/);
  assertRedacted(output, privateUrl);
  assertRedacted(output, gitIdentity);
});

test("allows loopback and localhost URLs", () => {
  const target = makeTempRepo();
  const urls = [
    "http://127.0.0.0/status",
    "http://127.0.0.1/status",
    "http://127.255.255.255:8080/status",
    "http://[::1]/status",
    "http://[::ffff:127.0.0.1]/status",
    "http://localhost/status",
    "http://localhost./status",
    "https://api.localhost/status",
    "https://deep.api.localhost:8443/status",
    "https://deep.api.localhost./status",
  ];

  fs.writeFileSync(path.join(target, "loopback.txt"), `${urls.join("\n")}\n`);

  const result = runScanner([target]);
  assert.equal(result.status, 0);
});

test("detects RFC1918, ULA, link-local, and local-domain URLs", () => {
  const target = makeTempRepo();
  const url = (host) => ["http:/", host, "status"].join("/");
  const urls = [
    url("10.0.0.1"),
    url("172.16.0.1"),
    url("172.31.255.254"),
    url("192.168.1.1"),
    url("169.254.0.0"),
    url("169.254.255.255"),
    url("[::ffff:192.168.1.1]"),
    url("[fc00::1]"),
    url("[fdff:ffff::1]"),
    url("[fe80::1]"),
    url("[febf::1]"),
    url("service.internal"),
    url("host.lan"),
    url("device.local"),
    url("sub.device.local"),
  ];

  fs.writeFileSync(path.join(target, "private-networks.txt"), `${urls.join("\n")}\n`);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  for (let line = 1; line <= urls.length; line += 1) {
    assert.match(output, new RegExp(`private-network-url private-networks\\.txt:${line} category=private-url`));
  }
  for (const url of urls) {
    assertRedacted(output, url);
  }
});

test("does not classify public network boundary addresses as private", () => {
  const target = makeTempRepo();
  const urls = [
    "http://9.255.255.255/status",
    "http://11.0.0.0/status",
    "http://172.15.255.255/status",
    "http://172.32.0.0/status",
    "http://192.167.255.255/status",
    "http://192.169.0.0/status",
    "http://169.253.255.255/status",
    "http://169.255.0.0/status",
    "http://[fbff::1]/status",
    "http://[fe7f::1]/status",
    "http://[fec0::1]/status",
    "https://example.com/status",
  ];

  fs.writeFileSync(path.join(target, "public-networks.txt"), `${urls.join("\n")}\n`);

  const result = runScanner([target]);
  assert.equal(result.status, 0);
});

test("still detects credentials and query strings on loopback URLs", () => {
  const target = makeTempRepo();
  const credentialUrl = ["http://user", "dummy-password@localhost/status"].join(":");
  const queryUrl = ["http://127.0.0.1/status", "token=dummy-value"].join("?");

  fs.writeFileSync(path.join(target, "loopback-sensitive.txt"), `${credentialUrl}\n${queryUrl}\n`);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /credential-url loopback-sensitive\.txt:1 category=credential/);
  assert.match(output, /url-with-query loopback-sensitive\.txt:2 category=url-query/);
  assert.doesNotMatch(output, /private-network-url/);
  assertRedacted(output, credentialUrl);
  assertRedacted(output, queryUrl);
});

test("blocks credential files and detects identities in local Git configuration", () => {
  const target = makeTempRepo();

  fs.writeFileSync(path.join(target, ".netrc"), "placeholder\n");
  fs.writeFileSync(
    path.join(target, ".gitconfig.local"),
    `[user]\nemail = ${["private-user", "example.invalid"].join("@")}\n`,
  );
  fs.mkdirSync(path.join(target, ".config", "git"), { recursive: true });
  fs.writeFileSync(
    path.join(target, ".config", "git", "config"),
    `[user]\nname = ${["Private", "User"].join(" ")}\n`,
  );

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /blocked-credential-file \.netrc category=credential/);
  assert.match(output, /git-config-identity \.gitconfig\.local:2 category=git-identity/);
  assert.match(output, /git-config-identity \.config\/git\/config:2 category=git-identity/);
});

test("allows placeholder identities in local Git configuration", () => {
  const target = makeTempRepo();

  fs.writeFileSync(path.join(target, ".gitconfig"), "[user]\nname = Example User\n");

  const result = runScanner([target]);
  assert.equal(result.status, 0);
});

test("redacts sensitive and control-character file names", () => {
  const target = makeTempRepo();
  const reportPath = path.join(target, "privacy-report.json");
  const sensitiveName = `${["ghp", "A".repeat(40)].join("_")}.txt`;
  const assignedName = `${["client_secret", "private-value"].join("=")}.txt`;
  const emailName = ["private-user", "example.invalid"].join("@") + ".txt";
  const controlName = ["unsafe", "name.txt"].join("\n");
  const findingValue = ["ghp", "B".repeat(40)].join("_");

  fs.writeFileSync(path.join(target, sensitiveName), findingValue);
  fs.writeFileSync(path.join(target, assignedName), findingValue);
  fs.writeFileSync(path.join(target, emailName), findingValue);
  fs.writeFileSync(path.join(target, controlName), findingValue);

  const result = runScanner(["--report", reportPath, target]);
  const output = combinedOutput(result);
  const report = fs.readFileSync(reportPath, "utf8");

  assert.equal(result.status, 1);
  assert.match(output, /github-token \[redacted-path\]:1 category=token/);
  assertRedacted(output, sensitiveName);
  assertRedacted(output, assignedName);
  assertRedacted(output, emailName);
  assertRedacted(output, controlName);
  assertRedacted(output, findingValue);
  assertRedacted(report, sensitiveName);
  assertRedacted(report, assignedName);
  assertRedacted(report, emailName);
  assertRedacted(report, controlName);
  assertRedacted(report, findingValue);
});

test("returns a generic error when a report cannot be written", () => {
  const target = makeTempRepo();
  const reportPath = path.join(target, "report-directory");
  fs.mkdirSync(reportPath);

  const result = runScanner(["--report", reportPath, target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 2);
  assert.match(output, /Privacy check could not complete safely\./);
  assertRedacted(output, reportPath);
  assertRedacted(output, "scripts/privacy-check.js");
});

test("does not write reports through symbolic links", () => {
  const target = makeTempRepo();
  const externalTarget = path.join(makeTempRepo(), "external-report.json");
  const reportPath = path.join(target, "privacy-report.json");
  fs.writeFileSync(externalTarget, "unchanged\n");
  fs.symlinkSync(externalTarget, reportPath);

  const result = runScanner(["--report", reportPath, target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 2);
  assert.equal(fs.readFileSync(externalTarget, "utf8"), "unchanged\n");
  assert.match(output, /Privacy check could not complete safely\./);
  assertRedacted(output, reportPath);
  assertRedacted(output, externalTarget);
});

test("does not echo an unknown option value", () => {
  const optionValue = `--${["ghp", "C".repeat(40)].join("_")}`;
  const result = runScanner([optionValue]);
  const output = combinedOutput(result);

  assert.equal(result.status, 2);
  assert.match(output, /Unknown option\./);
  assertRedacted(output, optionValue);
});

test("fails closed when a file cannot be read", () => {
  const target = makeTempRepo();
  const filePath = path.join(target, "unreadable.txt");
  const originalOpenSync = fs.openSync;
  fs.writeFileSync(filePath, "placeholder\n");

  fs.openSync = (candidate, ...args) => {
    if (candidate === filePath) {
      throw new Error("fixture read failure");
    }
    return originalOpenSync(candidate, ...args);
  };

  let result;
  try {
    result = runScanner([target]);
  } finally {
    fs.openSync = originalOpenSync;
  }

  assert.equal(result.status, 1);
  assert.match(combinedOutput(result), /unreadable-file unreadable\.txt category=scan-error/);
});

test("fails closed for oversized text files", () => {
  const target = makeTempRepo();
  fs.writeFileSync(path.join(target, "oversized.txt"), Buffer.alloc(11 * 1024 * 1024, 0x61));

  const result = runScanner([target]);

  assert.equal(result.status, 1);
  assert.match(combinedOutput(result), /oversized-text-file oversized\.txt category=scan-error/);
});

test("skips oversized binary files without treating them as text", () => {
  const target = makeTempRepo();
  const filePath = path.join(target, "large-binary.bin");
  fs.writeFileSync(filePath, Buffer.from([0]));
  fs.truncateSync(filePath, 11 * 1024 * 1024);

  const result = runScanner([target]);
  assert.equal(result.status, 0);
});

test("scans symbolic-link targets without following them", () => {
  const target = makeTempRepo();
  const rawTarget = ["", "home", "private-user", "outside"].join("/");
  fs.symlinkSync(rawTarget, path.join(target, "local-link"));

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /home-directory-path local-link:1 category=local-path/);
  assertRedacted(output, rawTarget);
});

test("detects SSH paths in Git history", () => {
  const findings = [];
  testInternals.checkPathRules(
    findings,
    ".ssh/config",
    {
      name: "config",
      isDirectory: () => false,
      isFile: () => true,
      isSymbolicLink: () => false,
    },
    "history",
  );

  assert.deepEqual(findings[0], {
    ruleId: "blocked-ssh-path",
    file: ".ssh/config",
    line: null,
    category: "local-credential",
    source: "history",
  });
  assert.equal(findings.length, 1);
});

test("detects .codex directories without inspecting their contents", () => {
  const target = makeTempRepo();
  const codexDirectory = path.join(target, ".codex");
  const sensitiveFileName = "private-session-metadata.json";
  const tokenLikeValue = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");
  fs.mkdirSync(codexDirectory);
  fs.writeFileSync(path.join(codexDirectory, sensitiveFileName), `${tokenLikeValue}\n`);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /blocked-codex-directory \.codex category=local-credential/);
  assert.doesNotMatch(output, /github-token/);
  assertRedacted(output, sensitiveFileName);
  assertRedacted(output, tokenLikeValue);
});

test("ignores untracked .codex directories until they are staged", () => {
  const target = makeTempRepo();
  const codexDirectory = path.join(target, ".codex");
  const sensitiveFileName = "session-metadata.json";

  execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
  fs.mkdirSync(codexDirectory);
  fs.writeFileSync(path.join(codexDirectory, sensitiveFileName), "placeholder\n");

  const untrackedResult = runScanner([target]);
  assert.equal(untrackedResult.status, 0);

  execFileSync("git", ["add", "--force", "--", ".codex"], { cwd: target, stdio: "ignore" });
  const stagedResult = runScanner([target]);
  const stagedOutput = combinedOutput(stagedResult);

  assert.equal(stagedResult.status, 1);
  assert.match(stagedOutput, /blocked-codex-directory \.codex category=local-credential/);
  assertRedacted(stagedOutput, sensitiveFileName);
});

test("detects historical .codex directories without reading stored files", () => {
  const target = makeTempRepo();
  const codexDirectory = path.join(target, ".codex");
  const sensitiveFileName = "private-session-metadata.json";
  const tokenLikeValue = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

  execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
  fs.mkdirSync(codexDirectory);
  fs.writeFileSync(path.join(codexDirectory, sensitiveFileName), `${tokenLikeValue}\n`);
  execFileSync("git", ["add", "--", ".codex"], { cwd: target, stdio: "ignore" });
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Example User",
      "-c",
      "user.email=example@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "Add test fixture",
    ],
    { cwd: target, stdio: "ignore" },
  );
  fs.rmSync(codexDirectory, { recursive: true });
  execFileSync("git", ["add", "--update"], { cwd: target, stdio: "ignore" });
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Example User",
      "-c",
      "user.email=example@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "Remove test fixture",
    ],
    { cwd: target, stdio: "ignore" },
  );

  const result = runScanner(["--mode", "history", target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /blocked-codex-directory \.codex category=local-credential/);
  assert.doesNotMatch(output, /github-token/);
  assertRedacted(output, sensitiveFileName);
  assertRedacted(output, tokenLikeValue);
});

test("reports .codex paths once at the directory boundary in history", () => {
  const findings = [];
  testInternals.checkPathRules(
    findings,
    "project/.codex/sessions/session.json",
    {
      name: "session.json",
      isDirectory: () => false,
      isFile: () => true,
      isSymbolicLink: () => false,
    },
    "history",
  );

  assert.deepEqual(findings[0], {
    ruleId: "blocked-codex-directory",
    file: "project/.codex",
    line: null,
    category: "local-credential",
    source: "history",
  });
  assert.equal(findings.length, 1);
});

test("does not treat an ordinary file named .codex as a directory", () => {
  const findings = [];
  testInternals.checkPathRules(
    findings,
    ".codex",
    {
      name: ".codex",
      isDirectory: () => false,
      isFile: () => true,
      isSymbolicLink: () => false,
    },
    "history",
  );

  assert.deepEqual(findings, []);
});

test("detects the original high-confidence content rules", () => {
  const target = makeTempRepo();
  const contentValues = [
    ["private-key-header", ["-----BEGIN", "PRIVATE KEY-----"].join(" ")],
    ["slack-token", ["xoxb", "A".repeat(24)].join("-")],
    ["aws-access-key-id", ["AKIA", "A".repeat(16)].join("")],
    ["home-directory-path", ["", "Users", "private-user", "project"].join("/")],
    ["url-with-query", ["https://example.invalid/resource", "private=value"].join("?")],
    ["dev-env-local-value", ["DEV_ENV_HOST", "private-host"].join("=")],
  ];
  const unsafeLoggingValues = [
    ["shell-xtrace", ["set", "-x"].join(" ")],
    ["shell-env-dump", ["printenv", "PRIVATE_VALUE"].join(" ")],
    ["shell-git-diff-dump", ["git", "diff"].join(" ")],
    ["shell-grep-match-output", ["grep", "pattern", "file"].join(" ")],
    ["shell-sensitive-file-dump", ["cat", ".env"].join(" ")],
    ["shell-sensitive-file-dump", ["cat", ".envrc"].join(" ")],
    ["shell-sensitive-file-dump", ["cat", ".codex/config.toml"].join(" ")],
    ["shell-sensitive-file-dump", ["head", "private.pfx"].join(" ")],
    ["shell-sensitive-file-dump", ["tail", "id_ed25519_sk"].join(" ")],
    ["shell-secret-variable-output", ["echo", "$PRIVATE_TOKEN"].join(" ")],
    ["runtime-env-dump", ["console.log", "process.env"].join("(") + ")"],
  ];
  const values = [...contentValues, ...unsafeLoggingValues];

  fs.writeFileSync(path.join(target, "rules.txt"), `${contentValues.map(([, value]) => value).join("\n")}\n`);
  fs.writeFileSync(
    path.join(target, "unsafe-logging.sh"),
    `${unsafeLoggingValues.map(([, value]) => value).join("\n")}\n`,
  );

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  for (const [ruleId, value] of values) {
    assert.match(output, new RegExp(ruleId));
    assertRedacted(output, value);
  }
});

test("ignores unsafe logging examples in documentation but still scans documentation for secrets", () => {
  const target = makeTempRepo();
  const rawSecret = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");
  const documentation = [
    ["git", "diff"].join(" "),
    ["printenv", "PRIVATE_VALUE"].join(" "),
    ["console.log", "process.env"].join("(") + ")",
    rawSecret,
  ];

  fs.writeFileSync(path.join(target, "DEVELOPMENT.md"), `${documentation.join("\n")}\n`);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /github-token DEVELOPMENT\.md:4 category=token/);
  assert.doesNotMatch(output, /category=unsafe-logging/);
  assertRedacted(output, rawSecret);
});

test("detects high-confidence credential paths and file names", () => {
  const target = makeTempRepo();
  const files = [
    "id_rsa",
    "ID_RSA",
    "id_ed25519_sk",
    "id_ecdsa_sk",
    "private.pem",
    "private.key",
    "private.p12",
    "private.pfx",
    ".env",
    ".ENV.PROD",
    ".envrc",
    ".env-local",
    "output.log",
  ];

  for (const fileName of files) {
    fs.writeFileSync(path.join(target, fileName), "placeholder\n");
  }
  fs.mkdirSync(path.join(target, ".ssh"));
  fs.writeFileSync(path.join(target, ".ssh", "config"), "Host example\n");
  fs.mkdirSync(path.join(target, ".aws"));
  fs.writeFileSync(path.join(target, ".aws", "credentials"), "placeholder\n");

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /blocked-private-ssh-key-filename id_rsa category=private-key/);
  assert.match(output, /blocked-private-ssh-key-filename ID_RSA category=private-key/);
  assert.match(output, /blocked-private-ssh-key-filename id_ed25519_sk category=private-key/);
  assert.match(output, /blocked-private-ssh-key-filename id_ecdsa_sk category=private-key/);
  assert.match(output, /blocked-private-key-extension private\.pem category=private-key/);
  assert.match(output, /blocked-private-key-extension private\.key category=private-key/);
  assert.match(output, /blocked-key-store-extension private\.p12 category=private-key/);
  assert.match(output, /blocked-key-store-extension private\.pfx category=private-key/);
  assert.match(output, /blocked-credential-path \.aws\/credentials category=credential/);
  assert.match(output, /blocked-env-file \.env category=env-file/);
  assert.match(output, /blocked-env-file \.ENV\.PROD category=env-file/);
  assert.match(output, /blocked-env-file \.envrc category=env-file/);
  assert.match(output, /blocked-env-file \.env-local category=env-file/);
  assert.match(output, /blocked-log-file output\.log category=log-file/);
  assert.match(output, /blocked-ssh-directory \.ssh category=local-credential/);
});

test("allows documented placeholders and non-printing grep checks", () => {
  const target = makeTempRepo();
  const placeholderExpression = ["$", "{{ secrets.TOKEN }}"].join("");
  const lines = [
    ["Authorization: Bearer", placeholderExpression].join(" "),
    ["git", "config", "user.name", placeholderExpression].join(" "),
    ["DEV_ENV_HOST", "placeholder"].join("="),
    ["DEV_ENV_HOST", "$LOCAL_HOST"].join("="),
    ["PASSWORD", placeholderExpression].join("="),
    ["SERVICE_TOKEN", "process.env.SERVICE_TOKEN"].join("="),
    ["DEPLOYMENT_SECRET", "getSecret()"].join("="),
    [`"SERVICE_SECRET": "`, "placeholder-value", `"`].join(""),
    ["TOKEN_COUNT", "12345678"].join("="),
    ["grep", "-R", "--quiet", "pattern", "directory"].join(" "),
    ["grep", "-Rl", "pattern", "directory"].join(" "),
    ["git", "diff", "--quiet"].join(" "),
  ];

  for (const fileName of [".env.example", ".env.sample", ".env.template", ".envelope", ".environment"]) {
    fs.writeFileSync(path.join(target, fileName), "TOKEN=placeholder\n");
  }
  fs.writeFileSync(path.join(target, "placeholders.txt"), `${lines.join("\n")}\n`);

  const result = runScanner([target]);
  assert.equal(result.status, 0);
});

test("allows DEV_ENV configuration plumbing and read-only Git identity queries", () => {
  const target = makeTempRepo();
  const lines = [
    ': "${DEV_ENV_ROOT:=/srv/projects}"',
    ': "${DEV_ENV_HOST:?required}"',
    "DEV_ENV_UPDATE_MODE=prompt",
    "DEV_ENV_INSTALL_METHOD=standalone",
    "git config user.name >/dev/null",
    "git config --global user.email 2>/dev/null",
    "identity=$(git config user.email 2>/dev/null)",
    "identity=$(git config user.name)",
    "git config user.email # optional value",
    "git config user.name github-actions[bot]",
  ];

  fs.writeFileSync(path.join(target, "configuration-helper.sh"), `${lines.join("\n")}\n`);

  const result = runScanner([target]);
  assert.equal(result.status, 0);
});

test("still blocks literal DEV_ENV local values and Git identity setters", () => {
  const target = makeTempRepo();
  const localHost = ["private", "host"].join("-");
  const identity = ["private", "example.invalid"].join("@");
  const credential = ["local", "credential"].join("-");
  const lines = [
    ["DEV_ENV_HOST", localHost].join("="),
    ["DEV_ENV_API_KEY", credential].join("="),
    ["git config user.email", identity].join(" "),
  ];

  fs.writeFileSync(path.join(target, "local-values.sh"), `${lines.join("\n")}\n`);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  assert.match(output, /dev-env-local-value local-values\.sh:1 category=local-env/);
  assert.match(output, /dev-env-local-value local-values\.sh:2 category=local-env/);
  assert.match(output, /git-config-identity local-values\.sh:3 category=git-identity/);
  assertRedacted(output, localHost);
  assertRedacted(output, credential);
  assertRedacted(output, identity);
});
