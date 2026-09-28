// File purpose: Verify the staged Git snapshot is scanned independently of the working tree.
// Inputs: Synthetic temporary Git repositories, index entries, and local worktrees.
// Outputs: Assertions over metadata-only findings, failures, and redacted reports.
// Security and privacy: Fixtures contain only constructed synthetic values and never leave local test repositories.

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, test } = require("node:test");

const { actionArgsFromEnvironment, runCli } = require("../scripts/privacy-check.js");

const roots = new Set();
const token = (letter = "A") => ["ghp", letter.repeat(40)].join("_");
const privateKeyHeader = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");
let reportNumber = 0;

function git(target, ...args) {
  return execFileSync("git", args, {
    cwd: target,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

function makeRepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "privacy-index-"));
  roots.add(root);
  const repo = path.join(root, "repo");
  fs.mkdirSync(repo);
  git(repo, "init", "--quiet");
  return { root, repo };
}

function write(repo, filePath, content) {
  const fullPath = path.join(repo, filePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content);
}

function commitAll(repo, message = "Add synthetic fixture") {
  git(repo, "add", "--all");
  git(repo, "-c", "user.name=Example User", "-c", "user.email=example@example.invalid", "commit", "--quiet", "-m", message);
}

function scan(fixture, mode, target = fixture.repo, args = []) {
  const reportPath = path.join(fixture.root, `report-${++reportNumber}.json`);
  const stdout = [];
  const stderr = [];
  const status = runCli(["--mode", mode, "--report", reportPath, ...args, target], {
    stdout: (message) => stdout.push(message),
    stderr: (message) => stderr.push(message),
  });
  const reportText = fs.existsSync(reportPath) ? fs.readFileSync(reportPath, "utf8") : null;
  return {
    status,
    output: [...stdout, ...stderr].join("\n"),
    reportText,
    report: reportText === null ? null : JSON.parse(reportText),
    reportPath,
  };
}

function expectClean(result, mode) {
  assert.equal(result.status, 0, result.output);
  assert.equal(result.report.mode, mode);
  assert.equal(result.report.findingCount, 0);
  assert.deepEqual(result.report.findings, []);
}

function expectFinding(result, ruleId, filePath, line, category, source) {
  assert.equal(result.status, 1, result.output);
  assert.equal(result.report.mode, source);
  assert.ok(result.report.findings.some((finding) =>
    finding.ruleId === ruleId && finding.file === filePath && finding.line === line &&
    finding.category === category && finding.source === source));
  assert.ok(result.output.includes(`- ${ruleId} ${filePath}${line === null ? "" : `:${line}`} category=${category}`));
}

function expectRedacted(result, fixture, ...values) {
  for (const value of [fixture.root, ...values]) {
    assert.equal(result.output.includes(value), false);
    assert.equal(result.reportText?.includes(value) ?? false, false);
  }
}

after(() => {
  for (const root of roots) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("index finds a newly staged secret that matches the working tree", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", `${token()}\n`);
  git(fixture.repo, "add", "fixture.txt");
  const result = scan(fixture, "index");
  expectFinding(result, "github-token", "fixture.txt", 1, "token", "index");
  expectFinding(scan(fixture, "current"), "github-token", "fixture.txt", 1, "token", "current");
  expectRedacted(result, fixture, token());
});

test("index retains a staged secret after the working tree is cleaned", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", `${token()}\n`);
  git(fixture.repo, "add", "fixture.txt");
  write(fixture.repo, "fixture.txt", "Clean working tree.\n");
  expectClean(scan(fixture, "current"), "current");
  const result = scan(fixture, "index");
  expectFinding(result, "github-token", "fixture.txt", 1, "token", "index");
  expectRedacted(result, fixture, token());
});

test("index ignores an unstaged secret after a clean version was staged", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", "Clean staged content.\n");
  git(fixture.repo, "add", "fixture.txt");
  write(fixture.repo, "fixture.txt", `${token()}\n`);
  expectFinding(scan(fixture, "current"), "github-token", "fixture.txt", 1, "token", "current");
  expectClean(scan(fixture, "index"), "index");
});

test("index reads the staged version of an existing tracked file", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", "Original clean content.\n");
  commitAll(fixture.repo);
  write(fixture.repo, "fixture.txt", `${token()}\n`);
  git(fixture.repo, "add", "fixture.txt");
  write(fixture.repo, "fixture.txt", "Clean again without staging.\n");
  expectClean(scan(fixture, "current"), "current");
  expectFinding(scan(fixture, "index"), "github-token", "fixture.txt", 1, "token", "index");
});

test("index sees only the staged lines in a partially staged equivalent state", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", "Clean base.\n");
  commitAll(fixture.repo);
  write(fixture.repo, "fixture.txt", `${token("A")}\nClean second line.\n`);
  git(fixture.repo, "add", "fixture.txt");
  write(fixture.repo, "fixture.txt", `Clean first line.\n${token("B")}\n`);
  const indexResult = scan(fixture, "index");
  expectFinding(indexResult, "github-token", "fixture.txt", 1, "token", "index");
  assert.equal(indexResult.report.findings.some((finding) => finding.line === 2), false);
  const currentResult = scan(fixture, "current");
  expectFinding(currentResult, "github-token", "fixture.txt", 2, "token", "current");
  assert.equal(currentResult.report.findings.some((finding) => finding.line === 1), false);
  expectRedacted(indexResult, fixture, token("A"), token("B"));
  expectRedacted(currentResult, fixture, token("A"), token("B"));
});

test("index excludes staged deletions", () => {
  const fixture = makeRepo();
  write(fixture.repo, "removed.key", "Harmless fixture.\n");
  commitAll(fixture.repo);
  git(fixture.repo, "rm", "--quiet", "removed.key");
  expectClean(scan(fixture, "index"), "index");
});

test("index uses the destination path of a staged rename", () => {
  const fixture = makeRepo();
  write(fixture.repo, "old.txt", "Harmless fixture.\n");
  commitAll(fixture.repo);
  git(fixture.repo, "mv", "old.txt", "moved.key");
  const result = scan(fixture, "index");
  expectFinding(result, "blocked-private-key-extension", "moved.key", null, "private-key", "index");
  assert.equal(result.output.includes("old.txt"), false);
});

test("index scans a staged symlink target without following it", () => {
  const fixture = makeRepo();
  write(fixture.repo, "untracked.txt", `${token()}\n`);
  fs.symlinkSync("untracked.txt", path.join(fixture.repo, "link.txt"));
  git(fixture.repo, "add", "link.txt");
  expectClean(scan(fixture, "index"), "index");
  expectFinding(scan(fixture, "current"), "github-token", "untracked.txt", 1, "token", "current");
});

test("index applies content rules to a staged symlink target", () => {
  const fixture = makeRepo();
  const syntheticHome = ["", "home", "private-user", "target"].join("/");
  fs.symlinkSync(syntheticHome, path.join(fixture.repo, "link.txt"));
  git(fixture.repo, "add", "link.txt");
  const result = scan(fixture, "index");
  expectFinding(result, "home-directory-path", "link.txt", 1, "local-path", "index");
  expectRedacted(result, fixture, syntheticHome);
});

test("index treats a gitlink as a path without reading its commit as file content", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", "Clean committed content.\n");
  commitAll(fixture.repo);
  const commit = git(fixture.repo, "rev-parse", "HEAD");
  git(fixture.repo, "update-index", "--add", "--cacheinfo", `160000,${commit},modules/fixture`);
  expectClean(scan(fixture, "index"), "index");
});

test("index excludes binary blob content", () => {
  const fixture = makeRepo();
  write(fixture.repo, "binary.dat", Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(token())]));
  git(fixture.repo, "add", "binary.dat");
  expectClean(scan(fixture, "index"), "index");
});

for (const encoding of ["LE", "BE"]) {
  test(`index detects a token in UTF-16${encoding} staged bytes`, () => {
    const fixture = makeRepo();
    const bytes = Buffer.from(`${token()}\n`, "utf16le");
    if (encoding === "BE") bytes.swap16();
    const bom = encoding === "LE" ? [0xff, 0xfe] : [0xfe, 0xff];
    write(fixture.repo, "utf16.txt", Buffer.concat([Buffer.from(bom), bytes]));
    git(fixture.repo, "add", "utf16.txt");
    const result = scan(fixture, "index");
    expectFinding(result, "github-token", "utf16.txt", 1, "token", "index");
    expectRedacted(result, fixture, token());
  });
}

test("index retains the text size limit", () => {
  const fixture = makeRepo();
  write(fixture.repo, "large.txt", Buffer.alloc(10 * 1024 * 1024 + 1, 65));
  git(fixture.repo, "add", "large.txt");
  expectFinding(scan(fixture, "index"), "oversized-text-file", "large.txt", null, "scan-error", "index");
});

for (const fileName of ["ca.pem", "expected.log"]) {
  test(`index allows harmless ${fileName} content`, () => {
    const fixture = makeRepo();
    write(fixture.repo, fileName, "Harmless public fixture.\n");
    git(fixture.repo, "add", fileName);
    expectClean(scan(fixture, "index"), "index");
  });
}

test("index still detects a private-key header in a PEM blob", () => {
  const fixture = makeRepo();
  write(fixture.repo, "ca.pem", `${privateKeyHeader}\n`);
  git(fixture.repo, "add", "ca.pem");
  const result = scan(fixture, "index");
  expectFinding(result, "private-key-header", "ca.pem", 1, "private-key", "index");
  expectRedacted(result, fixture, privateKeyHeader);
});

test("index still detects a token in a log blob", () => {
  const fixture = makeRepo();
  write(fixture.repo, "expected.log", `${token()}\n`);
  git(fixture.repo, "add", "expected.log");
  const result = scan(fixture, "index");
  expectFinding(result, "github-token", "expected.log", 1, "token", "index");
  expectRedacted(result, fixture, token());
});

for (const [fileName, ruleId] of [
  ["private.key", "blocked-private-key-extension"],
  ["private.ppk", "blocked-private-key-extension"],
  ["private.p12", "blocked-key-store-extension"],
  ["private.pfx", "blocked-key-store-extension"],
  ["private.jks", "blocked-key-store-extension"],
  ["private.keystore", "blocked-key-store-extension"],
]) {
  test(`index retains the ${fileName} path rule`, () => {
    const fixture = makeRepo();
    write(fixture.repo, fileName, "Harmless test content.\n");
    git(fixture.repo, "add", fileName);
    expectFinding(scan(fixture, "index"), ruleId, fileName, null, "private-key", "index");
  });
}

for (const [fileName, ruleId, category, reportedPath] of [
  [".ssh/id_rsa", "blocked-ssh-path", "local-credential", ".ssh/id_rsa"],
  [".codex/config.toml", "blocked-codex-directory", "local-credential", ".codex"],
  [".git-credentials", "blocked-credential-file", "credential", ".git-credentials"],
  [".env.local", "blocked-env-file", "env-file", ".env.local"],
]) {
  test(`index retains the ${fileName} path protection`, () => {
    const fixture = makeRepo();
    write(fixture.repo, fileName, "Harmless test content.\n");
    git(fixture.repo, "add", fileName);
    expectFinding(scan(fixture, "index"), ruleId, reportedPath, null, category, "index");
  });
}

test("index ignores untracked and unstaged files", () => {
  const fixture = makeRepo();
  write(fixture.repo, "untracked.txt", `${token()}\n`);
  expectClean(scan(fixture, "index"), "index");
  expectFinding(scan(fixture, "current"), "github-token", "untracked.txt", 1, "token", "current");
});

test("index excludes an intent-to-add placeholder absent from the next commit", () => {
  const fixture = makeRepo();
  write(fixture.repo, "base.txt", "Committed clean content.\n");
  commitAll(fixture.repo);
  write(fixture.repo, "not-staged.key", `${token()}\n`);
  git(fixture.repo, "add", "-N", "not-staged.key");
  assert.match(git(fixture.repo, "ls-files", "--stage", "not-staged.key"), /not-staged\.key/);
  expectClean(scan(fixture, "index"), "index");
  expectFinding(scan(fixture, "current"), "blocked-private-key-extension", "not-staged.key", null, "private-key", "current");
});

test("index excludes intent-to-add placeholders before the first commit", () => {
  const fixture = makeRepo();
  write(fixture.repo, "not-staged.key", "Only a working-tree file.\n");
  git(fixture.repo, "add", "-N", "not-staged.key");
  expectClean(scan(fixture, "index"), "index");
});

test("index includes an ignored file explicitly staged with git add -f", () => {
  const fixture = makeRepo();
  write(fixture.repo, ".gitignore", "build/\n");
  write(fixture.repo, "build/ignored.txt", `${token()}\n`);
  git(fixture.repo, "add", "--force", "build/ignored.txt");
  const result = scan(fixture, "index");
  expectFinding(result, "github-token", "build/ignored.txt", 1, "token", "index");
  expectRedacted(result, fixture, token());
});

test("index redacts private hostnames in finding paths and reports", () => {
  const fixture = makeRepo();
  const privateHost = ["desktop", "internal"].join(".");
  const filePath = `data/${privateHost}/fixture.txt`;
  write(fixture.repo, filePath, `${token()}\n`);
  git(fixture.repo, "add", filePath);
  const result = scan(fixture, "index");
  expectFinding(result, "github-token", "[redacted-path]", 1, "token", "index");
  expectRedacted(result, fixture, privateHost, token());
});

test("index runs current-only content rules on staged executable text", () => {
  const fixture = makeRepo();
  const line = ["echo", `"${["$", "TOKEN"].join("")}"`].join(" ");
  write(fixture.repo, "fixture.sh", `${line}\n`);
  git(fixture.repo, "add", "fixture.sh");
  expectFinding(scan(fixture, "index"), "shell-secret-variable-output", "fixture.sh", 1, "unsafe-logging", "index");
});

test("index rejects unmerged conflict stages without a report", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", "Clean base.\n");
  commitAll(fixture.repo);
  const mainBranch = git(fixture.repo, "branch", "--show-current");
  git(fixture.repo, "switch", "--quiet", "-c", "topic");
  write(fixture.repo, "fixture.txt", `${token("A")}\n`);
  commitAll(fixture.repo, "Add one synthetic version");
  git(fixture.repo, "switch", "--quiet", mainBranch);
  write(fixture.repo, "fixture.txt", `${token("B")}\n`);
  commitAll(fixture.repo, "Add another synthetic version");
  assert.throws(() => git(fixture.repo, "-c", "user.name=Example User", "-c", "user.email=example@example.invalid", "merge", "--no-edit", "topic"));
  assert.match(git(fixture.repo, "ls-files", "--stage", "fixture.txt"), /\s[123]\t/);
  const result = scan(fixture, "index");
  assert.equal(result.status, 2);
  assert.equal(result.report, null);
  assert.match(result.output, /fully resolved Git index/);
  assert.doesNotMatch(result.output, /findings=0|completed successfully/);
  expectRedacted(result, fixture, token("A"), token("B"));
});

test("index scans staged files before the first commit", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", `${token()}\n`);
  git(fixture.repo, "add", "fixture.txt");
  expectFinding(scan(fixture, "index"), "github-token", "fixture.txt", 1, "token", "index");
});

test("index succeeds on an empty index without commits", () => {
  const fixture = makeRepo();
  expectClean(scan(fixture, "index"), "index");
});

test("index fails safely in a non-Git directory", () => {
  const fixture = makeRepo();
  const plain = path.join(fixture.root, "plain");
  fs.mkdirSync(plain);
  const result = scan(fixture, "index", plain);
  assert.equal(result.status, 2);
  assert.equal(result.report, null);
  assert.match(result.output, /readable Git repository and index/);
  expectRedacted(result, fixture);
});

test("index resolves the worktree's own index through Git", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", "Clean shared commit.\n");
  commitAll(fixture.repo);
  const worktree = path.join(fixture.root, "worktree");
  git(fixture.repo, "worktree", "add", "--quiet", "--detach", worktree, "HEAD");
  assert.equal(fs.statSync(path.join(worktree, ".git")).isFile(), true);
  write(worktree, "fixture.txt", `${token()}\n`);
  git(worktree, "add", "fixture.txt");
  expectClean(scan(fixture, "index"), "index");
  const result = scan(fixture, "index", worktree);
  expectFinding(result, "github-token", "fixture.txt", 1, "token", "index");
  expectRedacted(result, fixture, token());
});

test("index rejects a subdirectory target rather than silently scanning part of the index", () => {
  const fixture = makeRepo();
  write(fixture.repo, "nested/fixture.txt", `${token()}\n`);
  git(fixture.repo, "add", "nested/fixture.txt");
  const result = scan(fixture, "index", path.join(fixture.repo, "nested"));
  assert.equal(result.status, 2);
  assert.equal(result.report, null);
  assert.match(result.output, /requires the Git worktree root/);
  expectRedacted(result, fixture, token());
});

test("index fails safely when the Git index is corrupt", () => {
  const fixture = makeRepo();
  write(fixture.repo, "fixture.txt", "Clean staged fixture.\n");
  git(fixture.repo, "add", "fixture.txt");
  fs.writeFileSync(path.join(fixture.repo, ".git", "index"), "Invalid synthetic index bytes.\n");
  const result = scan(fixture, "index");
  assert.equal(result.status, 2);
  assert.equal(result.report, null);
  assert.match(result.output, /readable Git repository and index/);
  expectRedacted(result, fixture);
});

test("index reports an unreadable staged blob instead of claiming success", () => {
  const fixture = makeRepo();
  const missingObject = "f".repeat(40);
  git(fixture.repo, "update-index", "--add", "--cacheinfo", `100644,${missingObject},missing.txt`);
  expectFinding(scan(fixture, "index"), "unreadable-index-file", "missing.txt", null, "scan-error", "index");
});

test("index report refuses a symbolic-link destination", () => {
  const fixture = makeRepo();
  const external = path.join(fixture.root, "outside.json");
  const link = path.join(fixture.root, "linked-report.json");
  fs.writeFileSync(external, "unchanged\n");
  fs.symlinkSync(external, link);
  const errors = [];
  const result = runCli(["--mode", "index", "--report", link, fixture.repo], {
    stdout: () => {}, stderr: (message) => errors.push(message),
  });
  assert.equal(result, 2);
  assert.deepEqual(errors, ["Privacy check could not complete safely."]);
  assert.equal(fs.readFileSync(external, "utf8"), "unchanged\n");
});

test("CLI help and Action input accept index while history attestations remain history-only", () => {
  const output = [];
  assert.equal(runCli(["--help"], { stdout: (message) => output.push(message) }), 0);
  assert.match(output.join("\n"), /--mode current\|index\|history/);
  assert.deepEqual(actionArgsFromEnvironment({ "INPUT_SCAN-MODE": "index" }), ["--mode", "index", "."]);
  const fixture = makeRepo();
  const result = scan(fixture, "index", fixture.repo, ["--history-attestations", "ignored.json"]);
  assert.equal(result.status, 2);
  assert.equal(result.report, null);
  assert.match(result.output, /History attestations require history mode/);
});
