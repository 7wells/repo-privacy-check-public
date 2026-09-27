// File purpose: Verify fail-closed history preconditions with real shallow repositories and worktrees.
// Inputs: Temporary Git repositories and local file:// clones containing synthetic fixtures.
// Outputs: Assertions over CLI status, redacted output, and report behavior.
// Security and privacy: No network access or real secrets; only explicit test steps fetch history.

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, test } = require("node:test");
const { pathToFileURL } = require("node:url");

const { runCli } = require("../scripts/privacy-check.js");

const temporaryRoots = new Set();
const syntheticToken = ["ghp", "S".repeat(40)].join("_");
const shallowError = "History mode requires a complete Git history; shallow repository detected.";

function git(target, args) {
  return execFileSync("git", args, {
    cwd: target,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

function makeFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "repo-privacy-shallow-"));
  temporaryRoots.add(root);
  const source = path.join(root, "source");
  fs.mkdirSync(source);
  git(source, ["init", "--quiet"]);
  return { root, source, clone: path.join(root, "clone"), url: pathToFileURL(source).href };
}

function commitAll(target, message) {
  git(target, ["add", "--all"]);
  git(target, ["-c", "user.name=Example User", "-c", "user.email=example@example.invalid", "commit", "--quiet", "-m", message]);
}

function makeShallowFixture() {
  const fixture = makeFixture();
  fs.writeFileSync(path.join(fixture.source, "fixture.txt"), `${syntheticToken}\n`);
  commitAll(fixture.source, "Add synthetic historical fixture");
  fs.writeFileSync(path.join(fixture.source, "fixture.txt"), "Clean current tree.\n");
  commitAll(fixture.source, "Remove synthetic historical content");
  // Local path clones may ignore --depth; file:// forces Git's shallow transport.
  git(fixture.root, ["clone", "--quiet", "--depth", "1", fixture.url, fixture.clone]);
  assert.equal(git(fixture.clone, ["rev-parse", "--is-shallow-repository"]), "true");
  assert.equal(git(fixture.clone, ["rev-list", "--count", "HEAD"]), "1");
  return fixture;
}

function scan(target, mode, reportPath, args = []) {
  const stdout = [];
  const stderr = [];
  const status = runCli(["--mode", mode, "--report", reportPath, ...args, target], {
    stdout: (message) => stdout.push(message),
    stderr: (message) => stderr.push(message),
  });
  return { status, stdout: stdout.join("\n"), stderr: stderr.join("\n"), output: [...stdout, ...stderr].join("\n") };
}

function assertRedacted(result, fixture) {
  for (const value of [syntheticToken, fixture.root, fixture.source, fixture.clone, fixture.url]) {
    assert.equal(result.output.includes(value), false);
  }
  assert.doesNotMatch(result.output, /file:\/\/|fatal:|stderr:|Command failed/);
}

function assertShallowFailure(result, reportPath, fixture) {
  assert.equal(result.status, 2);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, shallowError);
  assert.doesNotMatch(result.output, /completed successfully|findings=0/);
  assert.equal(fs.existsSync(reportPath), false);
  assertRedacted(result, fixture);
}

function assertTokenFinding(result, reportPath, mode, fixture) {
  assert.equal(result.status, 1);
  assert.match(result.stderr, /github-token fixture\.txt:1 category=token/);
  const reportText = fs.readFileSync(reportPath, "utf8");
  const report = JSON.parse(reportText);
  assert.equal(report.mode, mode);
  assert.equal(report.findings.length, 1);
  const [finding] = report.findings;
  assert.equal(finding.ruleId, "github-token");
  assert.equal(finding.file, "fixture.txt");
  assert.equal(finding.line, 1);
  assert.equal(finding.category, "token");
  assert.equal(finding.source, mode);
  assertRedacted(result, fixture);
  assertRedacted({ output: reportText }, fixture);
}

after(() => {
  for (const root of temporaryRoots) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("history rejects a real shallow clone without a success message or report", () => {
  const fixture = makeShallowFixture();
  const reportPath = path.join(fixture.root, "report.json");
  assertShallowFailure(scan(fixture.clone, "history", reportPath), reportPath, fixture);
  assert.equal(git(fixture.clone, ["rev-parse", "--is-shallow-repository"]), "true");
  assert.equal(git(fixture.clone, ["rev-list", "--count", "HEAD"]), "1");
});

test("current succeeds on the clean tree of a shallow clone", () => {
  const fixture = makeShallowFixture();
  const reportPath = path.join(fixture.root, "report.json");
  const result = scan(fixture.clone, "current", reportPath);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /mode=current findings=0/);
  assert.deepEqual(JSON.parse(fs.readFileSync(reportPath, "utf8")).findings, []);
  assertRedacted(result, fixture);
});

test("current still detects a token in a shallow clone's working file", () => {
  const fixture = makeShallowFixture();
  fs.writeFileSync(path.join(fixture.clone, "fixture.txt"), `${syntheticToken}\n`);
  const reportPath = path.join(fixture.root, "report.json");
  const result = scan(fixture.clone, "current", reportPath);
  assertTokenFinding(result, reportPath, "current", fixture);
});

test("history retains findings from older ancestors in a complete repository", () => {
  const fixture = makeShallowFixture();
  assert.equal(git(fixture.source, ["rev-parse", "--is-shallow-repository"]), "false");
  const reportPath = path.join(fixture.root, "report.json");
  const result = scan(fixture.source, "history", reportPath);
  assertTokenFinding(result, reportPath, "history", fixture);
});

test("history succeeds in a complete repository with only one root commit", () => {
  const fixture = makeFixture();
  fs.writeFileSync(path.join(fixture.source, "fixture.txt"), "Clean root commit.\n");
  commitAll(fixture.source, "Add clean root fixture");
  assert.equal(git(fixture.source, ["rev-parse", "--is-shallow-repository"]), "false");
  assert.equal(git(fixture.source, ["rev-list", "--count", "HEAD"]), "1");
  const result = scan(fixture.source, "history", path.join(fixture.root, "report.json"));
  assert.equal(result.status, 0);
  assert.match(result.stdout, /mode=history findings=0/);
  assertRedacted(result, fixture);
});

test("history detects the older token after an explicit local unshallow fetch", () => {
  const fixture = makeShallowFixture();
  const reportPath = path.join(fixture.root, "report.json");
  assertShallowFailure(scan(fixture.clone, "history", reportPath), reportPath, fixture);
  git(fixture.clone, ["fetch", "--quiet", "--unshallow", "origin"]);
  assert.equal(git(fixture.clone, ["rev-parse", "--is-shallow-repository"]), "false");
  assert.equal(git(fixture.clone, ["rev-list", "--count", "HEAD"]), "2");
  const result = scan(fixture.clone, "history", reportPath);
  assertTokenFinding(result, reportPath, "history", fixture);
});

test("an exact valid attestation cannot bypass the shallow history precondition", () => {
  const fixture = makeFixture();
  fs.writeFileSync(path.join(fixture.source, "fixture.txt"), "Clean root commit.\n");
  commitAll(fixture.source, "Add clean root fixture");
  fs.writeFileSync(path.join(fixture.source, "fixture.txt"), `${syntheticToken}\n`);
  commitAll(fixture.source, "Add synthetic current fixture");
  const sourceReportPath = path.join(fixture.root, "source-report.json");
  assert.equal(scan(fixture.source, "history", sourceReportPath).status, 1);
  const finding = JSON.parse(fs.readFileSync(sourceReportPath, "utf8")).findings.find((entry) => entry.ruleId === "github-token");
  assert.ok(finding);
  const { commit, blob, ruleId, line, findingId } = finding;
  const attestationsPath = path.join(fixture.root, "attestations.json");
  fs.writeFileSync(attestationsPath, JSON.stringify({ version: 1, attestations: [{ commit, blob, path: "fixture.txt", ruleId, line, findingId }] }));
  const args = ["--history-attestations", attestationsPath];
  assert.equal(scan(fixture.source, "history", sourceReportPath, args).status, 0);
  git(fixture.root, ["clone", "--quiet", "--depth", "1", fixture.url, fixture.clone]);
  assert.equal(git(fixture.clone, ["rev-parse", "--is-shallow-repository"]), "true");
  const reportPath = path.join(fixture.root, "shallow-report.json");
  assertShallowFailure(scan(fixture.clone, "history", reportPath, args), reportPath, fixture);
});

for (const shallow of [true, false]) {
  test(`history resolves the ${shallow ? "shallow" : "complete"} state of a worktree through Git`, () => {
    const fixture = makeShallowFixture();
    const worktree = path.join(fixture.root, "worktree");
    git(shallow ? fixture.clone : fixture.source, ["worktree", "add", "--quiet", "--detach", worktree, "HEAD"]);
    assert.equal(fs.statSync(path.join(worktree, ".git")).isFile(), true);
    assert.equal(git(worktree, ["rev-parse", "--is-shallow-repository"]), String(shallow));
    const reportPath = path.join(fixture.root, "report.json");
    const result = scan(worktree, "history", reportPath);
    if (shallow) {
      assertShallowFailure(result, reportPath, fixture);
    } else {
      assertTokenFinding(result, reportPath, "history", fixture);
    }
  });
}

for (const kind of ["non-Git", "broken-Git", "unborn-HEAD"]) {
  test(`history fails safely for a ${kind} target without a report`, () => {
    const fixture = makeFixture();
    const target = path.join(fixture.root, "target");
    fs.mkdirSync(target);
    if (kind === "broken-Git") {
      fs.writeFileSync(path.join(target, ".git"), `gitdir: ${path.join(fixture.root, "missing-git-directory")}\n`);
    } else if (kind === "unborn-HEAD") {
      git(target, ["init", "--quiet"]);
      assert.equal(git(target, ["rev-parse", "--is-shallow-repository"]), "false");
    }
    const reportPath = path.join(fixture.root, "report.json");
    const result = scan(target, "history", reportPath);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "History mode requires a readable Git repository.");
    assert.equal(fs.existsSync(reportPath), false);
    assertRedacted(result, fixture);
  });
}
