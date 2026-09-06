// File purpose: Validate home-directory path detection and the fail-closed generic-user allowlist.
// Inputs: Synthetic path strings and temporary files.
// Outputs: Node test assertions for accepted and rejected path forms.
// Security and privacy: Use only clearly synthetic usernames and paths in fixtures.

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, test } = require("node:test");

const { runCli, testInternals } = require("../scripts/privacy-check.js");

const {
  matchesHomeDirectoryPath,
  parseGenericHomeUserNames,
  sanitizeFindingPath,
} = testInternals;
const temporaryRepositories = new Set();

function makeTempRepo() {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), "repo-privacy-check-home-"));
  temporaryRepositories.add(target);
  execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
  return target;
}

function commitReadme(target, content, message) {
  fs.writeFileSync(path.join(target, "README.md"), content);
  execFileSync("git", ["add", "README.md"], { cwd: target, stdio: "ignore" });
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
      message,
    ],
    { cwd: target, stdio: "ignore" },
  );
}

function runScanner(args) {
  const stdout = [];
  const stderr = [];
  const status = runCli(args, {
    stdout: (message) => stdout.push(message),
    stderr: (message) => stderr.push(message),
  });
  return { status, output: `${stdout.join("\n")}\n${stderr.join("\n")}` };
}

function unixHome(userName, leaf = "project") {
  return ["", "home", userName, leaf].join("/");
}

function macHome(userName, leaf = "project") {
  return ["", "Users", userName, leaf].join("/");
}

function windowsHome(userName, leaf = "project") {
  return ["C:", "Users", userName, leaf].join("\\");
}

after(() => {
  for (const target of temporaryRepositories) {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test("reviewed generic home-user allowlist contains only approved bare names", () => {
  const allowlistPath = path.resolve(__dirname, "../config/generic-home-users.txt");
  assert.equal(fs.readFileSync(allowlistPath, "utf8"), "dev\nminecraft\n");
});

test("allows only exact reviewed generic home names", () => {
  for (const userName of ["dev", "minecraft"]) {
    assert.equal(matchesHomeDirectoryPath(unixHome(userName)), false);
    assert.equal(matchesHomeDirectoryPath(macHome(userName)), false);
    assert.equal(matchesHomeDirectoryPath(windowsHome(userName)), false);
  }

  for (const homePath of [
    unixHome("Dev"),
    unixHome("dev2"),
    unixHome("developer"),
    unixHome("local-user"),
    unixHome("Minecraft"),
    unixHome("minecraft2"),
    macHome("Dev"),
    windowsHome("dev2"),
  ]) {
    assert.equal(matchesHomeDirectoryPath(homePath), true, homePath);
  }
});

test("allows only the exact reviewed Windows home placeholder", () => {
  assert.equal(matchesHomeDirectoryPath(windowsHome("<USER>")), false);
  assert.equal(matchesHomeDirectoryPath(unixHome("<USER>")), false);

  for (const homePath of [
    windowsHome("<user>"),
    windowsHome("<USERNAME>"),
    windowsHome("USER"),
    unixHome("<user>"),
  ]) {
    assert.equal(matchesHomeDirectoryPath(homePath), true, homePath);
  }
});

test("allows reviewed generic home paths in Git history", () => {
  const target = makeTempRepo();
  const reviewedPaths = [unixHome("dev", ".bash_aliases"), unixHome("minecraft", "server")];

  commitReadme(target, `${reviewedPaths.join("\n")}\n`, "Add reviewed generic paths");
  commitReadme(target, "Use portable paths instead.\n", "Replace examples");

  const result = runScanner(["--mode", "history", target]);
  assert.equal(result.status, 0);
});

test("still detects nearby and non-generic home paths in Git history", () => {
  const target = makeTempRepo();
  const paths = [
    unixHome("Dev"),
    unixHome("dev2"),
    unixHome("developer"),
    unixHome("local-user"),
    unixHome("private-user"),
    unixHome("Minecraft"),
  ];

  commitReadme(target, `${paths.join("\n")}\n`, "Add local paths");
  commitReadme(target, "Use portable paths instead.\n", "Remove local paths");

  const result = runScanner(["--mode", "history", target]);
  assert.equal(result.status, 1);
  for (let line = 1; line <= paths.length; line += 1) {
    assert.match(result.output, new RegExp(`home-directory-path README\\.md:${line} category=local-path`));
  }
  for (const privatePath of paths) {
    assert.equal(result.output.includes(privatePath), false);
  }
});

test("rejects malformed allowlist entries instead of interpreting patterns", () => {
  const invalidBuffers = [
    Buffer.from("dev.*\n"),
    Buffer.from("dev\\d+\n"),
    Buffer.from("de\u0000v\n"),
    Buffer.from("Dev\n"),
    Buffer.from(`${"a".repeat(33)}\n`),
    Buffer.from("dev\n\n"),
    Buffer.from("dev\ndev\n"),
    Buffer.alloc(1025, 0x61),
  ];

  for (const buffer of invalidBuffers) {
    assert.throws(() => parseGenericHomeUserNames(buffer), /Invalid generic home-user allowlist/);
  }
});

test("parses valid allowlist entries as exact literal strings", () => {
  const entries = parseGenericHomeUserNames(Buffer.from("dev\nci-user\n"));
  assert.deepEqual([...entries], ["dev", "ci-user"]);
  assert.equal(entries.has("dev"), true);
  assert.equal(entries.has("Dev"), false);
  assert.equal(entries.has("dev2"), false);
});

test("redacts non-generic home paths embedded in finding paths", () => {
  const sensitiveFindingPath = ["artifact=", "home", "private-user", ".env"].join("/");
  const allowedFindingPath = ["artifact=", "home", "dev", "readme.txt"].join("/");

  assert.equal(sanitizeFindingPath(sensitiveFindingPath), "[redacted-path]");
  assert.equal(sanitizeFindingPath(allowedFindingPath), allowedFindingPath);
});
