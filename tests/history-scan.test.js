// File purpose: Validate history traversal, deduplication, deleted-file detection, and rule scope.
// Inputs: Synthetic temporary Git repositories created by each test.
// Outputs: Node test assertions over metadata-only history findings.
// Security and privacy: Fixtures are synthetic and must never contain real local identities or secrets.

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, test } = require("node:test");

const { runCli } = require("../scripts/privacy-check.js");

const temporaryRepositories = new Set();

function makeTempRepo() {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), "repo-privacy-history-"));
  temporaryRepositories.add(target);
  execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
  return target;
}

function commitAll(target, message) {
  execFileSync("git", ["add", "--all"], { cwd: target, stdio: "ignore" });
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

  return {
    status,
    output: `${stdout.join("\n")}\n${stderr.join("\n")}`,
  };
}

after(() => {
  for (const target of temporaryRepositories) {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test("history detects privacy data that was committed and later removed", () => {
  const target = makeTempRepo();
  const token = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

  fs.writeFileSync(path.join(target, "temporary.txt"), `${token}\n`);
  commitAll(target, "Add temporary test fixture");
  fs.rmSync(path.join(target, "temporary.txt"));
  commitAll(target, "Remove temporary test fixture");

  const result = runScanner(["--mode", "history", target]);

  assert.equal(result.status, 1);
  assert.match(result.output, /github-token temporary\.txt:1 category=token/);
  assert.equal(result.output.includes(token), false);
});

test("history keeps local path findings after the current tree is cleaned", () => {
  const target = makeTempRepo();
  const localPath = ["", "home", "private-user", "project"].join("/");

  fs.writeFileSync(path.join(target, "README.md"), `Path: ${localPath}\n`);
  commitAll(target, "Add local path fixture");
  fs.writeFileSync(path.join(target, "README.md"), "No local path here.\n");
  commitAll(target, "Remove local path fixture");

  const result = runScanner(["--mode", "history", target]);

  assert.equal(result.status, 1);
  assert.match(result.output, /home-directory-path README\.md:1 category=local-path/);
  assert.equal(result.output.includes(localPath), false);
});

test("history ignores obsolete unsafe logging patterns", () => {
  const target = makeTempRepo();
  const unsafeLine = ["grep", "pattern", "file"].join(" ");

  fs.writeFileSync(path.join(target, "check.sh"), `#!/bin/sh\n${unsafeLine}\n`);
  commitAll(target, "Add obsolete logging fixture");
  fs.writeFileSync(path.join(target, "check.sh"), "#!/bin/sh\ngrep --quiet pattern file\n");
  commitAll(target, "Fix obsolete logging fixture");

  const currentResult = runScanner([target]);
  const historyResult = runScanner(["--mode", "history", target]);

  assert.equal(currentResult.status, 0);
  assert.equal(historyResult.status, 0);
  assert.doesNotMatch(historyResult.output, /unsafe-logging/);
});

test("current mode still rejects unsafe logging patterns", () => {
  const target = makeTempRepo();
  const unsafeLine = ["grep", "pattern", "file"].join(" ");

  fs.writeFileSync(path.join(target, "check.sh"), `#!/bin/sh\n${unsafeLine}\n`);
  commitAll(target, "Add current logging fixture");

  const result = runScanner([target]);

  assert.equal(result.status, 1);
  assert.match(result.output, /shell-grep-match-output check\.sh:2 category=unsafe-logging/);
});

test("history scans the same blob separately when it appeared at different paths", () => {
  const target = makeTempRepo();
  const token = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

  fs.writeFileSync(path.join(target, "first.txt"), `${token}\n`);
  commitAll(target, "Add first path fixture");
  fs.renameSync(path.join(target, "first.txt"), path.join(target, "second.txt"));
  commitAll(target, "Move fixture");
  fs.rmSync(path.join(target, "second.txt"));
  commitAll(target, "Remove moved fixture");

  const result = runScanner(["--mode", "history", target]);

  assert.equal(result.status, 1);
  assert.match(result.output, /github-token first\.txt:1 category=token/);
  assert.match(result.output, /github-token second\.txt:1 category=token/);
  assert.equal(result.output.includes(token), false);
});
