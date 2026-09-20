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

function collectHistoryFindings(target) {
  const reportPath = path.join(target, ".git", "history-findings.json");
  const result = runScanner(["--mode", "history", "--report", reportPath, target]);
  const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  return { result, findings: report.findings };
}

function writeAttestations(target, attestations) {
  const attestationsPath = path.join(target, ".git", "history-attestations.json");
  fs.writeFileSync(
    attestationsPath,
    `${JSON.stringify({ version: 1, attestations }, null, 2)}\n`,
    { mode: 0o600 },
  );
  return attestationsPath;
}

function toAttestation(finding, filePath) {
  return {
    commit: finding.commit,
    blob: finding.blob,
    path: filePath,
    ruleId: finding.ruleId,
    line: finding.line,
    findingId: finding.findingId,
  };
}

after(() => {
  for (const target of temporaryRepositories) {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test("history detects privacy data in an ancestor of HEAD after it is removed", () => {
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

test("history ignores privacy findings reachable only from an unrelated branch", () => {
  const target = makeTempRepo();
  const localPath = ["", "home", "private-user", "unrelated-branch"].join("/");

  fs.writeFileSync(path.join(target, "README.md"), "Clean checked-out history.\n");
  commitAll(target, "Add clean base");
  const checkedOutBranch = execFileSync("git", ["branch", "--show-current"], {
    cwd: target,
    encoding: "utf8",
  }).trim();

  execFileSync("git", ["switch", "--quiet", "--create", "unrelated-finding"], {
    cwd: target,
    stdio: "ignore",
  });
  fs.writeFileSync(path.join(target, "unrelated.txt"), `Path: ${localPath}\n`);
  commitAll(target, "Add unrelated privacy fixture");
  execFileSync("git", ["switch", "--quiet", checkedOutBranch], {
    cwd: target,
    stdio: "ignore",
  });

  const result = runScanner(["--mode", "history", target]);

  assert.equal(result.status, 0);
  assert.doesNotMatch(result.output, /home-directory-path/);
  assert.equal(result.output.includes(localPath), false);
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

test("history attestations suppress only one exact finding and not another finding in the same blob", () => {
  const target = makeTempRepo();
  const localHost = ["private", "fixture-host"].join("-");
  const token = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");
  const filePath = "fixture.sh";

  fs.writeFileSync(
    path.join(target, filePath),
    `${["DEV_ENV_HOST", localHost].join("=")}\n${token}\n`,
  );
  commitAll(target, "Add synthetic historical findings");

  const { result: initialResult, findings } = collectHistoryFindings(target);
  const localValueFinding = findings.find((finding) => finding.ruleId === "dev-env-local-value");
  assert.equal(initialResult.status, 1);
  assert.ok(localValueFinding?.commit);
  assert.ok(localValueFinding?.blob);
  assert.match(localValueFinding?.findingId ?? "", /^sha256:[0-9a-f]{64}$/);

  const attestationsPath = writeAttestations(target, [toAttestation(localValueFinding, filePath)]);
  const attestedResult = runScanner([
    "--mode",
    "history",
    "--history-attestations",
    attestationsPath,
    target,
  ]);

  assert.equal(attestedResult.status, 1);
  assert.doesNotMatch(attestedResult.output, /dev-env-local-value fixture\.sh:1/);
  assert.match(attestedResult.output, /github-token fixture\.sh:2 category=token/);
  assert.equal(attestedResult.output.includes(localHost), false);
  assert.equal(attestedResult.output.includes(token), false);
});

test("an identical historical finding in a new commit does not inherit an older attestation", () => {
  const target = makeTempRepo();
  const localHost = ["private", "fixture-host"].join("-");
  const filePath = "fixture.sh";
  const content = `${["DEV_ENV_HOST", localHost].join("=")}\n`;

  fs.writeFileSync(path.join(target, filePath), content);
  commitAll(target, "Add original synthetic finding");
  const { findings } = collectHistoryFindings(target);
  const originalFinding = findings.find((finding) => finding.ruleId === "dev-env-local-value");
  const attestationsPath = writeAttestations(target, [toAttestation(originalFinding, filePath)]);

  fs.rmSync(path.join(target, filePath));
  commitAll(target, "Remove synthetic finding");
  fs.writeFileSync(path.join(target, filePath), content);
  commitAll(target, "Reintroduce identical synthetic finding");

  const result = runScanner([
    "--mode",
    "history",
    "--history-attestations",
    attestationsPath,
    target,
  ]);

  assert.equal(result.status, 1);
  assert.match(result.output, /dev-env-local-value fixture\.sh:1 category=local-env/);
  assert.match(result.output, /unused-history-attestation/);
  assert.equal(result.output.includes(localHost), false);
});

test("invalid, duplicate, and broad history attestations fail closed", () => {
  const target = makeTempRepo();
  const localHost = ["private", "fixture-host"].join("-");
  const filePath = "fixture.sh";

  fs.writeFileSync(path.join(target, filePath), `${["DEV_ENV_HOST", localHost].join("=")}\n`);
  commitAll(target, "Add synthetic finding");
  const { findings } = collectHistoryFindings(target);
  const finding = findings.find((candidate) => candidate.ruleId === "dev-env-local-value");
  const validAttestation = toAttestation(finding, filePath);
  const invalidDocuments = [
    { version: 1, attestations: [{ ...validAttestation, path: "fixtures/*.sh" }] },
    { version: 1, attestations: [{ ...validAttestation, blob: undefined }] },
    { version: 1, attestations: [{ ...validAttestation, unexpected: true }] },
    { version: 1, attestations: [validAttestation, validAttestation] },
  ];

  for (const document of invalidDocuments) {
    const attestationsPath = path.join(target, ".git", "invalid-attestations.json");
    fs.writeFileSync(attestationsPath, `${JSON.stringify(document)}\n`, { mode: 0o600 });
    const result = runScanner([
      "--mode",
      "history",
      "--history-attestations",
      attestationsPath,
      target,
    ]);
    assert.equal(result.status, 2);
    assert.match(result.output, /Privacy check could not complete safely\./);
    assert.equal(result.output.includes(localHost), false);
  }
});
