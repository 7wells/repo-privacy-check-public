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
const expectedGitIdentityKey = (suffix) => ["DEV_ENV_EXPECTED_GIT_USER", suffix].join("");
const devEnvKey = (...segments) => ["DEV_ENV", ...segments].join("_");
const jsonDevEnvLine = (segments, value) => JSON.stringify({ [devEnvKey(...segments)]: value });
const mixedDevEnvLine = (segments, literal, variable) =>
  `${devEnvKey(...segments)}=${literal}${["$", variable].join("")}`;
const fallbackDevEnvLine = (segments, variable, fallback) =>
  `${devEnvKey(...segments)}="${["$", "{", variable, ":-", fallback, "}"].join("")}"`;

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

function collectHistoryFindings(target, args = []) {
  const reportPath = path.join(target, ".git", "history-findings.json");
  const result = runScanner(["--mode", "history", "--report", reportPath, ...args, target]);
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

for (const directory of ["build", ".cache"]) {
  test(`history detects a tracked historical file under ${directory}`, () => {
    const target = makeTempRepo();
    const relativePath = `${directory}/fixture.txt`;
    const token = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

    fs.mkdirSync(path.dirname(path.join(target, relativePath)), { recursive: true });
    fs.writeFileSync(path.join(target, relativePath), `${token}\n`);
    commitAll(target, `Add tracked ${directory} privacy fixture`);

    const result = runScanner(["--mode", "history", target]);
    assert.equal(result.status, 1);
    assert.match(result.output, new RegExp(`github-token ${directory.replaceAll(".", "\\.")}\\/fixture\\.txt:1 category=token`));
    assert.equal(result.output.includes(token), false);
  });
}

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

test("history allows the exact public expected Git identity defaults", () => {
  const target = makeTempRepo();
  const expectedIdentity = [
    `readonly ${expectedGitIdentityKey("_NAME")}="7wells"`,
    `readonly ${expectedGitIdentityKey("_EMAIL")}="65889763+7wells@users.noreply.github.com"`,
  ];

  fs.writeFileSync(path.join(target, "expected-identity.sh"), `${expectedIdentity.join("\n")}\n`);
  commitAll(target, "Add public expected Git identity defaults");

  const result = runScanner(["--mode", "history", target]);
  assert.equal(result.status, 0);
});

const devEnvPublicValueFixtures = [
  { name: "the MONKEY suffix", key: ["MONKEY"], value: "banana" },
  { name: "the SKIP suffix", key: ["SKIP"], value: "always" },
  { name: "a package name", key: ["PACKAGE", "NAME"], value: "widget" },
  { name: "an include directory", key: ["INCLUDE", "DIR"], value: "include" },
  { name: "a public base URL", key: ["BASE", "URL"], value: "https://example.org" },
  { name: "the loopback host placeholder", key: ["HOST"], value: "127.0.0.1" },
  { name: "another public name field", key: ["MODULE", "NAME"], value: "widget" },
  { name: "another relative directory field", key: ["DOCS", "DIR"], value: "docs" },
  { name: "another public URL field", key: ["PUBLIC", "URL"], value: "https://example.org" },
];

for (const { name, key, value } of devEnvPublicValueFixtures) {
  test(`history scan allows ${name} in a DEV_ENV assignment`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${devEnvKey(...key)}=${value}\n`);
    commitAll(target, "Add a public DEV_ENV value fixture");

    const result = runScanner(["--mode", "history", target]);
    assert.equal(result.status, 0, result.output);
  });
}

const quotedJsonDevEnvFindings = [
  { name: "a concrete private host value", key: ["HOST"], value: "workstation" },
  { name: "a private URL value", key: ["BASE", "URL"], value: ["https://service", ".internal"].join("") },
];

for (const { name, key, value } of quotedJsonDevEnvFindings) {
  test(`history scan reports a quoted JSON key with ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.json"), `${jsonDevEnvLine(key, value)}\n`);
    commitAll(target, "Add one quoted JSON local value fixture");

    const result = runScanner(["--mode", "history", target]);
    assert.equal(result.status, 1);
    assert.match(result.output, /dev-env-local-value fixture\.json:1 category=local-env/);
    assert.equal(result.output.includes(value), false);
  });
}

const quotedJsonDevEnvAllowances = [
  { name: "an example host placeholder", key: ["HOST"], value: "example-host" },
  { name: "a public host name", key: ["HOST"], value: "example.org" },
  { name: "a generic service name", key: ["SERVICE", "NAME"], value: "widget" },
];

for (const { name, key, value } of quotedJsonDevEnvAllowances) {
  test(`history scan allows quoted JSON with ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.json"), `${jsonDevEnvLine(key, value)}\n`);
    commitAll(target, "Add a generic quoted JSON value fixture");

    const result = runScanner(["--mode", "history", target]);
    assert.equal(result.status, 0, result.output);
  });
}

test("history scan allows exact reviewed Git identity values in JSON", () => {
  const target = makeTempRepo();
  const identity = {
    [expectedGitIdentityKey("_NAME")]: "7wells",
    [expectedGitIdentityKey("_EMAIL")]: ["65889763+7wells", "@users.noreply.github.com"].join(""),
  };
  fs.writeFileSync(path.join(target, "identity.json"), `${JSON.stringify(identity)}\n`);
  commitAll(target, "Add exact reviewed Git identity JSON values");

  const result = runScanner(["--mode", "history", target]);
  assert.equal(result.status, 0, result.output);
});

test("history scan reports payload appended after an exact JSON Git identity value", () => {
  const target = makeTempRepo();
  const exactPair = JSON.stringify({ [expectedGitIdentityKey("_NAME")]: "7wells" });
  const line = `${exactPair.slice(0, -1)} synthetic-person}`;
  fs.writeFileSync(path.join(target, "identity.json"), `${line}\n`);
  commitAll(target, "Add a malformed JSON identity payload fixture");

  const result = runScanner(["--mode", "history", target]);
  assert.equal(result.status, 1);
  assert.match(result.output, /dev-env-local-value identity\.json:1 category=local-env/);
  assert.equal(result.output.includes("synthetic-person"), false);
});

const mixedDevEnvFindings = [
  {
    name: "a local host prefix followed by a variable",
    line: mixedDevEnvLine(["HOST"], "workstation", "ZONE"),
    value: "workstation",
  },
  {
    name: "a private URL prefix followed by a variable",
    line: mixedDevEnvLine(["BASE", "URL"], ["https://service", ".internal"].join(""), "ZONE"),
    value: ["https://service", ".internal"].join(""),
  },
  {
    name: "a home path prefix followed by a variable",
    line: mixedDevEnvLine(["PROJECT", "DIR"], ["", "home", "private-user", "project"].join("/"), "ZONE"),
    value: ["", "home", "private-user", "project"].join("/"),
  },
];

for (const { name, line, value } of mixedDevEnvFindings) {
  test(`history scan reports ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${line}\n`);
    commitAll(target, "Add one mixed DEV_ENV literal fixture");

    const result = runScanner(["--mode", "history", target]);
    assert.equal(result.status, 1);
    assert.match(result.output, /dev-env-local-value fixture\.sh:1 category=local-env/);
    assert.equal(result.output.includes(value), false);
  });
}

const mixedDevEnvAllowances = [
  { name: "a direct dynamic host", line: `${devEnvKey("HOST")}=$HOST` },
  { name: "a brace-only dynamic host", line: `${devEnvKey("HOST")}=${["$", "{", "HOST", "}"].join("")}` },
  { name: "an example prefix with a variable", line: mixedDevEnvLine(["HOST"], "example", "ZONE") },
  {
    name: "a public URL prefix with a variable",
    line: mixedDevEnvLine(["BASE", "URL"], "https://example.org/", "ZONE"),
  },
];

for (const { name, line } of mixedDevEnvAllowances) {
  test(`history scan allows ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${line}\n`);
    commitAll(target, "Add one dynamic or public DEV_ENV fixture");

    const result = runScanner(["--mode", "history", target]);
    assert.equal(result.status, 0, result.output);
  });
}

const shellFallbackFindings = [
  { name: "a local hostname", fallback: ["workstation", ".lan"].join("") },
  { name: "a private IPv4 address", fallback: ["192.168", "1.23"].join(".") },
  {
    name: "a local home path",
    key: ["PROJECT", "DIR"],
    variable: "PROJECT_DIR",
    fallback: ["", "home", "private-user", "project"].join("/"),
  },
];

for (const { name, key = ["HOST"], variable = "HOST", fallback } of shellFallbackFindings) {
  test(`history scan reports a shell fallback with ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${fallbackDevEnvLine(key, variable, fallback)}\n`);
    commitAll(target, "Add one local shell fallback fixture");

    const result = runScanner(["--mode", "history", target]);
    assert.equal(result.status, 1);
    assert.match(result.output, /dev-env-local-value fixture\.sh:1 category=local-env/);
    assert.equal(result.output.includes(fallback), false);
  });
}

const shellFallbackAllowances = [
  { name: "a direct dynamic expansion", fallback: ["$", "{", "HOST", "}"].join("") },
  { name: "a public hostname fallback", fallback: "example.org" },
  { name: "a generic placeholder fallback", fallback: "placeholder" },
];

for (const { name, fallback } of shellFallbackAllowances) {
  test(`history scan allows ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${fallbackDevEnvLine(["HOST"], "HOST", fallback)}\n`);
    commitAll(target, "Add one generic shell fallback fixture");

    const result = runScanner(["--mode", "history", target]);
    assert.equal(result.status, 0, result.output);
  });
}

const devEnvPrivateValueFixtures = [
  { name: "a private hostname", key: ["HOST"], value: ["workstation", ".lan"].join("") },
  { name: "a private IPv4 address", key: ["HOST"], value: ["192.168", "1.42"].join(".") },
  { name: "a loopback IPv4 value under another key", key: ["SERVICE"], value: "127.0.0.1" },
  { name: "a personal name", key: ["USER", "NAME"], value: ["private", "person"].join("-") },
  { name: "a personal email address", key: ["USER", "EMAIL"], value: ["person", "example.invalid"].join("@") },
  { name: "a local home path", key: ["PROJECT", "DIR"], value: ["", "home", "private-user", "work"].join("/") },
  { name: "a private URL", key: ["BASE", "URL"], value: ["https://service", ".internal/private"].join("") },
];

for (const { name, key, value } of devEnvPrivateValueFixtures) {
  test(`history scan reports ${name} as dev-env-local-value`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${devEnvKey(...key)}=${value}\n`);
    commitAll(target, "Add one private DEV_ENV value fixture");

    const result = runScanner(["--mode", "history", target]);
    assert.equal(result.status, 1);
    assert.match(result.output, /dev-env-local-value fixture\.sh:1 category=local-env/);
    assert.equal(result.output.includes(value), false);
  });
}

test("history scan leaves a plain loopback HOST assignment outside this DEV_ENV rule", () => {
  const target = makeTempRepo();
  fs.writeFileSync(path.join(target, "fixture.sh"), "HOST=127.0.0.1\n");
  commitAll(target, "Add a plain loopback host fixture");

  const result = runScanner(["--mode", "history", target]);
  assert.equal(result.status, 0, result.output);
});

const nonExactPublicIdentityAssignments = [
  {
    name: "name with an appended word inside quotes",
    line: `${expectedGitIdentityKey("_NAME")}="7wells synthetic-person"`,
  },
  {
    name: "name with text after the closing quote",
    line: `${expectedGitIdentityKey("_NAME")}="7wells" synthetic-person`,
  },
  {
    name: "name with a semicolon payload",
    line: `${expectedGitIdentityKey("_NAME")}="7wells";synthetic-payload`,
  },
  {
    name: "name with an unmatched quote",
    line: `${expectedGitIdentityKey("_NAME")}="7wells`,
  },
  {
    name: "name with a mismatched closing quote",
    line: `${expectedGitIdentityKey("_NAME")}="7wells'`,
  },
  {
    name: "different quoted personal name",
    line: `${expectedGitIdentityKey("_NAME")}="synthetic-private-person"`,
  },
  {
    name: "email with an appended word inside quotes",
    line: `${expectedGitIdentityKey("_EMAIL")}="65889763+7wells@users.noreply.github.com synthetic-person"`,
  },
  {
    name: "email with text after the closing quote",
    line: `${expectedGitIdentityKey("_EMAIL")}="65889763+7wells@users.noreply.github.com" synthetic-person`,
  },
  {
    name: "email with a semicolon payload",
    line: `${expectedGitIdentityKey("_EMAIL")}="65889763+7wells@users.noreply.github.com";synthetic-payload`,
  },
  {
    name: "email with an unmatched quote",
    line: `${expectedGitIdentityKey("_EMAIL")}="65889763+7wells@users.noreply.github.com`,
  },
  {
    name: "email with a mismatched closing quote",
    line: `${expectedGitIdentityKey("_EMAIL")}="65889763+7wells@users.noreply.github.com'`,
  },
  {
    name: "different quoted personal email",
    line: `${expectedGitIdentityKey("_EMAIL")}="person@example.invalid"`,
  },
];

for (const { name, line } of nonExactPublicIdentityAssignments) {
  test(`non-exact public identity ${name} remains a finding in current and history`, () => {
    const target = makeTempRepo();
    const filePath = "identity.sh";
    fs.writeFileSync(path.join(target, filePath), `${line}\n`);

    const currentResult = runScanner([target]);
    assert.equal(currentResult.status, 1, "current mode must report this assignment");
    assert.match(currentResult.output, /dev-env-local-value identity\.sh:1 category=local-env/);

    commitAll(target, "Add one non-exact public identity fixture");
    const historyResult = runScanner(["--mode", "history", target]);
    assert.equal(historyResult.status, 1, "history mode must report this assignment");
    assert.match(historyResult.output, /dev-env-local-value identity\.sh:1 category=local-env/);
  });
}

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

// Exercise real commits and blobs in both attestation orders, including unchanged
// matched lines in different blobs: an exact review must not cover another blob.
for (const fixture of ["local-value", "token", "same-line-different-blob"]) {
  for (const attestedVersion of ["newer", "older"]) {
    test(`history keeps the unattested ${fixture} when the ${attestedVersion} blob is attested`, () => {
      const target = makeTempRepo();
      const filePath = "fixture.sh";
      const ruleId = fixture === "token" ? "github-token" : "dev-env-local-value";
      const olderValue = fixture === "token"
        ? ["ghp", "A".repeat(40)].join("_")
        : ["private", "older-fixture"].join("-");
      const newerValue = fixture === "token"
        ? ["ghp", "B".repeat(40)].join("_")
        : fixture === "same-line-different-blob"
          ? olderValue
          : ["private", "newer-fixture"].join("-");
      const line = (value) => fixture === "token" ? value : ["DEV_ENV_HOST", value].join("=");

      fs.writeFileSync(path.join(target, filePath), `${line(olderValue)}\n# Older blob.\n`);
      commitAll(target, "Add older synthetic finding");
      const olderScan = collectHistoryFindings(target);
      assert.equal(olderScan.result.status, 1);
      assert.equal(olderScan.findings.length, 1);
      const olderFinding = olderScan.findings[0];
      assert.equal(olderFinding.ruleId, ruleId);
      assert.equal(olderFinding.line, 1);

      fs.writeFileSync(path.join(target, filePath), `${line(newerValue)}\n# Newer blob.\n`);
      commitAll(target, "Add newer synthetic finding at the same location");
      const newerScan = collectHistoryFindings(target);
      const newerFinding = newerScan.findings[0];
      const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: target, encoding: "utf8" }).trim();
      assert.equal(newerScan.result.status, 1);
      assert.equal(newerFinding.commit, head);
      assert.equal(newerFinding.ruleId, ruleId);
      assert.equal(newerFinding.line, 1);
      assert.notEqual(newerFinding.blob, olderFinding.blob);
      if (fixture === "same-line-different-blob") {
        assert.equal(newerScan.findings.length, 1);
        assert.equal(newerFinding.findingId, olderFinding.findingId);
      } else {
        assert.equal(newerScan.findings.length, 2);
        assert.notEqual(newerFinding.findingId, olderFinding.findingId);
      }

      const reviewed = attestedVersion === "newer" ? newerFinding : olderFinding;
      const unreviewed = attestedVersion === "newer" ? olderFinding : newerFinding;
      const attestationsPath = writeAttestations(target, [toAttestation(reviewed, filePath)]);
      const attestedScan = collectHistoryFindings(target, ["--history-attestations", attestationsPath]);

      assert.equal(attestedScan.result.status, 1);
      assert.deepEqual(attestedScan.findings, [unreviewed]);
      assert.doesNotMatch(attestedScan.result.output, /unused-history-attestation/);
      assert.equal(attestedScan.result.output.includes(olderValue), false);
      assert.equal(attestedScan.result.output.includes(newerValue), false);

      const bothAttestedPath = writeAttestations(target, [
        toAttestation(olderFinding, filePath),
        toAttestation(newerFinding, filePath),
      ]);
      const bothAttestedScan = collectHistoryFindings(target, ["--history-attestations", bothAttestedPath]);
      assert.equal(bothAttestedScan.result.status, 0);
      assert.deepEqual(bothAttestedScan.findings, []);
    });
  }
}

test("history reports different values at the same location without attestations", () => {
  const target = makeTempRepo();
  const filePath = "fixture.sh";
  const expectedFindings = [];

  for (const version of ["older", "newer"]) {
    const value = ["private", version, "fixture"].join("-");
    fs.writeFileSync(path.join(target, filePath), `${["DEV_ENV_HOST", value].join("=")}\n`);
    commitAll(target, `Add ${version} synthetic finding`);
    const { result, findings } = collectHistoryFindings(target);
    assert.equal(result.status, 1);
    assert.equal(findings[0].ruleId, "dev-env-local-value");
    expectedFindings.unshift(findings[0]);
  }

  const { result, findings } = collectHistoryFindings(target);
  assert.equal(result.status, 1);
  assert.deepEqual(findings, expectedFindings);
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
