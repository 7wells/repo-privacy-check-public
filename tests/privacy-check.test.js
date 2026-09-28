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
const expectedGitIdentityKey = (suffix) => ["DEV_ENV_EXPECTED_GIT_USER", suffix].join("");
const devEnvKey = (...segments) => ["DEV_ENV", ...segments].join("_");
const credentialKey = (...segments) => segments.join("_");
const quotedCredentialLine = (segments, value) => `${credentialKey(...segments)}="${value}"`;
const gitConfigCommand = (...args) => ["git", "config", ...args].join(" ");
const jsonDevEnvLine = (segments, value) => JSON.stringify({ [devEnvKey(...segments)]: value });
const mixedDevEnvLine = (segments, literal, variable) =>
  `${devEnvKey(...segments)}=${literal}${["$", variable].join("")}`;
const fallbackDevEnvLine = (segments, variable, fallback) =>
  `${devEnvKey(...segments)}="${["$", "{", variable, ":-", fallback, "}"].join("")}"`;

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

function scanCurrentLine(line) {
  const target = makeTempRepo();
  fs.writeFileSync(path.join(target, "fixture.sh"), `${line}\n`);
  const result = runScanner([target]);
  return { result, output: combinedOutput(result) };
}

function scanCurrentShell(content) {
  const target = makeTempRepo();
  fs.writeFileSync(path.join(target, "fixture.sh"), `#!/bin/sh\n${content}\n`);
  const result = runScanner([target]);
  return { result, output: combinedOutput(result) };
}

const shellVariable = (...segments) => ["$", segments.join("_")].join("");
const shellBracedVariable = (...segments) => ["${", segments.join("_"), "}"].join("");

test("action metadata avoids unquoted colon-space values", () => {
  const actionMetadata = fs.readFileSync(path.resolve(__dirname, "../action.yml"), "utf8");
  const unsafePlainScalar = /^\s*description:\s+[^"'\n][^\n]*:\s+/m;

  assert.doesNotMatch(actionMetadata, unsafePlainScalar);
  assert.match(actionMetadata, /^\s*using:\s+node24\s*$/m);
  assert.match(actionMetadata, /^\s*main:\s+scripts\/privacy-check\.js\s*$/m);
});

test("reusable workflow invokes the reviewed public action without a second Git checkout", () => {
  const workflow = fs.readFileSync(path.resolve(__dirname, "../.github/workflows/privacy-check.yml"), "utf8");
  const reviewedScannerSha = "c7afdb143cf1931280f39e2e7b01c17f0c2c15da";
  const checkoutUses = workflow.match(/^\s*uses:\s+actions\/checkout@/gm) ?? [];
  const runtimeUses = workflow.match(/^\s*uses:\s+7wells\/repo-privacy-check-public@[0-9a-f]{40}\b/gm) ?? [];

  assert.equal(checkoutUses.length, 1);
  assert.equal(runtimeUses.length, 2);
  assert.ok(runtimeUses.every((use) => use.includes(`@${reviewedScannerSha}`)));
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

for (const directory of ["build", ".cache"]) {
  test(`scans a tracked file under ${directory} by default`, () => {
    const target = makeTempRepo();
    const relativePath = `${directory}/tracked.txt`;
    const rawSecret = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

    execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
    fs.mkdirSync(path.dirname(path.join(target, relativePath)), { recursive: true });
    fs.writeFileSync(path.join(target, relativePath), rawSecret);
    execFileSync("git", ["add", "--force", "--", relativePath], { cwd: target, stdio: "ignore" });

    const result = runScanner([target]);
    const output = combinedOutput(result);
    assert.equal(result.status, 1);
    assert.match(output, new RegExp(`github-token ${directory.replaceAll(".", "\\.")}\\/tracked\\.txt:1 category=token`));
    assertRedacted(output, rawSecret);
  });

  for (const { kind, ignoreRule } of [
    { kind: "untracked", ignoreRule: null },
    { kind: "Git-ignored", ignoreRule: `${directory}/artifact.txt\n` },
  ]) {
    test(`keeps ${kind} artifacts under ${directory} excluded unless requested`, () => {
      const target = makeTempRepo();
      const relativePath = `${directory}/artifact.txt`;
      const rawSecret = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890"].join("_");

      execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
      if (ignoreRule) fs.writeFileSync(path.join(target, ".gitignore"), ignoreRule);
      fs.mkdirSync(path.dirname(path.join(target, relativePath)), { recursive: true });
      fs.writeFileSync(path.join(target, relativePath), rawSecret);

      const defaultResult = runScanner([target]);
      assert.equal(defaultResult.status, 0, `${kind} artifact must remain excluded by default`);
      assertRedacted(combinedOutput(defaultResult), rawSecret);

      const includedResult = runScanner(["--include-ignored", target]);
      const output = combinedOutput(includedResult);
      assert.equal(includedResult.status, 1, "include-ignored must scan this artifact");
      assert.match(output, new RegExp(`github-token ${directory.replaceAll(".", "\\.")}\\/artifact\\.txt:1 category=token`));
      assertRedacted(output, rawSecret);
    });
  }
}

test("maps GitHub Action inputs to CLI arguments without evaluating values", () => {
  const args = actionArgsFromEnvironment({
    "INPUT_HISTORY-ATTESTATIONS": "history-attestations.json",
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
    "--history-attestations",
    "history-attestations.json",
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

const literalCredentialFixtures = [
  {
    name: "a quoted uppercase token value",
    key: ["SERVICE", "TOKEN"],
    value: ["synthetic", "secret", "value"].join("-"),
  },
  {
    name: "a quoted lowercase token value",
    key: ["service", "token"],
    value: ["synthetic", "secret", "value"].join("-"),
  },
  { name: "a short quoted password", key: ["password"], value: ["s3cr", "3t"].join("") },
  { name: "a quoted password containing parentheses", key: ["PASSWORD"], value: ["ab", "(cd)", "12"].join("") },
];

for (const { name, key, value } of literalCredentialFixtures) {
  test(`current scan reports ${name} as literal-credential-assignment`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${quotedCredentialLine(key, value)}\n`);

    const result = runScanner([target]);
    const output = combinedOutput(result);
    assert.equal(result.status, 1);
    assert.match(output, /literal-credential-assignment fixture\.sh:1 category=credential/);
    assertRedacted(output, value);
  });
}

const credentialReferenceLines = [
  {
    name: "an uppercase constant on the right side",
    line: `const ${credentialKey("SERVICE", "TOKEN")} = MAX_RETRIES`,
  },
  {
    name: "another uppercase token reference",
    line: `${credentialKey("SERVICE", "TOKEN")} = ${credentialKey("OTHER", "TOKEN")}`,
  },
  { name: "a mixed-case identifier reference", line: `${credentialKey("SERVICE", "TOKEN")} = retryLimit` },
  { name: "a secret getter call", line: `${credentialKey("token")} = getSecret()` },
  {
    name: "a process environment reference",
    line: `${credentialKey("token")} = process.env.${credentialKey("SERVICE", "TOKEN")}`,
  },
  { name: "a configuration property reference", line: `${credentialKey("token")} = config.token` },
  { name: "a token placeholder", line: `${credentialKey("SERVICE", "TOKEN")} = placeholder` },
  { name: "a quoted environment variable placeholder", line: `${credentialKey("SERVICE", "TOKEN")} = "${["$", "SERVICE_TOKEN"].join("")}"` },
  { name: "a quoted secret template", line: `${credentialKey("SERVICE", "TOKEN")} = "${["${{", " secrets.", "SERVICE_TOKEN", " }}"].join("")}"` },
  { name: "an empty quoted token", line: `${credentialKey("SERVICE", "TOKEN")} = ""` },
  { name: "a boolean token value", line: `${credentialKey("SERVICE", "TOKEN")} = false` },
  { name: "a null token value", line: `${credentialKey("SERVICE", "TOKEN")} = null` },
];

for (const { name, line } of credentialReferenceLines) {
  test(`current scan allows ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${line}\n`);

    const result = runScanner([target]);
    assert.equal(result.status, 0, combinedOutput(result));
  });
}

const similarCredentialKeyLines = [
  { name: "a token count field", line: `${credentialKey("TOKEN", "COUNT")} = 12345678` },
  { name: "a tokenized label field", line: `${credentialKey("SERVICE", "TOKENIZER")} = synthetic-secret-value` },
  { name: "a token value suffix field", line: `${credentialKey("SERVICE", "TOKEN", "VALUE")} = synthetic-secret-value` },
];

for (const { name, line } of similarCredentialKeyLines) {
  test(`current scan allows ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${line}\n`);

    const result = runScanner([target]);
    assert.equal(result.status, 0, combinedOutput(result));
  });
}

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

const gitConfigSetterFixtures = [
  {
    name: "a replace-all email setter after the global option",
    args: ["--global", "--replace-all", "user.email", ["person", "example.invalid"].join("@")],
    value: ["person", "example.invalid"].join("@"),
  },
  {
    name: "a replace-all name setter before the global option",
    args: ["--replace-all", "--global", "user.name", ["Synthetic", "Person"].join(" ")],
    value: ["Synthetic", "Person"].join(" "),
  },
];

for (const { name, args, value } of gitConfigSetterFixtures) {
  test(`current scan reports ${name} as git-config-identity`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${gitConfigCommand(...args)}\n`);

    const result = runScanner([target]);
    const output = combinedOutput(result);
    assert.equal(result.status, 1);
    assert.match(output, /git-config-identity fixture\.sh:1 category=git-identity/);
    assertRedacted(output, value);
  });
}

const gitConfigReadOnlyLines = [
  { name: "an email getter with --get", args: ["--get", "user.email"] },
  { name: "a global name getter with --get", args: ["--global", "--get", "user.name"] },
  { name: "an email query without a value", args: ["user.email"] },
  { name: "an email query redirected to a sink", args: ["user.email", ">/dev/null"] },
  { name: "a replace-all option without a value", args: ["--global", "--replace-all", "user.email"] },
  { name: "a setter using an environment placeholder", args: ["--global", "--replace-all", "user.email", ["$", "GIT_EMAIL"].join("")] },
];

for (const { name, args } of gitConfigReadOnlyLines) {
  test(`current scan allows ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${gitConfigCommand(...args)}\n`);

    const result = runScanner([target]);
    assert.equal(result.status, 0, combinedOutput(result));
  });
}

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

const shellSecretOutputFindings = [
  { name: "TOKEN", line: ["echo", `"${shellVariable("TOKEN")}"`].join(" ") },
  {
    name: "SERVICE_TOKEN",
    line: ["echo", `"${shellBracedVariable("SERVICE", "TOKEN")}"`].join(" "),
  },
  {
    name: "PASSWORD through printf",
    line: ["printf", '"%s\\n"', `"${shellVariable("PASSWORD")}"`].join(" "),
  },
];

for (const { name, line } of shellSecretOutputFindings) {
  test(`current scan reports output of ${name} as shell-secret-variable-output`, () => {
    const { result, output } = scanCurrentLine(line);
    assert.equal(result.status, 1);
    assert.match(output, /shell-secret-variable-output fixture\.sh:1 category=unsafe-logging/);
  });
}

const shellSecretOutputAllowances = [
  { name: "TOKEN_COUNT through echo", line: ["echo", `"${shellVariable("TOKEN", "COUNT")}"`].join(" ") },
  { name: "SECRET_COUNT through echo", line: ["echo", `"${shellVariable("SECRET", "COUNT")}"`].join(" ") },
  {
    name: "TOKEN_COUNT through printf",
    line: ["printf", '"%s\\n"', `"${shellVariable("TOKEN", "COUNT")}"`].join(" "),
  },
];

for (const { name, line } of shellSecretOutputAllowances) {
  test(`current scan allows output of ${name}`, () => {
    const { result, output } = scanCurrentLine(line);
    assert.equal(result.status, 0, output);
    assert.doesNotMatch(output, /shell-secret-variable-output/);
  });
}

const shellGrepCountAllowances = [
  { name: "--count", line: ["grep", "--count", "pattern", "file"].join(" ") },
  { name: "-c", line: ["grep", "-c", "pattern", "file"].join(" ") },
  { name: "the count-only combined -ic form", line: ["grep", "-ic", "pattern", "file"].join(" ") },
  { name: "--files-with-matches", line: ["grep", "--files-with-matches", "pattern", "file"].join(" ") },
  { name: "-l", line: ["grep", "-l", "pattern", "file"].join(" ") },
  { name: "--quiet", line: ["grep", "--quiet", "pattern", "file"].join(" ") },
  { name: "-q", line: ["grep", "-q", "pattern", "file"].join(" ") },
];

for (const { name, line } of shellGrepCountAllowances) {
  test(`current scan allows grep ${name} without shell-grep-match-output`, () => {
    const { result, output } = scanCurrentLine(line);
    assert.equal(result.status, 0, output);
    assert.doesNotMatch(output, /shell-grep-match-output/);
  });
}

const shellGrepOutputFindings = [
  { name: "ordinary matching output", line: ["grep", "pattern", "file"].join(" ") },
  { name: "line-number matching output", line: ["grep", "-n", "pattern", "file"].join(" ") },
];

for (const { name, line } of shellGrepOutputFindings) {
  test(`current scan reports grep ${name} as shell-grep-match-output`, () => {
    const { result, output } = scanCurrentLine(line);
    assert.equal(result.status, 1);
    assert.match(output, /shell-grep-match-output fixture\.sh:1 category=unsafe-logging/);
  });
}

test("current scan distinguishes redirected grep matches from visible output", () => {
  const redirected = scanCurrentShell(['CRON_TMP="/tmp/privacy-grep-output"', 'grep -Fv "$SCRIPT" "$SOURCE" > "$CRON_TMP" || true'].join("\n"));
  const visible = scanCurrentShell('grep -Fv "$SCRIPT" "$SOURCE"');
  const stdoutAlias = scanCurrentShell('grep -Fv "$SCRIPT" "$SOURCE" > /dev/stdout');
  const stderrOnly = scanCurrentShell('grep -Fv "$SCRIPT" "$SOURCE" 2> "$ERROR_FILE"');
  const dynamicStdout = scanCurrentShell(['CRON_TMP=/dev/stdout', 'grep -Fv "$SCRIPT" "$SOURCE" > "$CRON_TMP"'].join("\n"));
  const pipeline = scanCurrentShell('grep -Fv "$SCRIPT" "$SOURCE" > "$CRON_TMP" | tee "$LOG_FILE"');
  const commentedRedirect = scanCurrentShell('grep -Fv "$SCRIPT" "$SOURCE" # > /tmp/example-output');
  const stderrDescriptor = scanCurrentShell('grep -Fv "$SCRIPT" "$SOURCE" 2> /tmp/example-error');
  const extraDescriptor = scanCurrentShell('grep -Fv "$SCRIPT" "$SOURCE" 3> /tmp/example-output');
  const annotatedRedirect = scanCurrentShell('grep -Fv "$SCRIPT" "$SOURCE" > /tmp/example-output # reviewed file output');

  assert.doesNotMatch(redirected.output, /shell-grep-match-output/);
  assert.doesNotMatch(annotatedRedirect.output, /shell-grep-match-output/);
  for (const result of [visible, stdoutAlias, stderrOnly, pipeline, commentedRedirect, stderrDescriptor, extraDescriptor]) {
    assert.match(result.output, /shell-grep-match-output fixture\.sh:2 category=unsafe-logging/);
  }
  assert.match(dynamicStdout.output, /shell-grep-match-output fixture\.sh:3 category=unsafe-logging/);
});

test("current scan distinguishes redirected secret printf from terminal output", () => {
  const redirected = scanCurrentShell(['PASSWORD_FILE="/tmp/privacy-output"', 'printf "%s\\n" "$SERVICE_PASSWORD" > "$PASSWORD_FILE"'].join("\n"));
  const visible = scanCurrentShell('printf "%s\\n" "$SERVICE_PASSWORD"');
  const stderr = scanCurrentShell('printf "%s\\n" "$SERVICE_PASSWORD" >&2');
  const stdoutAlias = scanCurrentShell('printf "%s\\n" "$SERVICE_PASSWORD" > /dev/stdout');
  const dynamicStdout = scanCurrentShell(['PASSWORD_FILE=/dev/stdout', 'printf "%s\\n" "$SERVICE_PASSWORD" > "$PASSWORD_FILE"'].join("\n"));
  const extraFileDescriptor = scanCurrentShell('printf "%s\\n" "$SERVICE_PASSWORD" > /dev/fd/3');
  const stderrOnly = scanCurrentShell('printf "%s\\n" "$SERVICE_PASSWORD" 2> "$ERROR_FILE"');
  const unknownTarget = scanCurrentShell('printf "%s\\n" "$SERVICE_PASSWORD" > "$PASSWORD_FILE"');
  const conditionalTarget = scanCurrentShell([
    'PASSWORD_FILE=/dev/stdout',
    'if false; then',
    '  PASSWORD_FILE=/tmp/privacy-output',
    'fi',
    'printf "%s\\n" "$SERVICE_PASSWORD" > "$PASSWORD_FILE"',
  ].join("\n"));
  const overwrittenByRead = scanCurrentShell([
    'PASSWORD_FILE=/tmp/privacy-output',
    'read PASSWORD_FILE',
    'printf "%s\\n" "$SERVICE_PASSWORD" > "$PASSWORD_FILE"',
  ].join("\n"));
  const overwrittenBySource = scanCurrentShell([
    'PASSWORD_FILE=/tmp/privacy-output',
    '. "$CONFIG_FILE"',
    'printf "%s\\n" "$SERVICE_PASSWORD" > "$PASSWORD_FILE"',
  ].join("\n"));

  assert.doesNotMatch(redirected.output, /shell-secret-variable-output/);
  for (const result of [visible, stderr, stdoutAlias, extraFileDescriptor, stderrOnly, unknownTarget]) {
    assert.match(result.output, /shell-secret-variable-output fixture\.sh:2 category=unsafe-logging/);
  }
  assert.match(dynamicStdout.output, /shell-secret-variable-output fixture\.sh:3 category=unsafe-logging/);
  assert.match(conditionalTarget.output, /shell-secret-variable-output fixture\.sh:6 category=unsafe-logging/);
  assert.match(overwrittenByRead.output, /shell-secret-variable-output fixture\.sh:4 category=unsafe-logging/);
  assert.match(overwrittenBySource.output, /shell-secret-variable-output fixture\.sh:4 category=unsafe-logging/);
});

test("current scan honors only clear enclosing shell block redirects", () => {
  const command = '  printf "%s\\n" "$SERVICE_PASSWORD"';
  const redirected = scanCurrentShell(['AUTH_CONFIG_FILE="/tmp/privacy-auth-config"', '{', command, '} > "$AUTH_CONFIG_FILE"'].join("\n"));
  const visible = scanCurrentShell(['{', command, '}'].join("\n"));
  const stdoutAlias = scanCurrentShell(['{', command, '} > /dev/stdout'].join("\n"));
  const innerStderr = scanCurrentShell(['{', `${command} >&2`, '} > "$AUTH_CONFIG_FILE"'].join("\n"));

  assert.doesNotMatch(redirected.output, /shell-secret-variable-output/);
  for (const result of [visible, stdoutAlias, innerStderr]) {
    assert.match(result.output, /shell-secret-variable-output fixture\.sh:3 category=unsafe-logging/);
  }
});

test("current scan keeps synthetic test credential literals visible pending a narrow policy", () => {
  const key = credentialKey("SERVICE", "PASSWORD");
  const synthetic = scanCurrentLine(quotedCredentialLine([key], ["TEST", "ONLY", "fixture"].join("_")));
  const realLike = scanCurrentLine(quotedCredentialLine([key], ["unreviewed", "credential"].join("-")));

  assert.match(synthetic.output, /literal-credential-assignment fixture\.sh:1 category=credential/);
  assert.match(realLike.output, /literal-credential-assignment fixture\.sh:1 category=credential/);
});

test("current scan does not mistake shell fallback expansion for an assignment", () => {
  const fallback = ["${", credentialKey("SERVICE", "PASSWORD"), ":-", "TEST_ONLY", "}"].join("");
  const assignment = ["${", credentialKey("SERVICE", "PASSWORD"), ":=", "unreviewed-credential", "}"].join("");
  const comparison = scanCurrentShell(`grep -Fxq "user = ${fallback}" "$CONFIG_FILE"`);
  const assigningExpansion = scanCurrentShell(`grep -Fxq "user = ${assignment}" "$CONFIG_FILE"`);
  const directAssignment = scanCurrentShell(quotedCredentialLine(["SERVICE", "PASSWORD"], "unreviewed-credential"));

  assert.doesNotMatch(comparison.output, /literal-credential-assignment/);
  assert.match(assigningExpansion.output, /literal-credential-assignment fixture\.sh:2 category=credential/);
  assert.match(directAssignment.output, /literal-credential-assignment fixture\.sh:2 category=credential/);
});

const runtimeEnvironmentDumpFindings = [
  {
    name: "JSON serialization of os.environ",
    line: ["print", "(", "json", ".dumps", "(", "os", ".environ", ")", ")"].join(""),
  },
  {
    name: "JSON serialization of dict(os.environ)",
    line: ["print", "(", "json", ".dumps", "(", "dict", "(", "os", ".environ", ")", ")", ")"].join(""),
  },
  {
    name: "the existing direct Python environment dump",
    line: ["print", "(", "dict", "(", "os", ".environ", ")", ")"].join(""),
  },
  {
    name: "the existing JavaScript environment dump",
    line: ["console.log", "process.env"].join("(") + ")",
  },
];

for (const { name, line } of runtimeEnvironmentDumpFindings) {
  test(`current scan reports ${name} as runtime-env-dump`, () => {
    const { result, output } = scanCurrentLine(line);
    assert.equal(result.status, 1);
    assert.match(output, /runtime-env-dump fixture\.sh:1 category=unsafe-logging/);
  });
}

const runtimeEnvironmentAccessAllowances = [
  {
    name: "a single Python HOME lookup",
    line: ["print", "(", "os", ".environ", '["HOME"]', ")"].join(""),
  },
  {
    name: "a single JavaScript PATH lookup",
    line: ["console.log", "process.env", ".PATH"].join("(") + ")",
  },
];

for (const { name, line } of runtimeEnvironmentAccessAllowances) {
  test(`current scan allows ${name} without runtime-env-dump`, () => {
    const { result, output } = scanCurrentLine(line);
    assert.equal(result.status, 0, output);
    assert.doesNotMatch(output, /runtime-env-dump/);
  });
}

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
    "private.key",
    "private.ppk",
    "private.p12",
    "private.pfx",
    "private.jks",
    "private.keystore",
    ".env",
    ".ENV.PROD",
    ".envrc",
    ".env-local",
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
  assert.match(output, /blocked-private-key-extension private\.key category=private-key/);
  assert.match(output, /blocked-private-key-extension private\.ppk category=private-key/);
  assert.match(output, /blocked-key-store-extension private\.p12 category=private-key/);
  assert.match(output, /blocked-key-store-extension private\.pfx category=private-key/);
  assert.match(output, /blocked-key-store-extension private\.jks category=private-key/);
  assert.match(output, /blocked-key-store-extension private\.keystore category=private-key/);
  assert.match(output, /blocked-credential-path \.aws\/credentials category=credential/);
  assert.match(output, /blocked-env-file \.env category=env-file/);
  assert.match(output, /blocked-env-file \.ENV\.PROD category=env-file/);
  assert.match(output, /blocked-env-file \.envrc category=env-file/);
  assert.match(output, /blocked-env-file \.env-local category=env-file/);
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

test("allows only the exact public expected Git identity defaults", () => {
  const target = makeTempRepo();
  const lines = [
    `readonly ${expectedGitIdentityKey("_NAME")}="7wells"`,
    `readonly ${expectedGitIdentityKey("_EMAIL")}="65889763+7wells@users.noreply.github.com"`,
  ];

  fs.writeFileSync(path.join(target, "expected-identity.sh"), `${lines.join("\n")}\n`);

  const result = runScanner([target]);
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
  test(`current scan allows ${name} in a DEV_ENV assignment`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${devEnvKey(...key)}=${value}\n`);

    const result = runScanner([target]);
    assert.equal(result.status, 0, combinedOutput(result));
  });
}

const quotedJsonDevEnvFindings = [
  { name: "a concrete private host value", key: ["HOST"], value: "workstation" },
  { name: "a private URL value", key: ["BASE", "URL"], value: ["https://service", ".internal"].join("") },
];

for (const { name, key, value } of quotedJsonDevEnvFindings) {
  test(`current scan reports a quoted JSON key with ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.json"), `${jsonDevEnvLine(key, value)}\n`);

    const result = runScanner([target]);
    const output = combinedOutput(result);
    assert.equal(result.status, 1);
    assert.match(output, /dev-env-local-value fixture\.json:1 category=local-env/);
    assertRedacted(output, value);
  });
}

const quotedJsonDevEnvAllowances = [
  { name: "an example host placeholder", key: ["HOST"], value: "example-host" },
  { name: "a public host name", key: ["HOST"], value: "example.org" },
  { name: "a generic service name", key: ["SERVICE", "NAME"], value: "widget" },
];

for (const { name, key, value } of quotedJsonDevEnvAllowances) {
  test(`current scan allows quoted JSON with ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.json"), `${jsonDevEnvLine(key, value)}\n`);

    const result = runScanner([target]);
    assert.equal(result.status, 0, combinedOutput(result));
  });
}

test("current scan allows exact reviewed Git identity values in JSON", () => {
  const target = makeTempRepo();
  const identity = {
    [expectedGitIdentityKey("_NAME")]: "7wells",
    [expectedGitIdentityKey("_EMAIL")]: ["65889763+7wells", "@users.noreply.github.com"].join(""),
  };
  fs.writeFileSync(path.join(target, "identity.json"), `${JSON.stringify(identity)}\n`);

  const result = runScanner([target]);
  assert.equal(result.status, 0, combinedOutput(result));
});

test("current scan reports payload appended after an exact JSON Git identity value", () => {
  const target = makeTempRepo();
  const exactPair = JSON.stringify({ [expectedGitIdentityKey("_NAME")]: "7wells" });
  const line = `${exactPair.slice(0, -1)} synthetic-person}`;
  fs.writeFileSync(path.join(target, "identity.json"), `${line}\n`);

  const result = runScanner([target]);
  const output = combinedOutput(result);
  assert.equal(result.status, 1);
  assert.match(output, /dev-env-local-value identity\.json:1 category=local-env/);
  assert.doesNotMatch(output, /synthetic-person/);
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
  test(`current scan reports ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${line}\n`);

    const result = runScanner([target]);
    const output = combinedOutput(result);
    assert.equal(result.status, 1);
    assert.match(output, /dev-env-local-value fixture\.sh:1 category=local-env/);
    assertRedacted(output, value);
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
  test(`current scan allows ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${line}\n`);

    const result = runScanner([target]);
    assert.equal(result.status, 0, combinedOutput(result));
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
  test(`current scan reports a shell fallback with ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${fallbackDevEnvLine(key, variable, fallback)}\n`);

    const result = runScanner([target]);
    const output = combinedOutput(result);
    assert.equal(result.status, 1);
    assert.match(output, /dev-env-local-value fixture\.sh:1 category=local-env/);
    assertRedacted(output, fallback);
  });
}

const shellFallbackAllowances = [
  { name: "a direct dynamic expansion", fallback: ["$", "{", "HOST", "}"].join("") },
  { name: "a public hostname fallback", fallback: "example.org" },
  { name: "a generic placeholder fallback", fallback: "placeholder" },
];

for (const { name, fallback } of shellFallbackAllowances) {
  test(`current scan allows ${name}`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${fallbackDevEnvLine(["HOST"], "HOST", fallback)}\n`);

    const result = runScanner([target]);
    assert.equal(result.status, 0, combinedOutput(result));
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
  test(`current scan reports ${name} as dev-env-local-value`, () => {
    const target = makeTempRepo();
    fs.writeFileSync(path.join(target, "fixture.sh"), `${devEnvKey(...key)}=${value}\n`);

    const result = runScanner([target]);
    const output = combinedOutput(result);
    assert.equal(result.status, 1);
    assert.match(output, /dev-env-local-value fixture\.sh:1 category=local-env/);
    assertRedacted(output, value);
  });
}

test("current scan leaves a plain loopback HOST assignment outside this DEV_ENV rule", () => {
  const target = makeTempRepo();
  fs.writeFileSync(path.join(target, "fixture.sh"), "HOST=127.0.0.1\n");

  const result = runScanner([target]);
  assert.equal(result.status, 0, combinedOutput(result));
});

test("still detects changed or similar DEV_ENV identity values", () => {
  const target = makeTempRepo();
  const localName = "private-workstation";
  const localEmail = "person@example.invalid";
  const lines = [
    `DEV_ENV_EXPECTED_GIT_USER_NAME=${localName}`,
    `DEV_ENV_EXPECTED_GIT_USER_EMAIL=${localEmail}`,
    ["DEV_ENV_GIT_USER_NAME", "7wells"].join("="),
    ["DEV_ENV_GIT_USER_EMAIL", "65889763+7wells@users.noreply.github.com"].join("="),
    `DEV_ENV_USER_NAME=${localName}`,
    `DEV_ENV_USER_EMAIL=${localEmail}`,
  ];

  fs.writeFileSync(path.join(target, "local-identities.sh"), `${lines.join("\n")}\n`);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  for (let line = 1; line <= lines.length; line += 1) {
    assert.match(output, new RegExp(`dev-env-local-value local-identities\\.sh:${line} category=local-env`));
  }
  assertRedacted(output, localName);
  assertRedacted(output, localEmail);
});

test("allows only exact generic WSL source roots in DEV_ENV assignments", () => {
  const target = makeTempRepo();
  const lowerCaseDriveRoot = ["", "mnt", "c", "src"].join("/");
  const upperCaseDriveRoot = ["", "mnt", "D", "src"].join("/");
  const lines = [
    ["DEV_ENV_PROJECT_COLLECTION_ROOT", lowerCaseDriveRoot].join("="),
    ["DEV_ENV_PROJECT_COLLECTION_ROOT", `"${upperCaseDriveRoot}"`].join("="),
  ];

  fs.writeFileSync(path.join(target, "generic-wsl-roots.sh"), `${lines.join("\n")}\n`);

  const result = runScanner([target]);
  assert.equal(result.status, 0);
});

test("still blocks paths below or resembling WSL roots and other private DEV_ENV values", () => {
  const target = makeTempRepo();
  const deeperWslPath = ["", "mnt", "c", "src", "private-project"].join("/");
  const prefixedWslPath = ["", "mnt", "c", "src-private"].join("/");
  const linuxHomePath = ["", "home", "master", "private-project"].join("/");
  const windowsHomePath = ["C:", "Users", "private-user", "private-project"].join("\\");
  const privateHost = ["private", "workstation"].join("-");
  const localCredential = ["local", "credential"].join("-");
  const values = [deeperWslPath, prefixedWslPath, linuxHomePath, windowsHomePath, privateHost, localCredential];
  const lines = [
    ["DEV_ENV_PROJECT_COLLECTION_ROOT", deeperWslPath].join("="),
    ["DEV_ENV_PROJECT_COLLECTION_ROOT", prefixedWslPath].join("="),
    ["DEV_ENV_PROJECT_COLLECTION_ROOT", linuxHomePath].join("="),
    ["DEV_ENV_PROJECT_COLLECTION_ROOT", windowsHomePath].join("="),
    ["DEV_ENV_HOST", privateHost].join("="),
    ["DEV_ENV_API_KEY", localCredential].join("="),
  ];

  fs.writeFileSync(path.join(target, "private-local-values.sh"), `${lines.join("\n")}\n`);

  const result = runScanner([target]);
  const output = combinedOutput(result);

  assert.equal(result.status, 1);
  for (let line = 1; line <= lines.length; line += 1) {
    assert.match(output, new RegExp(`dev-env-local-value private-local-values\\.sh:${line} category=local-env`));
  }
  assert.match(output, /home-directory-path private-local-values\.sh:3 category=local-path/);
  assert.match(output, /home-directory-path private-local-values\.sh:4 category=local-path/);
  for (const value of values) {
    assertRedacted(output, value);
  }
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
