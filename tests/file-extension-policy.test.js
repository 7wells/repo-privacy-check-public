// File purpose: Validate extension-only path policy while preserving normal content scans.
// Inputs: Synthetic files in temporary Git repositories, scanned as Current and History.
// Outputs: Assertions over metadata-only findings and redacted JSON reports.
// Security and privacy: Use constructed synthetic markers, credentials, and local paths only.

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, test } = require("node:test");

const { runCli } = require("../scripts/privacy-check.js");
const temporaryRepositories = new Set();
const privateKeyMarker = (kind = "PRIVATE KEY") => ["-----BEGIN", `${kind}-----`].join(" ");
const syntheticToken = () => ["ghp", "A".repeat(40)].join("_");

function makeTempRepo() {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), "privacy-extension-policy-"));
  temporaryRepositories.add(target);
  execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
  return target;
}

function scanFixture(mode, fileName, content) {
  const target = makeTempRepo();
  fs.writeFileSync(path.join(target, fileName), content);
  if (mode === "history") {
    execFileSync("git", ["add", fileName], { cwd: target, stdio: "ignore" });
    execFileSync("git", [
      "-c", "user.name=Example User", "-c", "user.email=example@example.invalid",
      "commit", "--quiet", "-m", "Add synthetic extension-policy fixture",
    ], { cwd: target, stdio: "ignore" });
  }

  const reportPath = path.join(target, ".git", "privacy-report.json");
  const output = [];
  const status = runCli(["--mode", mode, "--report", reportPath, target], {
    stdout: (message) => output.push(message),
    stderr: (message) => output.push(message),
  });
  const reportText = fs.readFileSync(reportPath, "utf8");
  return { status, output: output.join("\n"), reportText, report: JSON.parse(reportText) };
}

function assertAllowed(mode, fileName, content) {
  const { status, report } = scanFixture(mode, fileName, content);
  assert.equal(status, 0);
  assert.equal(report.findingCount, 0);
  assert.equal(report.findings.length, 0);
}

function assertFinding(mode, fileName, content, ruleId, category, line, sensitiveValue) {
  const { status, output, reportText, report } = scanFixture(mode, fileName, content);
  assert.equal(status, 1);
  assert.equal(report.findingCount, 1);
  assert.equal(report.mode, mode);
  assert.ok(output.includes(`- ${ruleId} ${fileName}${line === null ? "" : `:${line}`} category=${category}`));
  const [finding] = report.findings;
  assert.equal(finding.ruleId, ruleId);
  assert.equal(finding.file, fileName);
  assert.equal(finding.line, line);
  assert.equal(finding.category, category);
  assert.equal(finding.source, mode);
  assert.equal(output.includes(sensitiveValue), false);
  assert.equal(reportText.includes(sensitiveValue), false);
}

after(() => {
  for (const target of temporaryRepositories) fs.rmSync(target, { recursive: true, force: true });
});

for (const mode of ["current", "history"]) {
  for (const fileName of ["ca.pem", "certificate.pem", "public-chain.pem"]) {
    test(`${mode} allows harmless ${fileName} based on content`, () => {
      assertAllowed(mode, fileName, "Public certificate data.\n");
    });
  }

  test(`${mode} allows a public certificate marker in a PEM file`, () => {
    assertAllowed(mode, "certificate.pem", `${["-----BEGIN", "CERTIFICATE-----"].join(" ")}\n`);
  });

  for (const fileName of ["expected.log", "application.log"]) {
    test(`${mode} allows harmless ${fileName} based on content`, () => {
      assertAllowed(mode, fileName, "Expected application output.\n");
    });
  }

  for (const kind of [
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
  ]) {
    test(`${mode} scans ${kind} content in PEM files`, () => {
      const marker = privateKeyMarker(kind);
      assertFinding(mode, "certificate.pem", `${marker}\n`, "private-key-header", "private-key", 1, marker);
    });
  }

  test(`${mode} scans synthetic token content in log files`, () => {
    const fixtureValue = syntheticToken();
    assertFinding(mode, "expected.log", `${fixtureValue}\n`, "github-token", "token", 1, fixtureValue);
  });

  test(`${mode} scans credential assignments in log files`, () => {
    const key = ["SERVICE", "TOKEN"].join("_");
    const value = ["synthetic", "secret", "value"].join("-");
    const fixture = `${key}="${value}"\n`;
    assertFinding(mode, "application.log", fixture, "literal-credential-assignment", "credential", 1, fixture.trim());
  });

  test(`${mode} scans private home paths in log files`, () => {
    const privatePath = ["", "home", "private-user", "project"].join("/");
    const fixture = `PATH=${privatePath}\n`;
    assertFinding(mode, "application.log", fixture, "home-directory-path", "local-path", 1, privatePath);
  });

  test(`${mode} scans private-key markers in log files`, () => {
    const marker = privateKeyMarker();
    assertFinding(mode, "application.log", `${marker}\n`, "private-key-header", "private-key", 1, marker);
  });

  for (const [fileName, ruleId, category] of [
    ["fixture.key", "blocked-private-key-extension", "private-key"],
    ["fixture.ppk", "blocked-private-key-extension", "private-key"],
    ["fixture.p12", "blocked-key-store-extension", "private-key"],
    ["fixture.pfx", "blocked-key-store-extension", "private-key"],
    ["fixture.jks", "blocked-key-store-extension", "private-key"],
    ["fixture.keystore", "blocked-key-store-extension", "private-key"],
  ]) {
    test(`${mode} retains extension blocking for ${fileName}`, () => {
      const { status, output, report, reportText } = scanFixture(mode, fileName, "placeholder\n");
      assert.equal(status, 1);
      assert.equal(report.findingCount, 1);
      assert.ok(output.includes(`${ruleId} ${fileName} category=${category}`));
      assert.deepEqual(report.findings.map(({ ruleId: foundRule }) => foundRule), [ruleId]);
      assert.deepEqual(report.findings.map(({ file }) => file), [fileName]);
      assert.deepEqual(report.findings.map(({ line }) => line), [null]);
      assert.deepEqual(report.findings.map(({ category: foundCategory }) => foundCategory), [category]);
      assert.deepEqual(report.findings.map(({ source }) => source), [mode]);
      assert.equal(reportText.includes("placeholder"), false);
    });
  }
}
