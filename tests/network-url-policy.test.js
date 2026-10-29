// File purpose: Verify URL-host policy independently of credentials, queries, and path redaction.
// Inputs: Synthetic URLs committed to temporary Git repositories.
// Outputs: Metadata-only findings in current, index, and history modes.
// Security and privacy: Construct sensitive fixtures at runtime and verify output redaction.

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");
const { runCli, testInternals } = require("../scripts/privacy-check.js");

function scanFixture(mode, content, check) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "privacy-url-policy-"));
  try {
    const target = path.join(root, "repo");
    fs.mkdirSync(target);
    const git = (...args) => execFileSync("git", args, { cwd: target, stdio: "ignore" });
    git("init", "--quiet");
    fs.writeFileSync(path.join(target, "fixture.txt"), `${content}\n`);
    git("add", "fixture.txt");
    git("-c", "user.name=Example User", "-c", "user.email=example@example.invalid",
      "commit", "--quiet", "-m", "Add synthetic URL fixture");
    const reportPath = path.join(root, "report.json");
    const output = [];
    const status = runCli(["--mode", mode, "--report", reportPath, target], {
      stdout: (message) => output.push(message), stderr: (message) => output.push(message),
    });
    const reportText = fs.readFileSync(reportPath, "utf8");
    check({ status, output: output.join("\n"), reportText, report: JSON.parse(reportText) });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

const numericHosts = [
  "10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1", "169.254.1.1",
  "[fc00::1]", "[fdff:ffff::1]", "[fe80::1]", "[::ffff:192.168.1.1]",
  "127.0.0.1", "[::1]", "203.0.113.10",
];

for (const mode of ["current", "index", "history"]) {
  for (const host of numericHosts) {
    for (const scheme of ["http", "https"]) {
      test(`${mode} allows ${scheme} numeric host ${host}`, () => {
        scanFixture(mode, [scheme, "://", host, ":8080/status"].join(""), (result) => {
          assert.equal(result.status, 0, result.output);
          assert.deepEqual(result.report.findings, []);
        });
      });
    }
  }
  for (const host of ["service.internal", "host.lan", "device.local", "sub.device.local."]) {
    test(`${mode} detects internal hostname ${host}`, () => {
      checkFinding(mode, ["https://", host, "/status"].join(""), "private-network-url", "private-url", [host]);
    });
  }
  for (const host of ["10.0.0.1", "[fd00::1]"]) {
    test(`${mode} detects credentials with numeric host ${host}`, () => {
      const secret = ["synthetic", "password"].join("-");
      checkFinding(mode, ["https://synthetic-user:", secret, "@", host, "/status"].join(""),
        "credential-url", "credential", [secret, host]);
    });
    test(`${mode} detects sensitive query with numeric host ${host}`, () => {
      const value = ["synthetic", "query-value"].join("-");
      checkFinding(mode, ["https://", host, "/status?", "token=", value].join(""),
        "url-with-query", "url-query", [value, host]);
    });
  }
  test(`${mode} recognizes a known token shape in a numeric-host URL path`, () => {
    const token = ["gh", "p_", "A".repeat(36)].join("");
    checkFinding(mode, ["https://", "10.0.0.1/access/", token].join(""),
      "github-token", "token", [token]);
  });
  test(`${mode} documents the existing opaque URL-path access-value detection gap`, () => {
    const url = ["https://", "10.0.0.1/access/", "synthetic-opaque-access-value"].join("");
    scanFixture(mode, url, (result) => {
      assert.equal(result.status, 0, result.output);
      assert.deepEqual(result.report.findings, []);
      assert.equal(result.output.includes(url), false);
      assert.equal(result.reportText.includes(url), false);
    });
  });
}

function checkFinding(mode, url, ruleId, category, privateValues) {
  scanFixture(mode, url, (result) => {
    assert.equal(result.status, 1, result.output);
    assert.equal(result.report.findings.length, 1);
    const { ruleId: actualRule, file, line, source, category: actualCategory } = result.report.findings[0];
    assert.deepEqual({ ruleId: actualRule, file, line, source, category: actualCategory }, {
      ruleId, file: "fixture.txt", line: 1, source: mode, category,
    });
    assert.match(result.output, new RegExp(ruleId));
    for (const value of [url, ...privateValues]) {
      assert.equal(result.output.includes(value), false);
      assert.equal(result.reportText.includes(value), false);
    }
  });
}

for (const host of ["10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1", "service.internal"]) {
  test(`path redaction still protects ${host}`, () => {
    assert.equal(testInternals.sanitizeFindingPath(`fixtures/${host}/sample.txt`), "[redacted-path]");
  });
}
