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

function scanFixture(mode, content, check, file = "fixture.txt") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "privacy-url-policy-"));
  try {
    const target = path.join(root, "repo");
    fs.mkdirSync(target);
    const git = (...args) => execFileSync("git", args, { cwd: target, stdio: "ignore" });
    git("init", "--quiet");
    fs.mkdirSync(path.dirname(path.join(target, file)), { recursive: true });
    fs.writeFileSync(path.join(target, file), `${content}\n`);
    git("add", file);
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

for (const mode of ["current", "index", "history"]) {
  for (const host of ["example.org", "10.0.0.1", "[fd00::1]"]) {
    for (const key of ["token", "api_key", "password"]) {
      test(`${mode} detects ${key} path assignment on ${host}`, () => {
        checkFinding(mode, ["https://", host, "/", key, "=", "s3cr3t"].join(""),
          "literal-credential-assignment", "credential", ["s3cr3t"]);
      });
    }
    test(`${mode} detects once-encoded token on ${host}`, () => {
      const token = ["%67", "hp_", "A".repeat(36)].join("");
      checkFinding(mode, ["https://", host, "/access/", token].join(""), "github-token", "token", [token]);
    });
    test(`${mode} detects encoded credential assignment on ${host}`, () => {
      checkFinding(mode, ["https://", host, "/%74oken%3D", "s3cr3t"].join(""),
        "literal-credential-assignment", "credential", ["s3cr3t"]);
    });
    for (const suffix of ["resources/12345", "objects/" + "abcdef12".repeat(8),
      "resources/550e8400-e29b-41d4-a716-446655440000", "token=$TOKEN", "password=${PASSWORD}",
      "api_key=placeholder", "token=%24TOKEN", "token=", "resources/%ZZ"]) {
      test(`${mode} allows non-sensitive path ${suffix} on ${host}`, () => {
        scanFixture(mode, ["https://", host, "/", suffix].join(""), (result) => {
          assert.equal(result.status, 0, result.output);
          assert.deepEqual(result.report.findings, []);
        });
      });
    }
  }
  for (const context of ["token", "api_key", "password", "access", "%74oken"]) {
    test(`${mode} independently redacts opaque value under ${context}`, () => {
      const value = ["synthetic", "opaque-value"].join("-");
      scanFixture(mode, "Harmless text.", (result) => {
        assert.equal(result.status, 1);
        assert.equal(result.report.findings[0].ruleId, "blocked-private-key-extension");
        assert.equal(result.report.findings[0].file, "[redacted-path]");
        assert.equal(result.output.includes(value), false);
        assert.equal(result.reportText.includes(value), false);
      }, `fixtures/${context}/${value}/fixture.key`);
    });
  }
  test(`${mode} keeps an ordinary finding path usable`, () => {
    scanFixture(mode, "Harmless text.", (result) => {
      assert.equal(result.status, 1);
      assert.equal(result.report.findings[0].file, "resources/12345/fixture.key");
      assert.match(result.output, /resources\/12345\/fixture\.key/);
    }, "resources/12345/fixture.key");
  });
  for (const prefix of ["token=", "%74oken%3D", ""]) {
    test(`${mode} redacts sensitive encoded filename with prefix ${prefix}`, () => {
      const value = prefix ? "synthetic-value" : ["%67", "hp_", "A".repeat(36)].join("");
      scanFixture(mode, "Harmless text.", (result) => {
        assert.equal(result.report.findings[0].file, "[redacted-path]");
        assert.equal(result.output.includes(value), false);
        assert.equal(result.reportText.includes(value), false);
      }, `fixtures/${prefix}${value}/fixture.key`);
    });
  }
}
