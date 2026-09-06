// File purpose: Validate sensitive URL-query detection, parsing boundaries, and output redaction.
// Inputs: Synthetic URLs and temporary repositories.
// Outputs: Node test assertions over metadata-only findings.
// Security and privacy: Query values are synthetic and must never represent real endpoints or credentials.

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, test } = require("node:test");

const { runCli, testInternals } = require("../scripts/privacy-check.js");
const { matchesSensitiveUrlQuery } = testInternals;

const temporaryRepositories = new Set();

function makeTempRepo() {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), "repo-privacy-check-url-"));
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

function sensitiveLiteralUrl() {
  return ["https://example.invalid/callback?", "to", "ken=", "literal-test-value"].join("");
}

function sensitivePlaceholderUrl() {
  return ["https://example.invalid/callback?", "token=", "$", "{TOKEN}"].join("");
}

after(() => {
  for (const target of temporaryRepositories) {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test("allows ordinary public query URLs and runtime query placeholders", () => {
  assert.equal(
    matchesSensitiveUrlQuery("https://docs.example.invalid/page?highlight=dashboard_import"),
    false,
  );
  assert.equal(
    matchesSensitiveUrlQuery("https://maps.example.invalid/view?lang=de&scale=1000&layer=public"),
    false,
  );
  assert.equal(matchesSensitiveUrlQuery(sensitivePlaceholderUrl()), false);
  assert.equal(
    matchesSensitiveUrlQuery("https://geo.example.invalid/reverse?lat=${lat}&longitude=${lon}"),
    false,
  );
});

test("detects literal sensitive and personal query values", () => {
  assert.equal(matchesSensitiveUrlQuery(sensitiveLiteralUrl()), true);

  const personalUrl = ["https://example.invalid/profile?", "user", "name=", "local-person"].join("");
  assert.equal(matchesSensitiveUrlQuery(personalUrl), true);
});

test("history scan allows deleted ordinary public query URLs", () => {
  const target = makeTempRepo();
  const publicUrl = "https://docs.example.invalid/page?highlight=dashboard_import";

  commitReadme(target, `${publicUrl}\n`, "Add public documentation link");
  commitReadme(target, "Documentation moved.\n", "Replace documentation link");

  const result = runScanner(["--mode", "history", target]);
  assert.equal(result.status, 0);
});

test("history scan still detects deleted literal sensitive query values without printing them", () => {
  const target = makeTempRepo();
  const sensitiveUrl = sensitiveLiteralUrl();

  commitReadme(target, `${sensitiveUrl}\n`, "Add query value");
  commitReadme(target, "Use an environment-backed value instead.\n", "Remove query value");

  const result = runScanner(["--mode", "history", target]);
  assert.equal(result.status, 1);
  assert.match(result.output, /url-with-query README\.md:1 category=url-query/);
  assert.equal(result.output.includes(sensitiveUrl), false);
});
