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

function credentialUrl(scheme, username, password, resource = "/") {
  return [scheme, "://", username, ":", password, "@example.org", resource].join("");
}

function queryUrl(...parameters) {
  return ["https://example.org/resource?", parameters.join("&")].join("");
}

function scanUrlFixture(url, mode) {
  const target = makeTempRepo();
  const content = `${url}\n`;
  if (mode === "history") {
    commitReadme(target, content, "Add one synthetic URL fixture");
  } else {
    fs.writeFileSync(path.join(target, "README.md"), content);
  }
  return runScanner(["--mode", mode, target]);
}

function assertUrlFinding(url, mode, ruleId) {
  const result = scanUrlFixture(url, mode);
  assert.equal(result.status, 1, result.output);
  assert.match(result.output, new RegExp(`${ruleId} README\\.md:1 category=`));
  assert.equal(result.output.includes(url), false);
}

function assertUrlAllowed(url, mode, ruleId) {
  const result = scanUrlFixture(url, mode);
  assert.equal(result.status, 0, result.output);
  assert.doesNotMatch(result.output, new RegExp(ruleId));
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

const credentialUrlFindings = [
  {
    name: "literal HTTP credentials",
    url: credentialUrl("https", ["synthetic", "user"].join("-"), ["synthetic", "pass"].join("-")),
  },
  {
    name: "literal PostgreSQL credentials",
    url: credentialUrl("postgresql", ["synthetic", "user"].join("-"), ["synthetic", "pass"].join("-"), "/database"),
  },
  {
    name: "a literal username and dynamic password",
    url: credentialUrl("https", ["synthetic", "user"].join("-"), ["$", "PASSWORD"].join("")),
  },
  {
    name: "a dynamic username and literal password",
    url: credentialUrl("https", ["$", "{USER}"].join(""), ["synthetic", "pass"].join("-")),
  },
];

for (const mode of ["current", "history"]) {
  for (const { name, url } of credentialUrlFindings) {
    test(`${mode} scan reports ${name} as credential-url`, () => {
      assertUrlFinding(url, mode, "credential-url");
    });
  }
}

const credentialUrlAllowances = [
  {
    name: "fully dynamic $VAR userinfo",
    url: credentialUrl("https", ["$", "USER"].join(""), ["$", "PASSWORD"].join("")),
  },
  {
    name: "fully dynamic braced userinfo",
    url: credentialUrl("https", ["$", "{USER}"].join(""), ["$", "{PASSWORD}"].join("")),
  },
  {
    name: "generic example and placeholder userinfo",
    url: credentialUrl("https", ["example", "-user"].join(""), ["placeholder", "-password"].join("")),
  },
  { name: "a URL without userinfo", url: ["https://", "example.org/resource"].join("") },
  { name: "userinfo without a password", url: ["https://", "synthetic-user", "@example.org/"].join("") },
];

for (const mode of ["current", "history"]) {
  for (const { name, url } of credentialUrlAllowances) {
    test(`${mode} scan allows ${name} without credential-url`, () => {
      assertUrlAllowed(url, mode, "credential-url");
    });
  }
}

const sensitiveQueryFindings = [
  { name: "lat", url: queryUrl("lat=12.3456") },
  { name: "lon", url: queryUrl("lon=-45.6789") },
  { name: "latitude", url: queryUrl("latitude=12.3456") },
  { name: "longitude", url: queryUrl("longitude=-45.6789") },
  { name: "a personal user value", url: queryUrl(["user=", "local-person"].join("")) },
  { name: "a personal username value", url: queryUrl(["username=", "local-person"].join("")) },
];

for (const mode of ["current", "history"]) {
  for (const { name, url } of sensitiveQueryFindings) {
    test(`${mode} scan reports ${name} as url-with-query`, () => {
      assertUrlFinding(url, mode, "url-with-query");
    });
  }
}

const sensitiveQueryAllowances = [
  { name: "the public user value all", url: queryUrl("user=all") },
  { name: "a dynamic lat value", url: queryUrl(["lat=", "$", "{LAT}"].join("")) },
  { name: "a dynamic lon value", url: queryUrl(["lon=", "$", "LON"].join("")) },
  { name: "a placeholder lat value", url: queryUrl("lat=placeholder") },
  { name: "an example lon value", url: queryUrl("lon=example-coordinate") },
];

for (const mode of ["current", "history"]) {
  for (const { name, url } of sensitiveQueryAllowances) {
    test(`${mode} scan allows ${name} without url-with-query`, () => {
      assertUrlAllowed(url, mode, "url-with-query");
    });
  }
}

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
