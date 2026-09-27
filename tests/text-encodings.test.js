// File purpose: Validate private-key markers and shared text decoding in Current and History.
// Inputs: Synthetic byte buffers written to neutral fixture.txt files in temporary Git repositories.
// Outputs: Assertions over classification, metadata-only findings, and JSON reports.
// Security and privacy: Construct sensitive markers in segments; never use real keys or credentials.
// Maintenance invariants: Keep binary samples excluded and the text-size limit byte-based.

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, test } = require("node:test");

const { runCli, testInternals: { classifyTextBuffer } } = require("../scripts/privacy-check.js");
const temporaryRepositories = new Set();
const maxTextBytes = 10 * 1024 * 1024;
const privateMarker = (type = "PRIVATE KEY") => ["-----BEGIN", `${type}-----`].join(" ");
const publicMarker = ["-----BEGIN", "PUBLIC KEY-----"].join(" ");

function utf16Bytes(text, bigEndian, bom) {
  const bytes = Buffer.from(text, "utf16le");
  if (bigEndian) bytes.swap16();
  const prefix = Buffer.from(bigEndian ? [0xfe, 0xff] : [0xff, 0xfe]);
  return bom ? Buffer.concat([prefix, bytes]) : bytes;
}

const representations = [
  ["UTF-8", (text) => Buffer.from(text, "utf8")],
  ["UTF-16LE with BOM", (text) => utf16Bytes(text, false, true)],
  ["UTF-16BE with BOM", (text) => utf16Bytes(text, true, true)],
  ["UTF-16LE without BOM", (text) => utf16Bytes(text, false, false)],
  ["UTF-16BE without BOM", (text) => utf16Bytes(text, true, false)],
];

function scanBytes(bytes, mode) {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), "privacy-text-encoding-"));
  temporaryRepositories.add(target);
  execFileSync("git", ["init", "--quiet"], { cwd: target, stdio: "ignore" });
  fs.writeFileSync(path.join(target, "fixture.txt"), bytes);
  if (mode === "history") {
    execFileSync("git", ["add", "fixture.txt"], { cwd: target, stdio: "ignore" });
    execFileSync("git", [
      "-c", "user.name=Example User", "-c", "user.email=example@example.invalid",
      "commit", "--quiet", "-m", "Add synthetic encoding fixture",
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

function assertFinding(bytes, mode, ruleId, category, line, sensitiveValue) {
  const { status, output, reportText, report } = scanBytes(bytes, mode);
  assert.equal(status, 1);
  assert.equal(report.findingCount, 1);
  assert.equal(report.mode, mode);
  const [finding] = report.findings;
  assert.equal(finding.ruleId, ruleId);
  assert.equal(finding.file, "fixture.txt");
  assert.equal(finding.category, category);
  assert.equal(finding.line, line);
  assert.equal(finding.source, mode);
  assert.ok(output.includes(`${ruleId} fixture.txt${line ? `:${line}` : ""} category=${category}`));
  if (sensitiveValue) {
    assert.equal(output.includes(sensitiveValue), false);
    assert.equal(reportText.includes(sensitiveValue), false);
  }
}

function assertAllowed(bytes, mode) {
  const { status, report } = scanBytes(bytes, mode);
  assert.equal(status, 0);
  assert.equal(report.findingCount, 0);
}

after(() => {
  for (const target of temporaryRepositories) fs.rmSync(target, { recursive: true, force: true });
});

const utf8HeaderCases = [
  ["normal header", `Preamble\n${privateMarker()}\n`, 2],
  ["space-indented header", `Preamble\n  ${privateMarker()}\n`, 2],
  ["tab-indented header", `Preamble\n\t${privateMarker()}\n`, 2],
  ["UTF-8 BOM before header", `\uFEFF${privateMarker()}\n`, 1],
  ["UTF-8 BOM before indentation", `\uFEFF  ${privateMarker()}\n`, 1],
  ["UTF-8 BOM after indentation", `  \uFEFF${privateMarker()}\n`, 1],
  ...["RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PRIVATE KEY BLOCK"]
    .map((type) => [`${type} marker`, privateMarker(type) + "\n", 1]),
];

for (const mode of ["current", "history"]) {
  for (const [name, text, line] of utf8HeaderCases) {
    test(`${mode} detects ${name} without leaking its contents`, () => {
      const header = text.split("\n").find((value) => value.includes("-----BEGIN")).trim();
      assertFinding(Buffer.from(text, "utf8"), mode, "private-key-header", "private-key", line, header);
    });
  }

  for (const [name, encode] of representations) {
    test(`${mode} detects an indented private key in ${name}`, () => {
      assertFinding(encode(`Preamble\n  ${privateMarker()}\n`), mode, "private-key-header", "private-key", 2, privateMarker());
    });
    test(`${mode} allows a public-key marker in ${name}`, () => {
      assertAllowed(encode(publicMarker + "\n"), mode);
    });
    test(`${mode} preserves another content rule in ${name}`, () => {
      const fixtureValue = ["ghp", "A".repeat(40)].join("_");
      assertFinding(encode(`Preamble\n${fixtureValue}\n`), mode, "github-token", "token", 2, fixtureValue);
    });
  }

  for (const [name, text] of [
    ["embedded prose marker", `The following marker is an example: ${privateMarker()}\n`],
    ["incomplete marker", ["-----BEGIN", "PRIVATE KEY"].join(" ") + "\n"],
    ["malformed marker", ["-----BEGIN", "PRIVATE KEY----"].join(" ") + "\n"],
    ["ordinary UTF-8 text", "Normal public text with Unicode: caf\u00e9.\n"],
  ]) {
    test(`${mode} allows ${name}`, () => {
      assertAllowed(Buffer.from(text, "utf8"), mode);
    });
  }
}

for (const [name, bigEndian] of [["LE", false], ["BE", true]]) {
  test(`decodes BOM-marked UTF-16${name} Unicode without changing the input bytes`, () => {
    const text = "R\u00e9sum\u00e9 \u0395\u03bb\u03bb\u03b7\u03bd\u03b9\u03ba\u03ac \ud83d\ude00\n";
    const bytes = utf16Bytes(text, bigEndian, true);
    const original = Buffer.from(bytes);
    assert.deepEqual(classifyTextBuffer(bytes), { kind: "text", content: `\uFEFF${text}` });
    assert.deepEqual(bytes, original);
  });
}

test("preserves ordinary UTF-8 text exactly", () => {
  const text = "Normal public text: caf\u00e9.\n";
  assert.deepEqual(classifyTextBuffer(Buffer.from(text)), { kind: "text", content: text });
});

const binaryCases = [
  ["mixed-parity NUL bytes", Buffer.concat([Buffer.from([0, 1, 2, 0, 255, 3]), Buffer.from(`\n${privateMarker()}\n`)])],
  ["all NUL bytes", Buffer.alloc(64)],
  ["strong LE NUL parity with non-text controls", utf16Bytes(`\u0001${privateMarker()}\n`, false, false)],
  ["strong BE NUL parity with non-text controls", utf16Bytes(`\u0001${privateMarker()}\n`, true, false)],
  ["LE BOM with non-text controls", utf16Bytes(`\u0001${privateMarker()}\n`, false, true)],
  ["BE BOM with non-text controls", utf16Bytes(`\u0001${privateMarker()}\n`, true, true)],
  ["odd-length LE data", Buffer.concat([utf16Bytes(privateMarker() + "\n", false, false), Buffer.from([0])])],
  ["odd-length BE data", Buffer.concat([utf16Bytes(privateMarker() + "\n", true, false), Buffer.from([0])])],
  ["short BOM-less LE sample", utf16Bytes("abc", false, false)],
  ["short BOM-less BE sample", utf16Bytes("abc", true, false)],
];

for (const [name, bytes] of binaryCases) {
  test(`classifies ${name} as binary`, () => {
    assert.deepEqual(classifyTextBuffer(bytes), { kind: "binary" });
  });
  for (const mode of ["current", "history"]) {
    test(`${mode} skips ${name} without creating a content finding`, () => {
      assertAllowed(bytes, mode);
    });
  }
}

for (const mode of ["current", "history"]) {
  for (const [name, encode] of representations) {
    test(`${mode} preserves the byte-based oversized policy for ${name}`, () => {
      const characterCount = name === "UTF-8" ? maxTextBytes + 1 : maxTextBytes / 2 + 1;
      const bytes = encode("a".repeat(characterCount));
      assert.ok(bytes.length > maxTextBytes);
      assert.deepEqual(classifyTextBuffer(bytes), { kind: "too-large" });
      assertFinding(bytes, mode, "oversized-text-file", "scan-error", null);
    });
  }
}
