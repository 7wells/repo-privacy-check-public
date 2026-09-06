// File purpose: Validate the reusable workflow's scanner pin and failure-aggregation behavior.
// Inputs: The checked-in reusable workflow YAML.
// Outputs: Node test assertions over security-critical workflow invariants.
// Maintenance invariants: Update the reviewed SHA only after its exact runtime commit is validated.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

const workflowPath = path.resolve(__dirname, "../.github/workflows/privacy-check.yml");
const scannerSha = "b65a35428ba5391f1f9bf892946cbde72ddff0da";

test("reusable workflow uses the reviewed v0.3.4 implementation for both active scans", () => {
  const workflow = fs.readFileSync(workflowPath, "utf8");
  const activeScannerUses = [
    ...workflow.matchAll(/^\s*uses:\s+7wells\/repo-privacy-check-public@([0-9a-f]{40})\b/gm),
  ].map((match) => match[1]);

  assert.deepEqual(activeScannerUses, [scannerSha, scannerSha]);
  assert.match(workflow, /fetch-depth:\s*0/);
});

test("reusable workflow runs history after a current failure and aggregates failures", () => {
  const workflow = fs.readFileSync(workflowPath, "utf8");

  assert.match(workflow, /id:\s*current-scan[\s\S]*?continue-on-error:\s*true/);
  assert.match(workflow, /id:\s*history-scan[\s\S]*?if:\s*always\(\)[\s\S]*?continue-on-error:\s*true/);
  assert.match(
    workflow,
    /if:\s*always\(\)\s*&&\s*\(steps\.current-scan\.outcome\s*==\s*'failure'\s*\|\|\s*steps\.history-scan\.outcome\s*==\s*'failure'\)/,
  );
  assert.match(workflow, /run:\s*exit 1/);
});
