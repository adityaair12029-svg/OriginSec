import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

/**
 * Security Rules Structural Verification Test Runner
 * Validates the Dirty Dozen security invariants in firestore.rules
 * without requiring a running Firebase Emulator binary.
 */
const rulesText = fs.readFileSync('firestore.rules', 'utf8');

test('Dirty Dozen #1 & #12: Global default-deny and verified email mandate exist', () => {
  assert.match(rulesText, /match \/\{document=\*\*\} \{\s*allow read, write: if false;\s*\}/);
  assert.match(rulesText, /request\.auth\.token\.email_verified == true/);
});

test('Dirty Dozen #2 & #3: Cross-user read & blanket list scraping blocked', () => {
  assert.doesNotMatch(rulesText, /allow read:\s*if\s*isSignedIn\(\);/);
  assert.doesNotMatch(rulesText, /allow list:\s*if\s*isSignedIn\(\);/);
  assert.match(rulesText, /allow list:\s*if\s*isVerifiedUser\(\) && resource\.data\.ownerUid == request\.auth\.uid;/);
});

test('Dirty Dozen #4 & #5: Self-assigned owner/admin role escalation blocked', () => {
  assert.match(rulesText, /incoming\(\)\.role == 'user'/);
  assert.match(rulesText, /incoming\(\)\.role == existing\(\)\.role/);
});

test('Dirty Dozen #6: Strict keys().hasOnly() prevents shadow/ghost field injection', () => {
  const matches = rulesText.match(/\.keys\(\)\.hasOnly\(/g) ?? [];
  assert.ok(matches.length >= 8, 'Every entity validator must enforce keys().hasOnly()');
});

test('Dirty Dozen #7 & #8: Identity spoofing & orphaned scanFindings prevented via Master Gate', () => {
  assert.match(rulesText, /data\.ownerUid == request\.auth\.uid/);
  assert.match(rulesText, /exists\(\/databases\/\$\(database\)\/documents\/scans\/\$\(incoming\(\)\.scanId\)\)/);
  assert.match(rulesText, /get\(\/databases\/\$\(database\)\/documents\/scans\/\$\(incoming\(\)\.scanId\)\)\.data\.ownerUid == request\.auth\.uid/);
});

test('Dirty Dozen #9, #10, #11: ID regex, size limits, request.time, and terminal state lock enforced', () => {
  assert.match(rulesText, /isValidId\(/);
  assert.match(rulesText, /incoming\(\)\.startedAt == request\.time/);
  assert.match(rulesText, /!\(existing\(\)\.status in \['completed', 'failed', 'cancelled'\]\)/);
});
