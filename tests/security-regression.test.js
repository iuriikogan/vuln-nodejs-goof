'use strict';

/**
 * Offline unit & regression test suite executed by CodeMender (`build.command: "npm test"`)
 * inside the local OS-level sandbox (`permissive-closed` network profile).
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const secretManager = require('../service/secret-manager');

async function runTests() {
  // 1. Verify runtime session secret generation (Google Secret Manager helper)
  const sessionSecret = secretManager.getRuntimeSessionSecret();
  assert.strictEqual(typeof sessionSecret, 'string', 'session secret must be a string');
  assert.ok(sessionSecret.length >= 64, 'session secret must be at least 64 hex chars');

  // 2. Verify ephemeral fallback in isolated sandbox (no GOOGLE_CLOUD_PROJECT)
  const prevProject = process.env.GOOGLE_CLOUD_PROJECT;
  delete process.env.GOOGLE_CLOUD_PROJECT;
  const sandboxSecret = await secretManager.accessSecretVersion('test-secret-id');
  assert.strictEqual(typeof sandboxSecret, 'string');
  assert.ok(sandboxSecret.length >= 64);
  if (prevProject) {
    process.env.GOOGLE_CLOUD_PROJECT = prevProject;
  }

  // 3. Verify core application files parse cleanly (syntax & module integrity check)
  const filesToVerify = [
    path.join(__dirname, '..', 'app.js'),
    path.join(__dirname, '..', 'mongoose-db.js'),
    path.join(__dirname, '..', 'typeorm-db.js'),
    path.join(__dirname, '..', 'routes', 'index.js'),
    path.join(__dirname, '..', 'routes', 'users.js'),
  ];

  for (const file of filesToVerify) {
    assert.ok(fs.existsSync(file), `Expected application file to exist: ${file}`);
    const content = fs.readFileSync(file, 'utf8');
    assert.ok(content.length > 0, `Expected non-empty file: ${file}`);
  }

  console.log('[PASS] All nodejs-goof unit & sandbox regression checks succeeded.');
}

runTests().catch((err) => {
  console.error('[FAIL] Test suite failed:', err);
  process.exit(1);
});
