const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { randomUUID } = require('node:crypto');
const assert = require('node:assert/strict');
const exec = promisify(execFile);
const id = randomUUID();
const args = ['compose','--env-file','infra/.env.local','-f','infra/compose.yaml','run','--rm','cli','wp','eval-file','/tests/schema-race.php',id];
(async () => {
  try {
    const results = await Promise.all([exec('docker', [...args, '1']), exec('docker', [...args, '2'])]);
    assert.equal(results.filter(r=>r.stdout.includes('RACE_WIN')).length, 1);
    assert.equal(results.filter(r=>r.stdout.includes('RACE_LOSE')).length, 1);
    console.log('PASS: two concurrent workers, one unique external mapping');
  } finally { await exec('docker', [...args, 'cleanup']); }
})().catch(() => { console.error('FAIL: schema concurrency check.'); process.exitCode = 1; });
