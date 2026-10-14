const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { randomUUID } = require('node:crypto');
const assert = require('node:assert/strict');
const exec = promisify(execFile);
const base = ['compose','--env-file','infra/.env.local','-f','infra/compose.yaml','run','--rm','cli','wp','eval-file','/tests/worker-crash.php'];
(async () => {
  for (const boundary of ['order_saved','intention','before_request','after_request','result','projection','event_saved','event_verified','event_projection','mail_before_request','mail_after_request']) {
    const tag = randomUUID();
    try {
      let code;
      try { await exec('docker', [...base, tag, boundary, 'stop']); } catch (error) { code = error.code; }
      assert.equal(code, 73, `Abrupt PHP stop at ${boundary}`);
      const result = await exec('docker', [...base, tag, boundary, 'resume']);
      assert.ok(result.stdout.includes(`PASS: ${boundary}`), result.stdout);
      console.log(result.stdout.trim());
    } finally { await exec('docker', [...base, tag, boundary, 'cleanup']); }
  }
  console.log('PASS: 11 process-stop boundaries; database persisted across independent PHP processes');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
