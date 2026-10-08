const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const assert = require('node:assert/strict');
const exec = promisify(execFile);
const base = ['compose','--env-file','infra/.env.local','-f','infra/compose.yaml'];
(async () => {
  const since = new Date().toISOString();
  await exec('docker', [...base,'--profile','queue','up','-d','scheduler']);
  const deadline = Date.now()+145000;
  while (Date.now()<deadline) {
    const { stdout } = await exec('docker', [...base,'logs','--timestamps','--since',since,'scheduler']);
    const times = stdout.split('\n').filter(line=>line.includes('Success: Suhoput system queue completed.'))
      .map(line=>Date.parse(line.match(/\d{4}-\d\d-\d\dT\S+/)[0]));
    if (times.length>=2) {
      const gap = (times[1]-times[0])/1000;
      assert.ok(gap>=57 && gap<=63, `System minute interval was ${gap}s`);
      console.log(`PASS: two OS-driven ticks without HTTP: ${new Date(times[0]).toISOString()}, ${new Date(times[1]).toISOString()} (${gap.toFixed(2)}s)`);
      return;
    }
    await new Promise(resolve=>setTimeout(resolve,5000));
  }
  throw new Error('Two system minute ticks did not complete within 145 seconds');
})().catch(error=>{ console.error(error.message); process.exitCode=1; });
