const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const { randomUUID } = require('node:crypto');
const assert = require('node:assert/strict');
const exec = promisify(execFile);
const tag = randomUUID();
const base = ['compose','--env-file','infra/.env.local','-f','infra/compose.yaml','run','--rm','cli','wp','eval-file','/tests/queue-lock.php',tag];
(async () => {
  try {
    await exec('docker', [...base,'setup']);
    for (const [holdMode, checkMode] of [['hold','live'],['tick_hold','tick_live']]) {
    const holder = spawn('docker', [...base,holdMode]);
    let output='';
    const finished = new Promise((resolve,reject)=>{ holder.once('exit',code=>code===0 ? resolve() : reject(new Error('Holder failed'))); holder.once('error',reject); });
    await new Promise((resolve,reject)=>{ holder.stdout.on('data',chunk=>{ output+=chunk; if(output.includes('LOCKED')) resolve(); }); holder.once('error',reject); holder.once('exit',()=>{ if(!output.includes('LOCKED')) reject(new Error('No connection lock acquired')); }); });
    const live = await exec('docker', [...base,checkMode]); assert.ok(live.stdout.includes('PASS:')); console.log(live.stdout.trim());
    await finished;
    if (checkMode === 'live') { const dead = await exec('docker', [...base,'dead']); assert.ok(dead.stdout.includes('PASS: released')); console.log(dead.stdout.trim()); }
    }
    for (const mode of ['periodic_fail','periodic_resume']) { const result=await exec('docker',[...base,mode]); assert.ok(result.stdout.includes('PASS:')); console.log(result.stdout.trim()); }
  } finally { await exec('docker', [...base,'cleanup']); }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
