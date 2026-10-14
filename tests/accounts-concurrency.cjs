const {execFile,spawn}=require('node:child_process');
const {promisify}=require('node:util');
const {randomBytes}=require('node:crypto');
const assert=require('node:assert/strict');
const exec=promisify(execFile);
const base=['compose','--env-file','infra/.env.local','-f','infra/compose.yaml'];
const run=(tag,scenario,mode)=>exec('docker',[...base,'run','--rm','cli','wp','eval-file','/tests/accounts-race.php',tag,scenario,String(mode)],{timeout:60000});
(async()=>{
  for(const scenario of ['register','update','mixed','crash']) {
    const tag='race-'+randomBytes(6).toString('hex');
    const container='suhoput-account-'+tag;
    try {
      await run(tag,scenario,'setup');
      if(scenario!=='crash') {
        const results=await Promise.all([run(tag,scenario,1),run(tag,scenario,2)]);
        assert.equal(results.filter(r=>r.stdout.includes('RACE_WIN')).length,1);
        assert.equal(results.filter(r=>r.stdout.includes('RACE_LOSE')).length,1);
        assert.match((await run(tag,scenario,'verify')).stdout,/VERIFIED/);
      } else {
        const child=spawn('docker',[...base,'run','--rm','--name',container,'cli','wp','eval-file','/tests/accounts-race.php',tag,scenario,'1']);
        const closed=new Promise(resolve=>child.on('close',resolve));
        await new Promise((resolve,reject)=>{
          const timer=setTimeout(()=>reject(new Error('Claim barrier timeout')),30000);
          let out=''; child.stdout.on('data',b=>{out+=b.toString(); if(out.includes('CLAIM_READY')){clearTimeout(timer);resolve();}});
          child.on('error',reject); child.on('close',()=>{clearTimeout(timer);reject(new Error('Claim process ended early'));});
        });
        await exec('docker',['kill','--signal','KILL',container]);
        await closed;
        assert.match((await run(tag,scenario,'verify_crash')).stdout,/VERIFIED/);
        assert.match((await run(tag,scenario,2)).stdout,/RACE_WIN/);
        assert.match((await run(tag,scenario,'verify')).stdout,/VERIFIED/);
      }
      console.log('PASS: account '+scenario+' concurrency/recovery');
    } finally {
      if(scenario==='crash') await exec('docker',['rm','-f',container]).catch(()=>{});
      await run(tag,scenario,'cleanup');
    }
  }
})().catch(()=>{console.error('FAIL: account concurrency; raw outputs withheld.');process.exitCode=1;});
