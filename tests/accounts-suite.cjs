const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const exec=promisify(execFile);
const compose=['compose','--env-file','infra/.env.local','-f','infra/compose.yaml','run','--rm','cli','wp','eval-file'];
async function run(command,args){
  const {stdout}=await exec(command,args,{timeout:180000,maxBuffer:1024*1024});
  const lines=stdout.trim().split(/\r?\n/);
  if(!lines.length||lines.some(line=>!line.startsWith('PASS: ')))throw new Error('Unexpected check output');
  console.log(lines.join('\n'));
}
(async()=>{
  await run('docker',[...compose,'/tests/accounts.php']);
  for(const mode of ['password','crud','disconnect-insert','disconnect-update','disconnect-complete','disconnect-commit','form']){
    await run('docker',[...compose,'/tests/accounts-failures.php',mode]);
  }
  await run(process.execPath,['tests/accounts-concurrency.cjs']);
  await run(process.execPath,['tests/accounts-browser.cjs']);
})().catch(()=>{console.error('FAIL: local account suite; inspect the failed scenario. Raw mail/passwords/tokens withheld.');process.exitCode=1;});
