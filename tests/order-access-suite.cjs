const {chromium}=require('playwright');
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const {randomBytes}=require('node:crypto');
const assert=require('node:assert/strict');
const exec=promisify(execFile);
const tag='orders-'+randomBytes(6).toString('hex'),password='Aa!'+randomBytes(24).toString('hex');
const email=tag+'one@example.invalid';
const compose=['compose','--env-file','infra/.env.local','-f','infra/compose.yaml','run','--rm','cli','wp','eval-file'];
const fixture=async(mode,...args)=>(await exec('docker',[...compose,'/tests/order-access-fixture.php',tag,mode,...args],{timeout:120000,maxBuffer:1024*1024})).stdout.trim();
const delay=ms=>new Promise(r=>setTimeout(r,ms));
let stage='server',serverTag;
async function messages(prefix=tag){
  const r=await fetch('http://127.0.0.1:18881/api/v1/search?query='+encodeURIComponent('to:'+prefix)+'&limit=500');assert.equal(r.status,200);
  return (await r.json()).messages.filter(m=>m.To?.some(t=>t.Address.startsWith(prefix)&&t.Address.endsWith('@example.invalid')));
}
async function cleanupMail(prefix=tag){for(const m of await messages(prefix)){assert.equal((await fetch('http://127.0.0.1:18881/api/v1/messages',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({IDs:[m.ID]})})).status,200);}}
async function proofLink(before){
  for(let i=0;i<30;i++){
    const m=(await messages()).find(m=>!before.includes(m.ID)&&m.Subject==='Подтверждение доступа к заказу Suhoput');
    if(m){const mail=await (await fetch('http://127.0.0.1:18881/api/v1/message/'+m.ID)).json();const link=mail.Text.match(/http[^\s]+suhoput_token=[a-f0-9]{64}[^\s]*/)?.[0];assert.ok(link);return link;}
    await delay(200);
  }
  throw new Error('Local proof mail missing');
}
(async()=>{
  let browser;
  try {
    const server=(await exec('docker',[...compose,'/tests/order-access.php'],{timeout:120000,maxBuffer:1024*1024})).stdout.trim();
    assert.match(server,/^PASS: \d+ order ownership and proof checks; fixture=/);serverTag=server.match(/fixture=(history-[a-f0-9]{8})/)[1];console.log(server.split('; fixture=')[0]);
    stage='fixture';const setup=JSON.parse(await fixture('setup',password)),o=setup.orders;
    stage='atomic one-use';const cookie=randomBytes(32).toString('hex');
    for(const purpose of ['view','claim']){
      const {token}=JSON.parse(await fixture('race-setup',cookie,purpose));
      const results=await Promise.all([fixture('race-consume',cookie,token,purpose),fixture('race-consume',cookie,token,purpose)]);
      assert.equal(results.filter(r=>r==='WIN').length,1);assert.equal(results.filter(r=>r==='DENIED').length,1);
      assert.equal(await fixture('race-consume',cookie,token,purpose),'DENIED');
    }
    console.log('PASS: parallel guest view and claim consume exactly once');
    stage='browser';browser=await chromium.launch({headless:true});
    const owner=await browser.newContext(),attacker=await browser.newContext(),guest=await browser.newContext();
    const p=await owner.newPage(),a=await attacker.newPage(),g=await guest.newPage();
    async function login(page,suffix){await page.goto(setup.account);const f=page.locator('form.woocommerce-form-login');await f.locator('[name=username]').fill(tag+suffix+'@example.invalid');await f.locator('[name=password]').fill(password);await f.locator('[name=login]').click();await page.waitForSelector('.woocommerce-MyAccount-navigation');}
    async function nonce(context,suffix){const cookies=await context.cookies();const c=cookies.find(c=>c.name.startsWith('wordpress_logged_in_'));assert.ok(c);return fixture('rest-nonce',suffix,c.value);}
    await login(p,'one');await login(a,'two');
    const n=await nonce(owner,'one'),an=await nonce(attacker,'two');
    const api=(context,path,token)=>context.request.get(new URL(setup.account).origin+'/wp-json'+path,{headers:token?{'X-WP-Nonce':token}:{}});
    stage='all-state history';await p.goto(setup.account+'orders/');
    const links=await p.locator('.woocommerce-orders-table a.woocommerce-button.view').evaluateAll(xs=>xs.map(x=>x.href));
    for(const [name,order] of Object.entries(o)){
      stage='history '+name;
      if(name==='own'||name==='race'||name.startsWith('state-'))assert.ok(links.includes(order.view));
      else assert.ok(!links.includes(order.view));
    }
    stage='authenticated API history';const list=await api(owner,'/suhoput/v1/orders',n);assert.equal(list.status(),200);assert.match(list.headers()['cache-control'],/no-store/);
    assert.ok(!(await list.text()).includes('private-external'));
    stage='direct links and APIs';
    for(const name of ['foreign','manual']){
      assert.equal((await p.goto(o[name].view)).status(),404);
      assert.equal((await p.goto(o[name].received)).status(),404);
      assert.equal((await p.goto(o[name].pay)).status(),404);
      assert.equal((await api(owner,'/suhoput/v1/orders/'+o[name].id,n)).status(),404);
      assert.equal((await api(owner,'/wc/store/v1/order/'+o[name].id+'?key='+o[name].key+'&billing_email='+email,n)).status(),404);
    }
    assert.equal((await api(attacker,'/suhoput/v1/orders/'+o.own.id,an)).status(),404);
    assert.equal((await api(owner,'/suhoput/v1/orders/'+o.own.id,n)).status(),200);
    assert.equal((await api(owner,'/wc/store/v1/order/'+o.own.id,n)).status(),200);
    assert.equal((await api(owner,'/wc/store/v1/order/'+o.own.id+'?id='+o.guest.id+'&key='+o.guest.key+'&billing_email='+email,n)).status(),404);
    assert.equal((await owner.request.post(new URL(setup.account).origin+'/wp-json/wc/store/v1/checkout/'+o.own.id,{headers:{'X-WP-Nonce':n},data:{id:o.guest.id,key:o.guest.key,billing_email:email}})).status(),404);
    assert.equal((await api(owner,'/wc/v3/orders',n)).status(),404);
    assert.equal((await p.goto(o.own.view)).status(),200);
    for(const url of [o.guest.received,o.guest.pay,o.own.received])assert.equal((await g.goto(url)).status(),404);
    assert.equal((await api(guest,'/wc/store/v1/order/'+o.guest.id+'?key='+o.guest.key+'&billing_email='+email)).status(),404);
    for(const path of ['/WC/Store/v1/Order/','/wc/store/order/'])assert.equal((await api(guest,path+o.guest.id+'?key='+o.guest.key+'&billing_email='+email)).status(),404);
    for(const path of ['/WC/Store/v1/Checkout/','/wc/store/checkout/'])assert.equal((await guest.request.post(new URL(setup.account).origin+'/wp-json'+path+o.guest.id,{data:{key:o.guest.key,billing_email:email}})).status(),404);
    const alias=await api(owner,'/SuHoPuT/v1/Orders/'+o.own.id,n);assert.equal(alias.status(),200);assert.match(alias.headers()['cache-control'],/no-store/);
    assert.equal((await api(guest,'/suhoput/v1/orders')).status(),404);
    stage='typed email tracking';await g.goto(setup.tracking);
    assert.equal(await g.locator('.suhoput-order-request').count(),1);assert.ok(!(await g.locator('body').innerText()).includes('Private item guest'));
    stage='guest challenge and nonce';await g.goto(setup.account);
    const before=(await messages()).map(m=>m.ID);
    await g.request.post(setup.account,{form:{suhoput_order_action:'request',suhoput_order_id:String(o.guest.id),suhoput_email:email,suhoput_purpose:'view',suhoput_order_nonce:'invalid'}});
    assert.deepEqual((await messages()).map(m=>m.ID),before);
    async function requestProof(page,purpose){await page.goto(setup.account);const before=(await messages()).map(m=>m.ID);const form=page.locator('.suhoput-order-request');await form.locator('[name=suhoput_order_id]').fill(String(o.guest.id));await form.locator('[name=suhoput_email]').fill(email);await form.locator('[name=suhoput_purpose]').selectOption(purpose);await form.locator('button').click();return proofLink(before);}
    const view=await requestProof(g,'view');
    stage='email scanner GET';await g.goto(view);
    assert.match((await g.request.get(view)).headers()['referrer-policy'],/no-referrer/);
    assert.equal((await api(guest,'/suhoput/v1/orders/'+o.guest.id)).status(),404);
    stage='other browser proof';await a.goto(view);await a.locator('.suhoput-order-confirm button').click();await a.waitForSelector('.woocommerce-error');
    assert.equal((await api(attacker,'/suhoput/v1/orders/'+o.guest.id,an)).status(),404);
    stage='guest confirm';await g.locator('.suhoput-order-confirm button').click();await g.waitForSelector('.suhoput-proven-order');
    assert.ok((await g.locator('body').innerText()).includes('Private item guest'));
    assert.equal((await api(guest,'/suhoput/v1/orders/'+o.guest.id)).status(),200);
    assert.equal((await api(guest,'/wc/store/v1/order/'+o.guest.id+'?key='+o.guest.key+'&billing_email='+email)).status(),200);
    assert.equal((await api(guest,'/suhoput/v1/orders/'+o.own.id)).status(),404);
    stage='replay';await g.goto(view);await g.locator('.suhoput-order-confirm button').click();await g.waitForSelector('.woocommerce-error');
    // The resend throttle is verified by server tests; advance this isolated row only.
    await fixture('advance-guest');
    stage='claim requires fresh mail';const claim=await requestProof(p,'claim');await p.goto(claim);await p.locator('.suhoput-order-confirm button').click();await p.waitForURL(o.guest.view);
    assert.equal((await api(owner,'/suhoput/v1/orders/'+o.guest.id,n)).status(),200);
    assert.equal((await api(guest,'/suhoput/v1/orders/'+o.guest.id)).status(),404);
    assert.equal((await api(attacker,'/suhoput/v1/orders/'+o.guest.id,an)).status(),404);
    assert.equal(await fixture('verify'),'VERIFIED');
    console.log('PASS: browser own/all-state/disabled wholesale history, direct links, REST/Store API, Mailpit, nonce, scanner GET, ID isolation and replay');
  } finally {
    await browser?.close();
    assert.equal(await fixture('cleanup'),'CLEANUP');
    await cleanupMail();if(serverTag)await cleanupMail(serverTag);
  }
})().catch(e=>{const location=e.stack?.match(/order-access-suite\.cjs:\d+:\d+/)?.[0]||e.name;console.error('FAIL: order access '+stage+' ('+location+'); raw credentials/mail/tokens withheld.');process.exitCode=1;});
