const {chromium}=require('playwright');
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const {randomBytes}=require('node:crypto');
const assert=require('node:assert/strict');
const exec=promisify(execFile);
const tag='web-'+randomBytes(6).toString('hex');
const email=tag+'@example.invalid',changed=tag+'-changed@example.invalid';
const password='Aa!'+randomBytes(24).toString('hex'),replacement='Bb!'+randomBytes(24).toString('hex');
const rule='На один email можно зарегистрировать только один аккаунт: розничный или оптовый';
const duplicate='Этот email уже зарегистрирован. Войдите в аккаунт или восстановите пароль';
const fixture=mode=>exec('docker',['compose','--env-file','infra/.env.local','-f','infra/compose.yaml','run','--rm','cli','wp','eval-file','/tests/accounts-browser-fixture.php',tag,mode]);
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function mails(){
  const r=await fetch('http://127.0.0.1:18881/api/v1/search?query='+encodeURIComponent('to:'+tag)+'&limit=100');assert.equal(r.status,200);
  return (await r.json()).messages.filter(m=>m.To?.some(to=>to.Address.startsWith(tag)&&to.Address.endsWith('@example.invalid')));
}
async function mail(subject,to){
  for(let n=0;n<30;n++){
    const found=(await mails()).find(m=>subject.test(m.Subject)&&m.To.some(t=>t.Address===to));
    if(found){const r=await fetch('http://127.0.0.1:18881/api/v1/message/'+found.ID);assert.equal(r.status,200);return r.json();}
    await delay(200);
  }
  throw new Error('Expected local mail missing');
}
(async()=>{
  let browser;
  let activePage;
  const postStatuses=[];
  const postRequests=[];
  let stage='setup';
  try {
    const setup=JSON.parse((await fixture('setup')).stdout.trim());
    browser=await chromium.launch({headless:true});
    for(const width of [390,1440]){
      const p=await browser.newPage({viewport:{width,height:900}});await p.goto(setup.account);
      assert.equal(await p.locator('.suhoput-account-rule').innerText(),rule);
      await p.close();
    }
    stage='registration';
    const page=await browser.newPage();activePage=page;
    page.on('request',r=>{if(r.method()==='POST')postRequests.push(new URL(r.url()).pathname);});
    page.on('response',r=>{if(r.request().method()==='POST')postStatuses.push({path:new URL(r.url()).pathname,status:r.status()});});
    const jsErrors=[];page.on('pageerror',e=>jsErrors.push(e.name));
    await page.goto(setup.account);
    await page.waitForFunction(()=>typeof window.zxcvbn==='function');
    const register=page.locator('form.woocommerce-form-register');
    await register.locator('[name=email]').fill(' '+email.toUpperCase()+' ');
    await register.locator('[name=password]').fill(password);
    await register.locator('[name=password]').press('End');
    await register.locator('[name=password]').press('Tab');
    await register.locator('.woocommerce-password-strength.strong').waitFor();
    await register.locator('[name=register]').click();
    stage='registration dashboard';
    await page.waitForSelector('.woocommerce-MyAccount-navigation',{timeout:10000});
    stage='registration welcome mail';
    const welcome=await mail(/account|welcome/i,email);
    assert.ok(!(welcome.Text+welcome.HTML).includes(password),'No cleartext password sent');
    assert.equal((await mails()).filter(m=>/account|welcome/i.test(m.Subject)&&m.To.some(t=>t.Address===email)).length,1);
    await page.close();
    stage='duplicate and nonce';
    const publicPage=await browser.newPage();await publicPage.goto(setup.account);
    await publicPage.waitForFunction(()=>typeof window.zxcvbn==='function');
    const duplicateForm=publicPage.locator('form.woocommerce-form-register');
    await duplicateForm.locator('[name=email]').fill(email.toUpperCase());await duplicateForm.locator('[name=password]').fill(password);
    await duplicateForm.locator('[name=password]').press('End');
    await duplicateForm.locator('[name=password]').press('Tab');
    await duplicateForm.locator('.woocommerce-password-strength.strong').waitFor();
    await duplicateForm.locator('[name=register]').click();
    await publicPage.waitForSelector('.woocommerce-error');
    assert.ok((await publicPage.locator('.woocommerce-error').innerText()).includes(duplicate));
    assert.equal(await publicPage.locator('.woocommerce-error').getByRole('link',{name:'Вход',exact:true}).count(),1);
    assert.equal(await publicPage.locator('.woocommerce-error').getByRole('link',{name:'Восстановление пароля',exact:true}).count(),1);
    await publicPage.request.post(setup.account,{form:{register:'Register',email:tag+'-nonce@example.invalid',password,'woocommerce-register-nonce':'invalid'}});
    await publicPage.close();
    stage='login';
    const p=await browser.newPage();await p.goto(setup.account);
    activePage=p;
    const login=p.locator('form.woocommerce-form-login');
    await login.locator('[name=username]').fill(' '+email.toUpperCase()+' ');await login.locator('[name=password]').fill('bad-password');await login.locator('[name=login]').click();
    await p.waitForSelector('.woocommerce-error');
    await login.locator('[name=username]').fill(' '+email.toUpperCase()+' ');await login.locator('[name=password]').fill(password);await login.locator('[name=login]').click();
    await p.waitForSelector('.woocommerce-MyAccount-navigation');
    stage='change email conflict';
    await p.goto(setup.account+'edit-account/');
    const edit=p.locator('form.edit-account');
    await edit.locator('[name=account_first_name]').fill('Local');await edit.locator('[name=account_last_name]').fill('Fixture');
    await edit.locator('[name=account_email]').fill(tag+'-other@example.invalid');await edit.locator('[name=save_account_details]').click();
    await p.waitForSelector('.woocommerce-error');
    stage='change email success';
    await edit.locator('[name=account_first_name]').fill('Local');await edit.locator('[name=account_last_name]').fill('Fixture');
    await edit.locator('[name=account_email]').fill(' '+changed.toUpperCase()+' ');await edit.locator('[name=save_account_details]').click();
    await p.waitForSelector('.woocommerce-message');
    assert.equal(await p.locator('[name=account_email]').inputValue(),changed);
    await p.close();
    stage='lost password mail';
    const recovery=await browser.newPage();await recovery.goto(setup.account+'lost-password/');
    activePage=recovery;
    await recovery.locator('[name=user_login]').fill(changed);await recovery.locator('button[type=submit]').click();
    await recovery.waitForURL(/reset-link-sent=true/);
    const reset=await mail(/reset|password/i,changed);
    assert.ok(!(reset.Text+reset.HTML).includes(password));
    const links=[...(reset.HTML||'').matchAll(/href="([^"]+)"/g)].map(m=>m[1].replaceAll('&amp;','&'));
    const link=links.find(h=>{try{const u=new URL(h);return u.hostname==='localhost'&&u.port==='18880'&&u.searchParams.has('key');}catch{return false;}});
    assert.ok(link,'Reset link targets the local shop');
    stage='password reset';
    await recovery.goto(link);await recovery.waitForSelector('[name=password_1]');
    await recovery.waitForFunction(()=>typeof window.zxcvbn==='function');
    await recovery.locator('[name=password_1]').fill(replacement);await recovery.locator('[name=password_2]').fill(replacement);
    await recovery.locator('[name=password_1]').press('End');await recovery.locator('[name=password_2]').focus();
    await recovery.locator('.woocommerce-password-strength.strong').waitFor();
    stage='password reset submit';
    await recovery.locator('button[type=submit]').click();await recovery.waitForURL(/password-reset=true/);
    stage='old password rejected';
    await recovery.goto(setup.account);
    const recoveredLogin=recovery.locator('form.woocommerce-form-login');
    await recoveredLogin.locator('[name=username]').fill(changed);await recoveredLogin.locator('[name=password]').fill(password);await recoveredLogin.locator('[name=login]').click();
    await recovery.waitForSelector('.woocommerce-error');
    stage='new password login';
    await recoveredLogin.locator('[name=username]').fill(changed);await recoveredLogin.locator('[name=password]').fill(replacement);await recoveredLogin.locator('[name=login]').click();
    await recovery.waitForSelector('.woocommerce-MyAccount-navigation');await recovery.close();
    stage='reset replay';
    const replay=await browser.newPage();activePage=replay;await replay.goto(link);assert.equal(await replay.locator('[name=password_1]').count(),0);await replay.close();
    stage='guest checkout';
    const guest=await browser.newPage();await guest.goto('http://localhost:18880/?add-to-cart='+setup.product);await guest.goto(setup.checkout);
    await guest.waitForSelector('form.checkout');assert.equal(await guest.locator('[name=createaccount]').count(),0);assert.equal(await guest.locator('[name=account_password]').count(),0);
    assert.match((await fixture('guest')).stdout,/GUEST_PRESERVED/);await guest.close();
    assert.match((await fixture('verify')).stdout,/BROWSER_VERIFIED/);
    assert.equal(jsErrors.length,0);
    console.log('PASS: account forms at 390/1440px, registration/duplicate/nonce/login/email/reset/replay, local welcome/reset mail, guest checkout form and CRUD order');
  }catch(e){
    if(activePage&&!activePage.isClosed()){
      const notice=await activePage.locator('.woocommerce-error').allTextContents();
      console.error(JSON.stringify({known_account_error:notice.some(t=>t.includes('Не удалось сохранить аккаунт')),duplicate:notice.some(t=>t.includes(duplicate)),error_notices:notice.length}));
      console.error(JSON.stringify({postRequests,postStatuses,invalidFields:await activePage.locator('form input').evaluateAll(nodes=>nodes.filter(n=>!n.validity.valid).map(n=>({name:n.name,typeMismatch:n.validity.typeMismatch,valueMissing:n.validity.valueMissing,patternMismatch:n.validity.patternMismatch})))}));
      await activePage.screenshot({path:'.cache/account-browser-failure.png',fullPage:true});
    }
    console.error('FAIL: account browser stage '+stage+'; error_type='+e.name+'; raw mail/passwords/tokens withheld.');throw new Error('Account browser check failed');
  }
  finally {
    if(browser)await browser.close();
    try { const own=await mails();if(own.length){const r=await fetch('http://127.0.0.1:18881/api/v1/messages',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({IDs:own.map(m=>m.ID)})});assert.equal(r.status,200);} }
    finally { await fixture('cleanup'); }
  }
})().catch(()=>{process.exitCode=1;});
