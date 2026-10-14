const {chromium}=require('playwright');
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const {randomBytes}=require('node:crypto');
const assert=require('node:assert/strict');
const exec=promisify(execFile),tag='cart-'+randomBytes(6).toString('hex'),password='Aa!'+randomBytes(24).toString('hex');
const command=['compose','--env-file','infra/.env.local','-f','infra/compose.yaml','run','--rm','cli','wp','eval-file'];
const fixture=async(mode,...args)=>(await exec('docker',[...command,'/tests/commerce-fixture.php',tag,mode,...args],{timeout:120000,maxBuffer:1024*1024})).stdout.trim();
let stage='server',browser,setup;
(async()=>{
  try {
    const server=await exec('docker',[...command,'/tests/commerce.php'],{timeout:120000,maxBuffer:1024*1024});
    assert.match(server.stdout,/PASS: \d+ commerce server checks/);console.log(server.stdout.trim());
    setup=JSON.parse(await fixture('setup',password));stage='browser';browser=await chromium.launch({headless:true});
    const retail=await browser.newContext(),wholesale=await browser.newContext(),guest=await browser.newContext();
    const r=await retail.newPage(),w=await wholesale.newPage(),g=await guest.newPage();
    const origin=new URL(setup.account).origin;
    const api=(ctx,path,nonce,method='get',data)=>ctx.request[method](origin+'/wp-json'+path,{headers:nonce?{'X-WP-Nonce':nonce}:{},...(data?{data}:{})});
    async function login(page,type){await page.goto(setup.account);const f=page.locator('.woocommerce-form-login');await f.locator('[name=username]').fill(tag+type+'@example.invalid');await f.locator('[name=password]').fill(password);await f.locator('[name=login]').click();await page.waitForSelector('.woocommerce-MyAccount-navigation');}
    async function nonce(ctx,type){const c=(await ctx.cookies()).find(c=>c.name.startsWith('wordpress_logged_in_'));assert.ok(c);return fixture('nonce',type,c.value);}
    stage='guest direct pages';assert.equal((await g.goto(setup.wholesalePage)).status(),403);
    assert.equal((await api(guest,'/suhoput/v1/wholesale/context?context=wholesale')).status(),403);
    await g.goto(origin+'/?add-to-cart='+setup.product+'&context=wholesale');
    stage='public product ignores buyer context';
    assert.equal((await api(guest,'/wc/store/v1/products/'+setup.product+'?context=wholesale')).status(),400);
    const publicProduct=await api(guest,'/wc/store/v1/products/'+setup.product+'?buyer_type=wholesale');assert.equal(publicProduct.status(),200);
    assert.equal((await publicProduct.json()).prices.price,'1300000');assert.ok(!(await publicProduct.text()).includes('1200000'));
    stage='guest cart ignores buyer context';let gs=await api(guest,'/suhoput/v1/commerce/context?context=wholesale');assert.equal(gs.status(),200);assert.match(gs.headers()['cache-control'],/no-store/);
    assert.equal((await gs.json()).context,'retail');assert.equal(Number((await gs.json()).total),13000);
    stage='authenticated cart transition';await w.goto(origin+'/?add-to-cart='+setup.product);await login(w,'wholesale');
    const wn=await nonce(wholesale,'wholesale');let ws=await api(wholesale,'/suhoput/v1/commerce/context',wn);assert.equal(ws.status(),200);
    let wd=await ws.json();assert.equal(wd.context,'wholesale');assert.equal(Number(wd.total),12000);assert.equal(wd.review_required,true);
    assert.equal((await api(wholesale,'/suhoput/v1/commerce/confirm',wn,'post',{token:'forged'})).status(),409);
    assert.equal((await w.goto(setup.cart)).status(),200);
    if(await w.locator('.suhoput-cart-review').count()!==1){const debug=await (await api(wholesale,'/suhoput/v1/commerce/context',wn)).json();throw new Error('Cart review form missing: review='+debug.review_required+' total='+debug.total+' content='+(await w.locator('body').innerText()).slice(0,800));}
    await w.locator('.suhoput-cart-review button').click();
    ws=await api(wholesale,'/suhoput/v1/commerce/context',wn);assert.equal((await ws.json()).review_required,false);
    assert.equal((await w.goto(setup.wholesalePage)).status(),200);assert.match((await wholesale.request.get(setup.wholesalePage)).headers()['cache-control'],/no-store/);
    assert.equal((await api(wholesale,'/SuHoPuT/v1/Wholesale/context',wn)).status(),200);
    stage='native wholesale checkout cannot complete payment';await w.goto(setup.checkout);
    const checkoutNonce=await w.locator('[name="woocommerce-process-checkout-nonce"]').inputValue();
    const beforeCount=await fixture('wholesale-count');
    const native=await wholesale.request.post(origin+'/?wc-ajax=checkout',{form:{'woocommerce-process-checkout-nonce':checkoutNonce,billing_email:tag+'wholesale@example.invalid',billing_first_name:'Local',billing_last_name:'Fixture',billing_country:'RU',billing_city:'Local',billing_address_1:'Fixture',billing_postcode:'364000',billing_phone:'+70000000000',payment_method:'',terms:'1'}});
    const nativeResult=await native.json();assert.equal(nativeResult.result,'failure');assert.match(nativeResult.messages,/Отправка оптовой заявки пока недоступна/);
    assert.equal(await fixture('wholesale-count'),beforeCount);
    await login(r,'retail');const rn=await nonce(retail,'retail');
    assert.equal((await r.goto(setup.wholesalePage)).status(),403);assert.equal((await api(retail,'/suhoput/v1/wholesale/context',rn)).status(),403);
    stage='coupon and Store bypass';const cart=await api(guest,'/wc/store/v1/cart');assert.equal(cart.status(),200);
    const storeNonce=cart.headers().nonce,cartToken=cart.headers()['cart-token'];assert.ok(storeNonce);assert.ok(cartToken);
    assert.equal((await guest.request.post(origin+'/wp-json/wc/store/v1/cart/apply-coupon',{headers:{Nonce:storeNonce},data:{code:'anything'}})).status(),403);
    assert.equal((await retail.request.get(origin+'/wp-json/wc/store/v1/cart',{headers:{'X-WP-Nonce':rn,'Cart-Token':cartToken}})).status(),403);
    stage='batch outer token cannot bypass cookie session';
    const batch=await retail.request.post(origin+'/wp-json/wc/store/v1/batch',{headers:{'X-WP-Nonce':rn,'Cart-Token':cartToken},data:{requests:[{method:'POST',path:'/wc/store/v1/cart/update-customer',body:{billing_address:{first_name:'Token bypass fixture'}}}]}});
    assert.equal(batch.status(),403);
    for(const ctx of [guest,wholesale])for(const path of ['/wc/store/v1/checkout','/WC/Store/checkout/'+setup.wholesale.id]){
      assert.equal((await api(ctx,path,ctx===wholesale?wn:undefined,'post',{context:'retail',payment_method:'anything',id:setup.wholesale.id})).status(),ctx===guest&&path.includes(String(setup.wholesale.id))?404:403);
    }
    stage='wholesale direct payment';assert.equal((await w.goto(setup.wholesale.pay)).status(),403);
    assert.equal((await wholesale.request.post(setup.wholesale.pay,{form:{woocommerce_pay:'1',payment_method:'anything',context:'retail'}})).status(),403);
    assert.equal((await w.goto(setup.wholesale.view)).status(),200);
    stage='revoked rights';await fixture('revoke');assert.equal((await w.goto(setup.cart)).status(),403);
    assert.equal((await w.goto(setup.wholesalePage)).status(),403);assert.equal((await api(wholesale,'/suhoput/v1/wholesale/context',wn)).status(),403);
    assert.equal((await api(wholesale,'/suhoput/v1/orders/'+setup.wholesale.id,wn)).status(),200);assert.equal((await w.goto(setup.wholesale.view)).status(),200);
    ws=await api(wholesale,'/suhoput/v1/commerce/context',wn);wd=await ws.json();assert.equal(wd.context,null);assert.equal(Number(wd.total),0);
    stage='logout and cached responses';await w.goto(setup.account);await w.locator('.woocommerce-MyAccount-navigation-link--customer-logout a').click();
    assert.equal((await api(wholesale,'/suhoput/v1/wholesale/context')).status(),403);
    for(const ctx of [wholesale,retail,guest]){
      const response=await api(ctx,'/wc/store/v1/products/'+setup.product,ctx===retail?rn:undefined);assert.equal(response.status(),200);assert.equal((await response.json()).prices.price,'1300000');
    }
    stage='manager settings and validation';const manager=await browser.newContext(),m=await manager.newPage();await login(m,'manager');
    await m.goto(origin+'/wp-admin/admin.php?page=suhoput-commerce');
    await m.locator('[name="suhoput_guest_limits[actor_rate]"]').fill('6');await m.locator('#submit').click();
    assert.equal(JSON.parse(await fixture('settings')).actor_rate,6);
    await m.locator('[name="suhoput_guest_limits[actor_rate]"]').fill('0');await m.locator('#submit').click();
    assert.equal(JSON.parse(await fixture('settings')).actor_rate,6);
    await retail.request.post(origin+'/wp-admin/options.php',{form:{option_page:'suhoput-commerce',action:'update',_wpnonce:'invalid','suhoput_guest_limits[actor_rate]':'1'}});
    assert.equal(JSON.parse(await fixture('settings')).actor_rate,6);
    await g.goto(setup.cart);assert.equal(await g.locator('.coupon').count(),0);
    stage='guest order and captured simulated mail';assert.equal(await fixture('simulate-checkout',JSON.stringify(await guest.cookies())),'GUEST_CREATED');
    const mail=await fetch('http://127.0.0.1:18881/api/v1/search?query='+encodeURIComponent('to:'+tag+'guest@example.invalid'));
    assert.equal(mail.status,200);const messages=(await mail.json()).messages;assert.ok(messages.some(m=>m.Subject==='Local simulated order'));
    stage='HTTP rate while sharing IP';let denied=0;
    for(let i=0;i<12;i++){const response=await guest.request.post(origin+'/wp-json/wc/store/v1/cart/add-item',{headers:{Nonce:storeNonce},data:{id:0,quantity:1}});if(response.status()===429)denied++;}
    assert.ok(denied>=1);const another=await browser.newContext();await another.request.get(origin+'/');const secondCart=await api(another,'/wc/store/v1/cart');
    const second=await another.request.post(origin+'/wp-json/wc/store/v1/cart/add-item',{headers:{Nonce:secondCart.headers().nonce},data:{id:setup.product,quantity:1}});assert.equal(second.status(),201);
    console.log('PASS: HTTP context, rights, session transitions, price isolation, direct payment, coupons, manager settings, guest rate/shared IP and Mailpit');
    stage='concurrent durable limits';await fixture('rate-policy');
    const rates=await Promise.all(Array.from({length:4},()=>fixture('rate')));assert.equal(rates.filter(x=>x==='WIN').length,2);assert.equal(rates.filter(x=>x==='DENIED').length,2);
    const holds=await Promise.all([fixture('hold','0'),fixture('hold','1')]);assert.equal(holds.filter(x=>x==='WIN').length,1);assert.equal(holds.filter(x=>x==='DENIED').length,1);
    const shared=await Promise.all([2,3,4,5].map(i=>fixture('ip-hold',String(i))));assert.equal(shared.filter(x=>x==='WIN').length,2);assert.equal(shared.filter(x=>x==='DENIED').length,2);
    console.log('PASS: parallel rate cap, one actor slot, two different guests on shared IP; cookie rotation bounded');
  } catch(error){console.error('FAIL: commerce stage '+stage);console.error(error.cmd ? (error.stderr?.match(/RuntimeException: ([^\r\n]+)/)?.[1]||'Fixture command failed (arguments withheld)') : error.message);throw error;}
  finally{
    await browser?.close();
    try{if(setup)await fixture('cleanup');}finally{
      const response=await fetch('http://127.0.0.1:18881/api/v1/search?query='+encodeURIComponent('to:'+tag)+'&limit=500');
      if(response.ok){for(const m of (await response.json()).messages.filter(m=>m.To?.some(t=>t.Address.startsWith(tag)&&t.Address.endsWith('@example.invalid'))))assert.equal((await fetch('http://127.0.0.1:18881/api/v1/messages',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({IDs:[m.ID]})})).status,200);}
    }
  }
})().catch(()=>{process.exitCode=1;});
