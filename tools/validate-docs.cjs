const fs=require('fs'),path=require('path'),crypto=require('crypto');
const files=['AGENTS.md','README.md',...fs.readdirSync('docs').filter(n=>n.endsWith('.md')).map(n=>'docs/'+n)];
const assert=(ok,msg)=>{if(!ok)throw Error(msg)};
const text=Object.fromEntries(files.map(f=>{assert(fs.existsSync(f),'Нет '+f);return [f,fs.readFileSync(f,'utf8')]}));
const spec=text['docs/SPEC.md'], bytes=fs.readFileSync('docs/SPEC.md');
const hash=spec.match(/SHA-256 исходного файла: `([A-F0-9]{64})`/)[1];
const length=Number(spec.match(/Размер исходного блока: `(\d+)` байт/)[1]);
assert(crypto.createHash('sha256').update(bytes.subarray(0,length)).digest('hex').toUpperCase()===hash,'Исходный блок SPEC изменён');
const req=[...spec.matchAll(/<a id="req-(\d+)">/g)].map(m=>'REQ-'+m[1]);
const covered=[...text['docs/ACCEPTANCE.md'].matchAll(/^\| \[(REQ-\d+)\]\(SPEC\.md#req-\d+\) \|/gm)].map(m=>m[1]);
assert(req.length>0&&new Set(req).size===req.length,'REQ отсутствуют/повторяются');
assert(covered.length===req.length&&new Set(covered).size===covered.length&&req.every(r=>covered.includes(r)),'Покрытие REQ неполное');
const indexed=[...spec.matchAll(/^\| <a id="req-\d+"><\/a>REQ-\d+ \| (\d+) \|/gm)].map(m=>Number(m[1]));
const original=bytes.subarray(0,length).toString('utf8').split(/\r?\n/),expected=[];
let insideCode=false;
for(let i=0;i<original.length;i++){const s=original[i];if(s.startsWith(String.fromCharCode(96).repeat(3))){insideCode=!insideCode;continue}if(insideCode||!s.trim()||/^#{1,6} /.test(s)||/^Дата:/.test(s)||/^- \[/.test(s)||/^\|\s*:?-{3,}/.test(s)||s.startsWith('|')&&/^\|\s*:?-{3,}/.test(original[i+1]||''))continue;expected.push(i+1)}
assert(indexed.length===expected.length&&new Set(indexed).size===indexed.length&&expected.every(n=>indexed.includes(n)),'Исходный фрагмент не покрыт');
const checks=[...text['docs/ACCEPTANCE.md'].matchAll(/<a id="chk-\d+"><\/a>(CHK-\d+):/g)].map(m=>m[1]);
assert(checks.length===req.length&&new Set(checks).size===checks.length,'CHK отсутствуют/повторяются');
const acceptanceBlock=bytes.subarray(0,length).toString('utf8').split('## Критерии приёмки')[1].split('## Входные данные и действия владельца')[0];
const criteria=acceptanceBlock.split(/\r?\n/).filter(s=>s.startsWith('| ')&&!/^\| (Проверка|---)/.test(s)).length;
assert(criteria===62,'Число исходных критериев изменилось');
const slug=s=>s.toLowerCase().replace(/[^\p{L}\p{N}_\- ]/gu,'').replace(/ /g,'-');
const visible=s=>{let fence=false;return s.split(/\r?\n/).filter(l=>{if(/^```/.test(l)){fence=!fence;return false}return !fence}).join('\n')};
const anchors=s=>{const counts=new Map(),set=new Set();for(const m of visible(s).matchAll(/^#{1,6} (.+)$/gm)){const b=slug(m[1]),n=counts.get(b)||0;set.add(b+(n?'-'+n:''));counts.set(b,n+1)}for(const m of visible(s).matchAll(/<a id="([^"]+)">/g))set.add(m[1]);return set};
let links=0;
for(const [file,body]of Object.entries(text)){assert(!body.includes('\uFFFD'),'Ошибка UTF-8: '+file);for(const m of visible(body).matchAll(/!?\[[^\]\n]*\]\(([^)\n]+)\)/g)){const url=m[1];if(/^[a-z][a-z0-9+.-]*:/i.test(url))continue;const [p,a]=url.split('#');const target=p?path.posix.normalize(path.posix.join(path.posix.dirname(file),decodeURIComponent(p))):file;assert(fs.existsSync(target),'Нет цели '+file+': '+url);if(a)assert(anchors(text[target]||fs.readFileSync(target,'utf8')).has(decodeURIComponent(a)),'Нет якоря '+file+': '+url);links++}}
const rows=text['docs/PLAN.md'].split(/\r?\n/).filter(l=>/^\| <a id="task-/.test(l));
const tasks=new Map(rows.map(l=>{const cells=l.split(' | ');const id=l.match(/id="task-(\d{3})"/)[1];return [id,{deps:[...cells[2].matchAll(/\[TASK-(\d{3})\]/g)].map(m=>m[1]),req:[...cells[3].matchAll(/\[REQ-(\d+)\]/g)].map(m=>m[1])}]}));
assert(tasks.size===55&&rows.length===55,'TASK отсутствуют/повторяются');
const colors=new Map();
function visit(id){assert(colors.get(id)!==1,'Цикл TASK '+id);if(colors.get(id)===2)return;assert(tasks.has(id),'Нет зависимости TASK '+id);colors.set(id,1);tasks.get(id).deps.forEach(visit);colors.set(id,2)}
tasks.forEach((_,id)=>visit(id));
for(const row of text['docs/ACCEPTANCE.md'].split(/\r?\n/).filter(l=>/^\| \[REQ-/.test(l))){
 const id=row.match(/REQ-(\d+)/)[1];
 const actual=[...row.split(' | ')[3].matchAll(/TASK-(\d{3})\]/g)].map(m=>m[1]).sort();
 const expected=[...tasks].filter(([_,t])=>t.req.includes(id)).map(([id])=>id).sort();
 assert(actual.length>0&&actual.join()===expected.join(),'Связь TASK/REQ '+id);
}
const predecessors=new Set();
function collect(id){if(predecessors.has(id))return;predecessors.add(id);tasks.get(id).deps.forEach(collect)}
collect('050');
assert(predecessors.size===50&&tasks.get('051').deps.join()==='050','ЮKassa не последняя');
console.log(JSON.stringify({documents:files.length,requirements:req.length,originalRequirements:indexed.length,covered:covered.length,checks:checks.length,tasks:tasks.size,stages:(text['docs/PLAN.md'].match(/^### STAGE-/gm)||[]).length,originalAcceptanceRows:criteria,relativeLinks:links,acyclic:true,yooLast:true,sourceSHA256:hash,result:'PASS'}));
