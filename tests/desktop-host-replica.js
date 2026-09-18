'use strict';
const { Readable } = require('node:stream'); const { pathToFileURL } = require('node:url'); const path = require('node:path');
const entry = process.argv[2]; const responses = [];
const origWrite = process.stdout.write.bind(process.stdout);
process.stdout.write = (chunk) => { responses.push(String(chunk)); return true; };
const fake = new Readable({ read() {} });
for (const m of ['read','push','unshift','pause','resume','pipe','unpipe','on','once','removeListener','removeAllListeners','setEncoding','destroy','isPaused']) if (typeof fake[m]==='function') process.stdin[m]=fake[m].bind(fake);
process.argv = ['node', entry];
const messages = [
  { jsonrpc:'2.0', id:0, method:'initialize', params:{ protocolVersion:'2024-11-05', capabilities:{}, clientInfo:{name:'host-sim',version:'1'} } },
  { jsonrpc:'2.0', method:'notifications/initialized' },
  { jsonrpc:'2.0', id:1, method:'tools/list', params:{} },
  { jsonrpc:'2.0', id:10, method:'prompts/list', params:{} },
  { jsonrpc:'2.0', id:11, method:'resources/list', params:{} },
  { jsonrpc:'2.0', id:2, method:'tools/call', params:{ name:'Analyze', arguments:{ sheet_id:'188d099f_1c04_479e_9498_260894041c4e', instructions:'ROWGROUPBY Billing Class; DISPLAY' } } },
];
import(pathToFileURL(path.resolve(entry)).toString()).then(async () => {
  for (const m of messages) { fake.push(JSON.stringify(m)+'\n'); await new Promise(r=>setTimeout(r,150)); }
  const deadline = Date.now()+60000; while (responses.length<5 && Date.now()<deadline) await new Promise(r=>setTimeout(r,200));
  const parsed = responses.map(r=>JSON.parse(r));
  origWrite(`  responses received: ${parsed.length} (expected 5; notification gets none)\n`);
  for (const p of parsed) {
    const r = p.result||{};
    if (p.error) origWrite(`  id=${p.id} ERROR ${p.error.message}\n`);
    else if (r.serverInfo) origWrite(`  id=${p.id} initialize OK\n`);
    else if (r.tools) origWrite(`  id=${p.id} tools: ${r.tools.map(t=>t.name).join(', ')}\n`);
    else if ('prompts' in r || 'resources' in r) origWrite(`  id=${p.id} ${'prompts' in r?'prompts':'resources'}/list answered locally (empty)\n`);
    else if (r.content) origWrite(`  id=${p.id} Analyze isError=${r.isError}: ${r.content[0].text.split('\n').slice(0,2).join(' | ').slice(0,120)}\n`);
  }
  origWrite(parsed.length===5 && parsed.every(p=>!p.error) ? '  HOST SIMULATION: PASS\n' : '  HOST SIMULATION: FAIL\n');
  process.exit(0);
}).catch(e => { origWrite('  import failed: '+e.stack+'\n'); process.exit(1); });
