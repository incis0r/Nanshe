// Test logiki raportu bez przeglądarki i bez zewnętrznych zależności.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(tag, text = '') { this.tag = tag; this.textContent = text; this.children = []; this.style = {}; this.value = ''; this.attributes = {}; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(key, value) { this.attributes[key] = value; }
}
const ids = new Map();
const document = {
  getElementById(id) { if (!ids.has(id)) ids.set(id, new Element('div')); return ids.get(id); },
  createElement(tag) { return new Element(tag); },
  createTextNode(text) { return new Element('text', text); },
};
const region = { base: '0xffff800000001001', size: '4096', prot: 'rwx', kind: 'private', backing: null, label: '</script><script>bad()</script>', backing_deleted: false, rss: null, pss: null };
const inventory = { host: '<host>', os: 'linux', timestamp: 'test', processes: [
  { pid: 5, name: 'test', exe: '/bin/test', error: null, notes: [], regions: [region, { ...region, base: '0xffff800000003001', prot: 'r-x', backing: '/lib/a.so', rss: '1024', pss: '512' }] },
  { pid: 6, name: 'denied', exe: null, error: 'access denied', notes: [], regions: [] },
] };
document.getElementById('data').textContent = JSON.stringify(inventory);
document.getElementById('filter').value = 'all';
document.getElementById('group').value = 'file';
const template = fs.readFileSync('crates/nanshe-report/src/memory.html', 'utf8');
const script = template.match(/<script>\n([\s\S]*?)<\/script>/)[1];
const context = vm.createContext({ document });
vm.runInContext(script, context);
assert.equal(ids.get('rows').children.length, 2);
assert.equal(ids.get('processes').children.length, 2);
ids.get('bar').children[0].onclick();
assert(ids.get('details').textContent.includes('0xffff800000002001'), '64-bit address must stay exact');
assert(ids.get('details').textContent.includes('RSS: nieznane'), 'unknown is not zero');
assert(ids.get('details').textContent.includes(region.label), 'hostile label stays text');
ids.get('filter').value = 'deleted'; ids.get('filter').onchange();
assert.equal(ids.get('rows').children.length, 0);
ids.get('filter').value = 'signals'; ids.get('filter').onchange();
assert.equal(ids.get('rows').children.length, 1);
ids.get('processes').children[1].onclick();
assert.equal(ids.get('rows').children.length, 0);
assert(ids.get('status').children.some(e => e.textContent === 'access denied'));
ids.get('search').value = '/lib/a.so'; ids.get('search').oninput();
assert.equal(ids.get('processes').children.length, 1);
vm.runInContext("inventory.processes=[];selected=undefined;processList();render();", context);
assert.equal(ids.get('processes').children.length, 0);
assert.equal(ids.get('status').textContent, 'Brak procesów w inwentaryzacji.');
console.log('memory view: grouping, filters, errors, search, empty inventory, text safety and 64-bit addresses OK');
