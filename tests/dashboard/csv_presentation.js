// Exercise the dashboard's actual renderer without a browser or network.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync('dashboard/trace_viewer.html', 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(script); // syntax-check the complete page script
const escape = script.slice(script.indexOf('function escapeHtml('), script.indexOf('function shorten('));
const renderer = script.slice(script.indexOf('function parseEvidenceRows('), script.indexOf('function renderToolCall('));
const context = vm.createContext({});
vm.runInContext(escape + renderer, context);
const render = (text, opts) => context.renderEvidenceText(text, opts);

let out = render('Name,Detail,Empty\r\nAlpha,"comma, and ""quote""\nnext line",\r\n');
assert.match(out, /<table>/);
assert.match(out, /comma, and &quot;quote&quot;\nnext line/);
assert.doesNotMatch(out.split('<details>')[0], /<th>Empty<\/th>/);
assert.match(out, /<summary>Raw text<\/summary>/);
assert.match(render('Name\tDetail\nAlpha\tvalue\n'), /<table>/);
assert.match(render('Name,Detail\nAlpha,"unterminated'), /^<pre>/);
assert.match(render('Name,Name\nAlpha,value\n'), /^<pre>/);
assert.match(render('{"name":"Alpha","detail":"value"}'), /^<pre>/);
assert.match(render('ordinary prose\nnext line'), /^<pre>/);
out = render('Alpha,secret\n', {columns: ['Name', 'Hidden'], projection: ['Name']});
assert.doesNotMatch(out.split('<details>')[0], /secret/);
assert.match(out, /secret/); // retained raw toggle still works
out = render('Name,Detail\nAlpha,<script>alert(1)<\/script>\n');
assert.doesNotMatch(out, /<script>/);
assert.match(out, /&lt;script&gt;/);
out = render('Name,Detail\nAlpha,' + 'x'.repeat(500) + 'TAIL\n');
assert.doesNotMatch(out.split('<details>')[0], /TAIL/);
assert.match(out.split('<details>')[0], /field truncated/);
console.log('Dashboard CSV rendering checks passed.');
