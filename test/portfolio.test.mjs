import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Script } from 'node:vm';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const js = readFileSync(new URL('../script.js', import.meta.url), 'utf8');
const css = readFileSync(new URL('../styles.css', import.meta.url), 'utf8');

test('application JavaScript parses', () => {
  assert.doesNotThrow(() => new Script(js, { filename: 'script.js' }));
});

test('English portfolio declares metadata and actual canonical URL', () => {
  assert.match(html, /<html lang="en">/);
  assert.match(html, /<meta name="description"/);
  assert.match(html, /<link rel="canonical" href="https:\/\/ronoc2020.github.io\/roman.orlowski\/"/);
  assert.match(html, /<meta property="og:title"/);
});

test('scripts are nonblocking and load in deterministic order', () => {
  const ext = html.indexOf('<script defer src="https://cdn.jsdelivr.net/particles.js');
  const local = html.indexOf('<script defer src="script.js"></script>');
  assert.ok(ext >= 0 && local > ext);
  assert.match(js, /typeof particlesJS === 'function'/);
});

test('terminal renders commands as text, not markup', () => {
  assert.doesNotMatch(js, /commandLine\.innerHTML\s*=/);
  assert.match(js, /document\.createTextNode\(' ' \+ command\)/);
});

test('all statically referenced HTML IDs exist', () => {
  const ids = new Set([...html.matchAll(/\bid=["']([^"']+)["']/g)].map(m => m[1]));
  const refs = [
    ...[...js.matchAll(/getElementById\(['"]([^'"]+)['"]\)/g)].map(m => m[1]),
    ...[...js.matchAll(/querySelector\(['"]#([^'"]+)['"]\)/g)].map(m => m[1]),
  ];
  // Audio controls are optional; their handlers already check element existence.
  const optional = new Set(['audio-player', 'play-btn', 'pause-btn', 'next-btn', 'close-btn']);
  const missing = [...new Set(refs.filter(id => !ids.has(id) && !optional.has(id)))];
  assert.deepEqual(missing, []);
});

test('stylesheets remain available', () => {
  assert.match(html, /href="styles.css"/);
  assert.ok(css.length > 0);
});
