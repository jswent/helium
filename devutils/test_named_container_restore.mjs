// Copyright (c) 2026 The Helium Authors
// SPDX-License-Identifier: GPL-3.0-or-later
// Run with Node 22+ and the path to a desktop Helium executable.
// Pass --temporary-containers to repeat the lifecycle checks with temporary sessions.
// Pass --in-place-discard to exercise Chromium's alternate hibernation path.
import assert from 'node:assert/strict';
import {execFile, spawn} from 'node:child_process';
import {createHash, generateKeyPairSync, randomUUID} from 'node:crypto';
import {once} from 'node:events';
import {mkdtemp, mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {setTimeout as sleep} from 'node:timers/promises';
import {promisify} from 'node:util';

if (!process.argv[2]) throw Error('Usage: node test_named_container_restore.mjs <Helium executable>');
const binary = resolve(process.argv[2]);
const temporary = process.argv.includes('--temporary-containers');
const inPlaceDiscard = process.argv.includes('--in-place-discard');
const root = await mkdtemp(join(tmpdir(), 'helium-restore-'));
const profile = join(root, 'profile');
const extension = join(root, 'controller');
const visits = [];
const accounts = {work: 'Alice', personal: 'Bob', ordinary: 'Charlie'};
const tokens = new Map();
const server = createServer((request, response) => {
  const path = request.url.slice(1);
  response.setHeader('Cache-Control', 'no-store');
  if (path.startsWith('login/')) {
    const label = path.slice(6);
    const token = randomUUID();
    tokens.set(token, accounts[label]);
    response.writeHead(303, {Location: '/' + label,
      'Set-Cookie': 'session=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600'});
  } else {
    const token = request.headers.cookie?.match(/(?:^|; )session=([^;]+)/)?.[1];
    visits.push({path, account: tokens.get(token) || 'signed out'});
    response.setHeader('Content-Type', 'text/html');
    response.end('<title>Session fixture</title>Session fixture');
    return;
  }
  response.end();
});
await mkdir(extension);
await mkdir(profile);
const {publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
const key = publicKey.export({type: 'spki', format: 'der'});
const extensionId = [...createHash('sha256').update(key).digest('hex').slice(0, 32)]
    .map(ch => String.fromCharCode(97 + parseInt(ch, 16))).join('');
await writeFile(join(extension, 'manifest.json'), JSON.stringify({
  manifest_version: 3, name: 'Session restore test controller', version: '1',
  key: key.toString('base64'), permissions: ['tabs', 'sessions']
}));
await writeFile(join(extension, 'controller.html'), '<title>Session restore test controller</title>');
const controllerUrl = 'chrome-extension://' + extensionId + '/controller.html';
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const origin = 'http://127.0.0.1:' + server.address().port;
// Like Chromium's browser tests, keep the selected tab loadable when another
// desktop window covers this disposable browser. Background tabs stay lazy.
const common = ['--user-data-dir=' + profile, '--no-first-run', '--disable-backgrounding-occluded-windows',
                '--no-default-browser-check', '--use-mock-keychain'];
let child, exited, websocket, debuggerUrl;
let recentLog = '';

async function until(label, check, timeout = 30000) {
  const deadline = Date.now() + timeout;
  do {
    const value = await check();
    if (value) return value;
    await sleep(100);
  } while (Date.now() < deadline);
  throw Error('Timed out: ' + label);
}

async function connect(url) {
  const socket = new WebSocket(url);
  await once(socket, 'open');
  let id = 0;
  const pending = new Map();
  socket.onmessage = ({data}) => {
    const reply = JSON.parse(data);
    const cb = pending.get(reply.id);
    if (cb) { pending.delete(reply.id); cb(reply); }
  };
  return {socket, send(method, params = {}) {
    return new Promise((ok, fail) => {
      const seq = ++id;
      const timer = setTimeout(() => { pending.delete(seq); fail(Error(method + ' timed out')); }, 15000);
      pending.set(seq, reply => {
        clearTimeout(timer);
        if (reply.error) fail(Error(JSON.stringify(reply.error))); else ok(reply.result);
      });
      socket.send(JSON.stringify({id: seq, method, params}));
    });
  }};
}
async function api(expression, connection = websocket) {
  const reply = await connection.send('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true});
  if (reply.exceptionDetails) throw Error(reply.exceptionDetails.exception?.description || reply.exceptionDetails.text);
  return reply.result.value;
}
async function start(enabled, restore) {
  const portFile = join(profile, 'DevToolsActivePort');
  await rm(portFile, {force: true});
  const enabledFeatures = [enabled && 'HeliumNamedContainers', inPlaceDiscard && 'WebContentsDiscard'].filter(Boolean);
  const disabledFeatures = [!enabled && 'HeliumNamedContainers', !inPlaceDiscard && 'WebContentsDiscard'].filter(Boolean);
  child = spawn(binary, [...common, '--load-extension=' + extension,
    '--remote-debugging-port=0', '--enable-features=' + enabledFeatures.join(','),
    '--disable-features=' + disabledFeatures.join(','),
    ...(restore ? ['--restore-last-session'] : [])],
    {stdio: ['ignore', 'ignore', 'pipe']});
  exited = once(child, 'exit');
  child.stderr.on('data', chunk => {recentLog = (recentLog + chunk).slice(-4000);});
  const [port, path] = await until('debug port', async () => {
    if (child.exitCode !== null || child.signalCode) throw Error('Helium exited at startup');
    const lines = (await readFile(portFile, 'utf8').catch(() => '')).split('\n');
    return lines[1] && lines;
  }, 90000);
  const targets = async () => (await fetch('http://127.0.0.1:' + port + '/json/list')).json();
  debuggerUrl = 'ws://127.0.0.1:' + port + path;
  // Only attach DevTools to the controller, never to a tab being hibernated.
  const browser = await connect(debuggerUrl);
  const {targetId} = await browser.send('Target.createTarget', {url: controllerUrl});
  browser.socket.close();
  const target = await until('controller page', async () =>
    (await targets()).find(t => t.id === targetId && t.url === controllerUrl));
  websocket = await connect(target.webSocketDebuggerUrl);
  await until('extension APIs', () => api('typeof chrome.sessions?.restore === "function"'));
}
async function stop() {
  websocket.socket.close();
  const browser = await connect(debuggerUrl);
  await browser.send('Browser.close');
  await until('graceful shutdown', () => child.exitCode !== null || child.signalCode !== null, 30000);
  const [code] = await exited;
  assert.equal(code, 0);
  child = null;
}
async function open(path, name, useTemporary = temporary && !!name) {
  const switches = [];
  if (useTemporary) switches.push('--temporary-container');
  if (name) switches.push('--container=' + name);
  await promisify(execFile)(binary, [...common, ...switches, origin + '/' + path],
                             {timeout: 30000, cwd: root});
}
async function who(path, account, since) {
  const result = await until('request for /' + path, () => visits.slice(since).find(v => v.path === path));
  assert.equal(result.account, account, path);
}
const tabs = () => api('chrome.tabs.query({})');
async function tab(path) {
  return until('tab for /' + path, async () => (await tabs()).find(t => t.url === origin + '/' + path));
}
async function activate(id) {
  const windowId = await api('chrome.tabs.get(' + id + ').then(t => t.windowId)');
  await api('chrome.windows.update(' + windowId + ', {focused:true})');
  await api('chrome.tabs.update(' + id + ', {active:true})');
  await until('activated tab finished loading', () => api(
      'chrome.tabs.get(' + id + ').then(t => t.active && !t.discarded && t.status === "complete")'));
}
async function hibernate(path) {
  const {id} = await tab(path);
  await api('chrome.tabs.update(' + (await tab('ordinary')).id + ', {active:true})');
  await api('chrome.tabs.discard(' + id + ')');
  // The replacement-WebContents discard path assigns a new extension tab ID.
  const discarded = await until('browser acknowledged discard', async () =>
    (await tabs()).find(t => t.url === origin + '/' + path && t.discarded));
  return discarded.id;
}
async function closedId(path) {
  return until('recently closed /' + path, async () => {
    const list = await api('chrome.sessions.getRecentlyClosed({maxResults:25})');
    return list.find(e => e.tab?.url?.endsWith(origin + '/' + path))?.tab.sessionId;
  });
}
async function closeTab(path) {
  await api('chrome.tabs.remove(' + (await tab(path)).id + ')');
  return closedId(path);
}
async function reopen(sessionId) {
  const restored = await api('chrome.sessions.restore(' + JSON.stringify(sessionId) + ')');
  await activate(restored.tab.id);
  return restored.tab.id;
}

try {
  await start(true, false);
  for (const [label, name] of [['work','Work'], ['personal','Personal'], ['ordinary',null]]) {
    const since = visits.length;
    await open('login/' + label, name);
    await who(label, accounts[label], since);
  }
  if (temporary) {
    for (const [path, name, contained, expected] of [
      ['reuse-work', 'Work', true, 'Alice'],
      ['permanent-work', 'Work', false, 'signed out'],
      ['fresh-temporary', null, true, 'signed out'],
    ]) {
      const since = visits.length;
      await open(path, name, contained);
      await who(path, expected, since);
    }

    // This temporary container is referenced only by Recently Closed.
    accounts.closed = 'Dana';
    let since = visits.length;
    await open('login/closed', 'Closed only');
    await who('closed', accounts.closed, since);
    await closeTab('closed');
    await stop();

    // Model an abandoned partition from an interrupted session. The profile
    // is disposable and the browser is shut down while creating this fixture.
    const prefsPath = join(profile, 'Default', 'Preferences');
    const prefs = JSON.parse(await readFile(prefsPath, 'utf8'));
    const orphan = 't-' + randomUUID();
    prefs.helium.containers.temporary[orphan] = {name: 'Orphan', color: 0x488cff};
    await writeFile(prefsPath, JSON.stringify(prefs));
    const leaf = createHash('sha256').update(orphan).digest('hex').slice(0, 12).toUpperCase();
    const partition = join(profile, 'Default', 'Storage', 'ext', 'containers', leaf);
    const marker = join(partition, 'marker');
    await mkdir(partition, {recursive: true});
    await writeFile(marker, 'Unused temporary partition');
    since = visits.length;
    await start(true, true);
    await reopen(await closedId('closed'));
    await who('closed', accounts.closed, since);
    await until('unused temporary partition removed', async () => {
      try { await readFile(marker); return false; }
      catch (error) { if (error.code === 'ENOENT') return true; throw error; }
    });
    await until('unused temporary metadata removed', async () => {
      const saved = JSON.parse(await readFile(prefsPath, 'utf8'));
      return !Object.hasOwn(saved.helium.containers.temporary, orphan);
    });
    console.log('Temporary sessions: isolated from namesakes, fresh on demand, recently closed login restored, orphan removed.');
  }
  for (const label of ['work','personal']) {
    const id = await hibernate(label);
    const since = visits.length;
    await activate(id);
    await who(label, accounts[label], since);
    console.log('Hibernate/wake:', label, accounts[label]);
    const sessionId = await closeTab(label);
    const closedAt = visits.length;
    await reopen(sessionId);
    await who(label, accounts[label], closedAt);
    console.log('Reopen closed tab:', label, accounts[label]);
  }
  await hibernate('work');  // Also restart with one suspended account.
  await stop();
  const restartAt = visits.length;
  await start(true, true);
  for (const label of ['work','personal','ordinary']) {
    await activate((await tab(label)).id);
    await who(label, accounts[label], restartAt);
    console.log('Restart:', label, accounts[label]);
  }

  for (const [label, name] of [['work','Work'], ['personal','Personal']]) {
    const path = 'closed-' + label;
    const since = visits.length;
    await open(path, name);
    await who(path, accounts[label], since);
    await closeTab(path);
  }
  await hibernate('personal');
  await stop();

  const offAt = visits.length;
  await start(false, true);
  const protectedTabs = await until('two sealed session tabs', async () => {
    const found = (await tabs()).filter(t => t.url?.startsWith('containers+') &&
       (t.url.endsWith(origin + '/work') || t.url.endsWith(origin + '/personal')));
    return found.length === 2 && found;
  });
  for (const t of protectedTabs) {
    await activate(t.id);
    await api('chrome.tabs.reload(' + t.id + ', {bypassCache:true})');
    await until('blocked reload finished', () => api(
      'chrome.tabs.get(' + t.id + ').then(t => t.status === "complete")'));
  }
  for (const label of ['work','personal']) {
    await reopen(await closedId('closed-' + label));
  }
  await activate((await tab('ordinary')).id);
  await who('ordinary', accounts.ordinary, offAt);
  assert.deepEqual(visits.slice(offAt).filter(v =>
    ['work','personal','closed-work','closed-personal'].includes(v.path)), []);
  console.log('Flag disabled: two restored and two reopened tabs withheld; ordinary still Charlie.');
  await stop();

  // A blocked tab is saved without giving the ordinary renderer its page state.
  // Its original session can be recovered after the feature is enabled again.
  const backOn = visits.length;
  await start(true, true);
  for (const [path, account] of [['work', 'Alice'], ['personal', 'Bob'],
                                 ['closed-work', 'Alice'], ['closed-personal', 'Bob']]) {
    const t = await tab(path);
    await activate(t.id);
    await who(path, account, backOn);
    if (path === 'work' || path === 'personal') {
      const url = origin + '/' + path + '#saved-location';
      await api('chrome.tabs.update(' + t.id + ', ' + JSON.stringify({url, pinned: true}) + ')');
      await until('pin retained its fragment', () => api(
          'chrome.tabs.get(' + t.id + ').then(t => t.pinned && t.url === ' + JSON.stringify(url) + ')'));
    }
  }
  console.log('Re-enabled: both open and both recently closed sessions recovered.');
  // Set "Open the New Tab page" through the real settings page so startup
  // reads its pins independently of full session restore.
  const browser = await connect(debuggerUrl);
  const {targetId} = await browser.send('Target.createTarget', {url: 'chrome://settings/onStartup'});
  const settings = await connect(new URL('/devtools/page/' + targetId, debuggerUrl).href);
  await until('startup setting', () => api('typeof chrome.settingsPrivate?.setPref === "function"', settings));
  const changed = await api("new Promise(resolve => chrome.settingsPrivate.setPref('session.restore_on_startup', 5, '', resolve))", settings);
  assert.equal(changed, true);
  settings.socket.close();
  await browser.send('Target.closeTarget', {targetId});
  browser.socket.close();
  await stop();

  for (const enabled of [true, false, true]) {
    const since = visits.length;
    await start(enabled, false);
    const pins = await until('two pinned startup tabs', async () => {
      const found = (await tabs()).filter(t => t.pinned);
      return found.length === 2 && found;
    });
    for (const t of pins) {
      const label = t.url.endsWith('/work#saved-location') ? 'work' : 'personal';
      assert.ok(t.url.endsWith(origin + '/' + label + '#saved-location'));
      if (!enabled) assert.ok(t.url.startsWith('containers+'));
      await activate(t.id);
      if (enabled) await who(label, accounts[label], since);
    }
    if (!enabled) assert.deepEqual(visits.slice(since).filter(v => ['work','personal'].includes(v.path)), []);
    console.log('Pinned startup:', enabled ? 'Alice and Bob in their own tabs' : 'both pins withheld');
    await stop();
  }
  for (const {path, account} of visits) {
    const label = path.replace(/^closed-/, '');
    if (Object.hasOwn(accounts, label)) assert.equal(account, accounts[label], path);
  }
} catch (error) {
  console.error('Recent fixture requests:', visits.slice(-25), '\nBrowser:', recentLog);
  if (websocket?.socket.readyState === WebSocket.OPEN)
    console.error('Tabs:', await tabs().catch(() => []));
  throw error;
} finally {
  if (child && child.exitCode === null && child.signalCode === null) {
    child.kill();
    await exited;
  }
  server.closeAllConnections();
  server.close();
  await rm(root, {recursive: true, force: true, maxRetries: 3});
}
