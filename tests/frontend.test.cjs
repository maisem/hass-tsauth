const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const sourcePath = path.join(__dirname, '../custom_components/tsidp/frontend.js');
const rawQuery = 'client_id=https%3a%2f%2fhome-assistant.io%2fiOS&redirect_uri=homeassistant%3a%2f%2fauth-callback&state=a%2Bb%2Fc%3D&tsidp_local=1&opaque=x%2fy%3dz&tsidp_resume=1';
const expectedQuery = 'client_id=https%3a%2f%2fhome-assistant.io%2fiOS&redirect_uri=homeassistant%3a%2f%2fauth-callback&state=a%2Bb%2Fc%3D&opaque=x%2fy%3dz';

function browser({ pathname = '/auth/authorize', search = '?' + rawQuery, response = {}, status = 200 } = {}) {
  const handlers = new Map();
  const navigations = [];
  const calls = [];
  const location = {
    origin: 'https://ha.example.test', pathname, search,
    assign(url) { navigations.push(String(url)); },
    replace(url) { navigations.push(String(url)); },
    get href() { return this.origin + this.pathname + this.search; },
    set href(url) { navigations.push(String(url)); },
  };
  const window = {
    location,
    addEventListener(name, callback) {
      if (!handlers.has(name)) handlers.set(name, []);
      handlers.get(name).push(callback);
    },
    async fetch(...args) {
      calls.push(args);
      return new Response(JSON.stringify(response), { status, headers: { 'Content-Type': 'application/json' } });
    },
  };
  const context = vm.createContext({ window, location, URL, URLSearchParams, Request, Response, console });
  function load() { vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), context); }
  load();
  return {
    window, handlers, navigations, calls, load,
    select(type) {
      const event = { detail: { type, id: null }, stopped: false, stopImmediatePropagation() { this.stopped = true; }, stopPropagation() { this.stopped = true; }, preventDefault() {} };
      for (const callback of handlers.get('pick-auth-provider') || []) callback(event);
      return event;
    },
  };
}

function expectedNavigation(value) {
  const url = new URL(value, 'https://ha.example.test');
  assert.equal(url.origin, 'https://ha.example.test');
  assert.equal(url.pathname, '/auth/tsidp/start');
  assert.equal(url.search.slice(1), expectedQuery);
}

test('clicking Tailscale starts a fresh handoff, preserving opaque query bytes', () => {
  const b = browser();
  const event = b.select('tsidp');
  assert.equal(event.stopped, true);
  assert.equal(b.navigations.length, 1);
  expectedNavigation(b.navigations[0]);
});

test('local password selection is untouched', () => {
  const b = browser();
  assert.equal(b.select('homeassistant').stopped, false);
  assert.deepEqual(b.navigations, []);
});

test('missing or expired handoff restarts OAuth instead of leaving Login aborted', async () => {
  const b = browser({ response: { type: 'abort', handler: ['tsidp', null], reason: 'restart_sso' } });
  const response = await b.window.fetch('/auth/login_flow', { method: 'POST' });
  assert.deepEqual(await response.json(), { type: 'abort', handler: ['tsidp', null], reason: 'restart_sso' });
  assert.equal(b.navigations.length, 1);
  expectedNavigation(b.navigations[0]);
});

test('ordinary successful login and MFA forms do not restart', async () => {
  for (const response of [
    { type: 'create_entry', handler: ['tsidp', null], result: 'native-code' },
    { type: 'form', handler: ['tsidp', null], step_id: 'mfa' },
    { type: 'abort', handler: ['tsidp', null], reason: 'invalid_auth' },
    { type: 'abort', handler: ['homeassistant', null], reason: 'restart_sso' },
  ]) {
    const b = browser({ response });
    const result = await b.window.fetch('/auth/login_flow', { method: 'POST' });
    assert.deepEqual(await result.json(), response);
    assert.deepEqual(b.navigations, []);
  }
});

test('only same-origin POST to the native login endpoint is handled', async () => {
  const response = { type: 'abort', handler: ['tsidp', null], reason: 'restart_sso' };
  for (const [input, options] of [
    ['/auth/token', { method: 'POST' }],
    ['/auth/login_flow/other-step', { method: 'POST' }],
    ['/auth/login_flow', { method: 'GET' }],
    ['https://attacker.example/auth/login_flow', { method: 'POST' }],
  ]) {
    const b = browser({ response });
    await b.window.fetch(input, options);
    assert.deepEqual(b.navigations, []);
    assert.equal(b.calls.length, 1);
  }
});

test('Request inputs are supported', async () => {
  const b = browser({ response: { type: 'abort', handler: ['tsidp', null], reason: 'restart_sso' } });
  await b.window.fetch(new Request('https://ha.example.test/auth/login_flow', { method: 'POST' }));
  assert.equal(b.navigations.length, 1);
});

test('loading twice does not add duplicate listeners or fetch wrappers', () => {
  const b = browser();
  b.load();
  b.select('tsidp');
  assert.equal(b.navigations.length, 1);
});
