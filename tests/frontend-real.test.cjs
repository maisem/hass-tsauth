/* Optional contract tests against the installed, unmodified HA 20260930.3 bundle.
 * TSIDP_HA_FRONTEND=/path/to/hass_frontend node --test tests/*.test.cjs
 * Only Lit rendering/decorators are stubbed; native auth, picker and event
 * implementation functions below are executed directly from the real wheel.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = process.env.TSIDP_HA_FRONTEND;
const options = { skip: !root && 'Set TSIDP_HA_FRONTEND to the audited frontend wheel' };
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const query = `client_id=https%3a%2f%2fha.example.test%2f&redirect_uri=https%3a%2f%2fha.example.test%2f%3fauth_callback%3d1&state=a%2Bb%2Fc%3D&code_challenge=${challenge}&code_challenge_method=S256`;

function nativeModules(context) {
  const directory = path.join(root, 'frontend_latest');
  const file = fs.readdirSync(directory).find(name => /^authorize\.[^.]+\.js$/.test(name));
  const source = fs.readFileSync(path.join(directory, file), 'utf8');
  // Load module definitions without starting the browser entrypoint/runtime.
  // Fail on a changed bundler shape rather than pretending a new audit passed.
  const end = source.indexOf('},a={};function o(e){');
  assert.ok(end > 0, 'Audited Rspack module table must exist');
  vm.runInContext(source.slice(0, end + 1) + ';globalThis.modules=r;', context);
  return context.modules;
}

function loadModule(definition, dependencies = () => ({})) {
  const exports = {};
  const require = id => dependencies(id);
  require.r = () => {};
  require.d = (target, getters, values = {}) => {
    Object.assign(target, values);
    for (const [name, getter] of Object.entries(getters)) {
      Object.defineProperty(target, name, { get: getter });
    }
  };
  definition({}, exports, require);
  return exports;
}

function browser(response) {
  const navigations = [];
  const requests = [];
  const events = [];
  const listeners = new Map();
  const location = {
    origin: 'https://ha.example.test',
    pathname: '/auth/authorize',
    search: '?' + query + '&tsidp_resume=1',
    href: 'https://ha.example.test/auth/authorize?' + query + '&tsidp_resume=1',
    assign(value) { navigations.push(value); },
  };
  const window = {
    location,
    addEventListener(name, callback) { listeners.set(name, callback); },
    async fetch(url, init) {
      requests.push({ url, init });
      return new Response(JSON.stringify(response), { status: 200 });
    },
  };
  class NativeTarget {
    dispatchEvent(event) {
      events.push(event);
      listeners.get(event.type)?.(event);
      return true;
    }
  }
  const globals = { window, location, document: { location }, URL, Request, Response, Event };
  Object.defineProperty(globals, 'fetch', { get: () => window.fetch });
  const context = vm.createContext(globals);
  const modules = nativeModules(context);
  vm.runInContext(
    fs.readFileSync(path.join(__dirname, '../custom_components/tsidp/frontend.js'), 'utf8'),
    context,
  );
  const authDefinition = Object.values(modules).find(fn =>
    fn.toString().includes('fetch("/auth/login_flow"'),
  );
  assert.ok(authDefinition, 'Native login-flow API module must exist');
  const auth = loadModule(authDefinition);
  const createFlow = Object.values(auth).find(fn => fn.toString().includes('fetch("/auth/login_flow"'));
  return { context, modules, auth, createFlow, requests, navigations, events, NativeTarget };
}

test('real new frontend submits native S256 fields through the unchanged bridge', options, async () => {
  const b = browser({ type: 'form', step_id: 'mfa', handler: ['tsidp', null] });
  const result = await b.createFlow(
    'https://ha.example.test/', 'https://ha.example.test/?auth_callback=1',
    ['tsidp', null], challenge, 'S256',
  );
  assert.equal((await result.json()).step_id, 'mfa');
  assert.equal(b.requests[0].url, '/auth/login_flow');
  assert.equal(b.requests[0].init.method, 'POST');
  assert.equal(b.requests[0].init.credentials, 'same-origin');
  assert.deepEqual(JSON.parse(b.requests[0].init.body), {
    client_id: 'https://ha.example.test/',
    redirect_uri: 'https://ha.example.test/?auth_callback=1',
    handler: ['tsidp', null],
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  assert.deepEqual(b.navigations, []);
});

test('real new frontend ticketless POST restarts with opaque state and PKCE intact', options, async () => {
  const result = { type: 'abort', reason: 'restart_sso', handler: ['tsidp', null] };
  const b = browser(result);
  const response = await b.createFlow('https://ha.example.test/', 'https://ha.example.test/', ['tsidp', null], challenge, 'S256');
  assert.deepEqual(await response.json(), result);
  assert.deepEqual(b.navigations, ['/auth/tsidp/start?' + query]);
});

test('real picker and composed native event restart only Tailscale selection', options, () => {
  for (const type of ['tsidp', 'homeassistant']) {
    const b = browser({});
    const fireDefinition = Object.values(b.modules).find(fn =>
      fn.toString().includes('o.detail=r,e.dispatchEvent(o)'),
    );
    assert.ok(fireDefinition, 'Native composed event helper must exist');
    const fire = loadModule(fireDefinition);
    const directory = path.join(root, 'frontend_latest');
    const chunk = fs.readdirSync(directory).find(name => /^6917\.[^.]+\.js$/.test(name));
    assert.ok(chunk, 'Audited native picker chunk must exist');
    const source = fs.readFileSync(path.join(directory, chunk), 'utf8').replaceAll('export const ', 'const ');
    vm.runInContext(source + '\n;globalThis.pickerModules=__webpack_modules__;', b.context);
    const definition = Object.values(b.context.pickerModules).find(fn =>
      fn.toString().includes('"pick-auth-provider",'),
    );
    assert.ok(definition, 'Native picker implementation must exist');
    const noDecorator = () => () => {};
    const dependencies = id => ({
      20686: { WF: b.NativeTarget, AH: () => '' }, // Lit rendering only.
      89797: { Cg: (_decorators, target) => target },
      32379: { MZ: noDecorator, wk: noDecorator, EM: noDecorator },
      70465: { IW: noDecorator },
      86075: fire,
    })[id] || {};
    const { HaPickAuthProvider } = loadModule(definition, dependencies);
    const picker = new HaPickAuthProvider();
    picker._handlePick({ currentTarget: { auth_provider: { type, id: null } } });
    assert.equal(b.events[0].type, 'pick-auth-provider');
    assert.equal(b.events[0].composed, true);
    assert.equal(b.events[0].bubbles, true);
    assert.equal(b.events[0].detail.type, type);
    assert.deepEqual(b.navigations, type === 'tsidp' ? ['/auth/tsidp/start?' + query] : []);
  }
});

test('real new frontend keeps native remember-me callback and state encoding', options, () => {
  const b = browser({});
  const complete = Object.values(b.auth).find(fn => fn.toString().includes('storeToken=true'));
  assert.ok(complete, 'Native completion redirect must exist');
  complete('https://ha.example.test/?auth_callback=1', 'native-code', 'a+b/=', true);
  const redirect = new URL(b.navigations[0]);
  assert.equal(redirect.searchParams.get('code'), 'native-code');
  assert.equal(redirect.searchParams.get('state'), 'a+b/=');
  assert.equal(redirect.searchParams.get('storeToken'), 'true');
});
