import { beforeEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';
import { createTestDb } from './helpers/d1';
import { createApp } from '../src/app';
import { mintSession } from '../src/auth';
import { IntegrationCredentialService } from '../src/services/integration-credentials';

const KEY = 'k7Qp2xVn9sLw4TzRb8YdHf3JmUc6AeGo1NiXtKv0PqSa5ZyWh';
const APP_SECRET = 'S3cretAppSecretValue0123456789ab';
const VERIFY = 'verify-token-xyz';
const root = join(__dirname, '..', 'public');
const html = readFileSync(join(root, 'dashboard.html'), 'utf8');
const js = readFileSync(join(root, 'dashboard.js'), 'utf8');

let t: ReturnType<typeof createTestDb>;
let env: any;
let win: any;
let doc: Document;

const app = createApp({ fetch: async () => new Response(JSON.stringify({ error: { message: 'stub' } }), { status: 400 }) });

const settle = async (ms = 60) => {
  for (let i = 0; i < 6; i++) await new Promise((r) => setTimeout(r, ms / 3));
};
const q = <T extends Element = HTMLElement>(sel: string, scope: any = doc) => scope.querySelector(sel) as T | null;
const byText = (text: string, scope: any = doc) =>
  (Array.from(scope.querySelectorAll('button')) as HTMLButtonElement[]).find((b) => b.textContent?.trim() === text) as HTMLButtonElement | undefined;
const metaSection = () => q('section[aria-label="Meta (Facebook / Instagram)"]')!;
const submit = (form: Element) => form.dispatchEvent(new win.Event('submit', { bubbles: true, cancelable: true }));
const fill = (id: string, value: string) => { (q<HTMLInputElement>(`#${id}`)!).value = value; };

async function boot(user = 'alice') {
  const token = await mintSession(KEY, user);
  const dom = new JSDOM(html, { url: 'https://app.test/settings/integrations', runScripts: 'outside-only', pretendToBeVisual: true });
  win = dom.window;
  doc = win.document;
  // Bridge the page's fetch to the real app + real database.
  win.fetch = (path: string, init: any = {}) =>
    app.request(`https://app.test${path}`, { ...init, headers: { ...(init.headers ?? {}), authorization: `Bearer ${token}` } }, env);
  win.eval(js);
  await settle(120);
}

beforeEach(() => {
  t = createTestDb();
  t.raw.exec(`
    INSERT INTO workspaces (id,name) VALUES ('ws-a','Acme'),('ws-b','Other');
    INSERT INTO users (id,email,is_app_owner) VALUES ('owner','o@x.com',1),('alice','a@x.com',0),('bob','b@x.com',0);
    INSERT INTO workspace_members VALUES ('ws-a','alice','admin'),('ws-a','bob','member');
  `);
  env = { DB: t.d1, SECRET_KEY: KEY, APP_URL: 'https://app.test', WEBHOOK_QUEUE: { send: async () => {} } };
});

async function addMeta(name = 'Main') {
  byText('Add configuration', metaSection())!.click();
  await settle();
  fill('f-name', name);
  fill('f-app_id', '1234567890');
  fill('f-app_secret', APP_SECRET);
  fill('f-webhook_verify_token', VERIFY);
  q<HTMLInputElement>('#f-test')!.checked = false;
  submit(q('#dlg form')!);
  await settle(150);
}

describe('dashboard', () => {
  it('renders one section per provider, with the redirect URI to register', async () => {
    await boot();
    expect(doc.querySelectorAll('section.provider')).toHaveLength(5);
    expect(doc.querySelector('h1')!.textContent).toBe('API Credentials');
    expect(q('#scope-select')!.textContent).toContain('Workspace: Acme');
    expect(metaSection().textContent).toContain('https://app.test/oauth/callback/meta');
    expect(metaSection().textContent).toContain('Not configured');
    expect(doc.querySelector('#app')!.getAttribute('aria-busy')).toBe('false');
  });

  it('uses provider-specific forms', async () => {
    await boot();
    const open = async (label: string) => {
      byText('Add configuration', q(`section[aria-label="${label}"]`)!)!.click();
      await settle();
      const ids = Array.from(doc.querySelectorAll('#dlg input')).map((i) => i.id);
      (byText('Cancel') as HTMLButtonElement).click();
      return ids;
    };
    expect(await open('Meta (Facebook / Instagram)')).toEqual(expect.arrayContaining(['f-app_id', 'f-app_secret', 'f-graph_api_version', 'f-webhook_verify_token']));
    expect(await open('TikTok')).toEqual(expect.arrayContaining(['f-client_key', 'f-client_secret']));
    expect(await open('X')).toEqual(expect.arrayContaining(['f-api_key_secret', 'f-bearer_token']));
  });

  it('secret inputs are password fields that opt out of autofill', async () => {
    await boot();
    byText('Add configuration', metaSection())!.click();
    await settle();
    const secret = q<HTMLInputElement>('#f-app_secret')!;
    expect(secret.type).toBe('password');
    expect(secret.autocomplete).toBe('new-password');
    expect(q<HTMLInputElement>('#f-app_id')!.type).toBe('text');
    expect(q<HTMLInputElement>('#f-graph_api_version')!.value).toBe('v21.0');
  });

  it('saves a configuration and afterwards shows only masked values, anywhere in the page', async () => {
    await boot();
    await addMeta();
    const card = metaSection().querySelector('article.config')!;
    expect(card.textContent).toContain('Main');
    expect(card.textContent).toContain('1234567890'); // identifier is fine to show
    expect(card.textContent).toMatch(/App Secret\s*•{8,}/);
    expect(card.textContent).toContain('Not yet tested');
    expect(doc.querySelector('#dlg')!.children.length).toBe(0); // dialog closed and emptied

    const everything = doc.documentElement.outerHTML + Array.from(doc.querySelectorAll('input')).map((i) => (i as HTMLInputElement).value).join('|');
    expect(everything).not.toContain(APP_SECRET);
    expect(everything).not.toContain(VERIFY);
    expect(t.dumpAll()).not.toContain(APP_SECRET);
  });

  it('editing shows empty secret inputs; leaving them blank keeps the stored secret', async () => {
    await boot();
    await addMeta();
    byText('Edit', metaSection())!.click();
    await settle();
    expect(q<HTMLInputElement>('#f-app_secret')!.value).toBe('');
    expect(q<HTMLInputElement>('#f-app_secret')!.placeholder).toContain('unchanged');
    expect(q<HTMLInputElement>('#f-app_id')!.value).toBe('1234567890');
    fill('f-graph_api_version', 'v22.0');
    q<HTMLInputElement>('#f-test')!.checked = false;
    submit(q('#dlg form')!);
    await settle(150);

    const stored = await new IntegrationCredentialService(env).getForProvider('meta', 'ws-a');
    expect(stored?.credentials).toMatchObject({ app_secret: APP_SECRET, webhook_verify_token: VERIFY, graph_api_version: 'v22.0' });
  });

  it('replaces a single secret without touching the others', async () => {
    await boot();
    await addMeta();
    byText('Edit', metaSection())!.click();
    await settle();
    fill('f-app_secret', 'ReplacementSecretValue0123456789ab');
    q<HTMLInputElement>('#f-test')!.checked = false;
    submit(q('#dlg form')!);
    await settle(150);
    const stored = await new IntegrationCredentialService(env).getForProvider('meta', 'ws-a');
    expect(stored?.credentials.app_secret).toBe('ReplacementSecretValue0123456789ab');
    expect(stored?.credentials.webhook_verify_token).toBe(VERIFY);
  });

  it('shows field-level validation errors inline and keeps the dialog open', async () => {
    await boot();
    byText('Add configuration', metaSection())!.click();
    await settle();
    fill('f-name', 'Bad');
    fill('f-app_id', 'not-numeric');
    fill('f-app_secret', 'x');
    submit(q('#dlg form')!);
    await settle(150);
    expect(q('#dlg')!.children.length).toBeGreaterThan(0);
    const errors = Array.from(doc.querySelectorAll('#dlg .ferr')).filter((e) => !(e as HTMLElement).hidden).map((e) => e.textContent);
    expect(errors.length).toBeGreaterThanOrEqual(2);
  });

  it('renders hostile configuration names as text, never as markup', async () => {
    await boot();
    await addMeta('<img src=x onerror=alert(1)>');
    expect(doc.querySelector('img')).toBeNull();
    expect(metaSection().querySelector('article h3')!.textContent).toBe('<img src=x onerror=alert(1)>');
  });

  it('delete requires typing the exact name', async () => {
    await boot();
    await addMeta();
    byText('Delete', metaSection())!.click();
    await settle();
    const confirm = byText('Delete configuration')!;
    expect(confirm.disabled).toBe(true);
    const input = q<HTMLInputElement>('#del-name')!;
    input.value = 'nope';
    input.dispatchEvent(new win.Event('input'));
    expect(confirm.disabled).toBe(true);
    input.value = 'Main';
    input.dispatchEvent(new win.Event('input'));
    expect(confirm.disabled).toBe(false);
    confirm.click();
    await settle(150);
    expect(metaSection().querySelector('article.config')).toBeNull();
    expect(metaSection().textContent).toContain('No configuration yet');
  });

  it('enable/disable toggles the status label', async () => {
    await boot();
    await addMeta();
    expect(byText('Disable', metaSection())).toBeTruthy();
    byText('Disable', metaSection())!.click();
    await settle(150);
    expect(metaSection().querySelector('.badge')!.textContent).toContain('Disabled');
    expect(byText('Enable', metaSection())).toBeTruthy();
  });

  it('webhook dialog issues a URL and explains token vs signing secret without showing values', async () => {
    await boot();
    await addMeta();
    byText('Webhook', metaSection())!.click();
    await settle();
    byText('Create callback URL')!.click();
    await settle(150);
    const dlg = q('#dlg')!;
    expect(q<HTMLInputElement>('#wh-url', dlg)!.value).toMatch(/^https:\/\/app\.test\/webhooks\/meta\/[\w-]{20,}$/);
    expect(dlg.textContent).toContain('Verification token');
    expect(dlg.textContent).toContain('Webhook verification token: set');
    expect(dlg.textContent).toContain('Payloads signed with');
    expect(dlg.textContent).toContain('App Secret');
    expect(dlg.outerHTML).not.toContain(APP_SECRET);
    expect(dlg.outerHTML).not.toContain(VERIFY);
  });

  it('unauthenticated visitors see a sign-in message and no data', async () => {
    const dom = new JSDOM(html, { url: 'https://app.test/settings/integrations', runScripts: 'outside-only' });
    win = dom.window; doc = win.document;
    win.fetch = (path: string, init: any = {}) => app.request(`https://app.test${path}`, init, env);
    win.eval(js);
    await settle(120);
    expect(doc.querySelector('#app')!.textContent).toContain('Sign in');
    expect(doc.querySelectorAll('section.provider')).toHaveLength(0);
  });

  it('members who manage no workspace see an explanation, not forms', async () => {
    await boot('bob');
    expect(doc.querySelector('#app')!.textContent).toContain('do not manage any workspaces');
    expect(doc.querySelectorAll('section.provider')).toHaveLength(0);
  });

  it('app owner gets the platform scope and can add a shared configuration', async () => {
    await boot('owner');
    expect(q('#scope-select')!.textContent).toContain('Platform');
    expect(doc.querySelectorAll('section.provider')).toHaveLength(5);
    await addMeta('Shared');
    const stored = await new IntegrationCredentialService(env).getForProvider('meta'); // no workspace => global only
    expect(stored).toMatchObject({ scope: 'global', workspaceId: null, configurationName: 'Shared' });
    // and a workspace with no app of its own now resolves to the shared one
    expect((await new IntegrationCredentialService(env).getForProvider('meta', 'ws-b'))?.scope).toBe('global');
  });
});

describe('dashboard route', () => {
  it('serves the page with a CSP that forbids inline script and framing', async () => {
    const e = { ...env, ASSETS: { fetch: async () => new Response(html, { headers: { 'content-type': 'text/html' } }) } };
    const r = await app.request('https://app.test/settings/integrations', {}, e);
    const csp = r.headers.get('content-security-policy')!;
    expect(r.status).toBe(200);
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).toContain("frame-ancestors 'none'");
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)/i); // no inline scripts in the page
    expect(js).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/);
  });

  it('reports a missing ASSETS binding clearly', async () => {
    const r = await app.request('https://app.test/settings/integrations', {}, env);
    expect(r.status).toBe(500);
    expect(await r.text()).toContain('ASSETS');
  });
});
