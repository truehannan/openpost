/* Settings → Integrations → API Credentials
 * No HTML strings are ever built: all server-provided text goes through textContent, so
 * nothing returned by the API can be interpreted as markup.
 * The page only ever receives masked values; it has no access to stored secrets. */
(function () {
  'use strict';

  var state = { me: null, providers: [], scope: null, integrations: [], accounts: [], availability: {} };

  // ------------------------------------------------------------------ helpers
  function h(tag, attrs) {
    var el = document.createElement(tag);
    var a = attrs || {};
    Object.keys(a).forEach(function (k) {
      var v = a[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    });
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }
  function append(el, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) return c.forEach(function (x) { append(el, x); });
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  var $ = function (s) { return document.querySelector(s); };

  function api(method, path, body) {
    var init = { method: method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) { init.headers['content-type'] = 'application/json'; init.body = JSON.stringify(body); }
    return fetch(path, init).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var e = new Error((data && data.error && data.error.message) || 'Request failed (' + res.status + ')');
          e.code = data && data.error && data.error.code;
          e.details = data && data.error && data.error.details;
          e.status = res.status;
          throw e;
        }
        return data;
      });
    });
  }

  function toast(msg, kind) {
    var t = h('div', { class: 'toast' + (kind === 'error' ? ' error' : ''), text: msg });
    $('#toasts').append(t);
    setTimeout(function () { t.remove(); }, 6500);
  }

  function fmtTime(s) {
    if (!s) return 'never';
    var d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : s.replace(' ', 'T') + 'Z');
    return isNaN(d) ? s : d.toLocaleString();
  }

  function copy(text) {
    var done = function () { toast('Copied'); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () { toast('Copy failed', 'error'); });
    else toast('Copy is not available in this browser', 'error');
  }

  // ------------------------------------------------------------------ dialogs
  function openDialog(content) {
    var d = $('#dlg');
    d.replaceChildren(content);
    if (d.showModal) { if (!d.open) d.showModal(); } else d.setAttribute('open', '');
    var first = d.querySelector('input:not([readonly]), button');
    if (first) first.focus();
  }
  function closeDialog() {
    var d = $('#dlg');
    if (d.close) d.close(); else d.removeAttribute('open');
    d.replaceChildren();
  }

  function confirmDialog(title, message, confirmLabel, onConfirm) {
    var err = h('div', { class: 'alert', role: 'alert', hidden: true });
    var btn = h('button', { class: 'danger solid', type: 'button', text: confirmLabel });
    btn.addEventListener('click', function () {
      btn.disabled = true;
      Promise.resolve(onConfirm()).then(closeDialog, function (e) { err.hidden = false; err.textContent = e.message; btn.disabled = false; });
    });
    openDialog(h('div', {}, h('h2', { text: title }), h('p', { text: message }), err,
      h('div', { class: 'dialog-actions' }, h('button', { type: 'button', text: 'Cancel', onclick: closeDialog }), btn)));
  }

  // --------------------------------------------------------------------- data
  function providerSpec(id) { return state.providers.filter(function (p) { return p.id === id; })[0]; }
  function isGlobal() { return state.scope && state.scope.kind === 'global'; }

  function load() {
    $('#app').setAttribute('aria-busy', 'true');
    var calls = [];
    if (!state.me) calls.push(api('GET', '/api/me').then(function (r) { state.me = r; }));
    if (!state.providers.length) calls.push(api('GET', '/api/integrations/providers').then(function (r) { state.providers = r.providers; }));
    return Promise.all(calls).then(function () {
      if (!state.scope) state.scope = defaultScope();
      renderScopeBar();
      if (!state.scope) return renderEmpty('You do not manage any workspaces. Ask a workspace owner or admin to configure integrations.');
      return loadScope();
    }).catch(function (e) {
      renderEmpty(e.status === 401 ? 'Sign in to manage API credentials.' : e.message);
    }).then(function () { $('#app').setAttribute('aria-busy', 'false'); });
  }

  function manageable() {
    return (state.me.workspaces || []).filter(function (w) { return w.role === 'owner' || w.role === 'admin'; });
  }
  function defaultScope() {
    var ws = manageable();
    if (ws.length) return { kind: 'workspace', id: ws[0].id };
    return state.me.isAppOwner ? { kind: 'global' } : null;
  }

  function loadScope() {
    if (isGlobal()) {
      return api('GET', '/api/admin/integrations').then(function (r) {
        state.integrations = r.integrations; state.accounts = []; state.availability = {}; render();
      });
    }
    var base = '/api/workspaces/' + encodeURIComponent(state.scope.id);
    return Promise.all([api('GET', base + '/integrations'), api('GET', base + '/accounts'), api('GET', base + '/integrations/availability')])
      .then(function (r) {
        state.integrations = r[0].integrations; state.accounts = r[1].accounts; state.availability = r[2].availability; render();
      });
  }

  // ------------------------------------------------------------------- render
  function renderScopeBar() {
    var bar = $('#scope-bar');
    var sel = h('select', { id: 'scope-select', 'aria-label': 'Whose credentials to manage' });
    manageable().forEach(function (w) {
      sel.append(h('option', { value: 'workspace:' + w.id, text: 'Workspace: ' + w.name, selected: state.scope && state.scope.kind === 'workspace' && state.scope.id === w.id }));
    });
    if (state.me && state.me.isAppOwner) sel.append(h('option', { value: 'global', text: 'Platform (shared by all workspaces)', selected: isGlobal() }));
    sel.addEventListener('change', function () {
      var v = sel.value;
      state.scope = v === 'global' ? { kind: 'global' } : { kind: 'workspace', id: v.split(':')[1] };
      loadScope().catch(function (e) { toast(e.message, 'error'); });
    });
    bar.replaceChildren(h('label', { for: 'scope-select', text: 'Managing' }), sel);
    if (state.scope) bar.append(h('span', { class: 'muted', text: isGlobal()
      ? 'Used by any workspace that has not configured its own app.'
      : 'A workspace’s own app takes priority over the shared platform app.' }));
  }

  function renderEmpty(msg) { $('#app').replaceChildren(h('p', { class: 'muted', text: msg })); }

  function render() {
    $('#app').replaceChildren.apply($('#app'), state.providers.map(renderProvider));
  }

  function badgeClass(c) {
    if (c.statusLabel === 'Connected') return 'ok';
    if (c.statusLabel === 'Invalid credentials') return 'bad';
    if (c.statusLabel === 'Configuration incomplete' || c.statusLabel === 'Not yet tested') return 'warn';
    return '';
  }
  function badgeIcon(c) {
    return { 'Connected': '✓', 'Invalid credentials': '✕', 'Configuration incomplete': '!', 'Not yet tested': '○', 'Disabled': '–' }[c.statusLabel] || '';
  }

  function availabilityPill(id) {
    if (isGlobal()) return null;
    var a = state.availability[id];
    var t = a === 'workspace' ? 'Using this workspace’s app' : a === 'global' ? 'Using the platform’s shared app' : 'Not configured';
    return h('span', { class: 'pill', text: t });
  }

  function renderProvider(p) {
    var configs = state.integrations.filter(function (c) { return c.provider === p.id; });
    var canConnect = !isGlobal() && state.availability[p.id] && state.availability[p.id] !== 'none';

    var head = h('header', {}, h('div', {}, h('h2', { text: p.label }), availabilityPill(p.id)),
      h('div', { class: 'actions', style: 'margin:0' },
        canConnect ? h('button', { type: 'button', text: 'Connect account', onclick: function () { connectAccount(p, null); } }) : null,
        h('button', { type: 'button', class: 'primary', text: 'Add configuration', onclick: function () { openForm(p, null); } })));

    var redirect = h('div', { class: 'meta' }, 'OAuth redirect URI to register with ' + p.label + ':',
      h('code', { text: p.oauthRedirectUri }), h('button', { type: 'button', text: 'Copy', onclick: function () { copy(p.oauthRedirectUri); } }));

    var body = configs.length ? configs.map(function (c) { return renderConfig(p, c); })
      : h('div', { class: 'empty', text: 'No configuration yet. Add your ' + p.label + ' app credentials to get started.' });

    var accts = state.accounts.filter(function (a) { return a.provider === p.id; });
    return h('section', { class: 'provider', 'aria-label': p.label }, head, redirect, body, accts.length ? renderAccounts(p, accts) : null);
  }

  function renderConfig(p, c) {
    var fields = h('dl', { class: 'fields' });
    c.fields.forEach(function (f) {
      fields.append(h('dt', { text: f.label }));
      fields.append(h('dd', { class: f.isSet ? 'mono' : 'muted', text: f.isSet ? f.display : (f.required ? 'Required – not set' : 'Not set') }));
    });

    var toggle = h('button', { type: 'button', text: c.enabled ? 'Disable' : 'Enable', onclick: function () {
      api('POST', '/api/integrations/' + c.id + (c.enabled ? '/disable' : '/enable')).then(function () { toast(c.enabled ? 'Disabled' : 'Enabled'); return loadScope(); }, function (e) { toast(e.message, 'error'); });
    } });
    var test = h('button', { type: 'button', text: 'Test connection', onclick: function () {
      test.disabled = true; test.textContent = 'Testing…';
      api('POST', '/api/integrations/' + c.id + '/test').then(function (r) {
        var i = r.integration; toast(i.validationStatus === 'valid' ? 'Credentials verified' : (i.lastError || 'Could not verify credentials'), i.validationStatus === 'valid' ? undefined : 'error');
        return loadScope();
      }, function (e) { toast(e.message, 'error'); test.disabled = false; test.textContent = 'Test connection'; });
    } });

    return h('article', { class: 'config' },
      h('div', { class: 'config-head' }, h('h3', { text: c.configurationName }),
        h('span', {}, h('span', { class: 'badge ' + badgeClass(c) }, h('span', { 'aria-hidden': 'true', text: badgeIcon(c) }), c.statusLabel),
          ' ', h('span', { class: 'pill', text: c.scope === 'global' ? 'Platform' : 'Workspace' }))),
      fields,
      h('div', { class: 'facts' },
        h('span', { text: 'Last validated: ' + fmtTime(c.lastValidatedAt) }),
        h('span', { text: 'Connected accounts: ' + c.connectedAccountCount })),
      c.lastError ? h('div', { class: 'error-line', role: 'status', text: 'Last error: ' + c.lastError }) : null,
      h('details', {}, h('summary', { text: 'Required permissions (' + c.requiredPermissions.length + ')' }),
        h('ul', {}, c.requiredPermissions.map(function (x) { return h('li', {}, h('code', { text: x })); }))),
      h('div', { class: 'actions' },
        h('button', { type: 'button', text: 'Edit', onclick: function () { openForm(p, c); } }),
        test, toggle,
        p.webhook.supported ? h('button', { type: 'button', text: 'Webhook', onclick: function () { openWebhook(p, c); } }) : null,
        h('button', { type: 'button', class: 'danger', text: 'Delete', onclick: function () { openDelete(c); } })));
  }

  function renderAccounts(p, accts) {
    return h('div', { class: 'accounts' }, h('h4', { text: 'Connected accounts' }),
      accts.map(function (a) {
        var cfg = state.integrations.filter(function (c) { return c.id === a.credentialConfigId; })[0];
        return h('div', { class: 'account' },
          h('span', {}, h('strong', { text: a.displayName || a.providerAccountId }), ' ',
            h('span', { class: 'badge ' + (a.status === 'active' ? 'ok' : a.status === 'error' ? 'warn' : 'bad'), text: a.status }),
            h('span', { class: 'muted', text: ' via ' + (cfg ? cfg.configurationName : 'platform app') })),
          h('span', { class: 'actions', style: 'margin:0' },
            a.status !== 'active' ? h('button', { type: 'button', text: 'Reconnect', onclick: function () { connectAccount(p, a.credentialConfigId); } }) : null,
            h('button', { type: 'button', class: 'danger', text: 'Disconnect', onclick: function () {
              confirmDialog('Disconnect account?', 'Stored tokens for ' + (a.displayName || a.providerAccountId) + ' will be deleted.', 'Disconnect', function () {
                return api('DELETE', '/api/accounts/' + a.id).then(function () { toast('Disconnected'); return loadScope(); });
              });
            } })));
      }));
  }

  function connectAccount(p, configId) {
    api('POST', '/api/workspaces/' + encodeURIComponent(state.scope.id) + '/oauth/' + p.id + '/start', configId ? { configId: configId } : {})
      .then(function (r) {
        var u = new URL(r.authorizeUrl);
        if (u.protocol !== 'https:') throw new Error('Unexpected authorization URL.');
        window.location.assign(u.toString());
      }, function (e) { toast(e.message, 'error'); });
  }

  // ----------------------------------------------------------- create / edit
  function openForm(p, existing) {
    var editing = !!existing;
    var inputs = {}, clears = {}, errs = {};
    var name = h('input', { type: 'text', id: 'f-name', maxlength: '80', value: editing ? existing.configurationName : '', required: true });
    var nameErr = h('div', { class: 'ferr', hidden: true });
    var general = h('div', { class: 'alert', role: 'alert', hidden: true });
    var allowChange = h('input', { type: 'checkbox', id: 'f-allow' });
    var allowRow = h('div', { class: 'note', hidden: true }, h('label', {}, allowChange, ' I understand connected accounts will need to be reconnected.'));
    var testAfter = h('input', { type: 'checkbox', id: 'f-test', checked: true });
    var enableAfter = h('input', { type: 'checkbox', id: 'f-enable', checked: true });

    var fieldEls = p.fields.map(function (f) {
      var cur = editing ? existing.fields.filter(function (x) { return x.key === f.key; })[0] : null;
      var id = 'f-' + f.key;
      var input = h('input', {
        type: f.secret ? 'password' : 'text', id: id, autocomplete: f.secret ? 'new-password' : 'off', spellcheck: 'false', autocapitalize: 'off',
        value: !f.secret && cur && cur.isSet ? cur.display : (!f.secret && !editing && f.default ? f.default : ''),
        placeholder: f.secret && cur && cur.isSet ? '••••••••  (unchanged)' : '',
        'aria-describedby': id + '-help'
      });
      inputs[f.key] = input;
      errs[f.key] = h('div', { class: 'ferr', hidden: true, role: 'alert' });
      var clearBox = null;
      if (editing && cur && cur.isSet && !f.required) {
        clearBox = h('label', { class: 'hint' }, h('input', { type: 'checkbox', onchange: function (ev) { input.disabled = ev.target.checked; } }), ' Clear this value');
        clears[f.key] = clearBox.querySelector('input');
      }
      return h('div', { class: 'field' },
        h('label', { for: id }, f.label, f.required ? h('span', { class: 'req', 'aria-hidden': 'true', text: ' *' }) : null),
        input,
        h('div', { class: 'help', id: id + '-help', text: [f.secret ? (editing && cur && cur.isSet ? 'Currently set. Type a new value to replace it, or leave blank to keep it.' : 'Stored encrypted; not shown again after saving.') : null, f.help, f.patternHint].filter(Boolean).join(' ') }),
        errs[f.key], clearBox);
    });

    function showErrors(e) {
      general.hidden = true; nameErr.hidden = true;
      Object.keys(errs).forEach(function (k) { errs[k].hidden = true; });
      var shown = false;
      if (Array.isArray(e.details)) e.details.forEach(function (d) {
        if (errs[d.field]) { errs[d.field].textContent = d.message; errs[d.field].hidden = false; shown = true; }
      });
      if (e.code === 'CLIENT_ID_CHANGE_BLOCKED') allowRow.hidden = false;
      if (!shown || e.code !== 'VALIDATION') { general.textContent = e.message; general.hidden = false; }
    }

    var save = h('button', { type: 'submit', class: 'primary', text: editing ? 'Save changes' : 'Save configuration' });
    var form = h('form', { novalidate: true },
      h('h2', { text: (editing ? 'Edit ' : 'Add ') + p.label + ' configuration' }),
      general,
      h('div', { class: 'field' }, h('label', { for: 'f-name', text: 'Configuration name' }), name, nameErr,
        h('div', { class: 'help', text: 'For example “Main app”. You can keep several apps per provider.' })),
      fieldEls, allowRow,
      editing ? null : h('div', { class: 'field' }, h('label', {}, enableAfter, ' Enable after saving')),
      h('div', { class: 'field' }, h('label', {}, testAfter, ' Test connection after saving')),
      h('div', { class: 'dialog-actions' }, h('button', { type: 'button', text: 'Cancel', onclick: closeDialog }), save));

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var creds = {};
      p.fields.forEach(function (f) {
        var v = inputs[f.key].value.trim();
        var cur = editing ? existing.fields.filter(function (x) { return x.key === f.key; })[0] : null;
        if (clears[f.key] && clears[f.key].checked) { creds[f.key] = null; return; }
        if (!v) return;                                   // blank = keep (edit) or omit (create)
        if (editing && !f.secret && cur && cur.display === v) return; // unchanged identifier
        creds[f.key] = v;
      });
      save.disabled = true;
      var req;
      if (editing) {
        var body = { credentials: creds };
        if (name.value.trim() !== existing.configurationName) body.configurationName = name.value.trim();
        if (allowChange.checked) body.allowClientIdChange = true;
        req = api('PATCH', '/api/integrations/' + existing.id, body);
      } else {
        req = api(isGlobal() ? 'POST' : 'POST', isGlobal() ? '/api/admin/integrations' : '/api/workspaces/' + encodeURIComponent(state.scope.id) + '/integrations',
          { provider: p.id, configurationName: name.value.trim(), credentials: creds, enabled: enableAfter.checked });
      }
      req.then(function (r) {
        var id = r.integration.id;
        closeDialog();
        toast('Saved');
        return (testAfter.checked && r.integration.validationStatus !== 'incomplete' ? api('POST', '/api/integrations/' + id + '/test').then(function (t) {
          var ok = t.integration.validationStatus === 'valid';
          toast(ok ? 'Credentials verified' : (t.integration.lastError || 'Could not verify credentials'), ok ? undefined : 'error');
        }, function () {}) : null);
      }).then(loadScope, function (e) { showErrors(e); save.disabled = false; });
    });
    openDialog(form);
  }

  // ------------------------------------------------------------------ delete
  function openDelete(c) {
    var input = h('input', { type: 'text', id: 'del-name', autocomplete: 'off' });
    var btn = h('button', { type: 'button', class: 'danger solid', text: 'Delete configuration', disabled: true });
    var err = h('div', { class: 'alert', role: 'alert', hidden: true });
    input.addEventListener('input', function () { btn.disabled = input.value !== c.configurationName; });
    btn.addEventListener('click', function () {
      btn.disabled = true;
      api('DELETE', '/api/integrations/' + c.id, { confirmName: input.value }).then(function () { closeDialog(); toast('Deleted'); return loadScope(); },
        function (e) { err.textContent = e.message; err.hidden = false; btn.disabled = false; });
    });
    openDialog(h('div', {}, h('h2', { text: 'Delete configuration?' }),
      h('p', {}, 'This permanently removes the encrypted credentials for ', h('strong', { text: c.configurationName }), '. It cannot be undone.'),
      c.connectedAccountCount ? h('div', { class: 'note', text: c.connectedAccountCount + ' connected account(s) use this configuration. Disconnect them first, or disable the configuration instead.' }) : null,
      err,
      h('div', { class: 'field' }, h('label', { for: 'del-name', text: 'Type the configuration name to confirm' }), input),
      h('div', { class: 'dialog-actions' }, h('button', { type: 'button', text: 'Cancel', onclick: closeDialog }), btn)));
  }

  // ----------------------------------------------------------------- webhook
  function openWebhook(p, c) {
    var box = h('div', {}, h('p', { class: 'muted', text: 'Loading…' }));
    openDialog(h('div', {}, h('h2', { text: p.label + ' webhook – ' + c.configurationName }), box,
      h('div', { class: 'dialog-actions' }, h('button', { type: 'button', text: 'Close', onclick: closeDialog }))));
    var label = function (key) { var f = c.fields.filter(function (x) { return x.key === key; })[0]; return f ? f.label : key; };

    function show() {
      return api('GET', '/api/integrations/' + c.id + '/webhook').then(function (r) {
        var w = r.webhook;
        var kids = [];
        if (w.note) kids.push(h('div', { class: 'note', text: w.note }));
        if (!w.callbackUrl) {
          kids.push(h('p', { text: 'No callback URL has been issued for this configuration yet.' }),
            h('button', { type: 'button', class: 'primary', text: 'Create callback URL', onclick: function () {
              api('POST', '/api/integrations/' + c.id + '/webhook/enable').then(show, function (e) { toast(e.message, 'error'); });
            } }));
        } else {
          var urlInput = h('input', { type: 'text', readonly: true, value: w.callbackUrl, id: 'wh-url', 'aria-label': 'Webhook callback URL' });
          kids.push(h('div', { class: 'field' }, h('label', { for: 'wh-url', text: 'Callback URL' }),
            h('div', { class: 'row' }, urlInput, h('button', { type: 'button', text: 'Copy', onclick: function () { copy(w.callbackUrl); } }))));
          kids.push(h('dl', { class: 'fields' },
            h('dt', { text: 'Subscription' }), h('dd', {}, h('span', { class: 'badge ' + (w.subscriptionStatus === 'active' ? 'ok' : 'warn'), text: w.subscriptionStatus })),
            w.verifyTokenField ? [h('dt', { text: 'Verification token' }), h('dd', { text: label(w.verifyTokenField) + ': ' + (w.verifyTokenConfigured ? 'set' : 'not set – add it by editing the configuration') })] : null,
            w.signingSecretField ? [h('dt', { text: 'Payloads signed with' }), h('dd', { text: label(w.signingSecretField) })] : null,
            h('dt', { text: 'Last event' }), h('dd', { text: fmtTime(w.lastEventAt) })));
          if (w.lastError) kids.push(h('div', { class: 'error-line', text: 'Last error: ' + w.lastError }));
          kids.push(h('h4', { text: 'Recent deliveries' }));
          kids.push(w.recentEvents.length ? h('table', {}, h('thead', {}, h('tr', {}, h('th', { text: 'Received' }), h('th', { text: 'Status' }), h('th', { text: 'Signature' }), h('th', { text: 'Detail' }))),
            h('tbody', {}, w.recentEvents.map(function (e) {
              return h('tr', {}, h('td', { text: fmtTime(e.receivedAt) }), h('td', { text: e.status }), h('td', { text: e.signatureValid ? 'valid' : 'invalid' }), h('td', { text: e.error || '' }));
            }))) : h('p', { class: 'muted', text: 'No deliveries yet.' }));
          kids.push(h('div', { class: 'actions' },
            h('button', { type: 'button', text: 'Refresh', onclick: show }),
            h('button', { type: 'button', class: 'danger', text: 'Rotate callback URL', onclick: function () {
              confirmDialog('Rotate callback URL?', 'The current URL stops working immediately. Update it in the ' + p.label + ' developer dashboard afterwards.', 'Rotate', function () {
                return api('POST', '/api/integrations/' + c.id + '/webhook/rotate-key').then(function () { toast('URL rotated'); openWebhook(p, c); });
              });
            } })));
        }
        box.replaceChildren.apply(box, kids.flat());
      }, function (e) { box.replaceChildren(h('div', { class: 'alert', text: e.message })); });
    }
    show();
  }

  // -------------------------------------------------------------------- boot
  var ERRORS = {
    UNAUTHENTICATED: 'Sign in again, then retry connecting the account.',
    FORBIDDEN: 'That connection attempt belongs to a different user or workspace.',
    VALIDATION: 'The connection could not be completed. It may have expired or been declined. Please try again.',
    CONFIG_DISABLED: 'The integration was disabled or removed while connecting.',
    DECRYPT_FAILED: 'Stored credentials could not be read. Check SECRET_KEY.',
    SECRET_KEY_INVALID: 'SECRET_KEY is missing or invalid.'
  };
  function handleReturn() {
    var q = new URLSearchParams(window.location.search);
    if (q.get('connected')) toast('Connected ' + q.get('connected') + ' account');
    else if (q.get('error')) toast(ERRORS[q.get('error')] || 'Could not connect the account.', 'error');
    if (q.get('connected') || q.get('error')) window.history.replaceState(null, '', window.location.pathname);
  }

  function boot() { handleReturn(); load(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
