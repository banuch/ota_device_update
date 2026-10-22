'use strict';
// OTA Console -- single-page dashboard (no build step).
// Routes: #/overview  #/devices  #/devices/<imei>  #/releases  #/history  #/users  #/account
(() => {
  const view = document.getElementById('view');
  let me = null;
  const isAdmin = () => me && me.role === 'admin';

  // ── helpers ─────────────────────────────────────────────────────────────
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtTime = (sec) => (sec ? new Date(sec * 1000).toLocaleString() : '—');
  const fmtSize = (n) => (n > 1048576 ? (n / 1048576).toFixed(2) + ' MB' : (n / 1024).toFixed(1) + ' KB');
  function fmtAgo(sec) {
    if (!sec) return 'never';
    const d = Math.max(0, Date.now() / 1000 - sec);
    if (d < 90) return 'just now';
    if (d < 3600) return Math.round(d / 60) + ' min ago';
    if (d < 172800) return Math.round(d / 3600) + ' h ago';
    return Math.round(d / 86400) + ' d ago';
  }
  const fmtInterval = (s) => (s % 86400 === 0 ? s / 86400 + ' d' : s % 3600 === 0 ? s / 3600 + ' h' : Math.round(s / 60) + ' min');

  function toast(msg, isErr = false) {
    const el = document.createElement('div');
    el.className = 'toast' + (isErr ? ' err' : '');
    el.textContent = msg;
    document.getElementById('toast').appendChild(el);
    setTimeout(() => el.remove(), isErr ? 6000 : 3000);
  }

  async function api(method, path, body) {
    const headers = { 'X-OTA-Console': '1' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    if (res.status === 401) { location.replace('login.html'); throw new Error('Session expired'); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }
  const run = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

  const STATUS_CLASS = { running: 'ok', flashed: 'warn', downloading: 'warn', failed: 'bad', md5_fail: 'bad' };
  const statusChip = (s) => (s ? `<span class="chip ${STATUS_CLASS[s] || ''}">${esc(s)}</span>` : '<span class="muted">—</span>');
  const EVENT_CLASS = { ...STATUS_CLASS, offered: 'info', denied: 'bad', login_failed: 'bad', error: 'bad',
    download_aborted: 'bad', download_sent: 'ok', registered: 'info', registration_requested: 'warn',
    registration_key_changed: 'warn', registration_approved: 'ok', registration_rejected: 'bad', key_delivered: 'ok' };
  const eventChip = (t) => `<span class="chip ${EVENT_CLASS[t] || ''}">${esc(t)}</span>`;
  function targetCell(d) {
    if (d.reg_state === 'rejected') return '<span class="chip bad">rejected</span>';
    if (d.awaiting_approval) return '<span class="chip warn">awaiting approval</span>';
    if (!d.enabled) return '<span class="chip">disabled</span>';
    if (d.pending) return `<span class="chip warn">→ ${esc(d.target)}</span>`;
    if (d.target_reason === 'never_checked') return '<span class="muted">never checked</span>';
    return '<span class="chip ok">up to date</span>';
  }
  const versionOptions = (releases, selected, emptyLabel) =>
    `<option value="">${esc(emptyLabel)}</option>` +
    releases.map((r) => `<option value="${esc(r.version)}" ${r.version === selected ? 'selected' : ''}>${esc(r.version)}</option>`).join('');

  function eventsTable(events, { showImei = true } = {}) {
    if (!events.length) return '<div class="empty">No events.</div>';
    return `<div class="table-wrap"><table><thead><tr><th>Time</th>${showImei ? '<th>Device</th>' : ''}
      <th>Event</th><th>Version</th><th>By</th><th>Detail</th></tr></thead><tbody>
      ${events.map((e) => `<tr><td title="${esc(fmtTime(e.ts))}">${esc(fmtTime(e.ts))}</td>
        ${showImei ? `<td class="mono">${e.imei === '-' ? '<span class="muted">system</span>'
          : `<a href="#/devices/${esc(e.imei)}">${esc(e.imei)}</a>`}</td>` : ''}
        <td>${eventChip(e.type)}</td><td class="mono">${esc(e.version || '')}</td>
        <td>${esc(e.actor || '')}</td><td class="wrap muted">${esc(e.detail)}</td></tr>`).join('')}
      </tbody></table></div>`;
  }

  // ── router ──────────────────────────────────────────────────────────────
  const routes = {};
  async function render() {
    const parts = (location.hash.replace(/^#\/?/, '') || 'overview').split('/');
    const name = routes[parts[0]] ? parts[0] : 'overview';
    if (name === 'users' && !isAdmin()) { location.hash = '#/overview'; return; }
    document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === name));
    document.body.classList.remove('nav-open');
    try {
      await routes[name](parts.slice(1).map(decodeURIComponent));
    } catch (e) {
      view.innerHTML = `<div class="card"><div class="alert">${esc(e.message)}</div></div>`;
    }
  }

  // ── Overview ────────────────────────────────────────────────────────────
  routes.overview = async () => {
    const [s, releases] = await Promise.all([api('GET', 'api/stats'), api('GET', 'api/releases')]);
    const max = Math.max(1, ...s.versions.map((v) => v.count));
    view.innerHTML = `
      <div class="page-head"><div><h1>Overview</h1><div class="sub">Fleet state right now</div></div>
        <button class="ghost" id="refresh">Refresh</button></div>
      ${s.awaiting_approval ? `<div class="alert warn" style="margin-bottom:16px">
        <strong>${s.awaiting_approval}</strong> device(s) waiting for registration approval.
        <a href="#/devices" id="goAwaiting">Review →</a></div>` : ''}
      <div class="grid cols-4">
        <div class="card stat"><div class="label">Devices</div><div class="value">${s.devices}</div>
          <div class="hint">${s.disabled} disabled</div></div>
        <div class="card stat ok"><div class="label">Online</div><div class="value">${s.online}</div>
          <div class="hint">checked in within their interval</div></div>
        <div class="card stat ${s.pending ? 'warn' : ''}"><div class="label">Pending updates</div><div class="value">${s.pending}</div>
          <div class="hint">running ≠ target version</div></div>
        <div class="card stat ${s.failed_24h.events ? 'bad' : ''}"><div class="label">Failed updates (24 h)</div>
          <div class="value">${s.failed_24h.events}</div><div class="hint">${s.failed_24h.devices} device(s)</div></div>
      </div>
      <div class="grid cols-2" style="margin-top:16px">
        <div class="card"><h2>Versions in the field</h2>
          ${s.versions.length ? `<div class="bars">${s.versions.map((v) => `<div class="bar">
            <span class="mono">${esc(v.version)}</span>
            <div class="track"><div class="fill" style="width:${(v.count / max) * 100}%"></div></div>
            <span class="n">${v.count}</span></div>`).join('')}</div>` : '<div class="empty">No devices yet.</div>'}
        </div>
        <div class="card"><h2>Channels</h2>
          <p class="muted" style="margin-top:-6px">Devices without a pinned version follow their channel (upgrades only).</p>
          ${s.channels.map((c) => `<div class="row" style="margin-bottom:10px">
            <strong style="width:60px">${esc(c.name)}</strong>
            ${isAdmin()
              ? `<select data-channel="${esc(c.name)}">${versionOptions(releases, c.version, '— no release —')}</select>`
              : `<span class="mono">${esc(c.version || '— no release —')}</span>`}
            <span class="muted">${c.updated_at ? 'changed ' + fmtAgo(c.updated_at) : ''}</span></div>`).join('')}
        </div>
      </div>
      <div class="card" style="margin-top:16px"><div class="row"><h2>Recent activity</h2><span class="spacer"></span>
        <a href="#/history">All history →</a></div>${eventsTable(s.recent)}</div>`;
    view.querySelector('#refresh').onclick = render;
    const goAwaiting = view.querySelector('#goAwaiting');
    if (goAwaiting) goAwaiting.onclick = () => { devFilter.state = 'awaiting'; };
    view.querySelectorAll('[data-channel]').forEach((sel) => {
      sel.onchange = run(async () => {
        await api('PUT', `api/channels/${sel.dataset.channel}`, { version: sel.value || null });
        toast(`Channel ${sel.dataset.channel} → ${sel.value || 'none'}`);
        render();
      });
    });
  };

  // ── Devices list ────────────────────────────────────────────────────────
  const devFilter = { q: '', channel: '', state: '', version: '' };
  const selected = new Set();

  routes.devices = async (args) => {
    if (args[0]) return deviceDetail(args[0]);
    const [devices, releases] = await Promise.all([api('GET', 'api/devices'), api('GET', 'api/releases')]);
    const versions = [...new Set(devices.map((d) => d.current_ver).filter(Boolean))].sort();
    for (const imei of [...selected]) if (!devices.some((d) => d.imei === imei)) selected.delete(imei);

    view.innerHTML = `
      <div class="page-head"><div><h1>Devices</h1><div class="sub">${devices.length} registered</div></div>
        <form id="addDev" class="row admin-only">
          <input name="imei" placeholder="IMEI (15 digits)" required pattern="\\d{14,17}" style="width:170px">
          <input name="label" placeholder="Label (optional)" style="width:150px">
          <button class="primary">Add device</button></form></div>
      <div class="card">
        <div class="toolbar">
          <input type="search" id="q" placeholder="Search IMEI or label…" value="${esc(devFilter.q)}">
          <select id="fChannel"><option value="">All channels</option><option>stable</option><option>beta</option></select>
          <select id="fState"><option value="">Any state</option><option value="awaiting">Awaiting approval</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option><option value="pending">Update pending</option>
            <option value="failed">Last update failed</option><option value="pinned">Pinned</option>
            <option value="disabled">Disabled</option></select>
          <select id="fVersion"><option value="">Any version</option>${versions.map((v) => `<option>${esc(v)}</option>`).join('')}</select>
          <span class="spacer"></span><span class="muted" id="count"></span>
        </div>
        <div id="bulk" class="bulkbar admin-only hidden">
          <strong id="bulkN"></strong>
          <select id="bChannel"><option value="">Set channel…</option><option>stable</option><option>beta</option></select>
          <select id="bPin"><option value="">Pin version…</option><option value="__none">Unpin (follow channel)</option>
            ${releases.map((r) => `<option>${esc(r.version)}</option>`).join('')}</select>
          <button id="bEnable">Enable</button><button id="bDisable" class="danger">Disable</button>
          <button id="bApprove" class="primary">Approve registration</button>
          <span class="spacer"></span><button class="ghost" id="bClear">Clear selection</button>
        </div>
        <div class="table-wrap"><table><thead><tr>
          <th class="admin-only" style="width:32px"><input type="checkbox" id="all" aria-label="Select all"></th>
          <th></th><th>IMEI</th><th>Label</th><th>Running</th><th>Target</th><th>Last status</th>
          <th>Last seen</th><th>Channel</th><th>Pinned</th></tr></thead><tbody id="rows"></tbody></table></div>
      </div>`;

    const $ = (s) => view.querySelector(s);
    $('#fChannel').value = devFilter.channel;
    $('#fState').value = devFilter.state;
    $('#fVersion').value = devFilter.version;

    const matches = (d) => {
      const q = devFilter.q.trim().toLowerCase();
      if (q && !d.imei.includes(q) && !d.label.toLowerCase().includes(q)) return false;
      if (devFilter.channel && d.channel !== devFilter.channel) return false;
      if (devFilter.version && d.current_ver !== devFilter.version) return false;
      switch (devFilter.state) {
        case 'awaiting': return d.awaiting_approval;
        case 'online': return d.online;
        case 'offline': return !d.online;
        case 'pending': return d.pending;
        case 'failed': return d.last_status === 'failed' || d.last_status === 'md5_fail';
        case 'pinned': return !!d.pinned_version;
        case 'disabled': return !d.enabled;
        default: return true;
      }
    };

    function draw() {
      const shown = devices.filter(matches);
      // Bulk actions apply to the selection, so never keep rows the filters hide.
      const shownIds = new Set(shown.map((d) => d.imei));
      for (const imei of [...selected]) if (!shownIds.has(imei)) selected.delete(imei);
      $('#count').textContent = shown.length === devices.length ? '' : `${shown.length} of ${devices.length} shown`;
      $('#rows').innerHTML = shown.map((d) => `<tr class="click ${selected.has(d.imei) ? 'selected' : ''}" data-imei="${esc(d.imei)}">
        <td class="admin-only"><input type="checkbox" data-sel="${esc(d.imei)}" ${selected.has(d.imei) ? 'checked' : ''} aria-label="Select"></td>
        <td title="${d.online ? 'online' : 'offline'}"><span class="dot ${d.online ? 'on' : ''}"></span></td>
        <td class="mono">${esc(d.imei)}</td><td>${esc(d.label) || '<span class="muted">—</span>'}</td>
        <td class="mono">${esc(d.current_ver || '—')}</td><td>${targetCell(d)}</td>
        <td>${statusChip(d.last_status)}</td><td title="${esc(fmtTime(d.last_seen))}">${fmtAgo(d.last_seen)}</td>
        <td>${esc(d.channel)}</td><td class="mono">${esc(d.pinned_version || '')}</td></tr>`).join('')
        || `<tr><td colspan="10" class="empty">${devices.length ? 'No devices match the filters.'
          : 'No devices yet. Devices appear when they ask to register, or add one above.'}</td></tr>`;
      const allBox = $('#all');
      allBox.checked = shown.length > 0 && shown.every((d) => selected.has(d.imei));
      allBox.onchange = () => { shown.forEach((d) => (allBox.checked ? selected.add(d.imei) : selected.delete(d.imei))); draw(); };
      $('#bulk').classList.toggle('hidden', selected.size === 0);
      $('#bulkN').textContent = `${selected.size} selected`;
    }
    draw();

    $('#q').oninput = (e) => { devFilter.q = e.target.value; draw(); };
    $('#fChannel').onchange = (e) => { devFilter.channel = e.target.value; draw(); };
    $('#fState').onchange = (e) => { devFilter.state = e.target.value; draw(); };
    $('#fVersion').onchange = (e) => { devFilter.version = e.target.value; draw(); };
    $('#rows').onclick = (e) => {
      const box = e.target.closest('[data-sel]');
      if (box) { box.checked ? selected.add(box.dataset.sel) : selected.delete(box.dataset.sel); draw(); return; }
      if (e.target.closest('td.admin-only')) return;
      const tr = e.target.closest('tr[data-imei]');
      if (tr) location.hash = `#/devices/${tr.dataset.imei}`;
    };

    const bulk = run(async (set, label) => {
      if (!confirm(`${label} for ${selected.size} device(s)?`)) return;
      const r = await api('POST', 'api/devices/bulk', { imeis: [...selected], set });
      toast(`${r.updated} device(s) updated`);
      selected.clear();
      render();
    });
    $('#bChannel').onchange = (e) => e.target.value && bulk({ channel: e.target.value }, `Set channel ${e.target.value}`);
    $('#bPin').onchange = (e) => {
      if (!e.target.value) return;
      const v = e.target.value === '__none' ? null : e.target.value;
      bulk({ pinned_version: v }, v ? `Pin version ${v}` : 'Unpin');
    };
    $('#bEnable').onclick = () => bulk({ enabled: true }, 'Enable');
    $('#bDisable').onclick = () => bulk({ enabled: false }, 'Disable updates');
    $('#bClear').onclick = () => { selected.clear(); draw(); };
    $('#bApprove').onclick = run(async () => {
      const todo = devices.filter((d) => selected.has(d.imei) && d.awaiting_approval);
      if (!todo.length) throw new Error('None of the selected devices is waiting for approval');
      if (!confirm(`Approve registration of ${todo.length} device(s)? Each receives its device key on its next request.\n\n` +
        todo.map((d) => `${d.imei}  key ${d.reg_fingerprint}`).join('\n'))) return;
      for (const d of todo) await api('POST', `api/devices/${d.imei}/approve`, { fingerprint: d.reg_fingerprint });
      toast(`${todo.length} device(s) approved`);
      selected.clear();
      render();
    });

    $('#addDev').onsubmit = run(async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      await api('POST', 'api/devices', { imei: f.get('imei'), label: f.get('label') });
      toast('Device added');
      render();
    });
  };

  // ── Device detail ───────────────────────────────────────────────────────
  async function deviceDetail(imei) {
    const [d, releases] = await Promise.all([api('GET', `api/devices/${encodeURIComponent(imei)}`), api('GET', 'api/releases')]);
    const reasonText = {
      pinned: 'pinned version differs from running', channel: 'channel has a newer release',
      up_to_date: 'already on the channel release', pinned_already_running: 'already on the pinned version',
      running_newer_than_channel: 'running a newer version than its channel', channel_has_no_release: 'channel has no release',
      device_disabled: 'updates disabled for this device', never_checked: 'device has not checked in yet',
    };
    view.innerHTML = `
      <div class="page-head"><div><div class="sub"><a href="#/devices">← Devices</a></div>
        <h1 class="mono" style="font-size:18px">${esc(d.imei)}</h1>
        <div class="sub">${esc(d.label) || 'No label'}</div></div>
        <div class="row"><span class="chip ${d.online ? 'ok' : ''}"><span class="dot ${d.online ? 'on' : ''}"></span>
          ${d.online ? 'online' : 'offline'}</span>${targetCell(d)}</div></div>
      ${registrationCard(d)}
      <div class="grid cols-2">
        <div class="card"><h2>Status</h2><dl class="kv">
          <dt>Running</dt><dd class="mono">${esc(d.current_ver || '—')}</dd>
          <dt>Target</dt><dd>${d.target ? `<span class="mono">${esc(d.target)}</span> — ` : ''}${esc(reasonText[d.target_reason] || d.target_reason)}</dd>
          <dt>Last status</dt><dd>${statusChip(d.last_status)}</dd>
          <dt>Last seen</dt><dd>${fmtAgo(d.last_seen)} <span class="muted">${esc(fmtTime(d.last_seen))}</span></dd>
          <dt>Last IP</dt><dd class="mono">${esc(d.last_ip || '—')}</dd>
          <dt>Check interval</dt><dd>${fmtInterval(d.effective_interval_s)}${d.check_interval_s ? '' : ' <span class="muted">(server default)</span>'}</dd>
          <dt>Registered</dt><dd>${esc(fmtTime(d.created_at))}</dd></dl>
        </div>
        <div class="card"><h2>Settings</h2>
          <form id="edit" class="form-grid">
            <label class="field">Label<input name="label" value="${esc(d.label)}" maxlength="64"></label>
            <label class="field">Channel<select name="channel">${['stable', 'beta'].map((c) =>
              `<option ${c === d.channel ? 'selected' : ''}>${c}</option>`).join('')}</select></label>
            <label class="field">Pinned version<select name="pinned_version">${versionOptions(releases, d.pinned_version, 'Follow channel')}</select></label>
            <label class="field">Check interval (s)<input name="check_interval_s" type="number" min="300" max="2592000"
              placeholder="default" value="${d.check_interval_s ?? ''}"></label>
            <label class="check"><input type="checkbox" name="enabled" ${d.enabled ? 'checked' : ''}> Updates enabled</label>
            <div class="row end admin-only"><button class="primary">Save</button></div>
          </form>
          <div class="admin-only" style="margin-top:16px;border-top:1px solid var(--line);padding-top:14px">
            <div class="row"><strong>Device key</strong><span class="spacer"></span>
              <button id="showKey" class="ghost">Show key</button>
              <button id="delDev" class="danger">Delete device</button></div>
            <div id="keyBox" class="hidden" style="margin-top:10px"></div>
          </div>
        </div>
      </div>
      <div class="card" style="margin-top:16px"><h2>History</h2>${eventsTable(d.events, { showImei: false })}</div>`;

    const form = view.querySelector('#edit');
    if (!isAdmin()) form.querySelectorAll('input, select').forEach((el) => { el.disabled = true; });
    form.onsubmit = run(async (e) => {
      e.preventDefault();
      const f = new FormData(form);
      const iv = f.get('check_interval_s');
      await api('PATCH', `api/devices/${d.imei}`, {
        label: f.get('label'), channel: f.get('channel'),
        pinned_version: f.get('pinned_version') || null,
        check_interval_s: iv === '' ? null : Number(iv),
        enabled: form.enabled.checked,
      });
      toast('Saved');
      render();
    });
    const approve = view.querySelector('#regApprove');
    if (approve) approve.onclick = run(async () => {
      if (!confirm(`Approve ${d.imei}?\n\nOnly approve if the device shows key fingerprint ${d.reg_fingerprint} ` +
        '(GET_STATUS over USB or BLE) or you trust where this request came from.')) return;
      await api('POST', `api/devices/${d.imei}/approve`, { fingerprint: d.reg_fingerprint });
      toast('Approved — the device gets its key on its next request');
      render();
    });
    const reject = view.querySelector('#regReject');
    if (reject) reject.onclick = run(async () => {
      if (!confirm(`Reject ${d.imei}? It will not get a key. Delete the device later to let it ask again.`)) return;
      await api('POST', `api/devices/${d.imei}/reject`);
      toast('Registration rejected');
      render();
    });
    view.querySelector('#showKey').onclick = run(async () => {
      const r = await api('GET', `api/devices/${d.imei}/key`);
      const cmd = `SET secret=${r.device_key}`;
      const box = view.querySelector('#keyBox');
      box.innerHTML = `<div class="keybox"><code class="mono" style="flex:1">${esc(cmd)}</code>
        <button id="copyKey">Copy</button></div>
        <p class="muted" style="margin:6px 0 0">Send this to the device over USB serial or BLE. Treat it like a password.</p>`;
      box.classList.remove('hidden');
      box.querySelector('#copyKey').onclick = () => navigator.clipboard.writeText(cmd).then(() => toast('Copied'),
        () => toast('Copy failed — select the text instead', true));
    });
    view.querySelector('#delDev').onclick = run(async () => {
      if (!confirm(`Delete ${d.imei}? It can ask to register again unless registration is off.`)) return;
      await api('DELETE', `api/devices/${d.imei}`);
      toast('Device deleted');
      location.hash = '#/devices';
    });
  }

  function registrationCard(d) {
    if (!d.awaiting_approval && d.reg_state !== 'rejected') return '';
    const what = d.reg_state === 'rejected' ? 'Registration was rejected. Delete the device to let it ask again.'
      : d.reg_key_changed ? 'This device sent a <strong>new</strong> registration key (e.g. its memory was erased). ' +
        'It keeps working with its current key; approve only if you expected this.'
        : 'This device asked to register. Approving sends it its device key, encrypted for the key below.';
    return `<div class="card" style="margin-bottom:16px"><h2>Registration</h2>
      <div class="alert ${d.reg_state === 'rejected' ? '' : 'warn'}">${what}</div>
      <div class="row" style="margin-top:10px"><span>Key fingerprint</span>
        <code class="mono">${esc(d.reg_fingerprint || '—')}</code>
        <span class="muted">compare with GET_STATUS on the device</span><span class="spacer"></span>
        ${d.awaiting_approval ? `<span class="admin-only row"><button class="primary" id="regApprove">Approve</button>
          ${d.reg_state === 'pending' ? '<button class="danger" id="regReject">Reject</button>' : ''}</span>` : ''}</div></div>`;
  }

  // ── Releases ────────────────────────────────────────────────────────────
  routes.releases = async () => {
    const releases = await api('GET', 'api/releases');
    view.innerHTML = `
      <div class="page-head"><div><h1>Releases</h1><div class="sub">${releases.length} firmware image(s)</div></div></div>
      <div class="card admin-only"><h2>Upload release</h2>
        <form id="up" class="form-grid">
          <label class="field">Version<input name="version" placeholder="1.2.3" required pattern="\\d+\\.\\d+\\.\\d+"></label>
          <label class="field">Notes<input name="notes" placeholder="What changed" maxlength="500"></label>
          <label class="field">Firmware (.bin)<input name="file" type="file" accept=".bin" required></label>
          <div class="row end"><button class="primary" id="upBtn">Upload</button></div>
        </form>
        <div class="progress hidden" id="prog"><div></div></div>
        <p class="muted" style="margin:8px 0 0">Use the file from <span class="mono">firmware\\release\\</span>; the version must match
          <span class="mono">FW_VERSION</span> in that build.</p>
      </div>
      <div class="card"><div class="table-wrap"><table><thead><tr><th>Version</th><th>Size</th><th>Channels</th>
        <th>Pinned</th><th>Running</th><th>Uploaded</th><th>MD5</th><th>Notes</th><th class="admin-only"></th></tr></thead>
        <tbody>${releases.map((r) => `<tr><td class="mono"><strong>${esc(r.version)}</strong></td><td>${fmtSize(r.size)}</td>
          <td>${(r.channels || '').split(',').filter(Boolean).map((c) => `<span class="chip info">${esc(c)}</span>`).join(' ') || '<span class="muted">—</span>'}</td>
          <td>${r.pinned_devices || '<span class="muted">0</span>'}</td><td>${r.running_devices || '<span class="muted">0</span>'}</td>
          <td>${esc(fmtTime(r.created_at))}</td><td class="mono muted">${esc(r.md5)}</td><td class="wrap">${esc(r.notes)}</td>
          <td class="admin-only">${r.channels || r.pinned_devices ? '<span class="muted" title="In use by a channel or pinned devices">in use</span>'
            : `<button class="danger" data-del="${esc(r.version)}">Delete</button>`}</td></tr>`).join('')
          || '<tr><td colspan="9" class="empty">No releases uploaded yet.</td></tr>'}</tbody></table></div></div>`;

    const form = view.querySelector('#up');
    form.onsubmit = (e) => {
      e.preventDefault();
      const prog = view.querySelector('#prog');
      const bar = prog.firstElementChild;
      const btn = view.querySelector('#upBtn');
      const xhr = new XMLHttpRequest();
      xhr.open('POST', 'api/releases');
      xhr.setRequestHeader('X-OTA-Console', '1');
      xhr.upload.onprogress = (ev) => { if (ev.lengthComputable) bar.style.width = (ev.loaded / ev.total) * 100 + '%'; };
      xhr.onload = () => {
        btn.disabled = false;
        prog.classList.add('hidden');
        if (xhr.status === 401) return location.replace('login.html');
        let data = {};
        try { data = JSON.parse(xhr.responseText); } catch (_) { /* non-JSON */ }
        if (xhr.status === 201) { toast(`Uploaded ${data.version} (${fmtSize(data.size)})`); render(); }
        else toast(data.error || `Upload failed (HTTP ${xhr.status})`, true);
      };
      xhr.onerror = () => { btn.disabled = false; prog.classList.add('hidden'); toast('Upload failed — network error', true); };
      btn.disabled = true;
      bar.style.width = '0';
      prog.classList.remove('hidden');
      xhr.send(new FormData(form));
    };
    view.querySelectorAll('[data-del]').forEach((b) => {
      b.onclick = run(async () => {
        if (!confirm(`Delete release ${b.dataset.del}? The .bin file is removed too.`)) return;
        await api('DELETE', `api/releases/${b.dataset.del}`);
        toast('Release deleted');
        render();
      });
    });
  };

  // ── History ─────────────────────────────────────────────────────────────
  const histFilter = { imei: '', type: '', actor: '' };
  const EVENT_TYPES = ['registration_requested', 'registration_key_changed', 'registration_approved',
    'registration_rejected', 'key_delivered', 'registered', 'offered', 'download_start', 'download_sent', 'download_aborted', 'denied',
    'downloading', 'flashed', 'running', 'failed', 'md5_fail', 'error', 'admin_update', 'channel_set',
    'release_uploaded', 'release_deleted', 'device_deleted', 'key_viewed', 'login', 'login_failed', 'logout',
    'user_added', 'user_updated', 'user_deleted', 'password_changed'];

  routes.history = async () => {
    view.innerHTML = `
      <div class="page-head"><div><h1>History</h1><div class="sub">Device updates and admin actions</div></div></div>
      <div class="card">
        <form class="toolbar" id="hf">
          <input name="imei" placeholder="IMEI" value="${esc(histFilter.imei)}" style="width:170px">
          <select name="type"><option value="">All events</option>${EVENT_TYPES.map((t) =>
            `<option ${t === histFilter.type ? 'selected' : ''}>${t}</option>`).join('')}</select>
          <input name="actor" placeholder="By (user, device, api-token)" value="${esc(histFilter.actor)}" style="width:200px">
          <button class="primary">Filter</button><button type="button" class="ghost" id="hReset">Reset</button>
        </form>
        <div id="hBody"></div>
        <div class="row" style="justify-content:center;margin-top:12px"><button class="ghost hidden" id="more">Load more</button></div>
      </div>`;
    let rows = [];
    const PAGE = 100;
    const load = run(async (append) => {
      const qs = new URLSearchParams({ limit: PAGE });
      for (const k of ['imei', 'type', 'actor']) if (histFilter[k]) qs.set(k, histFilter[k]);
      if (append && rows.length) qs.set('before', rows[rows.length - 1].id);
      const page = await api('GET', `api/events?${qs}`);
      rows = append ? rows.concat(page) : page;
      view.querySelector('#hBody').innerHTML = eventsTable(rows);
      view.querySelector('#more').classList.toggle('hidden', page.length < PAGE);
    });
    view.querySelector('#hf').onsubmit = (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      for (const k of ['imei', 'type', 'actor']) histFilter[k] = String(f.get(k) || '').trim();
      load(false);
    };
    view.querySelector('#hReset').onclick = () => { Object.keys(histFilter).forEach((k) => { histFilter[k] = ''; }); render(); };
    view.querySelector('#more').onclick = () => load(true);
    await load(false);
  };

  // ── Users ───────────────────────────────────────────────────────────────
  routes.users = async () => {
    const users = await api('GET', 'api/users');
    view.innerHTML = `
      <div class="page-head"><div><h1>Users</h1><div class="sub">Admins can change everything; viewers are read-only</div></div></div>
      <div class="card"><h2>Add user</h2>
        <form id="addUser" class="form-grid">
          <label class="field">Username<input name="username" required pattern="[A-Za-z0-9._\\-]{3,32}" autocomplete="off"></label>
          <label class="field">Password (min 10)<input name="password" type="password" required minlength="10" autocomplete="new-password"></label>
          <label class="field">Role<select name="role"><option value="viewer">viewer</option><option value="admin">admin</option></select></label>
          <div class="row end"><button class="primary">Add user</button></div>
        </form></div>
      <div class="card"><div class="table-wrap"><table><thead><tr><th>Username</th><th>Role</th><th>Status</th>
        <th>Last login</th><th>Created</th><th></th></tr></thead><tbody>
        ${users.map((u) => {
          const self = u.username.toLowerCase() === me.username.toLowerCase();
          return `<tr data-id="${u.id}" data-name="${esc(u.username)}"><td><strong>${esc(u.username)}</strong>${self ? ' <span class="chip info">you</span>' : ''}</td>
          <td><select data-role ${self ? 'disabled title="You cannot change your own role"' : ''}>
            <option ${u.role === 'admin' ? 'selected' : ''}>admin</option><option ${u.role === 'viewer' ? 'selected' : ''}>viewer</option></select></td>
          <td>${u.enabled ? '<span class="chip ok">active</span>' : '<span class="chip bad">disabled</span>'}</td>
          <td>${u.last_login ? fmtAgo(u.last_login) : '<span class="muted">never</span>'}</td><td>${esc(fmtTime(u.created_at))}</td>
          <td><div class="row">
            <button data-reset>Reset password</button>
            ${self ? '' : `<button data-toggle>${u.enabled ? 'Disable' : 'Enable'}</button><button class="danger" data-delete>Delete</button>`}
          </div></td></tr>`;
        }).join('')}</tbody></table></div></div>`;

    view.querySelector('#addUser').onsubmit = run(async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      await api('POST', 'api/users', { username: f.get('username'), password: f.get('password'), role: f.get('role') });
      toast(`User ${f.get('username')} added`);
      render();
    });
    view.querySelector('tbody').onclick = run(async (e) => {
      const tr = e.target.closest('tr[data-id]');
      if (!tr) return;
      const { id, name } = tr.dataset;
      const u = users.find((x) => String(x.id) === id);
      if (e.target.closest('[data-reset]')) {
        const pw = prompt(`New password for ${name} (min 10 characters). Their sessions will be ended.`);
        if (!pw) return;
        await api('PATCH', `api/users/${id}`, { password: pw });
        toast(`Password for ${name} reset`);
      } else if (e.target.closest('[data-toggle]')) {
        await api('PATCH', `api/users/${id}`, { enabled: !u.enabled });
        toast(`${name} ${u.enabled ? 'disabled' : 'enabled'}`);
        render();
      } else if (e.target.closest('[data-delete]')) {
        if (!confirm(`Delete user ${name}?`)) return;
        await api('DELETE', `api/users/${id}`);
        toast(`${name} deleted`);
        render();
      }
    });
    view.querySelectorAll('[data-role]').forEach((sel) => {
      sel.onchange = run(async () => {
        const tr = sel.closest('tr');
        try {
          await api('PATCH', `api/users/${tr.dataset.id}`, { role: sel.value });
          toast(`${tr.dataset.name} is now ${sel.value}`);
        } finally { render(); }
      });
    });
  };

  // ── Account ─────────────────────────────────────────────────────────────
  routes.account = async () => {
    view.innerHTML = `
      <div class="page-head"><div><h1>Account</h1><div class="sub">Signed in as <strong>${esc(me.username)}</strong> (${esc(me.role)})</div></div></div>
      <div class="card" style="max-width:520px"><h2>Change password</h2>
        <form id="pw" class="grid">
          <label class="field">Current password<input name="current" type="password" required autocomplete="current-password"></label>
          <label class="field">New password (min 10)<input name="next" type="password" required minlength="10" autocomplete="new-password"></label>
          <label class="field">Repeat new password<input name="again" type="password" required minlength="10" autocomplete="new-password"></label>
          <div class="row end"><button class="primary">Change password</button></div>
        </form>
        <p class="muted" style="margin-bottom:0">Changing your password signs out your other sessions.</p></div>`;
    view.querySelector('#pw').onsubmit = run(async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      if (f.get('next') !== f.get('again')) throw new Error('New passwords do not match');
      await api('POST', 'auth/password', { current: f.get('current'), next: f.get('next') });
      e.target.reset();
      toast('Password changed');
    });
  };

  // ── boot ────────────────────────────────────────────────────────────────
  document.getElementById('menuBtn').onclick = () => document.body.classList.toggle('nav-open');
  document.getElementById('accountBtn').onclick = () => { location.hash = '#/account'; };
  document.getElementById('logoutBtn').onclick = run(async () => {
    await api('POST', 'auth/logout');
    location.replace('login.html');
  });
  document.querySelector('.sidebar').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) document.body.classList.remove('nav-open');
  });

  (async () => {
    try {
      me = await api('GET', 'auth/me');
    } catch (_) { return; } // api() already redirected to login
    document.body.classList.add(`role-${me.role}`);
    document.getElementById('who').textContent = me.username;
    document.getElementById('role').textContent = me.role === 'admin' ? 'Administrator' : 'Viewer (read-only)';
    window.addEventListener('hashchange', render);
    render();
  })();
})();
