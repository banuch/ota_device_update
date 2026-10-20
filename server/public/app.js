'use strict';
(() => {
  const $ = (s) => document.querySelector(s);
  let token = '';
  try { token = localStorage.getItem('otaAdminToken') || ''; } catch (_) { /* storage blocked */ }
  $('#token').value = token;
  let releases = [];
  let eventImei = null;

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtTime = (sec) => (sec ? new Date(sec * 1000).toLocaleString() : '—');
  const fmtSize = (n) => (n > 1048576 ? (n / 1048576).toFixed(2) + ' MB' : (n / 1024).toFixed(1) + ' KB');

  function msg(text, kind = 'ok') {
    const el = $('#msg');
    el.textContent = text;
    el.className = kind;
    if (kind === 'ok') setTimeout(() => { if (el.textContent === text) el.textContent = ''; }, 4000);
  }

  async function api(method, path, body, isForm) {
    const headers = { Authorization: `Bearer ${token}` };
    if (body && !isForm) headers['Content-Type'] = 'application/json';
    const res = await fetch('/api' + path, {
      method, headers, body: body ? (isForm ? body : JSON.stringify(body)) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  const versionOptions = (selected, emptyLabel) =>
    `<option value="">${emptyLabel}</option>` +
    releases.map((r) => `<option ${r.version === selected ? 'selected' : ''}>${esc(r.version)}</option>`).join('');

  async function loadAll() {
    if (!token) return msg('Enter the admin token to connect.', 'err');
    try {
      const [rel, ch, dev] = await Promise.all([api('GET', '/releases'), api('GET', '/channels'), api('GET', '/devices')]);
      releases = rel;
      renderReleases();
      renderChannels(ch);
      renderDevices(dev);
      await loadEvents();
    } catch (e) { msg(e.message, 'err'); }
  }

  function renderReleases() {
    $('#releases tbody').innerHTML = releases.map((r) => `<tr>
      <td class="mono">${esc(r.version)}</td><td>${fmtSize(r.size)}</td>
      <td class="mono">${esc(r.md5)}</td><td>${esc(r.notes)}</td><td>${fmtTime(r.created_at)}</td>
      <td><button class="danger" data-del-rel="${esc(r.version)}">Delete</button></td></tr>`).join('')
      || '<tr><td colspan="6" class="muted">No releases uploaded yet.</td></tr>';
  }

  function renderChannels(channels) {
    $('#channels').innerHTML = channels.map((c) => `<label class="row">
      <strong>${esc(c.name)}</strong>
      <select data-channel="${esc(c.name)}">${versionOptions(c.version, '— none —')}</select></label>`).join('');
  }

  function renderDevices(devices) {
    $('#devices tbody').innerHTML = devices.map((d) => `<tr data-imei="${esc(d.imei)}">
      <td class="mono"><a href="#" data-events="${esc(d.imei)}">${esc(d.imei)}</a></td>
      <td><input data-f="label" value="${esc(d.label)}" style="width:120px"></td>
      <td class="mono">${esc(d.current_ver || '—')}</td>
      <td class="st-${esc(d.last_status)}">${esc(d.last_status || '—')}</td>
      <td>${fmtTime(d.last_seen)}</td>
      <td><select data-f="channel">${['stable', 'beta'].map((c) =>
        `<option ${c === d.channel ? 'selected' : ''}>${c}</option>`).join('')}</select></td>
      <td><select data-f="pinned_version">${versionOptions(d.pinned_version, 'follow channel')}</select></td>
      <td><input data-f="check_interval_s" type="number" min="300" placeholder="default"
           value="${d.check_interval_s ?? ''}" style="width:90px"></td>
      <td><input data-f="enabled" type="checkbox" ${d.enabled ? 'checked' : ''}></td>
      <td class="row"><button data-key="${esc(d.imei)}">Key</button>
          <button class="danger" data-del-dev="${esc(d.imei)}">Remove</button></td></tr>`).join('')
      || '<tr><td colspan="10" class="muted">No devices yet. Devices appear after their first check.</td></tr>';
  }

  async function loadEvents() {
    const q = eventImei ? `?imei=${encodeURIComponent(eventImei)}&limit=200` : '?limit=200';
    const ev = await api('GET', '/events' + q);
    $('#evFilter').innerHTML = eventImei
      ? `— ${esc(eventImei)} <a href="#" data-events="">(show all)</a>` : '';
    $('#events tbody').innerHTML = ev.map((e) => `<tr>
      <td>${fmtTime(e.ts)}</td><td class="mono">${esc(e.imei)}</td>
      <td class="st-${esc(e.type)}">${esc(e.type)}</td><td class="mono">${esc(e.version || '')}</td>
      <td class="muted">${esc(e.detail)}</td></tr>`).join('')
      || '<tr><td colspan="5" class="muted">No events.</td></tr>';
  }

  // ── events ──────────────────────────────────────────────────────────────
  $('#saveToken').onclick = () => {
    token = $('#token').value.trim();
    try { localStorage.setItem('otaAdminToken', token); } catch (_) { /* ignore */ }
    loadAll();
  };
  $('#refresh').onclick = loadAll;

  $('#uploadForm').onsubmit = async (e) => {
    e.preventDefault();
    try {
      const r = await api('POST', '/releases', new FormData(e.target), true);
      msg(`Uploaded ${r.version} (${fmtSize(r.size)}, md5 ${r.md5})`);
      e.target.reset();
      loadAll();
    } catch (err) { msg(err.message, 'err'); }
  };

  $('#addDevice').onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api('POST', '/devices', { imei: f.get('imei'), label: f.get('label') });
      msg('Device registered');
      e.target.reset();
      loadAll();
    } catch (err) { msg(err.message, 'err'); }
  };

  document.addEventListener('change', async (e) => {
    const t = e.target;
    try {
      if (t.dataset.channel) {
        await api('PUT', `/channels/${t.dataset.channel}`, { version: t.value || null });
        msg(`Channel ${t.dataset.channel} → ${t.value || 'none'}`);
      } else if (t.dataset.f) {
        const imei = t.closest('tr').dataset.imei;
        let v = t.value;
        if (t.dataset.f === 'enabled') v = t.checked;
        else if (t.dataset.f === 'pinned_version') v = v || null;
        else if (t.dataset.f === 'check_interval_s') v = v === '' ? null : Number(v);
        await api('PATCH', `/devices/${imei}`, { [t.dataset.f]: v });
        msg(`${imei}: ${t.dataset.f} updated`);
      } else return;
      loadAll();
    } catch (err) { msg(err.message, 'err'); loadAll(); }
  });

  document.addEventListener('click', async (e) => {
    const t = e.target;
    try {
      if (t.dataset.delRel !== undefined) {
        if (!confirm(`Delete release ${t.dataset.delRel}?`)) return;
        await api('DELETE', `/releases/${t.dataset.delRel}`);
        msg('Release deleted'); loadAll();
      } else if (t.dataset.delDev !== undefined) {
        if (!confirm(`Remove device ${t.dataset.delDev}? It re-registers on its next check.`)) return;
        await api('DELETE', `/devices/${t.dataset.delDev}`);
        msg('Device removed'); loadAll();
      } else if (t.dataset.key !== undefined) {
        const r = await api('GET', `/devices/${t.dataset.key}/key`);
        prompt('Provision this device over serial/BLE with:', `SET secret=${r.device_key}`);
      } else if (t.dataset.events !== undefined) {
        e.preventDefault();
        eventImei = t.dataset.events || null;
        loadEvents();
      }
    } catch (err) { msg(err.message, 'err'); }
  });

  if (token) loadAll();
})();
