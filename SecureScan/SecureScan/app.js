/* ==========================================================================
   SecureScan front end
   Vanilla JS single-page app over the Flask/SQLite API.
   Design rules live in DESIGN.md. No emoji or Unicode glyph icons: every
   icon is an SVG from ICONS below; severity is always shape + colour + word.
   ========================================================================== */
(() => {
  'use strict';

  // ------------------------------------------------------------------------
  // Utilities
  // ------------------------------------------------------------------------
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const nf = new Intl.NumberFormat();
  const n = v => nf.format(Number(v) || 0);
  const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);
  const debounce = (fn, ms = 300) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  const store = {
    get(k) { try { return window.localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { window.localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
  };

  function toDate(v) { const d = v ? new Date(v) : null; return d && !Number.isNaN(d.getTime()) ? d : null; }
  function fmtDateTime(v) {
    const d = toDate(v); if (!d) return 'Unknown time';
    return d.toLocaleString([], { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  function fmtTime(v) { const d = toDate(v); return d ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '--:--:--'; }
  function fmtDate(v) { const d = toDate(v); return d ? d.toLocaleDateString([], { year: 'numeric', month: 'short', day: '2-digit' }) : ''; }
  function fmtDay(v) { const d = toDate(v); return d ? d.toLocaleDateString([], { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }) : 'Unknown date'; }
  function ago(v) {
    const d = toDate(v); if (!d) return '';
    const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    return `${Math.floor(s / 86400)} d ago`;
  }
  function highlight(text, q) {
    const safe = esc(text);
    if (!q) return safe;
    const re = new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'ig');
    return safe.replace(re, '<mark>$1</mark>');
  }

  // ------------------------------------------------------------------------
  // Icons (24px grid, 1.6 stroke). Drawn for SecureScan.
  // ------------------------------------------------------------------------
  const ICONS = {
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    bell: '<path d="M6 9a6 6 0 0 1 12 0c0 6.5 2.5 8 2.5 8h-17S6 15.5 6 9"/><path d="M10 20a2 2 0 0 0 4 0"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2.5 12h2M19.5 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5Z"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>',
    upload: '<path d="M12 15V4M7 9l5-5 5 5"/><path d="M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
    download: '<path d="M12 4v11M7 10l5 5 5-5"/><path d="M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
    play: '<path d="M7 5v14l11-7Z"/>',
    refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.7L20 8.6"/><path d="M20 4v4.6h-4.6"/>',
    chevron: '<path d="m9 6 6 6-6 6"/>',
    chevronDown: '<path d="m6 9 6 6 6-6"/>',
    external: '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>',
    printer: '<path d="M7 9V4h10v5"/><rect x="4" y="9" width="16" height="8" rx="1"/><path d="M7 14h10v6H7z"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    zoomIn: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5M11 8v6M8 11h6"/>',
    zoomOut: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5M8 11h6"/>',
    fit: '<path d="M4 9V5a1 1 0 0 1 1-1h4M15 4h4a1 1 0 0 1 1 1v4M20 15v4a1 1 0 0 1-1 1h-4M9 20H5a1 1 0 0 1-1-1v-4"/>',
    reset: '<path d="M4 12a8 8 0 1 0 2.3-5.7L4 8.6"/><path d="M4 4v4.6h4.6"/>',
    pass: '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
    warn: '<path d="M12 4 2.5 20h19Z"/><path d="M12 10v4M12 17.3v.01"/>',
    fail: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>',
    skipped: '<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.01"/>',
    overview: '<rect x="4" y="4" width="7" height="7" rx="1"/><rect x="13" y="4" width="7" height="4" rx="1"/><rect x="13" y="10" width="7" height="10" rx="1"/><rect x="4" y="13" width="7" height="7" rx="1"/>',
    audit: '<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4V3h6v1"/><path d="m9 13 2 2 4-4"/>',
    detections: '<circle cx="12" cy="12" r="8"/><path d="M12 2.5v4M12 17.5v4M2.5 12h4M17.5 12h4"/><circle cx="12" cy="12" r="1.5"/>',
    events: '<path d="M9 6h11M9 12h11M9 18h11"/><path d="M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
    process: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>',
    network: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v2"/>',
    files: '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M5.5 13 8 5h8l2.5 8"/><path d="M7 16.5h.01M11 16.5h3"/>',
    timeline: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    graph: '<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="m8.2 10.8 7.6-3.6M8.2 13.2l7.6 3.6"/>',
    report: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
    settings: '<path d="M4 7h10M18 7h2M4 17h4M12 17h8"/><circle cx="16" cy="7" r="2"/><circle cx="10" cy="17" r="2"/>',
    monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    wave: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    flag: '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
    trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    sort: '<path d="M7 4v16M4 7l3-3 3 3M17 20V4M14 17l3 3 3-3"/>',
    file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z"/><path d="M14 3v5h5"/>',
  };
  const icon = (name, cls = '') => `<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ''}</svg>`;

  const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  const SEV_SHAPE = {
    Critical: '<path d="M5 0.6 9.4 5 5 9.4 0.6 5Z" fill="currentColor"/>',
    High: '<path d="M5 1 9.5 9H0.5Z" fill="currentColor"/>',
    Medium: '<circle cx="5" cy="5" r="4" fill="currentColor"/>',
    Low: '<circle cx="5" cy="5" r="3.5" fill="none" stroke="currentColor" stroke-width="1.6"/>',
    Informational: '<rect x="1" y="4" width="8" height="2" rx="1" fill="currentColor"/>',
  };
  function sevMark(sev, { label = true, short = false } = {}) {
    const s = SEV_SHAPE[sev] ? sev : 'Informational';
    const word = short && s === 'Informational' ? 'Info' : s;
    return `<span class="sev sev-${s.toLowerCase()}"><svg viewBox="0 0 10 10" aria-hidden="true">${SEV_SHAPE[s]}</svg>${label ? `<span class="sev-label">${word}</span>` : `<span class="visually-hidden">${word}</span>`}</span>`;
  }
  const CHECK_LABEL = { pass: 'Passed', warn: 'Warning', fail: 'Failed', skipped: 'Not checked', error: 'Error' };
  const checkMark = st => `<span class="check check-${esc(st)}">${icon(st === 'error' ? 'info' : (ICONS[st] ? st : 'info'))}${CHECK_LABEL[st] || esc(st)}</span>`;
  const demoTag = e => (e && e.is_demo ? '<span class="tag demo">Demo</span>' : '');

  // ------------------------------------------------------------------------
  // API client
  // ------------------------------------------------------------------------
  const API = {
    async json(url, opts = {}) {
      let res;
      try { res = await fetch(url, opts); } catch { throw new Error('Cannot reach the SecureScan server. Check that app.py is running.'); }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Request failed (HTTP ${res.status}).`);
      return data;
    },
    get(url, params) {
      const q = params ? new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== '' && v !== 'all')) : null;
      return API.json(q && [...q].length ? `${url}?${q}` : url);
    },
    post(url, body) { return API.json(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }); },
    del(url) { return API.json(url, { method: 'DELETE' }); },
    upload(endpoint, file, onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', endpoint);
        xhr.responseType = 'json';
        xhr.upload.onprogress = e => { if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100)); };
        xhr.onload = () => {
          let data = xhr.response;
          if (typeof data === 'string') { try { data = JSON.parse(data); } catch { data = {}; } }
          data = data || {};
          if (xhr.status >= 200 && xhr.status < 300) resolve(data);
          else reject(new Error(data.error || `Upload failed (HTTP ${xhr.status}).`));
        };
        xhr.onerror = () => reject(new Error('The upload was interrupted. Check the connection to the server and try again.'));
        const fd = new FormData(); fd.append('file', file); xhr.send(fd);
      });
    },
  };

  // ------------------------------------------------------------------------
  // Pages
  // ------------------------------------------------------------------------
  const PAGES = {
    overview:   { group: null, label: 'Overview', icon: 'overview', title: 'Overview', desc: 'Current risk, what needs attention, and the evidence collected so far.' },
    audit:      { group: 'Audit', label: 'System audit', icon: 'audit', title: 'System audit', desc: 'Audit this workstation: Windows security configuration, a live Wireshark capture, and Autopsy disk analysis.' },
    detections: { group: 'Audit', label: 'Detections', icon: 'detections', title: 'Detections', desc: 'Events linked across sources into attack patterns, each mapped to MITRE ATT&CK and listed with the evidence that triggered it.', count: 'detections' },
    system:     { group: 'Evidence', label: 'Security events', icon: 'events', title: 'Security events', desc: 'Windows Security log, Linux auditd and host-audit findings: logons, privileges, accounts and configuration.', count: 'security' },
    process:    { group: 'Evidence', label: 'Processes', icon: 'process', title: 'Processes', desc: 'Process creation and command lines from Windows event 4688, Sysmon and the host audit.' },
    network:    { group: 'Evidence', label: 'Network', icon: 'network', title: 'Network', desc: 'Packets from Wireshark and TShark, Sysmon network events and live connections seen by the host audit.', count: 'network' },
    forensic:   { group: 'Evidence', label: 'Files and artifacts', icon: 'files', title: 'Files and artifacts', desc: 'Autopsy findings: deleted files, disguised executables, credential files, browser history and devices.', count: 'autopsy' },
    timeline:   { group: 'Investigate', label: 'Timeline', icon: 'timeline', title: 'Timeline', desc: 'Every source in one chronological sequence. Select an event to read its details.' },
    graph:      { group: 'Investigate', label: 'Relationship graph', icon: 'graph', title: 'Relationship graph', desc: 'Accounts, processes, addresses, domains and files linked by the events that connect them.' },
    reports:    { group: 'Investigate', label: 'Report', icon: 'report', title: 'Investigation report', desc: 'A printable summary of the audit, detections, findings and evidence intake log.' },
    settings:   { group: 'App', label: 'Settings', icon: 'settings', title: 'Settings', desc: 'Appearance, component status, evidence intake log and demo data.' },
  };

  // ------------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------------
  const state = {
    page: 'overview',
    stats: null,
    tools: { tshark: null, autopsy: null },
    lastEvents: [],
    filters: {},            // per page: { search, severity, quick }
    timeline: { sort: 'desc', range: 'all', source: 'all', selectedId: null },
    audit: { latest: null, capture: null, autopsy: null, pollTimer: null },
    notifications: [],
    loadToken: 0,
  };
  const filtersFor = page => (state.filters[page] ||= { search: '', severity: 'all', quick: 'all' });

  // ------------------------------------------------------------------------
  // Theme
  // ------------------------------------------------------------------------
  function applyTheme(mode) {
    const root = document.documentElement;
    if (mode === 'light' || mode === 'dark') root.dataset.theme = mode; else delete root.dataset.theme;
    store.set('securescan-theme', mode);
    const dark = mode === 'dark' || (mode !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const btn = $('#theme-button');
    if (btn) { btn.innerHTML = icon(dark ? 'sun' : 'moon'); btn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme'); }
  }
  const currentTheme = () => store.get('securescan-theme') || 'system';

  // ------------------------------------------------------------------------
  // Toasts and notifications
  // ------------------------------------------------------------------------
  function toast(message, isError = false) {
    const region = $('#toasts');
    const el = document.createElement('div');
    el.className = `toast${isError ? ' err' : ''}`;
    el.innerHTML = `${icon(isError ? 'warn' : 'info')}<span>${esc(message)}</span>`;
    region.appendChild(el);
    setTimeout(() => el.remove(), isError ? 7000 : 4200);
  }
  function notify(title, message) {
    state.notifications.unshift({ title, message, time: new Date().toISOString(), read: false });
    state.notifications = state.notifications.slice(0, 50);
    renderNotifButton();
  }
  function renderNotifButton() {
    const unread = state.notifications.filter(x => !x.read).length;
    const btn = $('#notif-button');
    btn.innerHTML = `${icon('bell')}${unread ? `<span class="badge-count">${unread}</span>` : ''}`;
    btn.setAttribute('aria-label', unread ? `Notifications, ${unread} unread` : 'Notifications');
  }
  function openNotifications() {
    const items = state.notifications.map(x => `
      <div class="notif-item ${x.read ? '' : 'unread'}">
        <strong>${esc(x.title)}</strong>
        <p>${esc(x.message)}</p>
        <time datetime="${esc(x.time)}">${esc(ago(x.time))}</time>
      </div>`).join('');
    openPanel(`
      <div class="side-panel-head">
        <div><h2 id="side-panel-title">Notifications</h2><div class="sub">Imports, audits and captures from this session</div></div>
        <button class="button ghost icon-only" data-close-panel aria-label="Close">${icon('x')}</button>
      </div>
      <div class="side-panel-body">${items || '<div class="empty"><strong>No notifications yet</strong><p>Results of imports, audits and captures you run will appear here.</p></div>'}</div>`);
    state.notifications.forEach(x => { x.read = true; });
    renderNotifButton();
  }

  // ------------------------------------------------------------------------
  // Side panel, dialogs
  // ------------------------------------------------------------------------
  let lastFocus = null;
  function openPanel(html) {
    lastFocus = document.activeElement;
    const p = $('#side-panel');
    p.innerHTML = html;
    p.classList.add('open'); p.setAttribute('aria-hidden', 'false');
    $('#panel-scrim').classList.add('open');
    (p.querySelector('[data-close-panel]') || p).focus();
  }
  function closePanel() {
    const p = $('#side-panel');
    if (!p.classList.contains('open')) return;
    p.classList.remove('open'); p.setAttribute('aria-hidden', 'true');
    $('#panel-scrim').classList.remove('open');
    lastFocus?.focus?.();
  }

  function openDialog(html, onMount) {
    lastFocus = document.activeElement;
    const root = $('#dialog-root');
    root.innerHTML = `<div class="dialog-backdrop" data-dialog-backdrop><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title">${html}</div></div>`;
    root.querySelector('[data-dialog-backdrop]').addEventListener('mousedown', e => { if (e.target.hasAttribute('data-dialog-backdrop')) closeDialog(); });
    $$('[data-close-dialog]', root).forEach(b => b.addEventListener('click', closeDialog));
    onMount?.(root);
    (root.querySelector('[data-autofocus]') || root.querySelector('button'))?.focus();
  }
  function closeDialog() { $('#dialog-root').innerHTML = ''; lastFocus?.focus?.(); }

  function confirmDialog({ title, message, confirmLabel, danger = true }, onConfirm) {
    openDialog(`
      <div class="dialog-head"><div><h2 id="dialog-title">${esc(title)}</h2><p>${esc(message)}</p></div></div>
      <div class="dialog-foot">
        <button class="button" data-close-dialog data-autofocus>Keep everything</button>
        <button class="button ${danger ? 'danger' : 'primary'}" id="confirm-ok">${esc(confirmLabel)}</button>
      </div>`, root => {
      $('#confirm-ok', root).addEventListener('click', () => { closeDialog(); onConfirm(); });
    });
  }

  // ------------------------------------------------------------------------
  // Event detail side panel
  // ------------------------------------------------------------------------
  function openEvent(ev) {
    if (!ev) return;
    let payload = '';
    if (ev.raw_payload) { try { payload = JSON.stringify(JSON.parse(ev.raw_payload), null, 2); } catch { payload = String(ev.raw_payload); } }
    const rows = [
      ['Time', fmtDateTime(ev.event_time), 'mono'],
      ['Reference', ev.evidence_reference, 'mono'],
      ['Source', ev.source],
      ['Category', ev.category],
      ['Account', ev.username],
      ['Source address', ev.source_ip, 'mono'],
      ['Destination', ev.destination_ip, 'mono'],
      ['Protocol', ev.protocol],
      ['Imported', ev.imported_at ? `${fmtDateTime(ev.imported_at)}` : ''],
    ].filter(r => r[1]);
    openPanel(`
      <div class="side-panel-head">
        <div>
          <h2 id="side-panel-title">${esc(ev.title || 'Event')}</h2>
          <div class="sub">${sevMark(ev.severity)}<span>${esc(ev.source || '')}</span>${demoTag(ev)}</div>
        </div>
        <button class="button ghost icon-only" data-close-panel aria-label="Close event details">${icon('x')}</button>
      </div>
      <div class="side-panel-body">
        <dl class="dl">${rows.map(([k, v, c]) => `<dt>${k}</dt><dd class="${c || ''}">${esc(v)}</dd>`).join('')}</dl>
        ${ev.command ? `<div><h3>Command or ports</h3><pre class="code">${esc(ev.command)}</pre></div>` : ''}
        <div><h3>What was observed</h3><p class="ink-2">${esc(ev.details || 'No further detail was recorded for this event.')}</p></div>
        ${payload ? `<div><div class="section-head"><h3>Original record</h3><button class="button small" id="copy-payload">${icon('copy', 'icon-sm')}Copy</button></div><pre class="code">${esc(payload)}</pre></div>` : ''}
        <div><button class="button" id="event-in-timeline">${icon('timeline')}Show in timeline</button></div>
      </div>`);
    $('#copy-payload')?.addEventListener('click', () => navigator.clipboard?.writeText(payload).then(() => toast('Original record copied.')));
    $('#event-in-timeline')?.addEventListener('click', () => {
      closePanel();
      filtersFor('timeline').search = ev.evidence_reference || ev.title || '';
      state.timeline.selectedId = ev.id;
      go('timeline');
    });
  }

  // ------------------------------------------------------------------------
  // Import dialog
  // ------------------------------------------------------------------------
  const IMPORTS = {
    windows:  { label: 'Windows Security log', endpoint: '/api/import/windows-audit', accept: '.json,.csv', hint: 'JSON or CSV from collectors\\windows_event_collector.ps1' },
    linux:    { label: 'Linux auditd log', endpoint: '/api/import/linux-audit', accept: '.log,.txt', hint: '/var/log/audit/audit.log' },
    sysmon:   { label: 'Sysmon events', endpoint: '/api/import/sysmon', accept: '.json', hint: 'JSON from collectors\\sysmon_collector.ps1' },
    network:  { label: 'Wireshark capture or export', endpoint: '/api/import/wireshark', accept: '.pcap,.pcapng,.csv', hint: '.pcap or .pcapng (parsed with TShark), or File > Export Packet Dissections > As CSV' },
    forensic: { label: 'Autopsy export', endpoint: '/api/import/autopsy', accept: '.csv,.tsv,.json,.txt', hint: 'Autopsy CSV, TSV or JSON report, or a Sleuth Kit body file' },
  };
  function endpointFor(kind, file) {
    const name = file.name.toLowerCase();
    if (/\.(pcap|pcapng)$/.test(name)) return '/api/import/pcap';
    return (IMPORTS[kind] || IMPORTS.windows).endpoint;
  }
  function openImport(kind = 'windows') {
    openDialog(`
      <div class="dialog-head">
        <div><h2 id="dialog-title">Import evidence</h2><p>Files are kept unchanged in uploads/ with their SHA-256 hash. Maximum 10 MB.</p></div>
        <button class="button ghost icon-only" data-close-dialog aria-label="Close">${icon('x')}</button>
      </div>
      <div class="dialog-body">
        <label class="field"><span class="field-label">Evidence type</span>
          <select class="select" id="import-kind" data-autofocus>${Object.entries(IMPORTS).map(([k, v]) => `<option value="${k}" ${k === kind ? 'selected' : ''}>${v.label}</option>`).join('')}</select>
          <span class="field-hint" id="import-hint">${esc((IMPORTS[kind] || IMPORTS.windows).hint)}</span>
        </label>
        <div class="dropzone" id="dropzone" tabindex="0" role="button" aria-label="Choose a file to import">
          ${icon('upload')}<strong>Drop a file here or choose one</strong><span>Accepted: <span id="import-accept">${esc((IMPORTS[kind] || IMPORTS.windows).accept)}</span></span>
        </div>
        <div class="progress" id="import-progress" hidden><i></i></div>
        <div id="import-result"></div>
      </div>
      <div class="dialog-foot"><button class="button" data-close-dialog>Close</button></div>`, root => {
      const kindSel = $('#import-kind', root);
      const zone = $('#dropzone', root);
      const syncKind = () => { const m = IMPORTS[kindSel.value]; $('#import-hint', root).textContent = m.hint; $('#import-accept', root).textContent = m.accept; };
      kindSel.addEventListener('change', syncKind);
      const run = file => uploadFile(file, kindSel.value, {
        progressEl: $('#import-progress', root), resultEl: $('#import-result', root),
      });
      const pick = () => chooseFile(IMPORTS[kindSel.value].accept, run);
      zone.addEventListener('click', pick);
      zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(); } });
      zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('is-over'); });
      zone.addEventListener('dragleave', () => zone.classList.remove('is-over'));
      zone.addEventListener('drop', e => { e.preventDefault(); e.stopPropagation(); zone.classList.remove('is-over'); if (e.dataTransfer.files[0]) run(e.dataTransfer.files[0]); });
    });
  }
  function chooseFile(accept, cb) {
    const input = $('#file-input');
    input.value = ''; input.accept = accept;
    input.onchange = () => { if (input.files[0]) cb(input.files[0]); };
    input.click();
  }
  async function uploadFile(file, kind, { progressEl, resultEl } = {}) {
    const okExt = /\.(json|csv|tsv|pcap|pcapng|log|txt)$/i.test(file.name);
    const show = html => { if (resultEl) resultEl.innerHTML = html; };
    if (!okExt) { const m = `${file.name} is not a supported file type. Use .json, .csv, .tsv, .log, .txt, .pcap or .pcapng.`; show(`<div class="callout err">${esc(m)}</div>`); toast(m, true); return; }
    if (file.size > 10 * 1024 * 1024) { const m = `${file.name} is larger than the 10 MB limit.`; show(`<div class="callout err">${esc(m)}</div>`); toast(m, true); return; }
    if (progressEl) { progressEl.hidden = false; progressEl.className = 'progress'; progressEl.firstElementChild.style.width = '4%'; }
    show(`<div class="callout busy">Importing <strong>${esc(file.name)}</strong>…</div>`);
    try {
      const res = await API.upload(endpointFor(kind, file), file, p => { if (progressEl) progressEl.firstElementChild.style.width = `${Math.max(4, p * 0.9)}%`; });
      if (progressEl) { progressEl.classList.add('done'); progressEl.firstElementChild.style.width = '100%'; }
      const added = res.successful_records ?? 0;
      const dups = res.duplicates_skipped ?? res.duplicate_records ?? 0;
      const failed = res.failed_records ?? 0;
      show(`<div class="callout ok"><strong>${n(added)} records imported from ${esc(file.name)}.</strong>
        <div class="muted">${n(dups)} duplicates skipped, ${n(failed)} lines could not be read, SHA-256 <span class="mono">${esc((res.sha256_hash || '').slice(0, 16))}</span></div></div>`);
      notify('Evidence imported', `${file.name}: ${added} records added, ${dups} duplicates skipped.`);
      toast(res.message || `${added} records imported.`);
      refreshCounts();
      if (!resultEl) load();
      else if (state.page !== 'audit') load();
      return res;
    } catch (err) {
      if (progressEl) { progressEl.classList.add('failed'); progressEl.firstElementChild.style.width = '100%'; }
      show(`<div class="callout err"><strong>Import failed.</strong> ${esc(err.message)}</div>`);
      toast(`Import failed: ${err.message}`, true);
    }
  }

  // ------------------------------------------------------------------------
  // Command palette
  // ------------------------------------------------------------------------
  const RULE_SHORTCUTS = [
    { page: 'system', q: '4625', title: 'Failed logons (event 4625)', desc: 'Possible password guessing' },
    { page: 'system', q: '4624', title: 'Successful logons (event 4624)', desc: 'Who signed in and from where' },
    { page: 'system', q: '4720', title: 'Accounts created (event 4720)', desc: 'New local accounts' },
    { page: 'system', q: '4672', title: 'Special privileges (event 4672)', desc: 'Administrator-level logons' },
    { page: 'process', q: 'powershell', title: 'PowerShell activity', desc: 'Script interpreter use' },
    { page: 'network', q: 'DNS', title: 'DNS lookups', desc: 'Domain names resolved' },
    { page: 'forensic', q: 'deleted', title: 'Deleted files', desc: 'Recovered by Autopsy' },
  ];
  function openPalette() {
    const root = $('#palette-root');
    if (root.innerHTML) { root.innerHTML = ''; return; }
    lastFocus = document.activeElement;
    root.innerHTML = `
      <div class="palette" data-palette-backdrop>
        <div class="palette-box" role="dialog" aria-modal="true" aria-label="Search">
          <div class="palette-input">${icon('search')}<input id="palette-q" placeholder="Search pages, event IDs, users, IP addresses" autocomplete="off" aria-controls="palette-list"><kbd>Esc</kbd></div>
          <ul class="palette-list" id="palette-list" role="listbox"></ul>
          <div class="palette-foot"><span>Arrow keys move</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span></div>
        </div>
      </div>`;
    const input = $('#palette-q');
    let items = []; let active = 0;
    const close = () => { root.innerHTML = ''; lastFocus?.focus?.(); };
    const render = () => {
      const q = input.value.trim().toLowerCase();
      const pages = Object.entries(PAGES).filter(([, p]) => !q || p.title.toLowerCase().includes(q) || p.desc.toLowerCase().includes(q))
        .map(([id, p]) => ({ group: 'Pages', icon: p.icon, title: p.title, desc: p.desc, run: () => go(id) }));
      const rules = RULE_SHORTCUTS.filter(r => !q || `${r.title} ${r.desc} ${r.q}`.toLowerCase().includes(q))
        .map(r => ({ group: 'Shortcuts', icon: PAGES[r.page].icon, title: r.title, desc: r.desc, run: () => { filtersFor(r.page).search = r.q; go(r.page); } }));
      const events = q.length > 1 ? state.lastEvents.filter(e => [e.title, e.username, e.source_ip, e.destination_ip, e.command, e.evidence_reference].join(' ').toLowerCase().includes(q)).slice(0, 6)
        .map(e => ({ group: 'Events on this page', icon: 'events', title: e.title, desc: `${e.source}, ${fmtDateTime(e.event_time)}`, run: () => openEvent(e) })) : [];
      items = [...pages, ...rules, ...events];
      active = Math.min(active, Math.max(0, items.length - 1));
      let group = '';
      $('#palette-list').innerHTML = items.length ? items.map((it, i) => {
        const head = it.group !== group ? `<li class="palette-group" role="presentation">${esc((group = it.group))}</li>` : '';
        return `${head}<li class="palette-item ${i === active ? 'is-active' : ''}" role="option" aria-selected="${i === active}" data-i="${i}">${icon(it.icon)}<div><strong>${highlight(it.title, q)}</strong><small>${highlight(it.desc, q)}</small></div></li>`;
      }).join('') : `<li class="empty"><strong>No matches for "${esc(input.value)}"</strong><p>Try a page name, an event ID such as 4625, a user name or an IP address.</p></li>`;
      $('.palette-item.is-active')?.scrollIntoView({ block: 'nearest' });
    };
    const runActive = () => { const it = items[active]; close(); it?.run(); };
    input.addEventListener('input', () => { active = 0; render(); });
    input.addEventListener('keydown', e => {
      if (e.key === 'ArrowDown') { e.preventDefault(); active = (active + 1) % Math.max(1, items.length); render(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); active = (active - 1 + items.length) % Math.max(1, items.length); render(); }
      else if (e.key === 'Enter') { e.preventDefault(); runActive(); }
      else if (e.key === 'Escape') close();
    });
    $('#palette-list').addEventListener('click', e => { const li = e.target.closest('.palette-item'); if (li) { active = Number(li.dataset.i); runActive(); } });
    root.querySelector('[data-palette-backdrop]').addEventListener('mousedown', e => { if (e.target.hasAttribute('data-palette-backdrop')) close(); });
    render(); input.focus();
  }

  // ------------------------------------------------------------------------
  // Shell: navigation, counts, tool status, demo notice
  // ------------------------------------------------------------------------
  function renderNav() {
    let html = ''; let group;
    for (const [id, p] of Object.entries(PAGES)) {
      if (p.group !== group) {
        if (group !== undefined) html += '</div>';
        group = p.group;
        html += `<div class="nav-group">${group ? `<div class="nav-group-label">${group}</div>` : ''}`;
      }
      html += `<button class="nav-item" data-nav="${id}" ${state.page === id ? 'aria-current="page"' : ''}>${icon(p.icon)}<span>${p.label}</span>${p.count ? `<span class="count" data-count="${p.count}"></span>` : ''}</button>`;
    }
    $('#nav').innerHTML = `${html}</div>`;
    updateCounts();
  }
  function updateCounts() {
    const s = state.stats; if (!s) return;
    const src = s.sources || {};
    const values = {
      detections: s.detections?.total || 0,
      security: (src.windows_audit || 0) + (src.linux_audit || 0) + (src.system_audit || 0),
      network: s.categories?.network || 0,
      autopsy: src.autopsy || 0,
    };
    $$('[data-count]').forEach(el => {
      const v = values[el.dataset.count] || 0;
      el.textContent = v ? n(v) : '';
      el.classList.toggle('alert', el.dataset.count === 'detections' && (s.detections?.severity_counts?.Critical || 0) > 0);
    });
    const demo = s.demo_records || 0;
    $('#demo-notice').innerHTML = demo ? `
      <div class="notice">${icon('info')}<span><strong>${n(demo)} demo records are loaded.</strong> They are tagged Demo and kept apart from real evidence.</span>
        <button class="button small" id="clear-demo">${icon('trash', 'icon-sm')}Clear demo data</button></div>` : '';
    $('#clear-demo')?.addEventListener('click', askClearDemo);
  }
  async function refreshCounts() {
    try { state.stats = await API.get('/api/stats'); updateCounts(); setConn(true); } catch { setConn(false); }
  }
  function setConn(ok) {
    const c = $('#conn');
    c.classList.toggle('is-down', !ok);
    c.lastElementChild.textContent = ok ? 'Connected' : 'Server offline';
  }
  async function loadToolStatus() {
    const [cap, aut] = await Promise.all([
      API.get('/api/capture/interfaces').catch(() => null),
      API.get('/api/autopsy/status').catch(() => null),
    ]);
    state.tools = { tshark: cap?.tshark || null, autopsy: aut || null, interfaces: cap?.interfaces || [] };
    const t = state.tools.tshark; const a = state.tools.autopsy;
    $('#tool-status').innerHTML = `
      <dt>Wireshark</dt><dd class="${t?.available ? 'state-ok' : 'state-bad'}">${t?.available ? 'Ready' : 'Not found'}</dd>
      <dt>Autopsy</dt><dd class="${a?.available ? 'state-ok' : 'state-bad'}">${a?.available ? 'Ready' : 'Not found'}</dd>`;
  }

  // ------------------------------------------------------------------------
  // Router
  // ------------------------------------------------------------------------
  const ACTIONS = {
    overview: () => `<button class="button" data-act="import">${icon('upload')}Import evidence</button><button class="button primary" data-go="audit">${icon('audit')}Run system audit</button>`,
    audit: () => `<button class="button primary" data-act="run-audit">${icon('play')}Run audit</button>`,
    detections: () => `<button class="button" data-act="scenario">${icon('flag')}Load attack scenario</button>`,
    system: () => `<button class="button" data-act="import" data-kind="linux">${icon('upload')}Import Linux log</button><button class="button primary" data-act="import" data-kind="windows">${icon('upload')}Import Windows log</button>`,
    process: () => `<button class="button primary" data-act="import" data-kind="sysmon">${icon('upload')}Import Sysmon events</button>`,
    network: () => `<button class="button" data-act="import" data-kind="network">${icon('upload')}Import capture</button><button class="button primary" data-go="audit">${icon('wave')}Start live capture</button>`,
    forensic: () => `<button class="button" data-act="import" data-kind="forensic">${icon('upload')}Import Autopsy export</button><button class="button primary" data-go="audit">${icon('files')}Analyze with Autopsy</button>`,
    timeline: () => `<a class="button" href="/api/reports/export.csv" download>${icon('download')}Export CSV</a>`,
    graph: () => '',
    reports: () => `<a class="button" href="/api/reports/export.csv" download>${icon('download')}Export evidence CSV</a><button class="button primary" data-act="print">${icon('printer')}Print or save as PDF</button>`,
    settings: () => '',
  };

  function go(page) {
    if (!PAGES[page]) page = 'overview';
    if (location.hash.slice(1) !== page) history.replaceState(null, '', `#${page}`);
    state.page = page;
    closePanel();
    $('#sidebar').classList.remove('open');
    const p = PAGES[page];
    document.title = `${p.title}, SecureScan`;
    $('#page-title').textContent = p.title;
    $('#page-desc').textContent = p.desc;
    $('#page-actions').innerHTML = ACTIONS[page]();
    $$('.nav-item').forEach(b => { if (b.dataset.nav === page) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    window.scrollTo(0, 0);
    load();
  }

  async function load() {
    const token = ++state.loadToken;
    const page = state.page;
    const root = $('#page');
    if (!root.dataset.page || root.dataset.page !== page) root.innerHTML = '<div class="region"><div class="skeleton"><i></i><i></i><i></i><i></i><i></i></div></div>';
    root.dataset.page = page;
    try {
      const html = await RENDER[page](token);
      if (token !== state.loadToken) return;
      if (typeof html === 'string') root.innerHTML = html;
      AFTER[page]?.();
      setConn(true);
    } catch (err) {
      if (token !== state.loadToken) return;
      root.innerHTML = `<div class="region"><div class="empty"><strong>This page could not load.</strong><p>${esc(err.message)}</p><button class="button" data-act="reload">${icon('refresh')}Try again</button></div></div>`;
      if (/reach the SecureScan server/.test(err.message)) setConn(false);
    }
  }

  // ------------------------------------------------------------------------
  // Shared: event table
  // ------------------------------------------------------------------------
  const COLS = {
    time: { h: 'Time', td: e => `<td class="time">${esc(fmtTime(e.event_time))}<small>${esc(fmtDate(e.event_time))}</small></td>` },
    sev: { h: 'Severity', td: e => `<td>${sevMark(e.severity, { short: true })}</td>` },
    title: { h: 'Event', td: (e, q) => `<td class="cell-title"><strong>${highlight(e.title || 'Event', q)}${demoTag(e)}</strong><span>${highlight(e.details || e.command || '', q)}</span></td>` },
    cmd: { h: 'Event and command line', td: (e, q) => `<td class="cell-title"><strong>${highlight(e.title || 'Process', q)}${demoTag(e)}</strong><span class="mono">${highlight(e.command || e.details || '', q)}</span></td>` },
    user: { h: 'Account', td: (e, q) => `<td>${highlight(e.username || '', q) || '<span class="muted">None</span>'}</td>` },
    ip: { h: 'Address', td: (e, q) => `<td class="mono">${highlight(e.source_ip || e.destination_ip || '', q) || '<span class="muted">Local</span>'}</td>` },
    src: { h: 'From', td: (e, q) => `<td class="mono">${highlight(e.source_ip || '', q) || '<span class="muted">None</span>'}</td>` },
    dst: { h: 'To', td: (e, q) => `<td class="mono">${highlight(e.destination_ip || '', q) || '<span class="muted">None</span>'}</td>` },
    proto: { h: 'Protocol', td: e => `<td>${e.protocol ? `<span class="tag">${esc(e.protocol)}</span>` : '<span class="muted">None</span>'}</td>` },
    source: { h: 'Source', td: e => `<td class="ink-2">${esc(e.source || '')}</td>` },
    ref: { h: 'Reference', td: e => `<td class="mono">${esc(e.evidence_reference || '')}</td>` },
  };
  function eventTable(events, cols, { q = '', empty = '', selectable = true, maxHeight = true } = {}) {
    const body = events.length ? events.map(e => `<tr class="${selectable ? 'clickable' : ''}" data-event-id="${esc(e.id)}" ${selectable ? 'tabindex="0"' : ''}>${cols.map(c => COLS[c].td(e, q)).join('')}</tr>`).join('')
      : `<tr><td colspan="${cols.length}">${empty}</td></tr>`;
    return `<div class="table-wrap ${maxHeight ? '' : 'no-max'}"><table class="data"><thead><tr>${cols.map(c => `<th scope="col">${COLS[c].h}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table></div>`;
  }
  function bindRows(scope, events) {
    $$('tr[data-event-id]', scope).forEach(tr => {
      const open = () => openEvent(events.find(e => e.id === tr.dataset.eventId));
      tr.addEventListener('click', open);
      tr.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); open(); } });
    });
  }
  const emptyBlock = (title, text, action = '') => `<div class="empty"><strong>${title}</strong><p>${text}</p>${action}</div>`;

  // ------------------------------------------------------------------------
  // Evidence pages (security events, processes, network, files)
  // ------------------------------------------------------------------------
  const textOf = e => `${e.title || ''} ${e.details || ''} ${e.command || ''}`.toLowerCase();
  const EVIDENCE = {
    system: {
      cols: ['time', 'sev', 'title', 'user', 'ip', 'source', 'ref'],
      placeholder: 'Search event ID, user, IP, check',
      quick: [['all', 'All sources'], ['Windows audit', 'Windows Security'], ['System audit', 'Host audit'], ['Linux audit', 'Linux auditd']],
      query: f => ({ source: f.quick === 'all' ? 'Windows audit,Linux audit,System audit' : f.quick }),
      clientQuick: false,
      empty: f => emptyBlock(f.search || f.severity !== 'all' ? 'No events match these filters' : 'No security events yet',
        f.search || f.severity !== 'all' ? 'Clear the search or choose another severity.' : 'Run the system audit, or import a Windows Security or Linux audit log.',
        '<button class="button primary" data-go="audit">Run system audit</button>'),
    },
    process: {
      cols: ['time', 'sev', 'cmd', 'user', 'source', 'ref'],
      placeholder: 'Search command line, program, hash',
      quick: [['all', 'All'], ['powershell', 'PowerShell'], ['cmd', 'cmd.exe'], ['whoami', 'Discovery'], ['mimikatz', 'Credential tools']],
      query: () => ({ category: 'Process' }),
      clientQuick: (e, q) => q === 'whoami' ? /whoami|net(\.exe)?\s|nltest|systeminfo|ipconfig/.test(textOf(e)) : q === 'mimikatz' ? /mimikatz|sekurlsa|lsass|procdump/.test(textOf(e)) : textOf(e).includes(q),
      empty: f => emptyBlock(f.search || f.quick !== 'all' ? 'No processes match these filters' : 'No process events yet',
        f.search || f.quick !== 'all' ? 'Clear the search or the quick filter.' : 'Import Sysmon events or a Windows Security log that includes event 4688.',
        '<button class="button primary" data-act="import" data-kind="sysmon">Import Sysmon events</button>'),
    },
    network: {
      cols: ['time', 'sev', 'title', 'src', 'dst', 'proto', 'ref'],
      placeholder: 'Search IP, port, protocol, domain',
      quick: [['all', 'All'], ['Wireshark', 'Wireshark'], ['System audit', 'Host connections'], ['Sysmon', 'Sysmon']],
      query: f => ({ category: 'Network', source: f.quick === 'all' ? undefined : f.quick }),
      clientQuick: false,
      empty: f => emptyBlock(f.search || f.severity !== 'all' ? 'No network events match these filters' : 'No network evidence yet',
        f.search || f.severity !== 'all' ? 'Clear the search or choose another severity.' : 'Start a live capture from System audit, or import a .pcap, .pcapng or Wireshark CSV.',
        '<button class="button primary" data-go="audit">Start live capture</button>'),
    },
    forensic: {
      cols: ['time', 'sev', 'title', 'ref'],
      placeholder: 'Search file name, path, hash',
      quick: [['all', 'All'], ['deleted', 'Deleted'], ['mismatch', 'Disguised'], ['credential', 'Credentials'], ['temp', 'Temp and downloads'], ['web', 'Web history'], ['usb', 'Devices']],
      query: () => ({ source: 'Autopsy' }),
      clientQuick: (e, q) => {
        const t = textOf(e);
        return ({
          deleted: /deleted|unallocated|recycle/.test(t),
          mismatch: /mismatch|same executable|disguis/.test(t),
          credential: /credential|password|id_rsa|private key|shadow|sam hive|\.kdbx|known-bad/.test(t),
          temp: /temp|tmp|download|staging/.test(t),
          web: /history|browser|cookie|web /.test(t),
          usb: /usb|device/.test(t),
        })[q] ?? true;
      },
      empty: f => emptyBlock(f.search || f.quick !== 'all' ? 'No artifacts match these filters' : 'No Autopsy findings yet',
        f.search || f.quick !== 'all' ? 'Clear the search or the quick filter.' : 'Analyze a folder or disk image with Autopsy from System audit, or import an Autopsy export.',
        '<button class="button primary" data-go="audit">Analyze with Autopsy</button>'),
    },
  };

  function renderEvidencePage(page) {
    const cfg = EVIDENCE[page]; const f = filtersFor(page);
    return async () => {
      const extra = page === 'network' ? await networkSummaryHTML() : '';
      return `${extra}
        <section class="region">
          <div class="toolbar">
            <div class="search-input">${icon('search')}<input class="input" type="search" id="ev-search" placeholder="${esc(cfg.placeholder)}" value="${esc(f.search)}" aria-label="Search events"></div>
            <select class="select" id="ev-sev" aria-label="Severity">
              <option value="all">All severities</option>${SEVERITIES.map(s => `<option ${f.severity === s ? 'selected' : ''}>${s}</option>`).join('')}
            </select>
            <div class="segmented" role="group" aria-label="Quick filter">${cfg.quick.map(([v, l]) => `<button type="button" data-quick="${esc(v)}" aria-pressed="${f.quick === v}">${esc(l)}<span class="n" data-qn="${esc(v)}"></span></button>`).join('')}</div>
            <span class="spacer"></span>
            <span class="result-count" id="ev-count"></span>
            <button class="button ghost small" id="ev-reset">Reset filters</button>
          </div>
          <div id="ev-table"><div class="skeleton"><i></i><i></i><i></i></div></div>
        </section>`;
    };
  }
  async function refreshEvidenceTable(page) {
    const cfg = EVIDENCE[page]; const f = filtersFor(page);
    const token = state.loadToken;
    const params = { ...cfg.query(f), severity: f.severity, search: f.search, limit: 1000 };
    let events = await API.get('/api/events', params);
    if (token !== state.loadToken) return;
    if (cfg.clientQuick) {
      cfg.quick.forEach(([v]) => { const el = $(`[data-qn="${CSS.escape(v)}"]`); if (el && v !== 'all') el.textContent = n(events.filter(e => cfg.clientQuick(e, v)).length); });
      if (f.quick !== 'all') events = events.filter(e => cfg.clientQuick(e, f.quick));
    }
    state.lastEvents = events;
    $('#ev-count').textContent = `${n(events.length)} ${events.length === 1 ? 'event' : 'events'}${events.length >= 1000 ? ' (first 1,000)' : ''}`;
    const wrap = $('#ev-table');
    wrap.innerHTML = eventTable(events, cfg.cols, { q: f.search, empty: cfg.empty(f) });
    bindRows(wrap, events);
  }
  function bindEvidencePage(page) {
    const f = filtersFor(page);
    const refresh = () => refreshEvidenceTable(page).catch(err => { $('#ev-table').innerHTML = emptyBlock('Events could not load.', esc(err.message)); });
    $('#ev-search').addEventListener('input', debounce(e => { f.search = e.target.value.trim(); refresh(); }, 300));
    $('#ev-sev').addEventListener('change', e => { f.severity = e.target.value; refresh(); });
    $$('[data-quick]').forEach(b => b.addEventListener('click', () => {
      f.quick = b.dataset.quick;
      $$('[data-quick]').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
      refresh();
    }));
    $('#ev-reset').addEventListener('click', () => { state.filters[page] = { search: '', severity: 'all', quick: 'all' }; load(); });
    refresh();
  }

  async function networkSummaryHTML() {
    const s = await API.get('/api/network/stats').catch(() => null);
    if (!s || !s.total_packets) return '';
    const protos = Object.entries(s.protocols || {}).slice(0, 6);
    const maxP = Math.max(1, ...protos.map(p => p[1]));
    const list = (rows, head, valueLabel) => `<table class="data"><thead><tr><th>${head}</th><th class="num">${valueLabel}</th></tr></thead><tbody>${rows || '<tr><td colspan="2" class="muted">None recorded</td></tr>'}</tbody></table>`;
    return `
      <div class="split section" style="grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--s5);margin-bottom:var(--s6)">
        <section class="region">${list(protos.map(([p, c]) => `<tr><td><div class="bar-cell"><span style="min-width:64px">${esc(p)}</span><span class="bar"><i style="width:${(c / maxP) * 100}%"></i></span></div></td><td class="num">${n(c)}</td></tr>`).join(''), 'Protocol', 'Events')}</section>
        <section class="region">${list((s.top_sources || []).slice(0, 6).map(r => `<tr><td class="mono">${esc(r.ip)}</td><td class="num">${n(r.count)}</td></tr>`).join(''), 'Busiest source address', 'Events')}</section>
        <section class="region">${list((s.dns_queries || []).slice(0, 6).map(r => `<tr><td class="mono">${esc(r.query)}</td><td class="num">${r.is_demo ? '<span class="tag demo">Demo</span>' : ''}</td></tr>`).join(''), 'Domain names looked up', '')}</section>
      </div>`;
  }

  // ------------------------------------------------------------------------
  // Overview
  // ------------------------------------------------------------------------
  const SOURCE_ROWS = [
    ['system_audit', 'Host audit', 'audit'], ['windows_audit', 'Windows Security log', 'system'], ['wireshark', 'Wireshark', 'network'],
    ['autopsy', 'Autopsy', 'forensic'], ['sysmon', 'Sysmon', 'process'], ['linux_audit', 'Linux auditd', 'system'],
  ];
  function riskScale(score) {
    return `<div class="scale" aria-label="Risk score ${score} out of 100">
      <div class="scale-marker" style="left:${Math.min(100, Math.max(0, score))}%">${score}</div>
      <div class="scale-track"><i></i><i></i><i></i><i></i></div>
      <div class="scale-labels"><span>Low</span><span>Medium</span><span>High</span><span>Critical</span></div>
    </div>`;
  }
  async function renderOverview() {
    const [stats, det, events] = await Promise.all([API.get('/api/stats'), API.get('/api/detections'), API.get('/api/events', { limit: 10 })]);
    state.stats = stats; updateCounts();
    state.lastEvents = events;
    const total = stats.total_events || 0;
    const sev = { Critical: stats.critical, High: stats.high, Medium: stats.medium, Low: stats.low, Informational: stats.informational };
    const top = (det.detections || []).slice(0, 5);
    const counts = det.severity_counts || {};
    const sentence = det.total
      ? `${n(det.total)} correlated ${det.total === 1 ? 'detection' : 'detections'}: ${['Critical', 'High', 'Medium'].filter(s => counts[s]).map(s => `${counts[s]} ${s.toLowerCase()}`).join(', ')}.`
      : 'No attack patterns were found in the current evidence.';
    const src = stats.sources || {};
    const maxSrc = Math.max(1, ...SOURCE_ROWS.map(([k]) => src[k] || 0));

    return `
      <section class="region posture">
        <div>
          <div class="posture-figure"><strong>${det.risk_score}</strong><span>/ 100 risk</span></div>
          <div class="posture-level">${esc(det.risk_level === 'None' ? 'No risk found' : `${det.risk_level} risk`)}</div>
          <p class="posture-text">${esc(sentence)} ${det.total ? '<button class="link-button" data-go="detections">Review detections</button>' : '<button class="link-button" data-go="audit">Run the system audit</button>'}</p>
        </div>
        ${riskScale(det.risk_score)}
      </section>

      <div class="split-2-1 section">
        <section>
          <div class="section-head"><h2>Needs attention</h2><span class="meta">Highest-severity detections first</span></div>
          ${top.length ? `<ul class="attention">${top.map(d => `
            <li>
              ${sevMark(d.severity)}
              <div class="what"><strong>${esc(d.name)}</strong><span>${esc(d.summary)}</span></div>
              <span class="when">${esc(fmtDate(d.first_seen))}</span>
            </li>`).join('')}</ul>
            <p class="section-note"><button class="link-button" data-go="detections">See all ${n(det.total)} detections and their evidence</button></p>`
            : `<div class="region">${emptyBlock('Nothing needs attention', 'The correlation engine found no attack patterns. Run the system audit or load the attack scenario to see how detections look.', '<button class="button" data-act="scenario">Load attack scenario</button>')}</div>`}
        </section>

        <section>
          <div class="section-head"><h2>Evidence</h2><span class="meta num">${n(total)} records</span></div>
          <div class="distribution" role="img" aria-label="Events by severity">${SEVERITIES.map(s => sev[s] ? `<i class="d-${s.toLowerCase()}" style="flex:${sev[s]}" title="${s}: ${sev[s]}"></i>` : '').join('')}</div>
          <div class="legend">${SEVERITIES.map(s => `<span>${sevMark(s, { label: false })} ${s === 'Informational' ? 'Info' : s} <span class="num">${n(sev[s] || 0)}</span></span>`).join('')}</div>
          <div class="region" style="margin-top:var(--s4)">
            <table class="data"><thead><tr><th>Source</th><th>Share</th><th class="num">Records</th></tr></thead><tbody>
              ${SOURCE_ROWS.map(([k, label, page]) => `<tr class="clickable" data-go="${page}" tabindex="0"><td>${label}</td><td><div class="bar-cell"><span class="bar"><i style="width:${((src[k] || 0) / maxSrc) * 100}%"></i></span></div></td><td class="num">${n(src[k] || 0)}</td></tr>`).join('')}
            </tbody></table>
          </div>
        </section>
      </div>

      <section class="section">
        <div class="section-head"><h2>Latest events</h2><button class="link-button" data-go="timeline">Open the full timeline</button></div>
        <div class="region" id="ov-events">${eventTable(events, ['time', 'sev', 'title', 'user', 'ip', 'source'], { empty: emptyBlock('No evidence yet', 'Start with the system audit. It checks this PC, captures network traffic and analyzes files.', '<button class="button primary" data-go="audit">Run system audit</button>'), maxHeight: false })}</div>
      </section>`;
  }

  // ------------------------------------------------------------------------
  // System audit console
  // ------------------------------------------------------------------------
  function checksHTML(latest) {
    if (!latest || !latest.available) {
      return emptyBlock('This workstation has not been audited yet', 'The audit runs 14 read-only checks in about 15 seconds. It does not need administrator rights and changes nothing.', `<button class="button primary" data-act="run-audit">${icon('play')}Run audit</button>`);
    }
    const c = latest.checks.reduce((a, x) => (a[x.status] = (a[x.status] || 0) + 1, a), {});
    return `
      <div class="toolbar">
        <div class="score-line">
          <span><span class="num">${c.pass || 0}</span> passed</span>
          <span><span class="num">${c.warn || 0}</span> warnings</span>
          <span><span class="num">${c.fail || 0}</span> failed</span>
          ${(c.skipped || 0) + (c.error || 0) ? `<span><span class="num">${(c.skipped || 0) + (c.error || 0)}</span> not checked</span>` : ''}
        </div>
        <span class="spacer"></span>
        <span class="result-count">${esc(latest.meta.computer)}, ${esc(latest.meta.os || '')}, audited ${esc(fmtDateTime(latest.meta.audit_time))}${latest.meta.is_admin ? '' : ' as a standard user'}</span>
      </div>
      <div class="table-wrap no-max"><table class="data">
        <thead><tr><th style="width:130px">Result</th><th style="width:220px">Check</th><th>Finding</th></tr></thead>
        <tbody>${latest.checks.map(x => `<tr><td>${checkMark(x.status)}</td><td>${esc(x.check)}</td><td class="ink-2">${esc(x.note)}</td></tr>`).join('')}</tbody>
      </table></div>`;
  }
  function autopsyJobHTML(job) {
    if (!job) return '';
    const s = job.summary;
    const cls = job.status === 'running' ? 'busy' : job.status === 'done' ? 'ok' : 'err';
    return `<div class="callout ${cls}">
      <strong>${esc(job.message || '')}</strong>
      <div class="mono muted">${esc(job.source || '')}</div>
      ${s ? `<div class="muted">${n(s.files_total)} files, ${n(s.files_deleted)} deleted, ${n(s.files_flagged)} flagged, ${n(Object.values(s.artifacts || {}).reduce((a, b) => a + b, 0))} Autopsy artifacts, case database SHA-256 <span class="mono">${esc((s.case_db_sha256 || '').slice(0, 16))}</span></div>
        <div class="actions"><button class="button small" data-go="forensic">View findings</button></div>` : ''}
    </div>`;
  }
  async function renderAudit() {
    const [latest, capture, autopsy] = await Promise.all([
      API.get('/api/audit/host/latest').catch(() => ({ available: false })),
      API.get('/api/capture/interfaces').catch(() => ({ tshark: { available: false }, interfaces: [] })),
      API.get('/api/autopsy/status').catch(() => ({ available: false, jobs: [] })),
    ]);
    Object.assign(state.audit, { latest, capture, autopsy });
    const ifaces = capture.interfaces || [];
    const preferred = ifaces.find(i => /^(wi-?fi|ethernet)$/i.test(i.name)) || ifaces.find(i => /wi-?fi|ethernet/i.test(i.name)) || ifaces[0];
    const tsharkOk = capture.tshark?.available;
    const lastJob = (autopsy.jobs || [])[0];
    return `
      <section class="section">
        <div class="section-head"><h2>Workstation security checks</h2><span class="meta">Accounts, administrators, open ports, connections, firewall, Defender, UAC, Remote Desktop, SMBv1, startup programs, scheduled tasks, updates, process locations, Security log</span></div>
        <div class="region" id="audit-checks">${checksHTML(latest)}</div>
      </section>

      <div class="tools section">
        <section class="region tool">
          <div class="tool-head">
            <h2>${icon('wave')}Network capture with Wireshark</h2>
            <p>${tsharkOk ? esc(capture.tshark.version) : 'TShark was not found. Install Wireshark with the TShark and Npcap components.'}</p>
          </div>
          <div class="tool-body">
            <label class="field"><span class="field-label">Interface</span>
              <select class="select" id="cap-iface" ${tsharkOk ? '' : 'disabled'}>${ifaces.map(i => `<option value="${esc(i.id)}" ${preferred && preferred.id === i.id ? 'selected' : ''}>${esc(i.name)}</option>`).join('')}</select>
            </label>
            <div class="form-grid">
              <label class="field"><span class="field-label">Duration in seconds</span><input class="input" id="cap-duration" type="number" min="5" max="120" value="20"></label>
              <label class="field"><span class="field-label">Packet limit</span><input class="input" id="cap-packets" type="number" min="10" max="20000" value="2000"></label>
            </div>
            <label class="field"><span class="field-label">Capture filter (optional)</span><input class="input" id="cap-filter" type="text" placeholder="tcp or udp port 53"><span class="field-hint">Berkeley Packet Filter syntax, as in Wireshark's capture filter box.</span></label>
            <div><button class="button primary" data-act="capture" ${tsharkOk ? '' : 'disabled'}>${icon('play')}Start capture</button></div>
            <div id="capture-result"></div>
          </div>
        </section>

        <section class="region tool">
          <div class="tool-head">
            <h2>${icon('files')}Disk and file analysis with Autopsy</h2>
            <p>${autopsy.available ? `Autopsy ${esc(autopsy.version)} found. Analysis usually takes one to five minutes.` : 'Autopsy was not found under Program Files.'}</p>
          </div>
          <div class="tool-body">
            <label class="field"><span class="field-label">Folder or disk image</span><input class="input" id="aut-source" type="text" placeholder="C:\\Users\\you\\Downloads   or   D:\\evidence\\disk.E01"><span class="field-hint">Autopsy creates a case, hashes and identifies every file, then SecureScan reads the case read-only.</span></label>
            <div><button class="button primary" data-act="autopsy" ${autopsy.available ? '' : 'disabled'}>${icon('play')}Analyze with Autopsy</button></div>
            <div id="autopsy-result">${autopsyJobHTML(lastJob)}</div>
            <div class="tool-or">or</div>
            <label class="field"><span class="field-label">Import a case built in the Autopsy app</span><input class="input" id="aut-case" type="text" placeholder="Case folder, .aut file or autopsy.db"></label>
            <div><button class="button" data-act="autopsy-case">${icon('upload')}Import case</button></div>
            <div id="autopsy-case-result"></div>
          </div>
        </section>
      </div>`;
  }
  function afterAudit() {
    const running = (state.audit.autopsy?.jobs || []).find(j => j.status === 'running');
    if (running) pollAutopsy(running.id);
  }
  function busy(btn, on, label) {
    if (!btn) return;
    if (on) { btn.dataset.html = btn.innerHTML; btn.textContent = label; btn.classList.add('is-busy'); btn.disabled = true; }
    else { btn.innerHTML = btn.dataset.html || btn.innerHTML; btn.classList.remove('is-busy'); btn.disabled = false; }
  }
  async function runAudit(btn) {
    $$('[data-act="run-audit"]').forEach(b => busy(b, true, 'Auditing, about 15 seconds'));
    try {
      const res = await API.post('/api/audit/host');
      state.audit.latest = { available: true, meta: res.meta, checks: res.checks, sha256_hash: res.sha256_hash };
      if (state.page === 'audit') $('#audit-checks').innerHTML = checksHTML(state.audit.latest);
      notify('System audit finished', res.message); toast(res.message);
      refreshCounts();
    } catch (err) { toast(err.message, true); }
    finally { $$('[data-act="run-audit"]').forEach(b => busy(b, false)); }
    if (state.page !== 'audit' && btn) go('audit');
  }
  async function runCapture(btn) {
    const body = { interface: $('#cap-iface')?.value, duration: Number($('#cap-duration').value || 20), max_packets: Number($('#cap-packets').value || 2000), filter: $('#cap-filter').value.trim() };
    busy(btn, true, `Capturing for ${body.duration} seconds`);
    $('#capture-result').innerHTML = `<div class="callout busy">Capturing on ${esc($('#cap-iface')?.selectedOptions[0]?.textContent || '')}. Traffic is written to a .pcapng evidence file.</div>`;
    try {
      const res = await API.post('/api/capture/live', body);
      $('#capture-result').innerHTML = `<div class="callout ok"><strong>${esc(res.message)}</strong>
        <div class="muted"><span class="mono">${esc(res.stored_file)}</span>, SHA-256 <span class="mono">${esc(res.sha256_hash.slice(0, 16))}</span></div>
        <div class="actions"><button class="button small" data-go="network">View packets</button></div></div>`;
      notify('Capture finished', res.message); toast(res.message); refreshCounts();
    } catch (err) {
      $('#capture-result').innerHTML = `<div class="callout err"><strong>The capture failed.</strong> ${esc(err.message)}</div>`;
      toast(err.message, true);
    } finally { busy(btn, false); }
  }
  function pollAutopsy(jobId) {
    clearTimeout(state.audit.pollTimer);
    const tick = async () => {
      try {
        const job = await API.get(`/api/autopsy/jobs/${encodeURIComponent(jobId)}`);
        const box = $('#autopsy-result'); if (box) box.innerHTML = autopsyJobHTML(job);
        const btn = $('[data-act="autopsy"]');
        if (job.status === 'running') { if (btn) btn.disabled = true; state.audit.pollTimer = setTimeout(tick, 3000); return; }
        if (btn) btn.disabled = false;
        if (job.status === 'done') { notify('Autopsy analysis finished', job.message); toast(job.message); refreshCounts(); }
        else toast(job.message, true);
      } catch (err) { toast(err.message, true); }
    };
    tick();
  }
  async function runAutopsy() {
    const path = $('#aut-source').value.trim();
    if (!path) { toast('Enter the path of a folder or disk image first.', true); $('#aut-source').focus(); return; }
    try { const res = await API.post('/api/autopsy/analyze', { path }); toast(res.message); pollAutopsy(res.job_id); }
    catch (err) { toast(err.message, true); }
  }
  async function importAutopsyCase(btn) {
    const path = $('#aut-case').value.trim();
    if (!path) { toast('Enter the Autopsy case path first.', true); $('#aut-case').focus(); return; }
    busy(btn, true, 'Reading case');
    try {
      const res = await API.post('/api/autopsy/import-case', { path });
      $('#autopsy-case-result').innerHTML = autopsyJobHTML({ status: 'done', message: res.message, source: res.summary.case_dir, summary: res.summary });
      toast(res.message); refreshCounts();
    } catch (err) {
      $('#autopsy-case-result').innerHTML = `<div class="callout err"><strong>The case could not be imported.</strong> ${esc(err.message)}</div>`;
      toast(err.message, true);
    } finally { busy(btn, false); }
  }

  // ------------------------------------------------------------------------
  // Detections
  // ------------------------------------------------------------------------
  async function renderDetections() {
    const d = await API.get('/api/detections');
    state.detections = d;
    const f = filtersFor('detections');
    const sc = d.severity_counts || {};
    const list = (d.detections || []).filter(x => f.quick === 'all' || x.severity === f.quick);
    const kc = (d.kill_chain || []).map(k => `<div class="kc ${k.count ? 'hit' : ''}" title="${esc(k.techniques.join('\n') || 'Nothing detected')}"><span class="n">${k.count}</span><span class="t">${esc(k.tactic)}</span></div>`).join('');
    const ents = (d.top_entities || []).map(e => `<tr><td class="ink-2">${e.type === 'ip' ? 'Address' : 'Account'}</td><td class="mono">${esc(e.value)}</td><td><div class="bar-cell"><span class="bar"><i style="width:${e.score}%;background:var(--crit)"></i></span><span class="num" style="min-width:24px;text-align:right">${e.score}</span></div></td></tr>`).join('');
    const items = list.map(x => {
      const entities = Object.entries(x.entities || {}).flatMap(([k, vs]) => vs.slice(0, 4).map(v => `<span class="tag" title="${esc(k)}">${esc(v)}</span>`)).join('');
      return `<li class="det">
        <div class="det-top">${sevMark(x.severity)}<h3>${esc(x.name)}</h3><span class="rule">${esc(x.rule_id)}</span>${demoTag(x)}<span class="when">${esc(fmtDateTime(x.first_seen))}, ${n(x.event_count)} events</span></div>
        <p class="summary">${esc(x.summary)}</p>
        <div class="row"><span class="label">ATT&CK</span>${(x.mitre || []).map(m => `<a class="tag mitre" href="https://attack.mitre.org/techniques/${esc(m.id.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer" title="${esc(m.tactic)}">${esc(m.id)} ${esc(m.name)}</a>`).join('')}</div>
        <div class="row"><span class="label">Involves</span>${entities}<span class="label" style="margin-left:8px">Seen in</span>${(x.sources || []).map(s => `<span class="tag">${esc(s)}</span>`).join('')}</div>
        <p class="reco"><strong>Next step:</strong> ${esc(x.recommendation)}</p>
        <details><summary>Show the ${n(x.evidence.length)} triggering events${x.event_count > x.evidence.length ? ` (of ${n(x.event_count)})` : ''}</summary>
          <div class="region">${eventTable(x.evidence, ['time', 'sev', 'title', 'source', 'ref'], { selectable: false, maxHeight: false })}</div>
        </details>
      </li>`;
    }).join('');
    return `
      <section class="region">
        <div class="posture">
          <div>
            <div class="posture-figure"><strong>${d.risk_score}</strong><span>/ 100 risk</span></div>
            <div class="posture-level">${esc(d.risk_level === 'None' ? 'No risk found' : `${d.risk_level} risk`)}</div>
            <p class="posture-text">${n(d.total)} detections from ${n(d.rules_evaluated)} correlation rules: ${n(sc.Critical || 0)} critical, ${n(sc.High || 0)} high, ${n(sc.Medium || 0)} medium.</p>
          </div>
          ${riskScale(d.risk_score)}
        </div>
        <div class="killchain" aria-label="MITRE ATT&CK tactics observed, in attack order">${kc}</div>
      </section>

      <div class="split-2-1 section">
        <section>
          <div class="region">
            <div class="toolbar">
              <div class="segmented" role="group" aria-label="Severity">${[['all', 'All', d.total], ['Critical', 'Critical', sc.Critical], ['High', 'High', sc.High], ['Medium', 'Medium', sc.Medium]].map(([v, l, c]) => `<button type="button" data-det-filter="${v}" aria-pressed="${f.quick === v}">${l}<span class="n">${n(c || 0)}</span></button>`).join('')}</div>
            </div>
            ${items ? `<ul class="det-list">${items}</ul>` : emptyBlock(d.total ? 'No detections at this severity' : 'No attack patterns found', d.total ? 'Choose another severity.' : `The engine checked ${d.rules_evaluated} correlation rules against all evidence. Load the attack scenario to see brute force, discovery, credential theft and command-and-control linked into one incident.`, d.total ? '' : '<button class="button" data-act="scenario">Load attack scenario</button>')}
          </div>
          <p class="section-note">${esc(d.disclaimer || '')}</p>
        </section>
        <section>
          <div class="section-head"><h2>Most involved</h2><span class="meta">Weighted by detection severity</span></div>
          <div class="region">${ents ? `<table class="data"><thead><tr><th>Type</th><th>Value</th><th>Score</th></tr></thead><tbody>${ents}</tbody></table>` : emptyBlock('No accounts or addresses involved', 'They appear here once detections exist.')}</div>
        </section>
      </div>`;
  }

  // ------------------------------------------------------------------------
  // Timeline
  // ------------------------------------------------------------------------
  async function renderTimeline() {
    const f = filtersFor('timeline'); const t = state.timeline;
    return `
      <section class="region">
        <div class="toolbar">
          <div class="search-input">${icon('search')}<input class="input" type="search" id="tl-search" placeholder="Search title, user, IP, reference" value="${esc(f.search)}" aria-label="Search timeline"></div>
          <select class="select" id="tl-sev" aria-label="Severity"><option value="all">All severities</option>${SEVERITIES.map(s => `<option ${f.severity === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
          <select class="select" id="tl-src" aria-label="Source">${[['all', 'All sources'], ['System audit', 'Host audit'], ['Windows audit', 'Windows Security'], ['Wireshark', 'Wireshark'], ['Autopsy', 'Autopsy'], ['Sysmon', 'Sysmon'], ['Linux audit', 'Linux auditd']].map(([v, l]) => `<option value="${esc(v)}" ${t.source === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
          <select class="select" id="tl-range" aria-label="Time range">${[['all', 'Any time'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']].map(([v, l]) => `<option value="${v}" ${t.range === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
          <button class="button" id="tl-sort">${icon('sort')}${t.sort === 'desc' ? 'Newest first' : 'Oldest first'}</button>
          <span class="spacer"></span><span class="result-count" id="tl-count"></span>
        </div>
        <div class="tl"><div class="tl-stream" id="tl-stream" role="listbox" aria-label="Events"><div class="skeleton"><i></i><i></i><i></i></div></div><div class="tl-detail" id="tl-detail"></div></div>
      </section>`;
  }
  async function refreshTimeline() {
    const f = filtersFor('timeline'); const t = state.timeline; const token = state.loadToken;
    let events = await API.get('/api/timeline', { search: f.search, severity: f.severity, source: t.source, limit: 500 });
    if (token !== state.loadToken) return;
    if (t.range !== 'all') {
      const cutoff = Date.now() - ({ '24h': 1, '7d': 7, '30d': 30 }[t.range]) * 86400000;
      events = events.filter(e => (toDate(e.event_time)?.getTime() || 0) >= cutoff);
    }
    events.sort((a, b) => (t.sort === 'asc' ? 1 : -1) * ((toDate(a.event_time)?.getTime() || 0) - (toDate(b.event_time)?.getTime() || 0)));
    state.lastEvents = events;
    $('#tl-count').textContent = `${n(events.length)} events`;
    if (!events.find(e => e.id === t.selectedId)) t.selectedId = events[0]?.id || null;
    let day = '';
    $('#tl-stream').innerHTML = events.length ? events.map(e => {
      const d = fmtDay(e.event_time);
      const head = d !== day ? `<div class="tl-day">${esc((day = d))}</div>` : '';
      return `${head}<button class="tl-item" role="option" data-id="${esc(e.id)}" aria-selected="${e.id === t.selectedId}">
        <span class="t">${esc(fmtTime(e.event_time))}</span><span class="m">${sevMark(e.severity, { label: false })}</span>
        <span><strong>${highlight(e.title || 'Event', f.search)}</strong><span class="s">${esc(e.source)}${e.username ? `, ${esc(e.username)}` : ''}${e.source_ip ? `, ${esc(e.source_ip)}` : ''}${e.is_demo ? ', Demo' : ''}</span></span>
      </button>`;
    }).join('') : emptyBlock('No events match', 'Clear the search or widen the time range.');
    showTimelineDetail();
    $$('.tl-item').forEach(b => b.addEventListener('click', () => {
      t.selectedId = b.dataset.id;
      $$('.tl-item').forEach(x => x.setAttribute('aria-selected', String(x === b)));
      showTimelineDetail();
    }));
    $('.tl-item[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  }
  function showTimelineDetail() {
    const e = state.lastEvents.find(x => x.id === state.timeline.selectedId);
    const box = $('#tl-detail');
    if (!e) { box.innerHTML = emptyBlock('Select an event', 'Its details appear here.'); return; }
    box.innerHTML = `
      <div>${sevMark(e.severity)} ${demoTag(e)}</div>
      <h2>${esc(e.title)}</h2>
      <dl class="dl">
        <dt>Time</dt><dd class="mono">${esc(fmtDateTime(e.event_time))}</dd>
        <dt>Source</dt><dd>${esc(e.source)}, ${esc(e.category || '')}</dd>
        ${e.username ? `<dt>Account</dt><dd>${esc(e.username)}</dd>` : ''}
        ${e.source_ip ? `<dt>From</dt><dd class="mono">${esc(e.source_ip)}</dd>` : ''}
        ${e.destination_ip ? `<dt>To</dt><dd class="mono">${esc(e.destination_ip)}</dd>` : ''}
        <dt>Reference</dt><dd class="mono">${esc(e.evidence_reference || '')}</dd>
      </dl>
      ${e.command ? `<pre class="code">${esc(e.command)}</pre>` : ''}
      <p class="ink-2">${esc(e.details || 'No further detail was recorded.')}</p>
      <div><button class="button" id="tl-open">${icon('external')}Open full record</button></div>`;
    $('#tl-open').addEventListener('click', () => openEvent(e));
  }
  function bindTimeline() {
    const f = filtersFor('timeline'); const t = state.timeline;
    const refresh = () => refreshTimeline().catch(err => { $('#tl-stream').innerHTML = emptyBlock('The timeline could not load.', esc(err.message)); });
    $('#tl-search').addEventListener('input', debounce(e => { f.search = e.target.value.trim(); refresh(); }, 300));
    $('#tl-sev').addEventListener('change', e => { f.severity = e.target.value; refresh(); });
    $('#tl-src').addEventListener('change', e => { t.source = e.target.value; refresh(); });
    $('#tl-range').addEventListener('change', e => { t.range = e.target.value; refresh(); });
    $('#tl-sort').addEventListener('click', e => { t.sort = t.sort === 'desc' ? 'asc' : 'desc'; e.currentTarget.innerHTML = `${icon('sort')}${t.sort === 'desc' ? 'Newest first' : 'Oldest first'}`; refresh(); });
    $('#tl-stream').addEventListener('keydown', e => {
      if (!['ArrowDown', 'ArrowUp'].includes(e.key)) return;
      e.preventDefault();
      const items = $$('.tl-item'); const i = items.findIndex(x => x.getAttribute('aria-selected') === 'true');
      const next = items[Math.min(items.length - 1, Math.max(0, i + (e.key === 'ArrowDown' ? 1 : -1)))];
      next?.click(); next?.focus();
    });
    refresh();
  }

  // ------------------------------------------------------------------------
  // Relationship graph
  // ------------------------------------------------------------------------
  const GRAPH_TYPES = [['user', 'Account'], ['process', 'Process'], ['network', 'Address'], ['dns', 'Domain'], ['file', 'File']];
  const shapeFor = (type, r) => ({
    user: `<circle class="shape" r="${r}"/>`,
    process: `<rect class="shape" x="${-r}" y="${-r}" width="${2 * r}" height="${2 * r}" rx="3"/>`,
    network: `<path class="shape" d="M0 ${-r * 1.2} ${r * 1.2} 0 0 ${r * 1.2} ${-r * 1.2} 0Z"/>`,
    dns: `<path class="shape" d="${[0, 1, 2, 3, 4, 5].map(i => { const a = Math.PI / 3 * i + Math.PI / 6; return `${i ? 'L' : 'M'}${(r * 1.1 * Math.cos(a)).toFixed(1)} ${(r * 1.1 * Math.sin(a)).toFixed(1)}`; }).join(' ')}Z"/>`,
    file: `<path class="shape" d="M${-r * 0.8} ${-r} H${r * 0.35} L${r * 0.8} ${-r * 0.55} V${r} H${-r * 0.8}Z"/>`,
  })[type] || `<circle class="shape" r="${r}"/>`;
  const legendShape = type => `<svg viewBox="-12 -12 24 24" aria-hidden="true"><g class="g-node t-${type}">${shapeFor(type, 8)}</g></svg>`;

  async function renderGraph() {
    const g = await API.get('/api/graph');
    state.graph = g;
    return `
      <section class="region">
        <div class="toolbar">
          <div class="search-input">${icon('search')}<input class="input" type="search" id="g-search" placeholder="Highlight a name, IP or process" aria-label="Highlight entities"></div>
          <div class="segmented" role="group" aria-label="Entity type"><button type="button" data-gtype="all" aria-pressed="true">All</button>${GRAPH_TYPES.map(([t, l]) => `<button type="button" data-gtype="${t}" aria-pressed="false">${l}s</button>`).join('')}</div>
          <span id="g-unlinked-wrap"></span>
          <span class="spacer"></span>
          <span class="result-count">${n(g.total_nodes || 0)} entities, ${n(g.total_edges || 0)} links</span>
          <div class="menu"><button class="button" id="g-export" aria-haspopup="true" aria-expanded="false">${icon('download')}Export</button>
            <div class="menu-list" id="g-export-menu" hidden><button data-export="svg">Vector image (.svg)</button><button data-export="png">Picture (.png)</button></div></div>
        </div>
        <div class="graph-layout">
          <div class="graph-stage" id="g-stage">
            <svg id="g-svg" viewBox="0 0 900 600" role="img" aria-label="Relationship graph"></svg>
            ${(g.nodes || []).length ? '' : `<div class="graph-empty">${emptyBlock('Nothing to link yet', 'The graph is built from accounts, processes, addresses, domains and files found in your evidence. Run the audit or import evidence first.', '<button class="button primary" data-go="audit">Run system audit</button>')}</div>`}
            <div class="graph-legend">${GRAPH_TYPES.map(([t, l]) => `<span class="legend-${t}">${legendShape(t)}<span style="color:var(--ink-2)">${l}</span></span>`).join('')}</div>
            <div class="graph-zoom">
              <button id="g-in" aria-label="Zoom in">${icon('zoomIn')}</button><button id="g-out" aria-label="Zoom out">${icon('zoomOut')}</button>
              <button id="g-fit" aria-label="Fit to view">${icon('fit')}</button><button id="g-reset" aria-label="Reset layout">${icon('reset')}</button>
            </div>
          </div>
          <aside class="graph-inspector" id="g-inspector"></aside>
        </div>
      </section>
      <p class="section-note">${esc(g.disclaimer || '')}</p>`;
  }

  function initGraph() {
    const g = state.graph || { nodes: [], edges: [] };
    const svg = $('#g-svg'); const stage = $('#g-stage');
    const W = 900; const H = 600;
    const allIds = new Set((g.nodes || []).map(x => x.id));
    const allEdges = (g.edges || []).filter(e => allIds.has(e.source) && allIds.has(e.target));
    const linkedIds = new Set(allEdges.flatMap(e => [e.source, e.target]));
    const showUnlinked = !!state.graphShowUnlinked || !linkedIds.size;
    const nodes = (g.nodes || []).filter(nd => showUnlinked || linkedIds.has(nd.id)).map(nd => ({ ...nd }));
    const byId = new Map(nodes.map(x => [x.id, x]));
    const edges = allEdges.filter(e => byId.has(e.source) && byId.has(e.target));
    const unlinkedCount = (g.nodes || []).length - linkedIds.size;
    $('#g-unlinked-wrap').innerHTML = unlinkedCount > 0 && linkedIds.size
      ? `<label class="field" style="flex-direction:row;align-items:center;gap:6px"><input type="checkbox" id="g-unlinked" ${showUnlinked ? 'checked' : ''}>Show ${n(unlinkedCount)} entities without links</label>` : '';
    $('#g-unlinked')?.addEventListener('change', e => { state.graphShowUnlinked = e.target.checked; initGraph(); });

    // Force-directed layout (deterministic seed): linked entities pull together,
    // all entities repel, a weak pull keeps the drawing centred.
    nodes.forEach((nd, i) => {
      const a = i * 2.39996; const r = 40 + 9 * Math.sqrt(i);
      nd.x = W / 2 + r * Math.cos(a); nd.y = H / 2 + r * Math.sin(a);
    });
    const deg = new Map(nodes.map(x => [x.id, 0]));
    edges.forEach(e => { deg.set(e.source, deg.get(e.source) + 1); deg.set(e.target, deg.get(e.target) + 1); });
    for (let it = 0; it < 320; it++) {
      const cool = 1 - it / 320;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i]; let fx = 0; let fy = 0;
        for (let j = 0; j < nodes.length; j++) {
          if (i === j) continue;
          const b = nodes[j]; const dx = a.x - b.x; const dy = a.y - b.y; const d2 = Math.max(64, dx * dx + dy * dy);
          fx += (dx / Math.sqrt(d2)) * (2600 / d2) * 60; fy += (dy / Math.sqrt(d2)) * (2600 / d2) * 60;
        }
        fx += (W / 2 - a.x) * 0.012; fy += (H / 2 - a.y) * 0.016;
        a.vx = fx; a.vy = fy;
      }
      edges.forEach(e => {
        const s = byId.get(e.source); const t = byId.get(e.target);
        const dx = t.x - s.x; const dy = t.y - s.y; const d = Math.max(1, Math.hypot(dx, dy)); const k = (d - 110) * 0.08;
        s.vx += (dx / d) * k; s.vy += (dy / d) * k; t.vx -= (dx / d) * k; t.vy -= (dy / d) * k;
      });
      nodes.forEach(nd => {
        const step = Math.hypot(nd.vx, nd.vy); const max = 18 * cool + 0.5;
        const f = step > max ? max / step : 1;
        nd.x = Math.max(40, Math.min(W - 40, nd.x + nd.vx * f)); nd.y = Math.max(30, Math.min(H - 40, nd.y + nd.vy * f));
      });
    }
    nodes.forEach(nd => { nd.x = Math.round(nd.x); nd.y = Math.round(nd.y); nd.x0 = nd.x; nd.y0 = nd.y; });
    let zoom = 1; let px = 0; let py = 0; let selected = null; let typeFilter = 'all'; let q = '';
    const linked = (a, b) => edges.some(e => (e.source === a && e.target === b) || (e.source === b && e.target === a));

    function draw() {
      const ql = q.toLowerCase();
      const edgeHTML = edges.map(e => {
        const s = byId.get(e.source); const t = byId.get(e.target);
        const on = selected && (e.source === selected || e.target === selected);
        const dim = selected && !on;
        return `<g><line class="g-edge ${on ? 'on' : ''} ${dim ? 'dim' : ''}" x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}"/>${on ? `<g class="g-edge-label" transform="translate(${(s.x + t.x) / 2},${(s.y + t.y) / 2})"><rect x="-38" y="-9" width="76" height="18" rx="3"/><text text-anchor="middle" y="3">${esc(e.relation)}</text></g>` : ''}</g>`;
      }).join('');
      const nodeHTML = nodes.map(nd => {
        const isSel = nd.id === selected;
        const dim = (typeFilter !== 'all' && nd.type !== typeFilter) || (ql && !nd.label.toLowerCase().includes(ql)) || (selected && !isSel && !linked(selected, nd.id));
        const r = isSel ? 14 : 11;
        const label = nd.label.length > 24 ? `${nd.label.slice(0, 22)}…` : nd.label;
        const showLabel = isSel || deg.get(nd.id) > 0 || (ql && nd.label.toLowerCase().includes(ql)) || nodes.length <= 25;
        return `<g class="g-node t-${esc(nd.type)} ${isSel ? 'selected' : ''} ${dim ? 'dim' : ''}" data-id="${esc(nd.id)}" transform="translate(${nd.x},${nd.y})" tabindex="0" role="button" aria-label="${esc(nd.type)} ${esc(nd.label)}"><title>${esc(nd.label)}</title>${shapeFor(nd.type, r)}${showLabel ? `<text class="label" y="${r + 14}" text-anchor="middle">${esc(label)}</text>` : ''}</g>`;
      }).join('');
      svg.innerHTML = `<rect id="g-bg" width="${W}" height="${H}" fill="transparent"/><g id="g-view" transform="translate(${px},${py}) scale(${zoom})">${edgeHTML}${nodeHTML}</g>`;
      $$('.g-node', svg).forEach(el => {
        el.addEventListener('pointerdown', ev => startDrag(ev, el.dataset.id));
        el.addEventListener('keydown', ev => { if (ev.key === 'Enter') select(el.dataset.id); });
      });
    }
    function inspector() {
      const box = $('#g-inspector');
      const nd = byId.get(selected);
      if (!nd) {
        box.innerHTML = nodes.length ? `<h2>Select an entity</h2><p class="ink-2">Click a shape to see what it is linked to and why. Drag shapes to rearrange them; drag the background to pan; use the mouse wheel to zoom.</p>` : '';
        return;
      }
      const rel = edges.filter(e => e.source === nd.id || e.target === nd.id);
      box.innerHTML = `
        <div class="ink-2">${esc((GRAPH_TYPES.find(t => t[0] === nd.type) || [0, nd.type])[1])}</div>
        <h2>${esc(nd.label)}</h2>
        <div>${sevMark(nd.max_severity || 'Low')} <span class="muted">in ${n(nd.count)} events</span></div>
        <h3 style="font-size:var(--fs-dense);margin-top:var(--s2)">${n(rel.length)} links</h3>
        <ul class="rel-list">${rel.map(e => { const other = byId.get(e.source === nd.id ? e.target : e.source); return `<li><span class="rel">${esc(e.relation)}</span> <strong>${esc(other?.label || '')}</strong><p>${esc(e.reason || '')}</p></li>`; }).join('') || '<li class="muted">No links recorded.</li>'}</ul>
        <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="button small" id="g-tl">${icon('timeline', 'icon-sm')}Show in timeline</button><button class="button small ghost" id="g-clear">Clear selection</button></div>`;
      $('#g-tl').addEventListener('click', () => { filtersFor('timeline').search = nd.label; go('timeline'); });
      $('#g-clear').addEventListener('click', () => select(null));
    }
    function select(id) { selected = id; draw(); inspector(); }
    function local(evt) {
      const pt = svg.createSVGPoint(); pt.x = evt.clientX; pt.y = evt.clientY;
      const m = $('#g-view', svg).getScreenCTM();
      return m ? pt.matrixTransform(m.inverse()) : { x: 0, y: 0 };
    }
    let drag = null; let pan = null;
    function startDrag(ev, id) { ev.stopPropagation(); drag = byId.get(id); stage.setPointerCapture(ev.pointerId); if (selected !== id) select(id); }
    stage.addEventListener('pointerdown', ev => { if (ev.target.id === 'g-bg' || ev.target === svg) { pan = { x: ev.clientX, y: ev.clientY, px, py }; stage.classList.add('is-panning'); stage.setPointerCapture(ev.pointerId); } });
    stage.addEventListener('pointermove', ev => {
      if (drag) { const p = local(ev); drag.x = Math.round(Math.max(20, Math.min(W - 20, p.x))); drag.y = Math.round(Math.max(20, Math.min(H - 20, p.y))); draw(); }
      else if (pan) { const r = svg.getBoundingClientRect(); const k = W / r.width; px = pan.px + (ev.clientX - pan.x) * k; py = pan.py + (ev.clientY - pan.y) * k; $('#g-view', svg).setAttribute('transform', `translate(${px},${py}) scale(${zoom})`); }
    });
    const end = () => { drag = null; pan = null; stage.classList.remove('is-panning'); };
    stage.addEventListener('pointerup', end); stage.addEventListener('pointercancel', end);
    stage.addEventListener('wheel', ev => { if (!nodes.length) return; ev.preventDefault(); setZoom(zoom * (ev.deltaY < 0 ? 1.12 : 0.89)); }, { passive: false });
    function setZoom(z) { const nz = Math.min(2.5, Math.max(0.4, z)); px = W / 2 - (W / 2 - px) * (nz / zoom); py = H / 2 - (H / 2 - py) * (nz / zoom); zoom = nz; draw(); }
    function fit() {
      if (!nodes.length) return;
      const xs = nodes.map(x => x.x); const ys = nodes.map(x => x.y);
      const minX = Math.min(...xs) - 60; const maxX = Math.max(...xs) + 60; const minY = Math.min(...ys) - 50; const maxY = Math.max(...ys) + 60;
      zoom = Math.min(2, Math.max(0.4, Math.min(W / (maxX - minX), H / (maxY - minY))));
      px = W / 2 - ((minX + maxX) / 2) * zoom; py = H / 2 - ((minY + maxY) / 2) * zoom; draw();
    }
    $('#g-in').addEventListener('click', () => setZoom(zoom * 1.2));
    $('#g-out').addEventListener('click', () => setZoom(zoom / 1.2));
    $('#g-fit').addEventListener('click', fit);
    $('#g-reset').addEventListener('click', () => { nodes.forEach(x => { x.x = x.x0; x.y = x.y0; }); zoom = 1; px = 0; py = 0; draw(); });
    $('#g-search').addEventListener('input', debounce(e => { q = e.target.value.trim(); draw(); }, 150));
    $$('[data-gtype]').forEach(b => b.addEventListener('click', () => { typeFilter = b.dataset.gtype; $$('[data-gtype]').forEach(x => x.setAttribute('aria-pressed', String(x === b))); draw(); }));

    // Export: a standalone exhibit with fixed print colours (OKLCH is not portable outside browsers).
    const menu = $('#g-export-menu'); const exportBtn = $('#g-export');
    exportBtn.addEventListener('click', e => { e.stopPropagation(); menu.hidden = !menu.hidden; exportBtn.setAttribute('aria-expanded', String(!menu.hidden)); });
    const PRINT = { user: '#2f5fb3', process: '#3d4655', network: '#1d7f8c', dns: '#7a4bb0', file: '#b44a2c' };
    function exhibit() {
      const xs = nodes.map(x => x.x); const ys = nodes.map(x => x.y);
      const minX = Math.min(...xs); const maxX = Math.max(...xs); const minY = Math.min(...ys); const maxY = Math.max(...ys);
      const s = Math.min(1.4, 1080 / Math.max(100, maxX - minX + 80), 560 / Math.max(100, maxY - minY + 80));
      const tx = 600 - ((minX + maxX) / 2) * s; const ty = 440 - ((minY + maxY) / 2) * s;
      const P = nd => [Math.round(nd.x * s + tx), Math.round(nd.y * s + ty)];
      const lines = edges.map(e => { const [x1, y1] = P(byId.get(e.source)); const [x2, y2] = P(byId.get(e.target)); return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#9aa3b2" stroke-width="1.4"/><text x="${(x1 + x2) / 2}" y="${(y1 + y2) / 2 - 4}" text-anchor="middle" font-size="9" fill="#5b6472" font-family="IBM Plex Mono, monospace">${esc(e.relation)}</text>`; }).join('');
      const shapes = nodes.map(nd => { const [x, y] = P(nd); const c = PRINT[nd.type] || '#3d4655'; return `<g transform="translate(${x},${y})" fill="#ffffff" stroke="${c}" stroke-width="2">${shapeFor(nd.type, 12).replace(/class="shape"/g, '')}</g><text x="${x}" y="${y + 28}" text-anchor="middle" font-size="11" fill="#1f2633" font-family="IBM Plex Sans, Arial, sans-serif">${esc(nd.label)}</text>`; }).join('');
      const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
      return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="860" viewBox="0 0 1200 860" font-family="IBM Plex Sans, Arial, sans-serif">
  <rect width="1200" height="860" fill="#ffffff"/>
  <text x="40" y="52" font-size="20" font-weight="600" fill="#1f2633">SecureScan relationship graph</text>
  <text x="40" y="76" font-size="12" fill="#5b6472">Exported ${stamp} UTC, ${nodes.length} entities, ${edges.length} links</text>
  <line x1="40" y1="96" x2="1160" y2="96" stroke="#1f2633" stroke-width="1.5"/>
  ${lines}${shapes}
  <text x="40" y="830" font-size="10.5" fill="#5b6472">Links show events recorded together in the evidence database. A link is not proof of malicious activity.</text>
</svg>`;
    }
    function save(blob, name) { const u = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = u; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 1000); }
    $$('[data-export]').forEach(b => b.addEventListener('click', () => {
      menu.hidden = true;
      if (!nodes.length) { toast('There is nothing to export yet. Import evidence first.', true); return; }
      const svgText = exhibit(); const stamp = Date.now();
      if (b.dataset.export === 'svg') { save(new Blob([svgText], { type: 'image/svg+xml' }), `securescan-graph-${stamp}.svg`); toast('Graph exported as SVG.'); return; }
      const img = new Image();
      img.onload = () => { const c = document.createElement('canvas'); c.width = 2400; c.height = 1720; const ctx = c.getContext('2d'); ctx.drawImage(img, 0, 0, 2400, 1720); c.toBlob(p => { if (p) { save(p, `securescan-graph-${stamp}.png`); toast('Graph exported as PNG.'); } }, 'image/png'); };
      img.onerror = () => toast('The PNG could not be created. Export as SVG instead.', true);
      img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svgText)}`;
    }));

    draw(); inspector(); if (nodes.length) fit();
  }

  // ------------------------------------------------------------------------
  // Report
  // ------------------------------------------------------------------------
  async function renderReport() {
    const [r, audit, imports] = await Promise.all([
      API.get('/api/reports/summary'),
      API.get('/api/audit/host/latest').catch(() => ({ available: false })),
      API.get('/api/imports').catch(() => []),
    ]);
    const sev = r.severity_summary || {};
    let sec = 0; const h = t => `<h3>${++sec}. ${t}</h3>`;
    return `
      <article class="region report">
        <header class="report-title">
          <div><h2>${esc(r.report_title || 'SecureScan investigation report')}</h2><p>Generated ${esc(fmtDateTime(r.generated_at))} from the SecureScan evidence database</p></div>
          <div style="text-align:right"><div class="posture-figure" style="justify-content:flex-end"><strong>${r.risk_score ?? 0}</strong><span>/ 100</span></div><div class="ink-2">${esc(r.risk_level || 'None')} risk</div></div>
        </header>

        <section>${h('Summary')}
          <div class="figures">
            <div><strong>${n(r.total_events)}</strong><span>Records analysed</span></div>
            <div><strong>${n(r.imported_records)}</strong><span>Real evidence</span></div>
            <div><strong>${n((r.detections || []).length)}</strong><span>Detections</span></div>
            <div><strong>${n((sev.Critical || 0) + (sev.High || 0))}</strong><span>Critical and high events</span></div>
          </div>
          ${r.demo_records ? `<p class="section-note">${n(r.demo_records)} demo records are included and tagged Demo. Clear them before using this report as evidence.</p>` : ''}
        </section>

        ${audit.available ? `<section>${h(`Workstation audit of ${esc(audit.meta.computer)}`)}
          <p class="ink-2" style="margin-bottom:var(--s3)">${esc(audit.meta.os || '')}, audited ${esc(fmtDateTime(audit.meta.audit_time))}${audit.meta.is_admin ? '' : ' as a standard user'}. Raw audit SHA-256 <span class="mono">${esc((audit.sha256_hash || '').slice(0, 16))}</span>.</p>
          <div class="region"><table class="data"><thead><tr><th>Result</th><th>Check</th><th>Finding</th></tr></thead><tbody>${audit.checks.map(x => `<tr><td>${checkMark(x.status)}</td><td>${esc(x.check)}</td><td class="ink-2">${esc(x.note)}</td></tr>`).join('')}</tbody></table></div>
        </section>` : ''}

        <section>${h('Correlated detections')}
          ${(r.detections || []).length ? `<div class="region"><table class="data"><thead><tr><th>Severity</th><th>Detection</th><th>ATT&CK</th><th>First seen</th></tr></thead><tbody>${r.detections.map(x => `<tr><td>${sevMark(x.severity)}</td><td class="cell-title"><strong>${esc(x.name)}</strong><span style="-webkit-line-clamp:3">${esc(x.summary)}</span></td><td class="mono">${(x.mitre || []).map(m => esc(m.id)).join('<br>')}</td><td class="time">${esc(fmtDateTime(x.first_seen))}</td></tr>`).join('')}</tbody></table></div>`
            : '<p class="ink-2">No correlated attack patterns were found.</p>'}
        </section>

        <section>${h('Critical and high events')}
          <div class="region">${eventTable(r.priority_findings || [], ['time', 'sev', 'title', 'source', 'ref'], { selectable: false, maxHeight: false, empty: '<div class="empty"><strong>None</strong></div>' })}</div>
        </section>

        <section>${h('Evidence intake log')}
          <div class="region"><table class="data"><thead><tr><th>Imported</th><th>File or run</th><th>Type</th><th class="num">Records</th><th>SHA-256</th></tr></thead><tbody>
            ${imports.length ? imports.slice(0, 40).map(i => `<tr><td class="time">${esc(fmtDateTime(i.imported_at))}</td><td>${esc(i.original_filename)}</td><td class="ink-2">${esc(i.source_type)}</td><td class="num">${n(i.successful_records)}</td><td class="mono">${esc((i.sha256_hash || '').slice(0, 16))}</td></tr>`).join('') : '<tr><td colspan="5" class="muted">No evidence has been imported.</td></tr>'}
          </tbody></table></div>
        </section>

        <section>${h('Handling notes')}<ol>${(r.investigation_notes || []).map(x => `<li>${esc(String(x).replace(/^\d+\.\s*/, ''))}</li>`).join('')}</ol></section>
        <section>${h('Recommendations')}<ul>${(r.recommendations || []).map(x => `<li>${esc(x)}</li>`).join('')}${(r.detections || []).slice(0, 5).map(x => `<li>${esc(x.recommendation)}</li>`).join('')}</ul></section>
      </article>`;
  }

  // ------------------------------------------------------------------------
  // Settings
  // ------------------------------------------------------------------------
  async function renderSettings() {
    const [health, cap, aut, imports] = await Promise.all([
      API.get('/api/health').catch(() => ({ status: 'error' })),
      API.get('/api/capture/interfaces').catch(() => ({ tshark: {} })),
      API.get('/api/autopsy/status').catch(() => ({})),
      API.get('/api/imports').catch(() => []),
    ]);
    const theme = currentTheme();
    const row = (name, ok, status, detail) => `<tr><td>${esc(name)}</td><td><span class="${ok ? 'state-ok' : 'state-bad'}">${esc(status)}</span></td><td class="ink-2">${detail}</td></tr>`;
    return `
      <section class="section">
        <div class="section-head"><h2>Appearance</h2></div>
        <div class="segmented" role="radiogroup" aria-label="Colour theme">${[['system', 'Match system'], ['light', 'Light'], ['dark', 'Dark']].map(([v, l]) => `<button type="button" role="radio" data-theme-choice="${v}" aria-pressed="${theme === v}" aria-checked="${theme === v}">${l}</button>`).join('')}</div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Components</h2><button class="button small" data-act="reload">${icon('refresh', 'icon-sm')}Check again</button></div>
        <div class="region"><table class="data"><thead><tr><th style="width:200px">Component</th><th style="width:130px">Status</th><th>Detail</th></tr></thead><tbody>
          ${row('SecureScan server', health.status === 'ok', health.status === 'ok' ? 'Running' : 'Offline', `Flask API on 127.0.0.1:5000, version ${esc(health.version || '')}`)}
          ${row('Evidence database', health.database === 'connected', health.database === 'connected' ? 'Connected' : 'Unavailable', `<span class="mono">${esc(health.database_path || '')}</span>, ${n(health.total_events)} records`)}
          ${row('Wireshark (TShark)', cap.tshark?.available, cap.tshark?.available ? 'Ready' : 'Not found', cap.tshark?.available ? `${esc(cap.tshark.version)}, <span class="mono">${esc(cap.tshark.path)}</span>` : 'Install Wireshark with TShark and Npcap to capture and read .pcap files.')}
          ${row('Autopsy', aut.available, aut.available ? 'Ready' : 'Not found', aut.available ? `Version ${esc(aut.version)}, <span class="mono">${esc(aut.path)}</span>` : 'Install Autopsy to analyze folders and disk images.')}
          ${row('Host audit collector', true, 'Ready', '<span class="mono">collectors/host_audit.ps1</span>, read-only, no administrator rights required')}
        </tbody></table></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Evidence intake log</h2><span class="meta">${n(imports.length)} imports, newest first</span></div>
        <div class="region"><div class="table-wrap"><table class="data"><thead><tr><th>Imported</th><th>File or run</th><th>Type</th><th class="num">Records</th><th class="num">Failed</th><th>SHA-256</th></tr></thead><tbody>
          ${imports.length ? imports.map(i => `<tr><td class="time">${esc(fmtDateTime(i.imported_at))}</td><td>${esc(i.original_filename)}</td><td class="ink-2">${esc(i.source_type)}</td><td class="num">${n(i.successful_records)}</td><td class="num">${n(i.failed_records)}</td><td class="mono" title="${esc(i.sha256_hash)}">${esc((i.sha256_hash || '').slice(0, 16))}</td></tr>`).join('') : `<tr><td colspan="6">${emptyBlock('Nothing imported yet', 'Each audit, capture, Autopsy analysis and file import is logged here with its SHA-256 hash.')}</td></tr>`}
        </tbody></table></div></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Demo data</h2></div>
        <p class="ink-2" style="max-width:80ch;margin-bottom:var(--s3)">Demo records are tagged Demo and kept apart from real evidence. Clearing them never touches imported evidence.</p>
        <div class="page-actions">
          <button class="button" data-act="demo">${icon('plus')}Add 10 demo events</button>
          <button class="button" data-act="scenario">${icon('flag')}Load attack scenario</button>
          <button class="button danger" data-act="clear-demo">${icon('trash')}Clear demo data</button>
        </div>
      </section>

      <section class="section">
        <div class="section-head"><h2>About</h2></div>
        <p class="ink-2" style="max-width:80ch">SecureScan audits a Windows workstation and brings together evidence from the host audit, Wireshark, Autopsy, the Windows Security log, Sysmon and Linux auditd. Evidence is stored in a local SQLite database; the server listens only on this computer. Keyboard: <kbd>Ctrl</kbd> <kbd>K</kbd> opens search, <kbd>Esc</kbd> closes panels.</p>
      </section>`;
  }

  // ------------------------------------------------------------------------
  // Page registry
  // ------------------------------------------------------------------------
  const RENDER = {
    overview: renderOverview,
    audit: renderAudit,
    detections: renderDetections,
    system: renderEvidencePage('system'),
    process: renderEvidencePage('process'),
    network: renderEvidencePage('network'),
    forensic: renderEvidencePage('forensic'),
    timeline: renderTimeline,
    graph: renderGraph,
    reports: renderReport,
    settings: renderSettings,
  };
  const AFTER = {
    overview: () => bindRows($('#ov-events'), state.lastEvents),
    audit: afterAudit,
    detections: () => $$('[data-det-filter]').forEach(b => b.addEventListener('click', () => { filtersFor('detections').quick = b.dataset.detFilter; load(); })),
    system: () => bindEvidencePage('system'),
    process: () => bindEvidencePage('process'),
    network: () => bindEvidencePage('network'),
    forensic: () => bindEvidencePage('forensic'),
    timeline: bindTimeline,
    graph: initGraph,
    settings: () => $$('[data-theme-choice]').forEach(b => b.addEventListener('click', () => {
      applyTheme(b.dataset.themeChoice);
      $$('[data-theme-choice]').forEach(x => { const on = x === b; x.setAttribute('aria-pressed', String(on)); x.setAttribute('aria-checked', String(on)); });
    })),
  };

  // ------------------------------------------------------------------------
  // Demo data actions
  // ------------------------------------------------------------------------
  async function addDemo() {
    try { const r = await API.post('/api/events/demo'); toast(r.message); notify('Demo events added', r.message); await refreshCounts(); load(); }
    catch (err) { toast(err.message, true); }
  }
  async function loadScenario(btn) {
    busy(btn, true, 'Loading scenario');
    try { const r = await API.post('/api/scenario'); toast(r.message); notify('Attack scenario loaded', r.message); await refreshCounts(); if (state.page === 'detections') load(); else go('detections'); }
    catch (err) { toast(err.message, true); }
    finally { busy(btn, false); }
  }
  function askClearDemo() {
    const count = state.stats?.demo_records || 0;
    confirmDialog({
      title: 'Clear demo data?',
      message: `${n(count)} demo records will be deleted. Imported evidence, audits and captures are not affected. This cannot be undone.`,
      confirmLabel: `Delete ${n(count)} demo records`,
    }, async () => {
      try { const r = await API.del('/api/events/demo'); toast(r.message); notify('Demo data cleared', r.message); await refreshCounts(); load(); }
      catch (err) { toast(err.message, true); }
    });
  }

  // ------------------------------------------------------------------------
  // Global wiring
  // ------------------------------------------------------------------------
  document.addEventListener('click', e => {
    if (!e.target.closest('.menu')) $$('.menu-list').forEach(m => { m.hidden = true; });
    const navEl = e.target.closest('[data-nav]');
    if (navEl) { e.preventDefault(); go(navEl.dataset.nav); return; }
    const goEl = e.target.closest('[data-go]');
    if (goEl) { e.preventDefault(); go(goEl.dataset.go); return; }
    if (e.target.closest('[data-close-panel]') || e.target.id === 'panel-scrim') { closePanel(); return; }
    const act = e.target.closest('[data-act]');
    if (!act) return;
    const a = act.dataset.act;
    if (a === 'import') openImport(act.dataset.kind || ({ process: 'sysmon', network: 'network', forensic: 'forensic' })[state.page] || 'windows');
    else if (a === 'run-audit') runAudit(act);
    else if (a === 'capture') runCapture(act);
    else if (a === 'autopsy') runAutopsy();
    else if (a === 'autopsy-case') importAutopsyCase(act);
    else if (a === 'scenario') loadScenario(act);
    else if (a === 'demo') addDemo();
    else if (a === 'clear-demo') askClearDemo();
    else if (a === 'print') window.print();
    else if (a === 'reload') load();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.matches('tr[data-go]')) go(e.target.dataset.go);
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); }
    else if (e.key === 'Escape') { if ($('#dialog-root').innerHTML) closeDialog(); else closePanel(); }
  });

  // Drop a file anywhere to import it into the current page's evidence type.
  let dragDepth = 0;
  window.addEventListener('dragenter', e => { if (e.dataTransfer?.types?.includes('Files')) dragDepth++; });
  window.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); });
  window.addEventListener('dragover', e => e.preventDefault());
  window.addEventListener('drop', e => {
    e.preventDefault(); dragDepth = 0;
    const file = e.dataTransfer?.files?.[0];
    if (file && !$('#dialog-root').innerHTML) {
      const kind = ({ process: 'sysmon', network: 'network', forensic: 'forensic' })[state.page] || (/\.(pcap|pcapng)$/i.test(file.name) ? 'network' : 'windows');
      openImport(kind);
      setTimeout(() => uploadFile(file, kind, { progressEl: $('#import-progress'), resultEl: $('#import-result') }), 0);
    }
  });

  $('#menu-button').innerHTML = icon('menu');
  $('#menu-button').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  $('#search-trigger').addEventListener('click', openPalette);
  $('#notif-button').addEventListener('click', openNotifications);
  $('#theme-button').addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme === 'dark' || (!document.documentElement.dataset.theme && window.matchMedia('(prefers-color-scheme: dark)').matches);
    applyTheme(dark ? 'light' : 'dark');
  });
  $$('[data-icon]').forEach(el => { el.outerHTML = icon(el.dataset.icon); });
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', () => applyTheme(currentTheme()));
  window.addEventListener('hashchange', () => { const p = location.hash.slice(1); if (p && p !== state.page) go(p); });

  // Boot
  applyTheme(currentTheme());
  renderNotifButton();
  state.page = PAGES[location.hash.slice(1)] ? location.hash.slice(1) : 'overview';
  renderNav();
  go(state.page);
  refreshCounts();
  loadToolStatus();

  window.SecureScan = { go, load, API, version: '3.0.0' };
})();
