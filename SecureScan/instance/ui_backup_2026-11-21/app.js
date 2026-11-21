(() => {
  'use strict';

  // =========================================================================
  // SECURESCAN — PRESTIGE FORENSIC COMMAND CENTRE CONTROLLER
  // =========================================================================

  const pageMeta = {
    overview: ['OVERVIEW', 'Command Overview', 'Unified security auditing, network telemetry, and digital forensic investigation analytics.'],
    system: ['SYSTEM INTELLIGENCE', 'Windows Audit', 'Review Windows 11 Security logs (Event IDs 4624, 4625, 4688, 4720, 4726, 4672) and system events.'],
    process: ['SYSTEM INTELLIGENCE', 'Process Intelligence', 'Analyze process execution hierarchies, command-line arguments, and process creations (Windows 4688 & Sysmon 1).'],
    network: ['SYSTEM INTELLIGENCE', 'Network Intelligence', 'Investigate packet captures, network sockets, DNS queries, and protocol observations from Wireshark & Sysmon.'],
    forensic: ['DIGITAL INVESTIGATION', 'Evidence Explorer', 'Explore file system findings, credential artefacts, deleted files, and Autopsy forensic reports.'],
    audit: ['SYSTEM AUDIT', 'System Audit Console', 'Audit this workstation live: Windows security configuration, Wireshark/TShark packet capture, and Autopsy forensic analysis.'],
    detections: ['DIGITAL INVESTIGATION', 'Threat Detections', 'Correlation engine that links events across all evidence sources into MITRE ATT&CK-mapped detections with a risk score.'],
    timeline: ['DIGITAL INVESTIGATION', 'Investigation Timeline', 'Chronologically sequence multi-source observations to reconstruct incident timelines.'],
    graph: ['DIGITAL INVESTIGATION', 'Relationship Graph', 'Interactive entity-relationship mapping between accounts, processes, network sockets, domains, and forensic artifacts.'],
    reports: ['DIGITAL INVESTIGATION', 'Investigation Studio', 'Generate formal digital forensic reports with executive summaries, findings, and evidence references.'],
    settings: ['APPLICATION', 'Settings & System Health', 'Monitor real-time system diagnostics, backend health, SQLite database, and integration engines.']
  };

  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  let currentPage = 'overview';
  let toastTimer;
  let activeSearch = '';
  let activeFilter = 'all';
  let activeSubfilter = 'all';
  let timelineSortOrder = 'desc';
  let timelineDateRange = 'all';
  let selectedTimelineEvent = null;
  let recentSearchFilter = '';
  let isLoading = false;
  let searchDebounceTimer;

  // Cached server telemetry
  let dashboardStats = null;
  let currentEvents = [];
  let currentGraphData = { nodes: [], edges: [] };
  let reportData = null;
  let detectionsData = null;
  let auditState = { latest: null, capture: null, autopsy: null };
  let autopsyPollTimer = null;
  let networkStats = null;
  let systemHealth = null;

  // Session Ingest Log
  let sessionImportHistory = [];

  // Notifications State
  let notifications = [
    {
      id: 'notif-boot',
      title: 'Forensic Engines Ready',
      message: 'SecureScan system audit & digital forensic engines initialised.',
      time: new Date().toISOString(),
      read: true
    }
  ];

  // =========================================================================
  // API CLIENT LAYER
  // =========================================================================
  const API = {
    async getHealth() {
      const res = await fetch('/api/health');
      if (!res.ok) throw new Error('Backend server unreachable');
      return await res.json();
    },

    async getStats() {
      const res = await fetch('/api/stats');
      if (!res.ok) throw new Error('Failed to load dashboard statistics');
      return await res.json();
    },

    async getEvents(params = {}) {
      const q = new URLSearchParams();
      if (params.source) q.set('source', params.source);
      if (params.category) q.set('category', params.category);
      if (params.severity && params.severity !== 'all') q.set('severity', params.severity);
      if (params.search) q.set('search', params.search);
      if (params.limit) q.set('limit', params.limit);
      
      const res = await fetch(`/api/events?${q.toString()}`);
      if (!res.ok) throw new Error('Failed to retrieve events');
      return await res.json();
    },

    async getTimeline(params = {}) {
      const q = new URLSearchParams();
      if (params.search) q.set('search', params.search);
      if (params.severity && params.severity !== 'all') q.set('severity', params.severity);
      if (params.source && params.source !== 'all') q.set('source', params.source);
      if (params.limit) q.set('limit', params.limit);

      const res = await fetch(`/api/timeline?${q.toString()}`);
      if (!res.ok) throw new Error('Failed to retrieve timeline');
      return await res.json();
    },

    async getGraph() {
      const res = await fetch('/api/graph');
      if (!res.ok) throw new Error('Failed to load relationship graph');
      return await res.json();
    },

    async getNetworkStats() {
      const res = await fetch('/api/network/stats');
      if (!res.ok) throw new Error('Failed to load network statistics');
      return await res.json();
    },

    async json(url, opts = {}) {
      const res = await fetch(url, opts);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Request failed (HTTP ${res.status})`);
      return data;
    },
    post(url, body) {
      return API.json(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    },

    async getDetections() {
      const res = await fetch('/api/detections');
      if (!res.ok) throw new Error('Failed to run detection engine');
      return await res.json();
    },

    async loadScenario() {
      const res = await fetch('/api/scenario', { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Failed to load attack scenario');
      return data;
    },

    async getReportSummary() {
      const res = await fetch('/api/reports/summary');
      if (!res.ok) throw new Error('Failed to load investigation report summary');
      return await res.json();
    },

    async generateDemo() {
      const res = await fetch('/api/events/demo', { method: 'POST' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to generate demo events');
      }
      return await res.json();
    },

    async clearDemo() {
      const res = await fetch('/api/events/demo', { method: 'DELETE' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to delete demo events');
      }
      return await res.json();
    },

    uploadEvidence(endpoint, file, onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', endpoint);
        xhr.responseType = 'json';

        if (xhr.upload && typeof onProgress === 'function') {
          xhr.upload.onprogress = (e) => {
            if (e.lengthComputable && e.total > 0) {
              const pct = Math.round((e.loaded / e.total) * 100);
              onProgress(pct, e.loaded, e.total);
            }
          };
        }

        xhr.onload = () => {
          let data = xhr.response;
          if (typeof data === 'string') {
            try { data = JSON.parse(data); } catch { data = {}; }
          }
          data = data || {};
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(data);
          } else {
            reject(new Error(data.error || `Upload failed with HTTP ${xhr.status}`));
          }
        };

        xhr.onerror = () => {
          reject(new Error('Network connectivity error during upload'));
        };

        const formData = new FormData();
        formData.append('file', file);
        xhr.send(formData);
      });
    }
  };

  // =========================================================================
  // UI UTILITIES & HELPERS
  // =========================================================================
  function toast(message, isError = false) {
    const el = $('#toast');
    if (!el) return;
    el.textContent = message;
    el.style.borderColor = isError ? '#FECACA' : '#7BB8FF';
    el.style.backgroundColor = isError ? '#991B1B' : '#050F2A';
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 3400);
  }

  function formatDate(value) {
    if (!value) return 'Timestamp unavailable';
    const d = new Date(value);
    return Number.isNaN(d.getTime())
      ? String(value)
      : d.toLocaleString([], {
          year: 'numeric',
          month: 'short',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit'
        });
  }

  function timeOnly(value) {
    if (!value) return '—';
    const d = new Date(value);
    return Number.isNaN(d.getTime())
      ? String(value)
      : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function timeAgo(isoString) {
    if (!isoString) return 'N/A';
    const diff = Math.max(0, (Date.now() - new Date(isoString).getTime()) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  function highlightMatch(text, query) {
    if (!query || !text) return esc(text);
    const qClean = query.trim();
    if (!qClean) return esc(text);
    const escapedTerm = qClean.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escapedTerm})`, 'gi');
    return esc(text).replace(regex, '<mark class="search-match">$1</mark>');
  }

  function severityBadge(severity) {
    const s = severity || 'Informational';
    const sClass = s.toLowerCase();
    return `<span class="badge-severity sev-${esc(sClass)}">${esc(s)}</span>`;
  }

  function sourceBadge(source) {
    const s = source || 'Unknown';
    return `<span class="badge-source">${esc(s)}</span>`;
  }

  function updateSidebarBadges() {
    const clearBtn = $('#clear-demo-banner-btn');
    if (clearBtn && dashboardStats) {
      const demoCount = dashboardStats.demo_records || 0;
      clearBtn.style.display = demoCount > 0 ? 'inline-flex' : 'none';
      clearBtn.textContent = `Clear Demo (${demoCount})`;
    }
    const navSysCount = $('#nav-system-count');
    if (navSysCount && dashboardStats && dashboardStats.sources) {
      const winCount = dashboardStats.sources.windows_audit || 0;
      const sysmonCount = dashboardStats.sources.sysmon || 0;
      const linuxCount = dashboardStats.sources.linux_audit || 0;
      navSysCount.textContent = winCount + sysmonCount + linuxCount;
    }
    const navDet = $('#nav-detections-count');
    if (navDet && dashboardStats && dashboardStats.detections) {
      navDet.textContent = dashboardStats.detections.total || 0;
      navDet.style.display = dashboardStats.detections.total ? '' : 'none';
    }
    const sidebarTshark = $('#sidebar-tshark-status');
    if (sidebarTshark && networkStats && networkStats.tshark) {
      sidebarTshark.textContent = networkStats.tshark.available ? 'Ready' : 'Not Detected';
      sidebarTshark.style.color = networkStats.tshark.available ? '#4ade80' : '#f87171';
    }
  }

  // =========================================================================
  // PHASE 1: ANIMATION & MOTION FOUNDATION
  // =========================================================================

  function animateCounters() {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const counters = $$('[data-counter]');

    counters.forEach(el => {
      const target = parseInt(el.dataset.counter, 10);
      if (isNaN(target)) return;
      if (prefersReducedMotion || target === 0) {
        el.textContent = target.toLocaleString();
        return;
      }

      const duration = Math.min(800, Math.max(350, target * 12));
      const startTime = performance.now();

      const step = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(1, elapsed / duration);
        const ease = 1 - Math.pow(1 - progress, 3);
        const current = Math.floor(ease * target);
        el.textContent = current.toLocaleString();

        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          el.textContent = target.toLocaleString();
        }
      };

      requestAnimationFrame(step);
    });
  }

  function initScrollReveal() {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const targets = $$('.reveal-on-scroll');

    if (prefersReducedMotion || !('IntersectionObserver' in window)) {
      targets.forEach(el => el.classList.add('is-revealed'));
      return;
    }

    const observer = new IntersectionObserver((entries, obs) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-revealed');
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.08 });

    targets.forEach(el => observer.observe(el));
  }

  function initScrollTracking() {
    const mainArea = $('#main-area') || window;
    const progressBar = $('#scroll-progress-bar');
    const topbar = $('#topbar');
    const backToTop = $('#back-to-top');
    const glow1 = $('.ambient-glow-1');
    const glow2 = $('.ambient-glow-2');
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const onScroll = () => {
      const scrollTop = window.scrollY || document.documentElement.scrollTop || (mainArea.scrollTop || 0);
      const scrollHeight = document.documentElement.scrollHeight || (mainArea.scrollHeight || 1);
      const clientHeight = window.innerHeight || (mainArea.clientHeight || 1);
      const maxScroll = Math.max(1, scrollHeight - clientHeight);
      const progress = Math.min(100, Math.max(0, (scrollTop / maxScroll) * 100));

      if (progressBar) progressBar.style.width = `${progress}%`;
      if (topbar) topbar.classList.toggle('scrolled', scrollTop > 20);
      if (backToTop) backToTop.classList.toggle('visible', scrollTop > 280);

      if (!prefersReducedMotion) {
        if (glow1) glow1.style.transform = `translateY(${scrollTop * 0.04}px)`;
        if (glow2) glow2.style.transform = `translateY(${-scrollTop * 0.03}px)`;
      }
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    if (mainArea !== window) mainArea.addEventListener('scroll', onScroll, { passive: true });

    backToTop?.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: prefersReducedMotion ? 'auto' : 'smooth' });
      if (mainArea !== window) mainArea.scrollTo({ top: 0, behavior: prefersReducedMotion ? 'auto' : 'smooth' });
    });
  }

  // =========================================================================
  // PHASE 7: NOTIFICATION CENTRE
  // =========================================================================
  function addNotification(title, message, type = 'info') {
    const notif = {
      id: 'notif-' + Date.now() + '-' + Math.random().toString(36).substr(2, 4),
      title,
      message,
      type,
      time: new Date().toISOString(),
      read: false
    };
    notifications.unshift(notif);
    if (notifications.length > 50) notifications.pop();
    updateNotificationUI();
  }

  function updateNotificationUI() {
    const unreadCount = notifications.filter(n => !n.read).length;
    const badge = $('#notification-badge');
    if (badge) {
      badge.textContent = unreadCount;
      badge.style.display = unreadCount > 0 ? 'flex' : 'none';
    }

    const list = $('#notification-list');
    if (!list) return;

    if (notifications.length === 0) {
      list.innerHTML = `
        <div class="empty-state" style="padding:40px 10px;">
          <div class="empty-icon">🔔</div>
          <strong>No Notifications</strong>
          <p>Genuine ingest logs, reports, and background telemetry events appear here.</p>
        </div>
      `;
      return;
    }

    list.innerHTML = notifications.map(n => `
      <div class="notification-item ${n.read ? '' : 'unread'}" data-notif-id="${esc(n.id)}">
        <div class="notification-item-top">
          <strong style="font-size:12px;color:var(--deep-navy);">${esc(n.title)}</strong>
          <span class="notification-item-time">${esc(timeAgo(n.time))}</span>
        </div>
        <div class="notification-item-msg">${esc(n.message)}</div>
      </div>
    `).join('');
  }

  function toggleNotificationDrawer(open = null) {
    const drawer = $('#notification-drawer');
    const backdrop = $('#notification-backdrop');
    if (!drawer || !backdrop) return;

    const willOpen = open !== null ? open : !drawer.classList.contains('open');
    drawer.classList.toggle('open', willOpen);
    backdrop.classList.toggle('open', willOpen);
    drawer.setAttribute('aria-hidden', (!willOpen).toString());

    if (willOpen) {
      updateNotificationUI();
    }
  }

  function initNotificationListeners() {
    $('#notification-trigger')?.addEventListener('click', () => toggleNotificationDrawer(true));
    $('#close-notification-drawer')?.addEventListener('click', () => toggleNotificationDrawer(false));
    $('#notification-backdrop')?.addEventListener('click', () => toggleNotificationDrawer(false));

    $('#mark-notifications-read')?.addEventListener('click', () => {
      notifications.forEach(n => n.read = true);
      updateNotificationUI();
      toast('All notifications marked as read');
    });

    $('#clear-notifications')?.addEventListener('click', () => {
      showConfirmModal('Clear All Notifications', 'Are you sure you want to clear your entire notification history?', () => {
        notifications = [];
        updateNotificationUI();
        toast('Notification history cleared');
      });
    });
  }

  // =========================================================================
  // PHASE 4: GLOBAL COMMAND PALETTE (CTRL + K)
  // =========================================================================
  function initCommandSearch() {
    const root = $('#command-palette-root');
    if (!root) return;

    const navItems = [
      { id: 'overview', title: 'Command Overview', desc: 'Unified telemetry & forensic health', group: 'Navigation Pages', icon: '◫' },
      { id: 'system', title: 'Windows Security Audit', desc: 'Event IDs 4624, 4625, 4688, 4720, 4672', group: 'Navigation Pages', icon: '⌘' },
      { id: 'process', title: 'Process Intelligence', desc: 'Sysmon Process & execution hierarchies', group: 'Navigation Pages', icon: '▣' },
      { id: 'network', title: 'Network Intelligence', desc: 'Wireshark, TShark PCAP & DNS queries', group: 'Navigation Pages', icon: '⌁' },
      { id: 'forensic', title: 'Evidence Explorer', desc: 'Autopsy artefacts, deleted files, registry', group: 'Navigation Pages', icon: '◈' },
      { id: 'timeline', title: 'Investigation Timeline', desc: 'Multi-source chronological evidence sequence', group: 'Navigation Pages', icon: '◷' },
      { id: 'graph', title: 'Evidence Relationship Graph', desc: 'Entity-relationship topology map', group: 'Navigation Pages', icon: '☊' },
      { id: 'reports', title: 'Investigation Studio', desc: 'Formal reports & forensic summaries', group: 'Navigation Pages', icon: '▤' },
      { id: 'settings', title: 'Settings & System Health', desc: 'Backend health, DB status & collectors', group: 'Navigation Pages', icon: '⚙' }
    ];

    const eventIdItems = [
      { id: 'system', sub: '4624', title: 'Event ID 4624: Successful Logon', desc: 'Windows Security user logon record', group: 'Security Event Rules', icon: '✓' },
      { id: 'system', sub: '4625', title: 'Event ID 4625: Failed Logon Attempt', desc: 'Potential brute force or unauthorized logon', group: 'Security Event Rules', icon: '✕' },
      { id: 'system', sub: '4688', title: 'Event ID 4688: Process Creation', desc: 'Command line audit & child process spawns', group: 'Security Event Rules', icon: '⚙' },
      { id: 'system', sub: '4720', title: 'Event ID 4720: User Account Created', desc: 'Account provisioning & backdoor detection', group: 'Security Event Rules', icon: '👤' },
      { id: 'system', sub: '4672', title: 'Event ID 4672: Special Privileges Assigned', desc: 'Administrator privilege delegation', group: 'Security Event Rules', icon: '★' },
      { id: 'process', sub: 'Sysmon 1', title: 'Sysmon ID 1: Process Create with Hash', desc: 'Process execution with SHA256 hashes', group: 'Microsoft Sysmon Rules', icon: '▣' },
      { id: 'network', sub: 'Sysmon 3', title: 'Sysmon ID 3: Network Connection', desc: 'Outbound socket communication tracking', group: 'Microsoft Sysmon Rules', icon: '⇄' },
      { id: 'process', sub: 'Sysmon 11', title: 'Sysmon ID 11: File Created', desc: 'File drops in monitored staging locations', group: 'Microsoft Sysmon Rules', icon: '📄' },
      { id: 'network', sub: 'Sysmon 22', title: 'Sysmon ID 22: DNS Query Resolution', desc: 'DNS domain lookups & external queries', group: 'Microsoft Sysmon Rules', icon: '🌐' }
    ];

    let selectedIndex = 0;
    let filteredList = [];

    const renderPalette = (query = '') => {
      const q = query.toLowerCase().trim();
      filteredList = [];

      // 1. Navigation items matching
      const matchedNav = navItems.filter(item => !q || item.title.toLowerCase().includes(q) || item.desc.toLowerCase().includes(q));
      matchedNav.forEach(i => filteredList.push({ type: 'nav', ...i }));

      // 2. Event IDs matching
      const matchedEvents = eventIdItems.filter(item => !q || item.title.toLowerCase().includes(q) || item.desc.toLowerCase().includes(q) || item.sub.toLowerCase().includes(q));
      matchedEvents.forEach(i => filteredList.push({ type: 'rule', ...i }));

      // 3. Live records matching
      if (q && currentEvents.length) {
        const matchedRecords = currentEvents.filter(e => {
          return (e.title && e.title.toLowerCase().includes(q)) ||
                 (e.username && e.username.toLowerCase().includes(q)) ||
                 (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
                 (e.destination_ip && e.destination_ip.toLowerCase().includes(q)) ||
                 (e.details && e.details.toLowerCase().includes(q)) ||
                 (e.command && e.command.toLowerCase().includes(q)) ||
                 (e.evidence_reference && e.evidence_reference.toLowerCase().includes(q));
        }).slice(0, 5);

        matchedRecords.forEach(e => {
          filteredList.push({
            type: 'event',
            id: 'timeline',
            eventId: e.id,
            title: e.title || 'Event Record',
            desc: `${e.username || 'System'} | ${e.source_ip || 'Local'} | ${e.source}`,
            group: 'Live Database Telemetry',
            icon: '◈',
            rawEvent: e
          });
        });
      }

      if (selectedIndex >= filteredList.length) selectedIndex = 0;

      const resultsList = $('#command-results-list');
      if (!resultsList) return;

      if (!filteredList.length) {
        resultsList.innerHTML = `
          <div style="padding:28px;text-align:center;color:var(--text-muted);font-size:12px;">
            <div style="font-size:24px;margin-bottom:6px;">⌕</div>
            No matching navigation pages, Event IDs, or records found for "<strong>${esc(query)}</strong>"
          </div>
        `;
        return;
      }

      let currentGroup = '';
      let html = '';

      filteredList.forEach((item, idx) => {
        if (item.group !== currentGroup) {
          currentGroup = item.group;
          html += `<div class="command-group-heading">${esc(currentGroup)}</div>`;
        }

        const isSelected = idx === selectedIndex;
        html += `
          <li class="command-result-item ${isSelected ? 'selected' : ''}" data-index="${idx}">
            <div class="command-result-left">
              <span class="command-result-icon">${esc(item.icon)}</span>
              <div class="command-result-text">
                <strong>${highlightMatch(item.title, query)}</strong>
                <small>${highlightMatch(item.desc, query)}</small>
              </div>
            </div>
            <kbd class="search-kbd" style="font-size:9px;">↵ Go</kbd>
          </li>
        `;
      });

      resultsList.innerHTML = html;

      const selectedEl = resultsList.querySelector('.command-result-item.selected');
      selectedEl?.scrollIntoView({ block: 'nearest' });
    };

    const executeItem = (item) => {
      closePalette();
      if (!item) return;

      if (item.type === 'event' && item.rawEvent) {
        showEventInspectionModal(item.rawEvent);
      } else if (item.type === 'rule') {
        setPage(item.id);
        if (item.sub) {
          activeSearch = item.sub;
          loadCurrentPage();
        }
      } else {
        setPage(item.id);
      }
    };

    const openPalette = () => {
      selectedIndex = 0;
      root.innerHTML = `
        <div class="command-palette-backdrop open" id="command-backdrop">
          <div class="command-palette-modal" id="command-modal" role="dialog" aria-modal="true">
            <div class="command-search-header">
              <span class="command-icon">⌕</span>
              <input type="text" class="command-palette-input" id="palette-search-input" placeholder="Type a command, Event ID, user, IP, or page..." autofocus>
              <kbd class="search-kbd">ESC</kbd>
            </div>
            <ul class="command-results-list" id="command-results-list" role="listbox"></ul>
            <div class="command-palette-footer">
              <div><kbd>↑</kbd><kbd>↓</kbd> Navigate</div>
              <div><kbd>↵</kbd> Select</div>
              <div><kbd>ESC</kbd> Close</div>
            </div>
          </div>
        </div>
      `;

      const input = $('#palette-search-input');
      input?.focus();
      renderPalette('');

      input?.addEventListener('input', (e) => {
        selectedIndex = 0;
        renderPalette(e.target.value);
      });

      input?.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          if (filteredList.length) {
            selectedIndex = (selectedIndex + 1) % filteredList.length;
            renderPalette(input.value);
          }
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          if (filteredList.length) {
            selectedIndex = (selectedIndex - 1 + filteredList.length) % filteredList.length;
            renderPalette(input.value);
          }
        } else if (e.key === 'Enter') {
          e.preventDefault();
          if (filteredList[selectedIndex]) {
            executeItem(filteredList[selectedIndex]);
          }
        } else if (e.key === 'Escape') {
          closePalette();
        }
      });

      $('#command-backdrop')?.addEventListener('click', (e) => {
        if (e.target.id === 'command-backdrop') closePalette();
      });

      $('#command-results-list')?.addEventListener('click', (e) => {
        const itemEl = e.target.closest('.command-result-item');
        if (itemEl) {
          const idx = parseInt(itemEl.dataset.index, 10);
          if (filteredList[idx]) executeItem(filteredList[idx]);
        }
      });
    };

    const closePalette = () => {
      root.innerHTML = '';
    };

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const isOpen = !!$('#command-modal');
        if (isOpen) closePalette();
        else openPalette();
      }
    });

    $('#command-search-trigger')?.addEventListener('click', openPalette);
  }

  // =========================================================================
  // PHASE 6: SMART DRAG & DROP AND IMPORT HANDLING
  // =========================================================================
  function initDragAndDrop() {
    let dragCounter = 0;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      window.addEventListener(eventName, e => e.preventDefault(), false);
    });

    window.addEventListener('dragenter', () => {
      dragCounter++;
      if (dragCounter === 1) {
        toast('Drop your forensic file (.json, .csv, .pcap, .pcapng, .log) to import');
      }
    });

    window.addEventListener('dragleave', () => {
      dragCounter--;
    });

    window.addEventListener('drop', (e) => {
      dragCounter = 0;
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) {
        handleFileUpload(files[0], currentPage);
      }
    });
  }

  function showSmartImportModal(targetModule = 'windows') {
    const modalRoot = $('#modal-root');
    if (!modalRoot) return;

    const moduleMeta = {
      windows: { title: 'Windows Security Event Log Ingest', endpoint: '/api/import/windows-audit', accept: '.json,.csv,.txt,.log', formats: ['JSON', 'CSV', 'TXT', 'LOG'] },
      sysmon: { title: 'Microsoft Sysmon Log Ingest', endpoint: '/api/import/sysmon', accept: '.json', formats: ['JSON'] },
      network: { title: 'Wireshark & TShark Network Ingest', endpoint: '/api/import/wireshark', accept: '.csv,.pcap,.pcapng', formats: ['PCAP', 'PCAPNG', 'CSV'] },
      pcap: { title: 'TShark Raw Packet Dissection', endpoint: '/api/import/pcap', accept: '.pcap,.pcapng', formats: ['PCAP', 'PCAPNG'] },
      forensic: { title: 'Autopsy Findings & Disk Artefacts (CAINE)', endpoint: '/api/import/autopsy', accept: '.csv,.tsv,.json,.txt', formats: ['CSV REPORT', 'TSV TABLE', 'JSON REPORT', 'BODYFILE (TSK)'] },
      linux: { title: 'Linux auditd Log Ingest', endpoint: '/api/import/linux-audit', accept: '.log,.txt', formats: ['LOG', 'TXT'] }
    };

    const conf = moduleMeta[targetModule] || moduleMeta.windows;

    modalRoot.innerHTML = `
      <div class="modal-backdrop" id="smart-import-backdrop">
        <div class="modal-dialog" role="dialog" aria-modal="true" style="max-width:560px;">
          <div class="modal-header">
            <div>
              <span class="page-eyebrow">SMART INGEST ENGINE</span>
              <h3 style="margin-top:4px;">${esc(conf.title)}</h3>
            </div>
            <button class="icon-button" id="close-smart-import-btn" aria-label="Close dialog">✕</button>
          </div>

          <div class="modal-body">
            <div class="smart-dropzone" id="modal-smart-dropzone">
              <div class="dropzone-icon">⇪</div>
              <div class="dropzone-title">Drop your forensic file here</div>
              <div class="dropzone-desc">Drag and drop file into this area, or click Browse to choose a file</div>
              <div class="format-badge-list">
                ${conf.formats.map(f => `<span class="format-badge">${esc(f)}</span>`).join('')}
              </div>
            </div>

            <div class="upload-progress-wrap" id="modal-upload-progress" style="display:none;">
              <div class="upload-progress-fill" id="modal-upload-fill"></div>
            </div>

            <div id="modal-upload-status" style="margin-top:10px;font-size:12px;color:var(--text-muted);text-align:center;">
              Target Endpoint: <code>${esc(conf.endpoint)}</code> (Max 10 MB)
            </div>

            <div style="display:flex;justify-content:center;margin-top:16px;">
              <button class="button button-sky" id="modal-browse-btn">Browse Local Files...</button>
            </div>
          </div>

          <div class="modal-footer">
            <button class="button button-secondary" id="close-smart-import-footer">Cancel</button>
          </div>
        </div>
      </div>
    `;

    const close = () => { modalRoot.innerHTML = ''; };
    $('#close-smart-import-btn')?.addEventListener('click', close);
    $('#close-smart-import-footer')?.addEventListener('click', close);
    $('#smart-import-backdrop')?.addEventListener('click', (e) => {
      if (e.target.id === 'smart-import-backdrop') close();
    });

    const dropzone = $('#modal-smart-dropzone');
    const browseBtn = $('#modal-browse-btn');

    const handleFile = (file) => {
      if (!file) return;
      const progressWrap = $('#modal-upload-progress');
      const progressFill = $('#modal-upload-fill');
      const statusText = $('#modal-upload-status');
      if (browseBtn) browseBtn.disabled = true;

      if (progressWrap) progressWrap.style.display = 'block';
      if (progressFill) {
        progressFill.style.width = '10%';
        progressFill.style.backgroundColor = 'var(--sky-blue)';
      }
      if (statusText) statusText.innerHTML = `Starting ingest of <strong>${esc(file.name)}</strong> (${(file.size/1024).toFixed(1)} KB)...`;

      const onProgress = (percent, loaded, total) => {
        if (progressFill) progressFill.style.width = `${percent}%`;
        if (statusText) {
          const loadedKb = (loaded / 1024).toFixed(1);
          const totalKb = (total / 1024).toFixed(1);
          statusText.innerHTML = `Uploading <strong>${esc(file.name)}</strong>: ${percent}% (${loadedKb} / ${totalKb} KB)... Parsing & writing to SQLite...`;
        }
      };

      handleFileUpload(file, targetModule, onProgress).then((res) => {
        if (progressFill) {
          progressFill.style.width = '100%';
          progressFill.style.backgroundColor = '#10B981';
        }
        const imported = res.successful_records ?? res.imported_packets ?? res.imported_records ?? 0;
        const dups = res.duplicate_records ?? res.duplicates ?? 0;
        const failed = res.failed_records ?? 0;
        if (statusText) {
          statusText.innerHTML = `
            <div style="background:rgba(16,185,129,0.12);border:1px solid #10B981;border-radius:8px;padding:10px 14px;margin-top:8px;color:#F2FDFF;font-size:12px;text-align:left;">
              <strong style="color:#10B981;">✓ Forensic Ingest Completed Successfully</strong>
              <div style="display:flex;gap:16px;margin-top:6px;font-family:monospace;flex-wrap:wrap;">
                <span>Imported: <strong style="color:#7BB8FF;">${imported}</strong></span>
                <span>Duplicates Prevented: <strong style="color:#F59E0B;">${dups}</strong></span>
                <span>Failed: <strong style="color:${failed > 0 ? '#EF4444' : '#94A3B8'};">${failed}</strong></span>
              </div>
            </div>
          `;
        }
        setTimeout(close, 1800);
      }).catch(err => {
        if (browseBtn) browseBtn.disabled = false;
        if (progressFill) {
          progressFill.style.width = '100%';
          progressFill.style.backgroundColor = '#EF4444';
        }
        if (statusText) {
          statusText.innerHTML = `
            <div style="background:rgba(239,68,68,0.12);border:1px solid #EF4444;border-radius:8px;padding:8px 12px;margin-top:8px;color:#FECACA;font-size:12px;text-align:left;">
              <strong>✗ Ingest Error:</strong> ${esc(err.message)}
            </div>
          `;
        }
      });
    };

    dropzone?.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-active');
    });

    dropzone?.addEventListener('dragleave', () => {
      dropzone.classList.remove('drag-active');
    });

    dropzone?.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-active');
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) handleFile(files[0]);
    });

    dropzone?.addEventListener('click', () => {
      triggerFileInput(targetModule, handleFile);
    });

    browseBtn?.addEventListener('click', () => {
      triggerFileInput(targetModule, handleFile);
    });
  }

  function triggerFileInput(targetModule, callback) {
    const input = $('#file-input');
    if (!input) return;
    input.dataset.targetModule = targetModule;
    input.value = '';
    const moduleMeta = {
      windows: '.json,.csv,.txt,.log',
      sysmon: '.json',
      network: '.csv,.pcap,.pcapng',
      pcap: '.pcap,.pcapng',
      forensic: '.csv,.tsv,.json,.txt',
      linux: '.log,.txt'
    };
    input.accept = moduleMeta[targetModule] || '*';
    input.onchange = (e) => {
      if (e.target.files?.[0]) callback(e.target.files[0]);
    };
    input.click();
  }

  // =========================================================================
  // SIGNATURE PAGE RENDERERS
  // =========================================================================

  function renderLoadingState(msg = 'Querying SQLite backend...') {
    return `
      <div class="panel reveal-on-scroll">
        <div class="skeleton-container">
          <div class="skeleton-shimmer skeleton-line skeleton-line-md"></div>
          <div class="skeleton-shimmer skeleton-line skeleton-line-sm"></div>
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:10px;">
            <div class="skeleton-shimmer skeleton-card"></div>
            <div class="skeleton-shimmer skeleton-card"></div>
            <div class="skeleton-shimmer skeleton-card"></div>
            <div class="skeleton-shimmer skeleton-card"></div>
          </div>
          <div class="skeleton-shimmer skeleton-line" style="height:140px;margin-top:14px;"></div>
        </div>
        <p style="text-align:center;font-size:11px;color:var(--text-muted);padding:10px;">${esc(msg)}</p>
      </div>
    `;
  }

  function renderErrorState(err) {
    return `<div class="empty-state reveal-on-scroll" style="padding: 60px 20px">
      <div class="empty-icon" style="color:#DC2626; border-color:#FECACA; background:#FEF2F2">!</div>
      <strong style="color:#991B1B">Database Communication Error</strong>
      <p>${esc(err.message || 'Unable to connect to Flask API. Ensure app.py is running on http://127.0.0.1:5000.')}</p>
      <button class="button button-secondary button-small" data-action="retry-load">Retry Connection</button>
    </div>`;
  }

  // -------------------------------------------------------------------------
  // PHASE 2: COMMAND DASHBOARD (Signature Page)
  // -------------------------------------------------------------------------
  function renderOverviewHTML() {
    if (!dashboardStats) return renderLoadingState();

    const total = dashboardStats.total_events || 0;
    const critical = dashboardStats.critical || 0;
    const high = dashboardStats.high || 0;
    const medium = dashboardStats.medium || 0;
    const low = dashboardStats.low || 0;
    const informational = dashboardStats.informational || 0;
    const priorityCount = critical + high;

    const sources = dashboardStats.sources || {};
    const winCount = sources.windows_audit || 0;
    const sysmonCount = sources.sysmon || 0;
    const wireCount = sources.wireshark || 0;
    const autCount = sources.autopsy || 0;
    const linuxCount = sources.linux_audit || 0;

    const dateFormatted = new Date().toLocaleDateString(undefined, {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    // Chart 1: Evidence Category Activity
    const cat = dashboardStats.categories || {};
    const catLabels = ['Auth', 'Process', 'Network', 'Forensic', 'Account', 'System'];
    const catValues = [
      cat.authentication || 0,
      cat.process || 0,
      cat.network || 0,
      cat.forensic || 0,
      cat.account || 0,
      cat.system || 0
    ];
    const maxCat = Math.max(1, ...catValues);

    const barsHTML = catValues.map((v, i) => {
      const heightPercent = v > 0 ? Math.max(8, Math.round((v / maxCat) * 100)) : 5;
      return `<div class="bar-column" data-tooltip="${catLabels[i]}: ${v} events">
        <div class="bar-pill" style="height:${heightPercent}%"></div>
        <span class="bar-label">${catLabels[i]}</span>
      </div>`;
    }).join('');

    // Chart 2: Event Severity Distribution
    const sevList = [
      ['Critical', critical, 'var(--sev-critical)', (total ? (critical/total)*100 : 0)],
      ['High', high, 'var(--sev-high)', (total ? (high/total)*100 : 0)],
      ['Medium', medium, 'var(--sev-medium)', (total ? (medium/total)*100 : 0)],
      ['Low', low, 'var(--sev-low)', (total ? (low/total)*100 : 0)],
      ['Informational', informational, 'var(--sev-info)', (total ? (informational/total)*100 : 0)]
    ];

    const sevHTML = sevList.map(([name, val, col, pct]) => `
      <div class="severity-item" data-tooltip="${name}: ${val} (${pct.toFixed(1)}%)">
        <span class="sev-title">${name}</span>
        <div class="sev-bar-bg">
          <div class="sev-bar-fill" style="width:${pct}%;background:${col}"></div>
        </div>
        <span class="sev-count">${val}</span>
      </div>
    `).join('');

    // Chart 3: Data Sources Distribution
    const sourceList = [
      ['Windows Security', winCount, '#7BB8FF', total ? (winCount / total) * 100 : 0],
      ['Microsoft Sysmon', sysmonCount, '#050F2A', total ? (sysmonCount / total) * 100 : 0],
      ['Wireshark / TShark', wireCount, '#0284c7', total ? (wireCount / total) * 100 : 0],
      ['Autopsy Findings', autCount, '#B8A0FF', total ? (autCount / total) * 100 : 0],
      ['Linux auditd', linuxCount, '#E11D48', total ? (linuxCount / total) * 100 : 0]
    ];

    const sourceBarsHTML = sourceList.map(([name, val, col, pct]) => `
      <div class="severity-item" data-tooltip="${name}: ${val} (${pct.toFixed(1)}%)">
        <span class="sev-title" style="font-size:11px;">${name}</span>
        <div class="sev-bar-bg">
          <div class="sev-bar-fill" style="width:${pct}%;background:${col}"></div>
        </div>
        <span class="sev-count">${val}</span>
      </div>
    `).join('');

    // Chart 4: Network Protocols Breakdown
    const netTotal = networkStats?.total_network_events || wireCount;
    const dnsCount = networkStats?.dns_queries_count || 0;
    const tcpCount = Math.max(0, netTotal - dnsCount);

    const netList = [
      ['TCP / TLS Sockets', tcpCount, '#0284c7', netTotal ? (tcpCount / netTotal) * 100 : 0],
      ['DNS Domain Queries', dnsCount, '#7c3aed', netTotal ? (dnsCount / netTotal) * 100 : 0]
    ];

    const netBarsHTML = netList.map(([name, val, col, pct]) => `
      <div class="severity-item" data-tooltip="${name}: ${val} (${pct.toFixed(1)}%)">
        <span class="sev-title" style="font-size:11px;">${name}</span>
        <div class="sev-bar-bg">
          <div class="sev-bar-fill" style="width:${pct}%;background:${col}"></div>
        </div>
        <span class="sev-count">${val}</span>
      </div>
    `).join('');

    // Recent activity rows (filtered by recentSearchFilter if active)
    let filteredRecent = currentEvents;
    if (recentSearchFilter) {
      const q = recentSearchFilter.toLowerCase();
      filteredRecent = filteredRecent.filter(e =>
        (e.title && e.title.toLowerCase().includes(q)) ||
        (e.username && e.username.toLowerCase().includes(q)) ||
        (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
        (e.details && e.details.toLowerCase().includes(q))
      );
    }

    const recentRows = filteredRecent.length ? filteredRecent.slice(0, 7).map(e => `
      <tr class="interactive-event-row" data-event-id="${esc(e.id)}">
        <td class="table-time-col">
          <strong>${esc(timeOnly(e.event_time))}</strong>
          <span style="display:block;font-size:10px;color:var(--text-faint)">${esc(e.event_time ? new Date(e.event_time).toLocaleDateString() : '')}</span>
        </td>
        <td class="table-title-cell">
          <strong>${esc(e.title || 'Untitled event')}${e.is_demo ? '<span class="badge-demo">DEMO</span>' : ''}</strong>
          <span>${esc(e.details || e.command || 'No details')}</span>
        </td>
        <td><strong>${esc(e.username || '—')}</strong></td>
        <td class="mono-cell">${esc(e.source_ip || e.destination_ip || '—')}</td>
        <td>${sourceBadge(e.source)}</td>
        <td>${severityBadge(e.severity)}</td>
        <td class="mono-cell">${esc(e.evidence_reference || '—')}</td>
      </tr>
      <tr class="recent-details-row" id="recent-details-${esc(e.id)}" style="display:none;background:var(--surface-alt);">
        <td colspan="7" style="padding:10px 16px;font-size:11.5px;">
          <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;">
            <span><strong>User:</strong> ${esc(e.username || 'System')}</span>
            <span><strong>Endpoint:</strong> ${esc(e.source_ip || 'Local')}</span>
            <span><strong>Dest:</strong> ${esc(e.destination_ip || 'N/A')}</span>
            <span><strong>Protocol:</strong> ${esc(e.protocol || '—')}</span>
            <span><strong>Ref:</strong> <code>${esc(e.evidence_reference || 'N/A')}</code></span>
          </div>
          ${e.command ? `<div style="margin-top:6px;font-family:var(--font-mono);font-size:11px;background:#050F2A;color:#7BB8FF;padding:6px 10px;border-radius:4px;">CMD: ${esc(e.command)}</div>` : ''}
        </td>
      </tr>
    `).join('') : `<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">⌕</div><strong>No recent events matching criteria</strong><p>Import evidence or generate demo records to populate this overview.</p></div></td></tr>`;

    const det = dashboardStats.detections || { total: 0, risk_score: 0, risk_level: 'None', severity_counts: {} };
    const riskBanner = `
      <section class="risk-banner risk-${esc((det.risk_level || 'none').toLowerCase())} reveal-on-scroll">
        <div class="risk-banner-score"><strong>${det.risk_score}</strong><small>/100</small></div>
        <div class="risk-banner-text">
          <span class="page-eyebrow">CORRELATED THREAT POSTURE · ${esc(det.risk_level)}</span>
          <strong>${det.total ? `${det.total} correlated detection${det.total === 1 ? '' : 's'} across your evidence` : 'No correlated threats detected yet'}</strong>
          <small>${det.total
            ? `${det.severity_counts.Critical || 0} critical · ${det.severity_counts.High || 0} high · ${det.severity_counts.Medium || 0} medium — mapped to MITRE ATT&CK.`
            : 'Import evidence or load the attack scenario to see the correlation engine in action.'}</small>
        </div>
        <button class="button button-sky button-small" data-action="goto-detections">Open Threat Detections →</button>
      </section>`;

    return riskBanner + `
      <!-- A. WELCOME SECTION -->
      <section class="dashboard-welcome-banner reveal-on-scroll">
        <div class="dashboard-welcome-left">
          <span class="page-eyebrow">COMMAND TELEMETRY</span>
          <h2>Investigation Command Centre</h2>
          <p>Correlating multi-source Windows Security logs, Microsoft Sysmon, Wireshark dissections, and Autopsy forensic artefacts into an authoritative SQLite timeline.</p>
        </div>
        <div class="dashboard-welcome-right">
          <div class="dashboard-welcome-date">
            <span style="color:var(--sky-blue);">📅</span>
            <span>${esc(dateFormatted)}</span>
          </div>
        </div>
      </section>

      <!-- E. QUICK ACTIONS BAR -->
      <section class="quick-actions-bar reveal-on-scroll">
        <span class="quick-action-label">Quick Actions:</span>
        <button class="button button-sky button-small" data-import="windows">＋ Import Windows Logs</button>
        <button class="button button-secondary button-small" data-import="sysmon">＋ Import Sysmon Records</button>
        <button class="button button-secondary button-small" data-import="network">＋ Import Wireshark Capture</button>
        <button class="button button-secondary button-small" data-import="forensic">＋ Import Autopsy Findings</button>
        <button class="button button-secondary button-small" data-go="reports">▤ Generate Report</button>
      </section>

      <!-- B. 4 HERO ANIMATED METRIC CARDS -->
      <section class="intelligence-grid reveal-on-scroll">
        <article class="stat-card" style="--card-accent: var(--sky-blue)" data-tooltip="Total events across all SQLite tables">
          <div class="stat-top">
            <span class="stat-label">Total Events Analysed</span>
            <span class="stat-icon" style="--card-icon-bg: var(--sky-blue-soft)">▤</span>
          </div>
          <div class="stat-value" data-counter="${total}">${total}</div>
          <div class="stat-meta"><span>Authoritative records in SQLite</span></div>
        </article>

        <article class="stat-card" style="--card-accent: var(--sev-critical)" data-tooltip="High and Critical risk observations">
          <div class="stat-top">
            <span class="stat-label">Priority Security Leads</span>
            <span class="stat-icon" style="--card-icon-bg: #FEE2E2; color: var(--sev-critical)">⚠</span>
          </div>
          <div class="stat-value" data-counter="${priorityCount}">${priorityCount}</div>
          <div class="stat-meta"><span>Critical and High severity alerts</span></div>
        </article>

        <article class="stat-card" style="--card-accent: #38bdf8" data-tooltip="Frames and sockets parsed via TShark or CSV">
          <div class="stat-top">
            <span class="stat-label">Network Dissections</span>
            <span class="stat-icon" style="--card-icon-bg: #E0F2FE; color: #0284c7">⇄</span>
          </div>
          <div class="stat-value" data-counter="${wireCount}">${wireCount}</div>
          <div class="stat-meta"><span>Packets analysed via TShark / CSV</span></div>
        </article>

        <article class="stat-card" style="--card-accent: var(--lavender)" data-tooltip="Disk findings and registry artefacts">
          <div class="stat-top">
            <span class="stat-label">Forensic Artefacts</span>
            <span class="stat-icon" style="--card-icon-bg: var(--lavender-soft); color: #7c3aed">◈</span>
          </div>
          <div class="stat-value" data-counter="${autCount}">${autCount}</div>
          <div class="stat-meta"><span>Findings from Autopsy disk analysis</span></div>
        </article>
      </section>

      <!-- C. 4 INTERACTIVE CHARTS GRID -->
      <section class="dashboard-charts-grid reveal-on-scroll">
        <!-- Chart 1: Activity Category -->
        <article class="panel">
          <div class="panel-header">
            <div>
              <div class="panel-title">Activity by Evidence Category</div>
              <div class="panel-subtitle">Calculated live from SQLite records</div>
            </div>
            <span class="badge-source">${total} events</span>
          </div>
          <div class="chart-box">
            <div class="chart-bars-wrap">${barsHTML}</div>
            <div class="chart-footer-note">
              <span>ⓘ</span>
              <span>Bar distribution calculated live from SQLite records. Reflects real imported telemetry.</span>
            </div>
          </div>
        </article>

        <!-- Chart 2: Severity Distribution -->
        <article class="panel">
          <div class="panel-header">
            <div>
              <div class="panel-title">Event Severity Classification</div>
              <div class="panel-subtitle">Rule categorization of all events</div>
            </div>
          </div>
          <div class="severity-stack">${sevHTML}</div>
        </article>

        <!-- Chart 3: Data Sources Overview -->
        <article class="panel">
          <div class="panel-header">
            <div>
              <div class="panel-title">Data Sources Overview</div>
              <div class="panel-subtitle">Ingestion engine contribution breakdown</div>
            </div>
          </div>
          <div class="severity-stack">${sourceBarsHTML}</div>
        </article>

        <!-- Chart 4: Network Protocols -->
        <article class="panel">
          <div class="panel-header">
            <div>
              <div class="panel-title">Network Telemetry Overview</div>
              <div class="panel-subtitle">Protocol dissections & DNS resolutions</div>
            </div>
          </div>
          <div class="severity-stack">${netBarsHTML}</div>
        </article>
      </section>

      <!-- D & F. RECENT ACTIVITY TABLE WITH IN-LINE SEARCH -->
      <section class="panel reveal-on-scroll">
        <div class="panel-header">
          <div>
            <div class="panel-title">Recent Investigation Activity</div>
            <div class="panel-subtitle">Authoritative chronological log from SQLite (Click row to inspect)</div>
          </div>
          <button class="button button-secondary button-small" data-go="timeline">View Full Timeline →</button>
        </div>

        <div style="padding: 10px 18px 0;">
          <div class="search-field" style="max-width:320px;">
            <span class="search-icon-symbol">⌕</span>
            <input type="search" id="dashboard-recent-search" placeholder="Search recent activity..." value="${esc(recentSearchFilter)}">
          </div>
        </div>

        <div class="table-container">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>EVENT / EVIDENCE TITLE</th>
                <th>ACCOUNT</th>
                <th>ENDPOINT / IP</th>
                <th>SOURCE</th>
                <th>SEVERITY</th>
                <th>REFERENCE</th>
              </tr>
            </thead>
            <tbody>${recentRows}</tbody>
          </table>
        </div>
      </section>
    `;
  }

  // -------------------------------------------------------------------------
  // 2. WINDOWS AUDIT MODULE (System Audit)
  // -------------------------------------------------------------------------
  function renderWindowsAuditHTML() {
    const isFiltered = activeSearch || activeFilter !== 'all' || activeSubfilter !== 'all';
    const rowsHTML = currentEvents.length ? currentEvents.map(e => `
      <tr class="interactive-event-row" data-event-id="${esc(e.id)}">
        <td class="table-time-col">
          <strong>${esc(timeOnly(e.event_time))}</strong>
          <span style="display:block;font-size:10px;color:var(--text-faint)">${esc(e.event_time ? new Date(e.event_time).toLocaleDateString() : '')}</span>
        </td>
        <td class="table-title-cell">
          <strong>${esc(e.title || 'Windows Event')}${e.is_demo ? '<span class="badge-demo">DEMO</span>' : ''}</strong>
          <span>${esc(e.details || e.command || 'No details')}</span>
        </td>
        <td><strong>${esc(e.username || '—')}</strong></td>
        <td class="mono-cell">${esc(e.source_ip || 'Local / System')}</td>
        <td>${sourceBadge(e.source)}</td>
        <td>${severityBadge(e.severity)}</td>
        <td class="mono-cell">${esc(e.evidence_reference || '—')}</td>
      </tr>
    `).join('') : `<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">⌘</div><strong>No audit events found</strong><p>${isFiltered ? 'No records match your active filters.' : 'Import a Windows Security JSON/CSV export to populate this audit workspace.'}</p></div></td></tr>`;

    return `
      <section class="panel reveal-on-scroll">
        <div class="panel-header">
          <div>
            <div class="panel-title">Windows 11 Security Audit</div>
            <div class="panel-subtitle">Event log analysis covering logon, privilege escalation, and account provisioning</div>
          </div>
          <span class="badge-source">${currentEvents.length} events in SQLite</span>
        </div>

        <div class="toolbar-wrap">
          <div class="toolbar-left">
            <div class="search-field">
              <span class="search-icon-symbol">⌕</span>
              <input type="search" id="table-search" placeholder="Search user, IP, command, Event ID..." value="${esc(activeSearch)}">
            </div>

            <select class="select-filter" id="severity-filter" aria-label="Filter by severity">
              <option value="all">All Severities</option>
              ${['Critical', 'High', 'Medium', 'Low', 'Informational'].map(s => `<option value="${s}" ${activeFilter === s ? 'selected' : ''}>${s}</option>`).join('')}
            </select>

            <div class="pill-filter-bar">
              <button class="filter-pill ${activeSubfilter === 'all' ? 'active' : ''}" data-subfilter="all">All Events</button>
              <button class="filter-pill ${activeSubfilter === '4624' ? 'active' : ''}" data-subfilter="4624">4624 Logon</button>
              <button class="filter-pill ${activeSubfilter === '4625' ? 'active' : ''}" data-subfilter="4625">4625 Failed</button>
              <button class="filter-pill ${activeSubfilter === '4688' ? 'active' : ''}" data-subfilter="4688">4688 Process</button>
              <button class="filter-pill ${activeSubfilter === '4720' ? 'active' : ''}" data-subfilter="4720">4720 Created</button>
              <button class="filter-pill ${activeSubfilter === '4672' ? 'active' : ''}" data-subfilter="4672">4672 Privileged</button>
            </div>
          </div>

          <div class="toolbar-right">
            <button class="button button-secondary button-small" id="clear-filters">Reset</button>
            <button class="button button-sky button-small" data-import="windows">＋ Import Security JSON</button>
          </div>
        </div>

        <div class="table-container">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>EVENT NARRATIVE</th>
                <th>ACCOUNT</th>
                <th>IP / HOST</th>
                <th>SOURCE</th>
                <th>SEVERITY</th>
                <th>EVIDENCE REF</th>
              </tr>
            </thead>
            <tbody id="table-body">${rowsHTML}</tbody>
          </table>
        </div>
      </section>
    `;
  }

  // -------------------------------------------------------------------------
  // 3. PROCESS INTELLIGENCE MODULE (Sysmon & 4688)
  // -------------------------------------------------------------------------
  function renderProcessIntelligenceHTML() {
    const isFiltered = activeSearch || activeFilter !== 'all' || activeSubfilter !== 'all';
    const rowsHTML = currentEvents.length ? currentEvents.map(e => `
      <tr class="interactive-event-row" data-event-id="${esc(e.id)}">
        <td class="table-time-col">
          <strong>${esc(timeOnly(e.event_time))}</strong>
          <span style="display:block;font-size:10px;color:var(--text-faint)">${esc(e.event_time ? new Date(e.event_time).toLocaleDateString() : '')}</span>
        </td>
        <td class="table-title-cell">
          <strong>${esc(e.title || 'Process Event')}${e.is_demo ? '<span class="badge-demo">DEMO</span>' : ''}</strong>
          <span>${esc(e.command || e.details || '—')}</span>
        </td>
        <td><strong>${esc(e.username || 'SYSTEM')}</strong></td>
        <td>${sourceBadge(e.source)}</td>
        <td>${severityBadge(e.severity)}</td>
        <td class="mono-cell">${esc(e.evidence_reference || '—')}</td>
      </tr>
    `).join('') : `<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">▣</div><strong>No process events recorded</strong><p>${isFiltered ? 'No records match your active query.' : 'Import Microsoft Sysmon JSON or Windows Event 4688 logs to analyze process executions.'}</p></div></td></tr>`;

    return `
      <section class="panel reveal-on-scroll">
        <div class="panel-header">
          <div>
            <div class="panel-title">Process & Execution Intelligence</div>
            <div class="panel-subtitle">Process creation tracking, parent-child lineages, and hash analysis from Windows 4688 & Sysmon</div>
          </div>
          <span class="badge-source">${currentEvents.length} process records</span>
        </div>

        <div class="toolbar-wrap">
          <div class="toolbar-left">
            <div class="search-field">
              <span class="search-icon-symbol">⌕</span>
              <input type="search" id="table-search" placeholder="Search command line, binary, hash, parent..." value="${esc(activeSearch)}">
            </div>

            <select class="select-filter" id="severity-filter" aria-label="Filter by severity">
              <option value="all">All Severities</option>
              ${['Critical', 'High', 'Medium', 'Low', 'Informational'].map(s => `<option value="${s}" ${activeFilter === s ? 'selected' : ''}>${s}</option>`).join('')}
            </select>

            <div class="pill-filter-bar">
              <button class="filter-pill ${activeSubfilter === 'all' ? 'active' : ''}" data-subfilter="all">All</button>
              <button class="filter-pill ${activeSubfilter === 'powershell' ? 'active' : ''}" data-subfilter="powershell">powershell</button>
              <button class="filter-pill ${activeSubfilter === 'cmd' ? 'active' : ''}" data-subfilter="cmd">cmd.exe</button>
              <button class="filter-pill ${activeSubfilter === 'mimikatz' ? 'active' : ''}" data-subfilter="mimikatz">mimikatz</button>
              <button class="filter-pill ${activeSubfilter === 'whoami' ? 'active' : ''}" data-subfilter="whoami">whoami</button>
            </div>
          </div>

          <div class="toolbar-right">
            <button class="button button-secondary button-small" id="clear-filters">Reset</button>
            <button class="button button-sky button-small" data-import="sysmon">＋ Import Sysmon JSON</button>
          </div>
        </div>

        <div class="table-container">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>PROCESS & COMMAND LINE EXECUTION</th>
                <th>ACCOUNT</th>
                <th>SOURCE</th>
                <th>SEVERITY</th>
                <th>EVIDENCE REF</th>
              </tr>
            </thead>
            <tbody id="table-body">${rowsHTML}</tbody>
          </table>
        </div>
      </section>
    `;
  }

  // -------------------------------------------------------------------------
  // 4. NETWORK INTELLIGENCE MODULE (Wireshark / PCAP / Sysmon 3 & 22)
  // -------------------------------------------------------------------------
  function renderNetworkIntelligenceHTML() {
    const isFiltered = activeSearch || activeFilter !== 'all';
    const net = networkStats || {};
    const tshark = net.tshark || {};

    const rowsHTML = currentEvents.length ? currentEvents.map(e => `
      <tr class="interactive-event-row" data-event-id="${esc(e.id)}">
        <td class="table-time-col">
          <strong>${esc(timeOnly(e.event_time))}</strong>
          <span style="display:block;font-size:10px;color:var(--text-faint)">${esc(e.event_time ? new Date(e.event_time).toLocaleDateString() : '')}</span>
        </td>
        <td class="table-title-cell">
          <strong>${esc(e.title || 'Network Observation')}${e.is_demo ? '<span class="badge-demo">DEMO</span>' : ''}</strong>
          <span>${esc(e.details || '—')}</span>
        </td>
        <td class="mono-cell">${esc(e.source_ip || '—')}</td>
        <td class="mono-cell">${esc(e.destination_ip || '—')}</td>
        <td><span class="badge-source" style="background:#E0F2FE;color:#0369a1;border-color:#BAE6FD;">${esc(e.protocol || 'IP')}</span></td>
        <td>${severityBadge(e.severity)}</td>
        <td class="mono-cell">${esc(e.evidence_reference || '—')}</td>
      </tr>
    `).join('') : `<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">⌁</div><strong>No network packets or connections found</strong><p>${isFiltered ? 'No records match your active query.' : 'Upload a Wireshark CSV or raw PCAP/PCAPNG capture to dissect network telemetry.'}</p></div></td></tr>`;

    return `
      <!-- NETWORK SUMMARY STRIP -->
      <section class="intelligence-grid reveal-on-scroll" style="margin-bottom:20px;">
        <div class="stat-card" style="--card-accent:#0284c7">
          <div class="stat-top">
            <span class="stat-label">Total Network Events</span>
            <span class="stat-icon" style="--card-icon-bg:#E0F2FE;color:#0284c7">⇄</span>
          </div>
          <div class="stat-value" data-counter="${net.total_network_events || 0}">${net.total_network_events || 0}</div>
          <div class="stat-meta"><span>SQLite network rows</span></div>
        </div>

        <div class="stat-card" style="--card-accent:#7c3aed">
          <div class="stat-top">
            <span class="stat-label">DNS Query Events</span>
            <span class="stat-icon" style="--card-icon-bg:var(--lavender-soft);color:#7c3aed">🌐</span>
          </div>
          <div class="stat-value" data-counter="${net.dns_queries_count || 0}">${net.dns_queries_count || 0}</div>
          <div class="stat-meta"><span>Domain queries resolved</span></div>
        </div>

        <div class="stat-card" style="--card-accent:${tshark.available ? '#16a34a' : '#ea580c'}">
          <div class="stat-top">
            <span class="stat-label">TShark Dissector</span>
            <span class="stat-icon" style="--card-icon-bg:${tshark.available ? '#DCFCE7' : '#FFEDD5'};color:${tshark.available ? '#16a34a' : '#ea580c'}">${tshark.available ? '✓' : '!'}</span>
          </div>
          <div style="font-size:16px;font-weight:800;color:var(--deep-navy);margin-top:6px;">${tshark.available ? 'Available' : 'Unavailable'}</div>
          <div class="stat-meta"><span>${tshark.available ? 'Direct PCAP parsing supported' : 'Install Wireshark with TShark'}</span></div>
        </div>
      </section>

      <!-- TABLE & TOOLBAR -->
      <section class="panel reveal-on-scroll">
        <div class="panel-header">
          <div>
            <div class="panel-title">Network Telemetry & Packet Observations</div>
            <div class="panel-subtitle">IPv4/IPv6 socket tracing, protocol analysis, and DNS queries from Wireshark & Sysmon</div>
          </div>
          <span class="badge-source">${currentEvents.length} records</span>
        </div>

        <div class="toolbar-wrap">
          <div class="toolbar-left">
            <div class="search-field">
              <span class="search-icon-symbol">⌕</span>
              <input type="search" id="table-search" placeholder="Search IP, port, protocol, domain..." value="${esc(activeSearch)}">
            </div>

            <select class="select-filter" id="severity-filter" aria-label="Filter by severity">
              <option value="all">All Severities</option>
              ${['Critical', 'High', 'Medium', 'Low', 'Informational'].map(s => `<option value="${s}" ${activeFilter === s ? 'selected' : ''}>${s}</option>`).join('')}
            </select>
          </div>

          <div class="toolbar-right">
            <button class="button button-secondary button-small" id="clear-filters">Reset</button>
            <button class="button button-sky button-small" data-import="network">＋ Import Wireshark CSV</button>
            <button class="button button-secondary button-small" data-import="pcap">＋ Import PCAP/PCAPNG</button>
          </div>
        </div>

        <div class="table-container">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>OBSERVATION & NARRATIVE</th>
                <th>SOURCE IP</th>
                <th>DESTINATION IP</th>
                <th>PROTOCOL</th>
                <th>SEVERITY</th>
                <th>EVIDENCE REF</th>
              </tr>
            </thead>
            <tbody id="table-body">${rowsHTML}</tbody>
          </table>
        </div>
      </section>
    `;
  }

  // -------------------------------------------------------------------------
  // 5. EVIDENCE EXPLORER (Forensic Evidence / Autopsy)
  // -------------------------------------------------------------------------
  function renderEvidenceExplorerHTML() {
    const isFiltered = activeSearch || activeFilter !== 'all' || activeSubfilter !== 'all';

    // Metrics calculations
    const totalCount = currentEvents.length;
    const deletedCount = currentEvents.filter(e => {
      const text = ((e.title || '') + ' ' + (e.details || '')).toLowerCase();
      return text.includes('deleted') || text.includes('recycle') || text.includes('unallocated');
    }).length;
    const credCount = currentEvents.filter(e => {
      const text = ((e.title || '') + ' ' + (e.details || '')).toLowerCase();
      return ['Critical', 'High'].includes(e.severity) || text.includes('credential') || text.includes('password') || text.includes('id_rsa') || text.includes('shadow');
    }).length;
    const webCount = currentEvents.filter(e => {
      const text = ((e.title || '') + ' ' + (e.details || '')).toLowerCase();
      return text.includes('history') || text.includes('browser') || text.includes('download') || text.includes('cookie') || text.includes('places.sqlite');
    }).length;
    const usbCount = currentEvents.filter(e => {
      const text = ((e.title || '') + ' ' + (e.details || '')).toLowerCase();
      return text.includes('usb') || text.includes('device') || text.includes('storage') || text.includes('peripheral');
    }).length;

    const rowsHTML = currentEvents.length ? currentEvents.map(e => `
      <tr class="interactive-event-row" data-event-id="${esc(e.id)}">
        <td class="table-time-col">
          <strong>${esc(timeOnly(e.event_time))}</strong>
          <span style="display:block;font-size:10px;color:var(--text-faint)">${esc(e.event_time ? new Date(e.event_time).toLocaleDateString() : '')}</span>
        </td>
        <td class="table-title-cell">
          <strong>${esc(e.title || 'Forensic Finding')}${e.is_demo ? '<span class="badge-demo">DEMO</span>' : ''}</strong>
          <span>${esc(e.details || '—')}</span>
        </td>
        <td>${sourceBadge(e.source)}</td>
        <td>${severityBadge(e.severity)}</td>
        <td class="mono-cell"><strong>${esc(e.evidence_reference || '—')}</strong></td>
      </tr>
    `).join('') : `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">◈</div><strong>No forensic artefacts found</strong><p>${isFiltered ? 'No records match your active query or sub-filter.' : 'Import Autopsy CSV, TSV, JSON, or SleuthKit Bodyfile exports from CAINE Linux to catalog forensic artefacts.'}</p></div></td></tr>`;

    return `
      <!-- TOP FORENSIC TELEMETRY CARDS -->
      <section class="stats-grid reveal-on-scroll">
        <div class="stat-card" style="--card-accent: var(--sky-blue)">
          <div class="stat-top">
            <span class="stat-label">Total Artefacts</span>
            <span class="stat-icon" style="--card-icon-bg: var(--sky-blue-soft)">◈</span>
          </div>
          <div class="stat-value" data-counter="${totalCount}">${totalCount}</div>
          <div class="stat-meta"><span>Indexed forensic findings</span></div>
        </div>

        <div class="stat-card" style="--card-accent: #f59e0b">
          <div class="stat-top">
            <span class="stat-label">Deleted Files</span>
            <span class="stat-icon" style="--card-icon-bg: #FEF3C7; color: #d97706">🗑</span>
          </div>
          <div class="stat-value" data-counter="${deletedCount}">${deletedCount}</div>
          <div class="stat-meta"><span>Unallocated / recycle entries</span></div>
        </div>

        <div class="stat-card" style="--card-accent: var(--sev-critical)">
          <div class="stat-top">
            <span class="stat-label">Sensitive Credentials</span>
            <span class="stat-icon" style="--card-icon-bg: #FEE2E2; color: var(--sev-critical)">🔑</span>
          </div>
          <div class="stat-value" data-counter="${credCount}">${credCount}</div>
          <div class="stat-meta"><span>Passwords, keys & shadow items</span></div>
        </div>

        <div class="stat-card" style="--card-accent: #38bdf8">
          <div class="stat-top">
            <span class="stat-label">Web & Downloads</span>
            <span class="stat-icon" style="--card-icon-bg: #E0F2FE; color: #0284c7">🌐</span>
          </div>
          <div class="stat-value" data-counter="${webCount}">${webCount}</div>
          <div class="stat-meta"><span>Browser history & cookies</span></div>
        </div>

        <div class="stat-card" style="--card-accent: var(--lavender)">
          <div class="stat-top">
            <span class="stat-label">USB & Hardware</span>
            <span class="stat-icon" style="--card-icon-bg: var(--lavender-soft); color: #7c3aed">🔌</span>
          </div>
          <div class="stat-value" data-counter="${usbCount}">${usbCount}</div>
          <div class="stat-meta"><span>Attached external devices</span></div>
        </div>
      </section>

      <!-- AUTOPSY QUICK INGEST PANEL -->
      <section class="panel reveal-on-scroll" style="margin-bottom:20px;background:var(--surface-white);border:1px solid var(--border-light);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:10px;">
          <div>
            <span class="page-eyebrow">CAINE LINUX & AUTOPSY INGEST HUB</span>
            <h3 style="font-family:var(--font-display);font-size:16px;color:var(--deep-navy);margin-top:2px;">Examiner Evidence Ingest</h3>
            <p style="font-size:12px;color:var(--text-muted);margin:0;">Incorporate disk analysis exports from Autopsy & The Sleuth Kit into the authoritative SQLite evidence pool.</p>
          </div>
          <div class="format-badge-list">
            <span class="format-badge">CSV REPORT</span>
            <span class="format-badge">TSV TABLE</span>
            <span class="format-badge">JSON REPORT</span>
            <span class="format-badge">BODYFILE (TSK)</span>
          </div>
        </div>

        <div class="smart-dropzone" id="forensic-inline-dropzone" style="padding:22px;background:var(--surface-alt);">
          <div class="dropzone-icon" style="font-size:26px;margin-bottom:4px;">⇪</div>
          <div class="dropzone-title" style="font-size:13.5px;">Drag & Drop Autopsy Report File Here</div>
          <div class="dropzone-desc" style="font-size:11.5px;">Supports CSV, TSV, JSON, and SleuthKit 11-column pipe bodyfiles (Max 10 MB)</div>
          <div style="margin-top:10px;">
            <button class="button button-sky button-small" id="forensic-inline-browse">Browse Forensic File...</button>
          </div>
        </div>

        <div class="upload-progress-wrap" id="forensic-inline-progress" style="display:none;margin-top:10px;">
          <div class="upload-progress-fill" id="forensic-inline-fill"></div>
        </div>

        <div id="forensic-inline-status" style="display:none;margin-top:8px;font-size:12px;text-align:center;"></div>
      </section>

      <!-- MAIN TABLE PANEL -->
      <section class="panel reveal-on-scroll">
        <div class="panel-header">
          <div>
            <div class="panel-title">Forensic Evidence & Artefact Explorer</div>
            <div class="panel-subtitle">File system artefacts, deleted entries, browser history, and sensitive files organized from Autopsy</div>
          </div>
          <span class="badge-source">${currentEvents.length} artefacts</span>
        </div>

        <div class="toolbar-wrap">
          <div class="toolbar-left" style="flex-wrap:wrap;gap:8px;">
            <div class="search-field">
              <span class="search-icon-symbol">⌕</span>
              <input type="search" id="table-search" placeholder="Search file, path, hash, tag..." value="${esc(activeSearch)}">
            </div>

            <select class="select-filter" id="severity-filter" aria-label="Filter by severity">
              <option value="all">All Severities</option>
              ${['Critical', 'High', 'Medium', 'Low', 'Informational'].map(s => `<option value="${s}" ${activeFilter === s ? 'selected' : ''}>${s}</option>`).join('')}
            </select>
          </div>

          <div class="toolbar-right">
            <button class="button button-secondary button-small" id="clear-filters">Reset Filters</button>
            <button class="button button-sky button-small" data-import="forensic">＋ Smart Ingest Modal</button>
          </div>
        </div>

        <!-- ARTIFACT SUBCATEGORY FILTER PILLS -->
        <div class="subfilter-pills" style="display:flex;gap:6px;flex-wrap:wrap;padding:0 24px 14px 24px;">
          <button class="filter-pill ${activeSubfilter === 'all' ? 'active' : ''}" data-subfilter="all">All Artefacts (${totalCount})</button>
          <button class="filter-pill ${activeSubfilter === 'deleted' ? 'active' : ''}" data-subfilter="deleted">Deleted Files (${deletedCount})</button>
          <button class="filter-pill ${activeSubfilter === 'credential' ? 'active' : ''}" data-subfilter="credential">Credentials & Keys (${credCount})</button>
          <button class="filter-pill ${activeSubfilter === 'history' ? 'active' : ''}" data-subfilter="history">Web History (${webCount})</button>
          <button class="filter-pill ${activeSubfilter === 'temp' ? 'active' : ''}" data-subfilter="temp">Temp & Staging</button>
          <button class="filter-pill ${activeSubfilter === 'usb' ? 'active' : ''}" data-subfilter="usb">USB Devices (${usbCount})</button>
        </div>

        <div class="table-container">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>TIMESTAMP (UTC)</th>
                <th>ARTEFACT NAME & DETAILS</th>
                <th>SOURCE ENGINE</th>
                <th>SEVERITY</th>
                <th>EVIDENCE REFERENCE</th>
              </tr>
            </thead>
            <tbody id="table-body">${rowsHTML}</tbody>
          </table>
        </div>
      </section>
    `;
  }

  function initForensicInlineDropzone() {
    const dropzone = $('#forensic-inline-dropzone');
    const browseBtn = $('#forensic-inline-browse');
    const progressWrap = $('#forensic-inline-progress');
    const progressFill = $('#forensic-inline-fill');
    const statusBox = $('#forensic-inline-status');
    if (!dropzone) return;

    const runUpload = (file) => {
      if (!file) return;
      if (progressWrap) progressWrap.style.display = 'block';
      if (progressFill) {
        progressFill.style.width = '12%';
        progressFill.style.backgroundColor = 'var(--sky-blue)';
      }
      if (statusBox) {
        statusBox.style.display = 'block';
        statusBox.innerHTML = `Ingesting <strong>${esc(file.name)}</strong> (${(file.size/1024).toFixed(1)} KB)...`;
      }

      const onProgress = (percent, loaded, total) => {
        if (progressFill) progressFill.style.width = `${percent}%`;
        if (statusBox) {
          const loadedKb = (loaded / 1024).toFixed(1);
          const totalKb = (total / 1024).toFixed(1);
          statusBox.innerHTML = `Uploading <strong>${esc(file.name)}</strong>: ${percent}% (${loadedKb} / ${totalKb} KB)... Ingesting into SQLite...`;
        }
      };

      handleFileUpload(file, 'forensic', onProgress).then(res => {
        if (progressFill) {
          progressFill.style.width = '100%';
          progressFill.style.backgroundColor = '#10B981';
        }
        const imported = res.successful_records ?? res.imported_records ?? 0;
        const dups = res.duplicate_records ?? res.duplicates ?? 0;
        const failed = res.failed_records ?? 0;
        if (statusBox) {
          statusBox.innerHTML = `
            <div style="background:rgba(16,185,129,0.12);border:1px solid #10B981;border-radius:6px;padding:8px 12px;display:inline-block;color:#065F46;font-size:12px;">
              <strong style="color:#10B981;">✓ Ingest Successful:</strong>
              ${imported} records added, ${dups} duplicates skipped, ${failed} failed.
            </div>
          `;
        }
        setTimeout(() => {
          if (progressWrap) progressWrap.style.display = 'none';
          if (statusBox) statusBox.style.display = 'none';
        }, 3500);
      }).catch(err => {
        if (progressFill) {
          progressFill.style.width = '100%';
          progressFill.style.backgroundColor = '#EF4444';
        }
        if (statusBox) {
          statusBox.innerHTML = `
            <div style="background:rgba(239,68,68,0.12);border:1px solid #EF4444;border-radius:6px;padding:8px 12px;display:inline-block;color:#991B1B;font-size:12px;">
              <strong>✗ Ingest Failed:</strong> ${esc(err.message)}
            </div>
          `;
        }
      });
    };

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-active');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('drag-active');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-active');
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) runUpload(files[0]);
    });

    dropzone.addEventListener('click', (e) => {
      if (e.target.closest('#forensic-inline-browse')) return;
      triggerFileInput('forensic', runUpload);
    });

    browseBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      triggerFileInput('forensic', runUpload);
    });
  }

  // -------------------------------------------------------------------------
  // PHASE 3: INTERACTIVE INVESTIGATION TIMELINE (with Side Inspection Panel)
  // -------------------------------------------------------------------------
  function renderTimelineHTML() {
    let sorted = [...currentEvents];

    // Date range filtering
    if (timelineDateRange !== 'all') {
      const now = Date.now();
      const cutoff = timelineDateRange === '24h' ? now - 24 * 3600 * 1000 :
                     timelineDateRange === '7d' ? now - 7 * 24 * 3600 * 1000 :
                     now - 30 * 24 * 3600 * 1000;
      sorted = sorted.filter(e => e.event_time && new Date(e.event_time).getTime() >= cutoff);
    }

    if (timelineSortOrder === 'asc') {
      sorted.sort((a, b) => new Date(a.event_time) - new Date(b.event_time));
    } else {
      sorted.sort((a, b) => new Date(b.event_time) - new Date(a.event_time));
    }

    if (!selectedTimelineEvent && sorted.length) {
      selectedTimelineEvent = sorted[0];
    }

    const itemsHTML = sorted.length ? sorted.map(e => {
      const isSelected = selectedTimelineEvent && selectedTimelineEvent.id === e.id;
      return `
        <div class="storyline-node-item timeline-card reveal-on-scroll ${isSelected ? 'selected-node' : ''}" data-event-id="${esc(e.id)}">
          <div class="storyline-node-dot"></div>
          <div class="storyline-node-header">
            <span class="storyline-timestamp">${esc(formatDate(e.event_time))}</span>
            <div style="display:flex;gap:6px;align-items:center;">
              ${sourceBadge(e.source)}
              ${severityBadge(e.severity)}
            </div>
          </div>
          <div class="storyline-node-title">
            ${esc(e.title || 'Event Observation')}
            ${e.is_demo ? '<span class="badge-demo">DEMO</span>' : ''}
          </div>
          <div class="storyline-node-details">
            ${esc(e.details || e.command || 'No additional narrative provided.')}
          </div>
          
          <!-- Expandable Details Inline Drawer -->
          <button class="timeline-expand-toggle" data-toggle-drawer="${esc(e.id)}">
            <span class="arrow-icon">▼</span>
            <span class="toggle-text">Toggle Inline Details</span>
          </button>

          <div class="timeline-details-drawer" id="drawer-${esc(e.id)}">
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:10px;background:var(--surface-alt);padding:10px;border-radius:var(--radius-sm);border:1px solid var(--border-light);font-size:11px;">
              <div><strong>User:</strong> ${esc(e.username || 'System')}</div>
              <div><strong>Source IP:</strong> ${esc(e.source_ip || 'Local')}</div>
              <div><strong>Dest IP:</strong> ${esc(e.destination_ip || '—')}</div>
              <div><strong>Protocol:</strong> ${esc(e.protocol || '—')}</div>
              <div><strong>Reference:</strong> ${esc(e.evidence_reference || 'N/A')}</div>
              <div><strong>Imported:</strong> ${esc(timeAgo(e.imported_at))}</div>
            </div>
            ${e.command ? `<div style="margin-top:8px;font-family:var(--font-mono);font-size:11px;background:#050F2A;color:#7BB8FF;padding:8px;border-radius:4px;word-break:break-all;"><strong>CMD:</strong> ${esc(e.command)}</div>` : ''}
          </div>

          <div class="storyline-node-footer">
            <span class="mono-cell" style="color:var(--text-muted)"><strong>REF:</strong> ${esc(e.evidence_reference || 'N/A')}</span>
            ${e.username ? `<span class="mono-cell" style="color:var(--text-muted)"><strong>USER:</strong> ${esc(e.username)}</span>` : ''}
            ${e.source_ip ? `<span class="mono-cell" style="color:var(--text-muted)"><strong>IP:</strong> ${esc(e.source_ip)}</span>` : ''}
            <button class="button button-ghost button-small open-modal-btn" data-event-id="${esc(e.id)}" style="margin-left:auto;font-size:11px;color:var(--sky-blue);font-weight:700">Full Modal ↗</button>
          </div>
        </div>
      `;
    }).join('') : `
      <div class="empty-state">
        <div class="empty-icon">◷</div>
        <strong>Investigation Timeline is Empty</strong>
        <p>Import evidence from Windows Security, Sysmon, Wireshark, or Autopsy to reconstruct this incident timeline.</p>
      </div>
    `;

    // Side panel contents
    const sel = selectedTimelineEvent;
    const sidePanelHTML = sel ? `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
        <span class="page-eyebrow">SELECTED TIMELINE EVENT</span>
        ${severityBadge(sel.severity)}
      </div>
      <h3 style="font-family:var(--font-display);font-size:15px;color:var(--deep-navy);margin-bottom:6px;">${esc(sel.title || 'Event Observation')}</h3>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:14px;">${esc(formatDate(sel.event_time))}</div>

      <div style="background:var(--surface-alt);border:1px solid var(--border-light);border-radius:var(--radius-sm);padding:10px;margin-bottom:14px;font-size:11.5px;display:flex;flex-direction:column;gap:6px;">
        <div><strong>Source Engine:</strong> ${esc(sel.source || '—')}</div>
        <div><strong>Category:</strong> ${esc(sel.category || 'General')}</div>
        <div><strong>User Account:</strong> ${esc(sel.username || 'System')}</div>
        <div><strong>Endpoint / IP:</strong> ${esc(sel.source_ip || sel.destination_ip || 'Local / System')}</div>
        <div><strong>Evidence Tag:</strong> <code>${esc(sel.evidence_reference || 'N/A')}</code></div>
      </div>

      <div style="margin-bottom:14px;">
        <strong style="font-size:11px;color:var(--deep-navy);display:block;margin-bottom:4px;">Forensic Narrative:</strong>
        <p style="font-size:11.5px;color:var(--text-secondary);line-height:1.5;background:#FFFFFF;border:1px solid var(--border-light);border-radius:var(--radius-sm);padding:10px;">
          ${esc(sel.details || 'No additional details logged.')}
        </p>
      </div>

      ${sel.command ? `
        <div style="margin-bottom:14px;">
          <strong style="font-size:11px;color:var(--deep-navy);display:block;margin-bottom:4px;">Command Line:</strong>
          <pre class="payload-pre" style="font-size:10.5px;max-height:120px;">${esc(sel.command)}</pre>
        </div>
      ` : ''}

      <div style="border-top:1px dashed var(--border-light);padding-top:12px;margin-top:14px;">
        <strong style="font-size:11px;color:var(--deep-navy);display:block;margin-bottom:4px;">Correlation Context:</strong>
        <p style="font-size:11px;color:var(--text-muted);line-height:1.4;">
          Correlated with surrounding audit events via matching identifier <code>${esc(sel.username || sel.source_ip || 'local-host')}</code>. Note: Correlation confirms chronological co-occurrence; judicial attribution requires secondary corroboration.
        </p>
      </div>

      <div style="display:flex;gap:8px;margin-top:14px;">
        <button class="button button-sky button-small open-modal-btn" data-event-id="${esc(sel.id)}" style="flex:1;">Full Inspection Modal</button>
      </div>
    ` : `
      <div class="timeline-side-panel-empty">
        <div style="font-size:24px;margin-bottom:6px;">◷</div>
        <strong>Select a Timeline Event</strong>
        <p>Click any event card in the timeline stream to review correlated metadata, command line executions, and attribution indicators.</p>
      </div>
    `;

    return `
      <section class="panel reveal-on-scroll">
        <div class="panel-header">
          <div>
            <div class="panel-title">Evidence Storyline & Incident Timeline</div>
            <div class="panel-subtitle">Chronologically organized multi-source records with side-panel inspection</div>
          </div>
          <span class="badge-source">${currentEvents.length} events sequenced</span>
        </div>

        <div class="toolbar-wrap">
          <div class="toolbar-left">
            <div class="search-field">
              <span class="search-icon-symbol">⌕</span>
              <input type="search" id="table-search" placeholder="Search narrative, user, IP, rule..." value="${esc(activeSearch)}">
            </div>

            <select class="select-filter" id="severity-filter" aria-label="Filter by severity">
              <option value="all">All Severities</option>
              ${['Critical', 'High', 'Medium', 'Low', 'Informational'].map(s => `<option value="${s}" ${activeFilter === s ? 'selected' : ''}>${s}</option>`).join('')}
            </select>

            <select class="select-filter" id="timeline-source-filter" aria-label="Filter by evidence source">
              <option value="all">All Sources</option>
              <option value="Windows audit">Windows Security</option>
              <option value="Sysmon">Microsoft Sysmon</option>
              <option value="Wireshark">Wireshark</option>
              <option value="Autopsy">Autopsy</option>
              <option value="Linux audit">Linux auditd</option>
            </select>

            <select class="select-filter" id="timeline-date-filter" aria-label="Filter by date range">
              <option value="all" ${timelineDateRange === 'all' ? 'selected' : ''}>All Timestamps</option>
              <option value="24h" ${timelineDateRange === '24h' ? 'selected' : ''}>Last 24 Hours</option>
              <option value="7d" ${timelineDateRange === '7d' ? 'selected' : ''}>Last 7 Days</option>
              <option value="30d" ${timelineDateRange === '30d' ? 'selected' : ''}>Last 30 Days</option>
            </select>
          </div>

          <div class="toolbar-right">
            <button class="button button-secondary button-small" id="toggle-timeline-sort">
              <span>⇅</span> Sort: ${timelineSortOrder === 'desc' ? 'Newest First' : 'Oldest First'}
            </button>
            <button class="button button-secondary button-small" id="clear-filters">Reset Filters</button>
          </div>
        </div>

        <!-- SPLIT LAYOUT: TIMELINE STREAM + STICKY SIDE PANEL -->
        <div class="timeline-split-view">
          <div class="storyline-container" style="margin-bottom:0;">
            <div class="storyline-stream" id="timeline-container">
              ${itemsHTML}
            </div>
          </div>

          <aside class="timeline-side-panel" id="timeline-side-panel">
            ${sidePanelHTML}
          </aside>
        </div>
      </section>
    `;
  }

  // -------------------------------------------------------------------------
  // PHASE 5: EVIDENCE RELATIONSHIP GRAPH (Topology)
  // -------------------------------------------------------------------------
  function renderGraphHTML() {
    const nodes = currentGraphData.nodes || [];
    const edges = currentGraphData.edges || [];

    return `
      <section class="panel reveal-on-scroll">
        <div class="panel-header">
          <div>
            <div class="panel-title">Evidence Relationship Topology</div>
            <div class="panel-subtitle">Interactive entity-relationship mapping constructed strictly from imported SQLite events</div>
          </div>
          <span class="badge-source" id="graph-summary-badge">${nodes.length} entities • ${edges.length} relationships</span>
        </div>

        <div class="toolbar-wrap">
          <div class="toolbar-left">
            <div class="search-field">
              <span class="search-icon-symbol">⌕</span>
              <input type="search" id="graph-search" placeholder="Highlight node by name, IP, or process...">
            </div>

            <div class="pill-filter-bar">
              <button class="filter-pill active" data-graph-filter="all">All Types</button>
              <button class="filter-pill" data-graph-filter="user">Users</button>
              <button class="filter-pill" data-graph-filter="process">Processes</button>
              <button class="filter-pill" data-graph-filter="network">Network / IPs</button>
              <button class="filter-pill" data-graph-filter="dns">DNS Domains</button>
              <button class="filter-pill" data-graph-filter="file">Files</button>
            </div>
          </div>

          <div class="toolbar-right">
            <button class="button button-secondary button-small" id="reset-layout-btn" title="Reset all nodes to default layout positions"><span>⟲</span> Reset Layout</button>
            <button class="button button-secondary button-small" id="fit-screen-btn" title="Scale and frame all nodes in canvas"><span>⛶</span> Fit to Screen</button>
            
            <div class="dropdown-wrap" id="export-dropdown-wrap">
              <button class="button button-sky button-small" id="export-exhibit-btn" title="Export graph as forensic evidence exhibit">
                <span>📥</span> Export Exhibit ▾
              </button>
              <div class="dropdown-menu" id="export-menu">
                <button class="dropdown-item" id="export-svg-btn">
                  <span>📐</span> Export as Vector SVG (.svg)
                </button>
                <button class="dropdown-item" id="export-png-btn">
                  <span>🖼</span> Export as High-Res PNG (.png)
                </button>
              </div>
            </div>

            <button class="button button-secondary button-small" data-go="timeline">View Events Timeline →</button>
          </div>
        </div>

        <div class="graph-stage">
          <div class="graph-canvas-container" id="graph-container">
            <svg id="graph-svg" class="graph-svg" viewBox="0 0 900 560" preserveAspectRatio="xMidYMid meet"></svg>

            <!-- Interactive Zoom & Framing Controls -->
            <div class="graph-controls">
              <button class="graph-control-btn" id="graph-zoom-in" title="Zoom In (+)" aria-label="Zoom in">+</button>
              <button class="graph-control-btn" id="graph-zoom-out" title="Zoom Out (−)" aria-label="Zoom out">−</button>
              <button class="graph-control-btn" id="graph-zoom-fit" title="Fit to Screen (⛶)" aria-label="Fit to Screen">⛶</button>
              <button class="graph-control-btn" id="graph-zoom-reset" title="Reset Layout (⟲)" aria-label="Reset layout">⟲</button>
            </div>

            <!-- Legend Overlay -->
            <div class="graph-legend">
              <div class="graph-legend-item"><span class="graph-legend-dot" style="background:#7BB8FF;"></span> User</div>
              <div class="graph-legend-item"><span class="graph-legend-dot" style="background:#050F2A;"></span> Process</div>
              <div class="graph-legend-item"><span class="graph-legend-dot" style="background:#0284c7;"></span> Network/IP</div>
              <div class="graph-legend-item"><span class="graph-legend-dot" style="background:#B8A0FF;"></span> DNS Domain</div>
              <div class="graph-legend-item"><span class="graph-legend-dot" style="background:#E11D48;"></span> File Artefact</div>
            </div>

            <!-- Empty State Overlay (shown if 0 nodes) -->
            <div class="graph-empty-state" id="graph-empty-state" style="${nodes.length ? 'display:none;' : ''}">
              <div class="graph-empty-icon">☊</div>
              <h3 style="font-family:var(--font-display);font-size:16px;color:var(--deep-navy);margin-bottom:6px;">Insufficient Evidence in Database</h3>
              <p style="font-size:12px;color:var(--text-muted);max-width:440px;margin-bottom:16px;line-height:1.5;">
                No correlated entity relationships found. Import Windows Security logs (Event IDs 4624, 4688), Sysmon events (IDs 1, 3, 11, 22), or Wireshark network captures to automatically reconstruct this topology.
              </p>
              <button class="button button-sky button-small" data-action="open-import">Ingest Evidence Now</button>
            </div>
          </div>

          <!-- Selected Entity Inspector -->
          <div class="graph-inspector-card" id="graph-inspector">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
              <span class="page-eyebrow" id="inspector-type">ENTITY INSPECTOR</span>
              <span class="badge-source" id="inspector-count">${nodes.length ? 'Click or drag node to inspect' : 'Awaiting Ingest'}</span>
            </div>
            <h3 id="inspector-name" style="font-family:var(--font-display);font-size:16px;color:var(--deep-navy);margin-bottom:4px;">
              ${nodes.length ? 'No Entity Selected' : 'Topology Awaiting Evidence'}
            </h3>
            <p id="inspector-desc" style="font-size:12px;color:var(--text-secondary);line-height:1.5;">
              ${nodes.length 
                ? 'Click or drag any node in the topology above to examine its evidence relationships, connected processes, and linked database events.' 
                : 'Correlated entities (users, processes, IPs, files, domains) will appear here once forensic logs are ingested.'}
            </p>
            <div id="inspector-relations" style="margin-top:12px;font-size:11.5px;color:var(--text-muted);"></div>

            <!-- Integrity Statement Callout -->
            <div class="evidence-disclaimer-box" id="inspector-disclaimer">
              <span class="evidence-disclaimer-icon">ℹ</span>
              <div>
                <strong>Evidence Integrity Notice:</strong>
                <span style="display:block;margin-top:2px;">
                  Topological connections represent observed events recorded in SQLite (<code>instance/securescan.db</code>). Correlation illustrates logical and chronological linkage; it does not constitute definitive proof of malicious activity.
                </span>
              </div>
            </div>

            <!-- Inspector Actions -->
            <div id="inspector-actions" style="margin-top:14px;display:none;gap:8px;">
              <button class="button button-secondary button-small" id="inspector-timeline-btn">Filter Timeline to Entity ↗</button>
              <button class="button button-ghost button-small" id="inspector-deselect-btn">Deselect</button>
            </div>
          </div>
        </div>
      </section>
    `;
  }

  // -------------------------------------------------------------------------
  // 8. INVESTIGATION STUDIO (Reports)
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // SYSTEM AUDIT CONSOLE (Windows host audit + Wireshark live capture + Autopsy)
  // -------------------------------------------------------------------------
  function renderChecksHTML(latest) {
    if (!latest || !latest.available) {
      return '<p class="det-muted">No audit has been run yet. Click <b>Run system audit</b> to check this workstation.</p>';
    }
    const icon = { pass: '✓', warn: '!', fail: '✕', error: '?', skipped: '–' };
    const counts = latest.checks.reduce((a, c) => (a[c.status] = (a[c.status] || 0) + 1, a), {});
    return `
      <div class="audit-meta">
        <span><b>${esc(latest.meta.computer)}</b> · ${esc(latest.meta.os || '')}</span>
        <span>Audited ${esc(formatDate(latest.meta.audit_time))} · run ${esc(latest.meta.run_id)}
          ${latest.meta.is_admin ? '' : ' · <i>standard user (admin-only checks skipped)</i>'}</span>
        <span class="mono-cell" title="SHA-256 of the stored raw audit JSON">SHA-256 ${esc((latest.sha256_hash || '').slice(0, 16))}…</span>
      </div>
      <div class="audit-score">
        <span class="chk chk-pass">${counts.pass || 0} passed</span>
        <span class="chk chk-warn">${counts.warn || 0} warnings</span>
        <span class="chk chk-fail">${counts.fail || 0} failed</span>
        ${counts.skipped || counts.error ? `<span class="chk chk-skipped">${(counts.skipped || 0) + (counts.error || 0)} not checked</span>` : ''}
      </div>
      <table class="forensic-table audit-table">
        <thead><tr><th style="width:70px">RESULT</th><th>CHECK</th><th>DETAIL</th></tr></thead>
        <tbody>${latest.checks.map(c => `
          <tr><td><span class="chk chk-${esc(c.status)}">${icon[c.status] || '?'} ${esc(c.status)}</span></td>
              <td><strong>${esc(c.check)}</strong></td><td>${esc(c.note)}</td></tr>`).join('')}
        </tbody>
      </table>`;
  }

  function renderAutopsyJobHTML(job) {
    if (!job) return '';
    const s = job.summary;
    return `<div class="audit-result audit-${esc(job.status)}">
      <strong>${job.status === 'running' ? '⏳' : job.status === 'done' ? '✓' : '✕'} ${esc(job.message || '')}</strong>
      <small class="mono-cell">${esc(job.source)}</small>
      ${s ? `<small>${s.files_total} files · ${s.files_deleted} deleted · ${s.files_flagged} flagged · ${Object.values(s.artifacts || {}).reduce((a, b) => a + b, 0)} Autopsy artifacts · case DB SHA-256 ${esc(s.case_db_sha256.slice(0, 16))}…</small>
             <button class="button button-secondary button-small" data-action="goto-forensic">View findings in Evidence Explorer →</button>` : ''}
    </div>`;
  }

  function renderAuditConsoleHTML() {
    const { latest, capture, autopsy } = auditState;
    const ifaces = (capture && capture.interfaces) || [];
    const preferred = ifaces.find(i => /wi-?fi|ethernet/i.test(i.name) && !/\d$/.test(i.name)) || ifaces[0];
    const tsharkOk = capture && capture.tshark && capture.tshark.available;
    const lastJob = (autopsy.jobs || [])[0];

    return `
      <section class="panel reveal-on-scroll" style="margin-bottom:20px">
        <div class="panel-header">
          <div><div class="panel-title">1 · Windows host security audit</div>
            <div class="panel-subtitle">Read-only checks of this PC: accounts, admins, open ports, live connections, firewall, Defender, UAC, RDP, SMBv1, autoruns, scheduled tasks, patch level, Security log</div></div>
          <button class="button button-sky button-small" data-action="run-host-audit">▶ Run system audit</button>
        </div>
        <div class="audit-body" id="host-audit-body">${renderChecksHTML(latest)}</div>
      </section>

      <div class="audit-grid">
        <section class="panel reveal-on-scroll">
          <div class="panel-header"><div><div class="panel-title">2 · Network audit with Wireshark (TShark)</div>
            <div class="panel-subtitle">${tsharkOk ? esc(capture.tshark.version) : 'TShark not found – install Wireshark with TShark + Npcap'}</div></div></div>
          <div class="audit-body">
            <label class="audit-field">Interface
              <select id="cap-iface" ${tsharkOk ? '' : 'disabled'}>
                ${ifaces.map(i => `<option value="${esc(i.id)}" ${preferred && preferred.id === i.id ? 'selected' : ''}>${esc(i.id)}. ${esc(i.name)}</option>`).join('')}
              </select></label>
            <div class="audit-row">
              <label class="audit-field">Duration (s)<input id="cap-duration" type="number" min="5" max="120" value="20"></label>
              <label class="audit-field">Max packets<input id="cap-packets" type="number" min="10" max="20000" value="2000"></label>
            </div>
            <label class="audit-field">Capture filter (optional, BPF)<input id="cap-filter" type="text" placeholder="e.g. tcp or udp port 53"></label>
            <button class="button button-sky" data-action="run-capture" ${tsharkOk ? '' : 'disabled'}>● Start live capture</button>
            <div id="capture-result"></div>
            <p class="det-muted">The capture is saved as a .pcapng evidence file with its SHA-256 hash, dissected by TShark and correlated with the host audit (process ↔ packet).</p>
          </div>
        </section>

        <section class="panel reveal-on-scroll">
          <div class="panel-header"><div><div class="panel-title">3 · Disk & file forensics with Autopsy</div>
            <div class="panel-subtitle">${autopsy.available ? `Autopsy ${esc(autopsy.version)} detected` : 'Autopsy not found under Program Files'}</div></div></div>
          <div class="audit-body">
            <label class="audit-field">Folder or disk image to analyse
              <input id="aut-source" type="text" placeholder="e.g. C:\\Users\\you\\Downloads  or  D:\\evidence\\disk.E01"></label>
            <button class="button button-sky" data-action="run-autopsy" ${autopsy.available ? '' : 'disabled'}>⚙ Analyse with Autopsy</button>
            <div id="autopsy-result">${renderAutopsyJobHTML(lastJob)}</div>
            <hr class="audit-sep">
            <label class="audit-field">…or import a case you built in the Autopsy GUI
              <input id="aut-case" type="text" placeholder="Case folder, .aut file or autopsy.db"></label>
            <button class="button button-secondary" data-action="import-autopsy-case">⇪ Import Autopsy case</button>
            <div id="autopsy-case-result"></div>
            <p class="det-muted">Autopsy runs headless (create case → add data source → ingest: hashing, file-type ID, recent activity…). SecureScan then reads the case database read-only and flags deleted files, disguised executables, credential files and duplicates.</p>
          </div>
        </section>
      </div>`;
  }

  function setBusy(btn, busy, label) {
    if (!btn) return;
    if (busy) { btn.dataset.label = btn.innerHTML; btn.innerHTML = label; btn.disabled = true; }
    else { btn.innerHTML = btn.dataset.label || btn.innerHTML; btn.disabled = false; }
  }

  async function handleHostAudit(btn) {
    setBusy(btn, true, '⏳ Auditing… (~15 s)');
    try {
      const res = await API.post('/api/audit/host');
      auditState.latest = { available: true, meta: res.meta, checks: res.checks, sha256_hash: res.sha256_hash };
      $('#host-audit-body').innerHTML = renderChecksHTML(auditState.latest);
      toast(res.message); addNotification('System Audit Complete', res.message, 'success');
    } catch (err) { toast(err.message, true); }
    finally { setBusy(btn, false); }
  }

  async function handleCapture(btn) {
    const body = { interface: $('#cap-iface')?.value, duration: Number($('#cap-duration')?.value || 20),
                   max_packets: Number($('#cap-packets')?.value || 2000), filter: $('#cap-filter')?.value || '' };
    setBusy(btn, true, `⏳ Capturing for ${body.duration} s…`);
    $('#capture-result').innerHTML = '';
    try {
      const res = await API.post('/api/capture/live', body);
      $('#capture-result').innerHTML = `<div class="audit-result audit-done"><strong>✓ ${esc(res.message)}</strong>
        <small class="mono-cell">${esc(res.stored_file)} · SHA-256 ${esc(res.sha256_hash.slice(0, 16))}…</small>
        <button class="button button-secondary button-small" data-action="goto-network">Open Network Intelligence →</button></div>`;
      toast(res.message); addNotification('Live Capture Complete', res.message, 'success');
    } catch (err) {
      $('#capture-result').innerHTML = `<div class="audit-result audit-error"><strong>✕ ${esc(err.message)}</strong></div>`;
      toast(err.message, true);
    } finally { setBusy(btn, false); }
  }

  function pollAutopsyJob(jobId) {
    clearTimeout(autopsyPollTimer);
    const tick = async () => {
      try {
        const job = await API.json(`/api/autopsy/jobs/${encodeURIComponent(jobId)}`);
        const box = $('#autopsy-result');
        if (box) box.innerHTML = renderAutopsyJobHTML(job);
        if (job.status === 'running') { autopsyPollTimer = setTimeout(tick, 3000); return; }
        const btn = $('[data-action="run-autopsy"]'); if (btn) btn.disabled = false;
        if (job.status === 'done') { toast(job.message); addNotification('Autopsy Analysis Complete', job.message, 'success'); }
        else toast(job.message, true);
      } catch (err) { toast(err.message, true); }
    };
    tick();
  }

  async function handleAutopsyAnalyze(btn) {
    const path = ($('#aut-source')?.value || '').trim();
    if (!path) { toast('Enter a folder or disk image path first.', true); return; }
    try {
      const res = await API.post('/api/autopsy/analyze', { path });
      if (btn) btn.disabled = true;
      toast(res.message); pollAutopsyJob(res.job_id);
    } catch (err) { toast(err.message, true); }
  }

  async function handleAutopsyImport(btn) {
    const path = ($('#aut-case')?.value || '').trim();
    if (!path) { toast('Enter the Autopsy case path first.', true); return; }
    setBusy(btn, true, '⏳ Reading case…');
    try {
      const res = await API.post('/api/autopsy/import-case', { path });
      $('#autopsy-case-result').innerHTML = renderAutopsyJobHTML({ status: 'done', message: res.message, source: res.summary.case_dir, summary: res.summary });
      toast(res.message);
    } catch (err) {
      $('#autopsy-case-result').innerHTML = `<div class="audit-result audit-error"><strong>✕ ${esc(err.message)}</strong></div>`;
      toast(err.message, true);
    } finally { setBusy(btn, false); }
  }

  // -------------------------------------------------------------------------
  // THREAT DETECTIONS (Correlation engine + MITRE ATT&CK)
  // -------------------------------------------------------------------------
  function renderDetectionsHTML() {
    if (!detectionsData) return renderLoadingState('Running correlation rules...');
    const d = detectionsData;
    const sev = d.severity_counts || {};
    const level = (d.risk_level || 'None').toLowerCase();
    const list = (d.detections || []).filter(x => activeFilter === 'all' || x.severity === activeFilter);

    const killChain = (d.kill_chain || []).map(k => `
      <div class="kc-step ${k.count ? 'kc-hit' : ''}" title="${esc(k.techniques.join('\n') || 'No detections')}">
        <span class="kc-count">${k.count}</span>
        <span class="kc-name">${esc(k.tactic)}</span>
      </div>`).join('<span class="kc-arrow">›</span>');

    const entities = (d.top_entities || []).map(e => `
      <div class="entity-row">
        <span class="entity-type">${esc(e.type.toUpperCase())}</span>
        <span class="entity-value mono-cell">${esc(e.value)}</span>
        <div class="entity-bar"><div style="width:${e.score}%"></div></div>
        <span class="entity-score">${e.score}</span>
      </div>`).join('') || '<p class="det-muted">No implicated entities.</p>';

    const filters = ['all', 'Critical', 'High', 'Medium'].map(f => `
      <button class="det-filter ${activeFilter === f ? 'active' : ''}" data-det-filter="${f}">
        ${f === 'all' ? `All (${d.total})` : `${f} (${sev[f] || 0})`}
      </button>`).join('');

    const cards = list.map(x => {
      const ents = Object.entries(x.entities || {}).flatMap(([k, vals]) =>
        vals.slice(0, 5).map(v => `<span class="det-chip"><b>${esc(k.replace(/s$/, ''))}</b> ${esc(v)}</span>`)).join('');
      const mitre = (x.mitre || []).map(m =>
        `<a class="mitre-chip" href="https://attack.mitre.org/techniques/${esc(m.id.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer" title="${esc(m.tactic)}">${esc(m.id)} · ${esc(m.name)}</a>`).join('');
      const evidence = (x.evidence || []).map(e => `
        <tr>
          <td class="mono-cell">${esc(timeOnly(e.event_time))}</td>
          <td>${sourceBadge(e.source)}</td>
          <td>${severityBadge(e.severity)}</td>
          <td>${esc(e.title)}</td>
          <td class="mono-cell">${esc(e.evidence_reference || '—')}</td>
        </tr>`).join('');
      return `
        <article class="det-card det-${esc(x.severity.toLowerCase())} reveal-on-scroll">
          <header class="det-card-head">
            <div>
              <div class="det-meta">
                ${severityBadge(x.severity)}
                <span class="det-rule mono-cell">${esc(x.rule_id)}</span>
                <span class="det-conf">Confidence: ${esc(x.confidence)}</span>
                ${x.is_demo ? '<span class="badge-demo">DEMO</span>' : ''}
              </div>
              <h3>${esc(x.name)}</h3>
            </div>
            <div class="det-window mono-cell">
              ${esc(formatDate(x.first_seen))}<br><small>→ ${esc(timeOnly(x.last_seen))} · ${x.event_count} events</small>
            </div>
          </header>
          <p class="det-summary">${esc(x.summary)}</p>
          <div class="det-chips">${mitre}</div>
          <div class="det-chips">${ents}${(x.sources || []).map(s => sourceBadge(s)).join('')}</div>
          <div class="det-reco"><strong>Recommended action:</strong> ${esc(x.recommendation)}</div>
          <details class="det-evidence">
            <summary>Show triggering evidence (${x.evidence.length}${x.event_count > x.evidence.length ? ' of ' + x.event_count : ''})</summary>
            <div class="table-container"><table class="forensic-table">
              <thead><tr><th>TIME</th><th>SOURCE</th><th>SEVERITY</th><th>EVENT</th><th>REFERENCE</th></tr></thead>
              <tbody>${evidence}</tbody>
            </table></div>
          </details>
        </article>`;
    }).join('');

    const empty = `
      <div class="empty-state reveal-on-scroll" style="padding:48px 20px">
        <div class="empty-icon">✓</div>
        <strong>${d.total ? 'No detections at this severity' : 'No correlated threats in the current evidence'}</strong>
        <p>The engine evaluated ${d.rules_evaluated} correlation rules. Load the multi-source attack scenario to see
           how brute force, discovery, credential dumping and C2 beaconing are linked into one incident.</p>
        <button class="button button-sky button-small" data-action="load-scenario">Load attack scenario</button>
      </div>`;

    return `
      <section class="det-top reveal-on-scroll">
        <div class="risk-gauge risk-${esc(level)}">
          <div class="risk-ring" style="--pct:${d.risk_score}">
            <div><strong>${d.risk_score}</strong><small>RISK / 100</small></div>
          </div>
          <div class="risk-gauge-text">
            <span class="page-eyebrow">OVERALL THREAT POSTURE</span>
            <h2>${esc(d.risk_level)}</h2>
            <p>${d.total} detections from ${d.rules_evaluated} correlation rules.</p>
            <div class="risk-sev-row">
              <span class="sev-critical badge-severity">${sev.Critical || 0} Critical</span>
              <span class="sev-high badge-severity">${sev.High || 0} High</span>
              <span class="sev-medium badge-severity">${sev.Medium || 0} Medium</span>
            </div>
            <button class="button button-secondary button-small" data-action="load-scenario" style="margin-top:12px">⚑ Load attack scenario</button>
          </div>
        </div>
        <div class="panel det-entities">
          <div class="panel-header"><div><div class="panel-title">Most implicated entities</div>
            <div class="panel-subtitle">Users and IPs weighted by severity of the detections they appear in</div></div></div>
          ${entities}
        </div>
      </section>

      <section class="panel reveal-on-scroll" style="margin-bottom:20px">
        <div class="panel-header"><div><div class="panel-title">MITRE ATT&CK kill chain</div>
          <div class="panel-subtitle">Tactics observed, in attack-progression order (hover for techniques)</div></div></div>
        <div class="kill-chain">${killChain}</div>
      </section>

      <div class="det-filter-row">${filters}</div>
      ${list.length ? cards : empty}
      <p class="det-muted" style="margin-top:16px">${esc(d.disclaimer || '')}</p>
    `;
  }

  function renderReportsHTML() {
    if (!reportData) return renderLoadingState('Compiling Investigation Report...');

    const total = reportData.total_events || 0;
    const imported = reportData.imported_records || 0;
    const demo = reportData.demo_records || 0;
    const sev = reportData.severity_summary || {};
    const src = reportData.sources_summary || {};
    const priority = reportData.priority_findings || [];
    const notes = (reportData.investigation_notes || []).map(n => `<li>${esc(n)}</li>`).join('');
    const recs = (reportData.recommendations || []).map(r => `<li>${esc(r)}</li>`).join('');

    const priorityRows = priority.length ? priority.map(e => `
      <tr>
        <td class="mono-cell">${esc(formatDate(e.event_time))}</td>
        <td class="table-title-cell">
          <strong>${esc(e.title)}</strong>
          <span>${esc(e.details || '—')}</span>
        </td>
        <td>${sourceBadge(e.source)}</td>
        <td>${severityBadge(e.severity)}</td>
        <td class="mono-cell">${esc(e.evidence_reference || '—')}</td>
      </tr>
    `).join('') : `<tr><td colspan="5"><div class="empty-state"><strong>No critical/high observations</strong><p>High priority items will appear here.</p></div></td></tr>`;

    return `
      <div class="report-paper reveal-on-scroll">
        <div class="report-doc-header">
          <div class="report-doc-title">
            <span class="page-eyebrow">FORMAL FORENSIC RECORD</span>
            <h2>${esc(reportData.report_title || 'SecureScan Digital Forensics Investigation Report')}</h2>
            <p>Authoritative case summary generated from SQLite evidence database (instance/securescan.db)</p>
          </div>
          <div class="report-doc-meta">
            <div><strong>Generated:</strong> ${esc(formatDate(reportData.generated_at))}</div>
            <div><strong>Classification:</strong> Official Academic Prototype</div>
          </div>
        </div>

        <div style="display:flex;gap:12px;margin-bottom:28px;">
          <button class="button button-sky" id="print-report"><span>⎙</span> Print / Save PDF</button>
          <a href="/api/reports/export.csv" class="button button-secondary" download><span>↓</span> Export Evidence CSV</a>
        </div>

        <!-- EXECUTIVE SUMMARY STATS -->
        <div class="report-section">
          <h3>1. Executive Summary & Evidence Ingest Totals</h3>
          <div class="intelligence-grid" style="margin-top:14px;">
            <div class="stat-card">
              <div class="stat-label">Total Records</div>
              <div class="stat-value" data-counter="${total}">${total}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Real Ingested</div>
              <div class="stat-value" data-counter="${imported}">${imported}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Demo Synthetic</div>
              <div class="stat-value" data-counter="${demo}">${demo}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">High / Critical Leads</div>
              <div class="stat-value" data-counter="${(sev.Critical || 0) + (sev.High || 0)}">${(sev.Critical || 0) + (sev.High || 0)}</div>
            </div>
          </div>
        </div>

        <!-- PRIORITY FINDINGS -->
        <div class="report-section">
          <h3>2. High & Critical Priority Investigative Leads</h3>
          <div class="table-container" style="border:1px solid var(--border-light);border-radius:var(--radius-md);">
            <table class="forensic-table">
              <thead>
                <tr>
                  <th>TIMESTAMP</th>
                  <th>OBSERVATION & CONTEXT</th>
                  <th>SOURCE</th>
                  <th>SEVERITY</th>
                  <th>REFERENCE</th>
                </tr>
              </thead>
              <tbody>${priorityRows}</tbody>
            </table>
          </div>
        </div>

        <!-- CORRELATED DETECTIONS -->
        <div class="report-section">
          <h3>3. Correlated Detections & MITRE ATT&CK Mapping (Risk ${reportData.risk_score ?? 0}/100 · ${esc(reportData.risk_level || 'None')})</h3>
          <div class="table-container" style="border:1px solid var(--border-light);border-radius:var(--radius-md);">
            <table class="forensic-table">
              <thead><tr><th>RULE</th><th>DETECTION</th><th>ATT&CK</th><th>SEVERITY</th><th>WINDOW</th></tr></thead>
              <tbody>${(reportData.detections || []).length ? reportData.detections.map(x => `
                <tr>
                  <td class="mono-cell">${esc(x.rule_id)}</td>
                  <td class="table-title-cell"><strong>${esc(x.name)}</strong><span>${esc(x.summary)}</span></td>
                  <td class="mono-cell">${(x.mitre || []).map(m => esc(m.id)).join('<br>')}</td>
                  <td>${severityBadge(x.severity)}</td>
                  <td class="mono-cell">${esc(formatDate(x.first_seen))}</td>
                </tr>`).join('') : `<tr><td colspan="5"><div class="empty-state"><strong>No correlated detections</strong><p>The correlation engine found no multi-event attack patterns.</p></div></td></tr>`}
              </tbody>
            </table>
          </div>
        </div>

        <!-- INVESTIGATION GUIDELINES & RECOMMENDATIONS -->
        <div class="report-section">
          <h3>4. Forensic Standards & Chain of Custody</h3>
          <ul>${notes}</ul>
        </div>

        <div class="report-section">
          <h3>5. Investigative Recommendations</h3>
          <ul>${recs}</ul>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // 9. SETTINGS & SYSTEM HEALTH
  // -------------------------------------------------------------------------
  function renderSettingsHTML() {
    const health = systemHealth || {};
    const tshark = networkStats?.tshark || {};

    const historyRows = sessionImportHistory.length ? sessionImportHistory.map(h => `
      <tr>
        <td class="mono-cell">${esc(timeOnly(h.time))}</td>
        <td><strong>${esc(h.filename)}</strong></td>
        <td><span class="badge-source">${esc(h.targetModule)}</span></td>
        <td><span class="badge-severity sev-low">${esc(h.status)}</span></td>
        <td class="mono-cell">${esc(h.records)} records</td>
      </tr>
    `).join('') : `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:14px;">No files uploaded in this session yet.</td></tr>`;

    return `
      <section style="margin-bottom:24px;" class="reveal-on-scroll">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
          <div>
            <h2 style="font-family:var(--font-display);font-size:16px;font-weight:800;color:var(--deep-navy);">System Diagnostics & Health</h2>
            <p style="font-size:11.5px;color:var(--text-muted)">Real-time status of local backend APIs, database connections, and packet dissectors</p>
          </div>
          <button class="button button-sky button-small" id="recheck-health-btn">Re-Check System Health</button>
        </div>

        <div class="diagnostics-grid">
          <div class="diag-card">
            <div>
              <div class="diag-card-top">
                <span class="diag-card-title">Python Flask Backend</span>
                <span class="diag-status-badge ${health.status === 'ok' ? 'diag-status-ok' : 'diag-status-err'}">${health.status === 'ok' ? 'ACTIVE' : 'OFFLINE'}</span>
              </div>
              <p class="diag-card-body">Serving REST API endpoints at <code>http://127.0.0.1:5000</code> with parameterised SQLite operations.</p>
            </div>
            <div class="diag-card-footer">Version: ${esc(health.version || '1.0.0')} | Total DB Events: ${esc(health.total_events ?? '0')}</div>
          </div>

          <div class="diag-card">
            <div>
              <div class="diag-card-top">
                <span class="diag-card-title">SQLite Database</span>
                <span class="diag-status-badge ${health.database === 'connected' ? 'diag-status-ok' : 'diag-status-err'}">${health.database === 'connected' ? 'CONNECTED' : 'DISCONNECTED'}</span>
              </div>
              <p class="diag-card-body">Authoritative storage at <code>instance/securescan.db</code> with indexed tables for rapid timeline querying.</p>
            </div>
            <div class="diag-card-footer">Foreign Keys: Enforced | Path: ${esc(health.database_path || 'securescan.db')}</div>
          </div>

          <div class="diag-card">
            <div>
              <div class="diag-card-top">
                <span class="diag-card-title">TShark Packet Dissector</span>
                <span class="diag-status-badge ${tshark.available ? 'diag-status-ok' : 'diag-status-warn'}">${tshark.available ? 'AVAILABLE' : 'NOT DETECTED'}</span>
              </div>
              <p class="diag-card-body">${esc(tshark.install_guide || 'Enables direct PCAP and PCAPNG ingestion without manual CSV exporting.')}</p>
            </div>
            <div class="diag-card-footer">Path: ${esc(tshark.path || 'Not in PATH')}</div>
          </div>

          <div class="diag-card">
            <div>
              <div class="diag-card-top">
                <span class="diag-card-title">Windows Event Collector</span>
                <span class="diag-status-badge diag-status-ok">READY</span>
              </div>
              <p class="diag-card-body">PowerShell collector script at <code>collectors/windows_event_collector.ps1</code>. Collects Security IDs 4624, 4625, 4688, 4720, 4726, 4672.</p>
            </div>
            <div class="diag-card-footer">Requires Administrator or Event Log Readers group</div>
          </div>

          <div class="diag-card">
            <div>
              <div class="diag-card-top">
                <span class="diag-card-title">Microsoft Sysmon Collector</span>
                <span class="diag-status-badge diag-status-ok">READY</span>
              </div>
              <p class="diag-card-body">Sysmon operational collector script at <code>collectors/sysmon_collector.ps1</code>. Supports Event IDs 1, 3, 11, and 22 with XML extraction.</p>
            </div>
            <div class="diag-card-footer">Config: config/sysmon-config.xml (Schema 4.91)</div>
          </div>

          <div class="diag-card">
            <div>
              <div class="diag-card-top">
                <span class="diag-card-title">Autopsy CSV Dissector</span>
                <span class="diag-status-badge diag-status-ok">ACTIVE</span>
              </div>
              <p class="diag-card-body">Ingests file search, deleted file records, browser history, and credential artefact CSV reports from Autopsy examinations.</p>
            </div>
            <div class="diag-card-footer">Engine: parser_autopsy.py</div>
          </div>
        </div>
      </section>

      <!-- SESSION IMPORT HISTORY -->
      <section class="panel reveal-on-scroll" style="margin-bottom:24px;">
        <div class="panel-header">
          <div>
            <div class="panel-title">Session Ingest Log & Upload History</div>
            <div class="panel-subtitle">Tracks evidentiary files processed during this active browser session</div>
          </div>
          <span class="badge-source">${sessionImportHistory.length} uploads logged</span>
        </div>
        <div class="table-container">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>TIME</th>
                <th>FILENAME</th>
                <th>TARGET ENGINE</th>
                <th>STATUS</th>
                <th>INGESTED</th>
              </tr>
            </thead>
            <tbody>${historyRows}</tbody>
          </table>
        </div>
      </section>

      <!-- MAINTENANCE ACTIONS -->
      <section class="panel reveal-on-scroll">
        <div class="panel-header">
          <div>
            <div class="panel-title">Prototype Evaluation & Demo Data Management</div>
            <div class="panel-subtitle">Generate or purge clearly labeled synthetic records without affecting real evidence</div>
          </div>
        </div>
        <div style="padding:22px;display:flex;gap:14px;align-items:center;flex-wrap:wrap;">
          <button class="button button-sky" id="settings-generate-demo"><span>＋</span> Generate Demo Evidence Pack</button>
          <button class="button button-danger" id="settings-clear-demo">Clear Demo Records Only</button>
        </div>
      </section>
    `;
  }

  // =========================================================================
  // INTERACTIVE GRAPH ENGINE (SVG Topology)
  // =========================================================================
  function initGraphCanvas() {
    const svg = $('#graph-svg');
    const container = $('#graph-container');
    if (!svg || !container) return;

    const data = currentGraphData || { nodes: [], edges: [] };
    const rawNodes = data.nodes || [];
    const edges = data.edges || [];

    // Dropdown toggle
    const exportBtn = $('#export-exhibit-btn');
    const exportMenu = $('#export-menu');
    if (exportBtn && exportMenu) {
      exportBtn.onclick = (e) => {
        e.stopPropagation();
        exportMenu.classList.toggle('show');
      };
      document.addEventListener('click', () => {
        exportMenu.classList.remove('show');
      });
    }

    if (!rawNodes.length) {
      const emptyState = $('#graph-empty-state');
      if (emptyState) emptyState.style.display = 'flex';
      svg.innerHTML = `
        <defs>
          <radialGradient id="graph-bg-grad" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#F2FDFF" stop-opacity="0.8"/>
            <stop offset="100%" stop-color="#FFFFFF" stop-opacity="1"/>
          </radialGradient>
        </defs>
        <rect width="900" height="560" fill="url(#graph-bg-grad)"/>
      `;
      $('#export-svg-btn')?.addEventListener('click', () => toast('No evidence records to export. Ingest logs first.', true));
      $('#export-png-btn')?.addEventListener('click', () => toast('No evidence records to export. Ingest logs first.', true));
      return;
    }

    const cx = 450;
    const cy = 280;
    const radius = Math.min(cx - 70, cy - 60);

    const typeColors = {
      user: '#7BB8FF',
      process: '#050F2A',
      network: '#0284c7',
      dns: '#B8A0FF',
      file: '#E11D48'
    };

    const typeIcons = {
      user: '👤',
      process: '⚙',
      network: '⇄',
      dns: '🌐',
      file: '📄'
    };

    // Calculate initial positions with deterministic spread
    const positionedNodes = rawNodes.map((node, i) => {
      const angle = (i / rawNodes.length) * 2 * Math.PI - Math.PI / 2;
      const r = radius * (0.65 + (i % 3) * 0.15);
      const x = Math.round(cx + r * Math.cos(angle));
      const y = Math.round(cy + r * Math.sin(angle));
      return {
        ...node,
        x,
        y,
        defaultX: x,
        defaultY: y
      };
    });

    const nodeMap = new Map(positionedNodes.map(n => [n.id, n]));

    let zoomLevel = 1;
    let panX = 0;
    let panY = 0;
    let selectedNodeId = null;
    let activeFilter = 'all';
    let searchQuery = '';

    // Drag state
    let isDraggingNode = false;
    let dragNode = null;
    let isPanning = false;
    let startPointerX = 0;
    let startPointerY = 0;
    let startPanX = 0;
    let startPanY = 0;

    function isNeighbor(id1, id2) {
      return edges.some(e => (e.source === id1 && e.target === id2) || (e.source === id2 && e.target === id1));
    }

    function updateTransform() {
      const transformGroup = svg.querySelector('#graph-transform-group');
      if (transformGroup) {
        transformGroup.setAttribute('transform', `translate(${panX}, ${panY}) scale(${zoomLevel})`);
      }
    }

    function getLocalCoords(clientX, clientY) {
      const pt = svg.createSVGPoint();
      pt.x = clientX;
      pt.y = clientY;
      const transformGroup = svg.querySelector('#graph-transform-group');
      if (!transformGroup) return { x: 450, y: 280 };
      const groupCTM = transformGroup.getScreenCTM();
      if (!groupCTM) return { x: (clientX - panX) / zoomLevel, y: (clientY - panY) / zoomLevel };
      const localPt = pt.matrixTransform(groupCTM.inverse());
      return { x: localPt.x, y: localPt.y };
    }

    function renderScene(filterType = 'all', searchQ = '', selNodeId = null) {
      activeFilter = filterType;
      searchQuery = searchQ;
      selectedNodeId = selNodeId;
      const q = searchQuery.toLowerCase().trim();

      const edgesHTML = edges.map(edge => {
        const src = nodeMap.get(edge.source);
        const tgt = nodeMap.get(edge.target);
        if (!src || !tgt) return '';

        const isConnected = selectedNodeId && (src.id === selectedNodeId || tgt.id === selectedNodeId);
        const strokeCol = isConnected ? '#7BB8FF' : '#CBD5E1';
        const strokeW = isConnected ? 2.5 : 1.3;
        const opacity = selectedNodeId ? (isConnected ? 1 : 0.15) : 0.75;
        const midX = (src.x + tgt.x) / 2;
        const midY = (src.y + tgt.y) / 2;

        return `
          <g class="graph-edge ${isConnected ? 'is-connected' : (selectedNodeId ? 'is-dimmed' : '')}" id="edge-${esc(edge.id)}" data-edge-id="${esc(edge.id)}" style="opacity:${opacity};">
            <line class="edge-line" x1="${src.x}" y1="${src.y}" x2="${tgt.x}" y2="${tgt.y}" stroke="${strokeCol}" stroke-width="${strokeW}" marker-end="url(#arrow)" />
            ${isConnected ? `
              <g class="edge-tag" transform="translate(${midX}, ${midY})">
                <rect x="-30" y="-9" width="60" height="18" rx="4" fill="#050F2A" stroke="#7BB8FF" stroke-width="0.8"/>
                <text y="3" text-anchor="middle" fill="#7BB8FF" font-size="9" font-family="var(--font-mono)" font-weight="600">${esc(edge.relation)}</text>
              </g>
            ` : ''}
          </g>
        `;
      }).join('');

      const nodesHTML = positionedNodes.map(node => {
        const matchesFilter = activeFilter === 'all' || node.type === activeFilter;
        const matchesSearch = !q || node.label.toLowerCase().includes(q) || node.type.toLowerCase().includes(q);
        const isSelected = selectedNodeId === node.id;
        const isDimmed = (activeFilter !== 'all' && !matchesFilter) || (q && !matchesSearch) || (selectedNodeId && !isSelected && !isNeighbor(selectedNodeId, node.id));

        const baseColor = typeColors[node.type] || '#64748B';
        const icon = typeIcons[node.type] || '•';
        const r = isSelected ? 24 : 18;

        return `
          <g class="graph-node ${isSelected ? 'is-selected' : ''}" id="node-${esc(node.id)}" data-node-id="${esc(node.id)}" transform="translate(${node.x}, ${node.y})" style="opacity:${isDimmed ? 0.18 : 1};">
            <circle class="node-halo" r="${r + 7}" />
            <circle class="node-base" r="${r}" fill="#FFFFFF" stroke="${isSelected ? 'var(--sky-blue)' : baseColor}" stroke-width="${isSelected ? 3.5 : 2}" />
            <circle class="node-tint" r="${r - 4}" fill="${baseColor}" opacity="0.14" />
            <text class="node-icon" y="4" text-anchor="middle" font-size="${isSelected ? 14 : 11}" fill="${baseColor}">${icon}</text>
            <text class="node-label" y="${r + 14}" text-anchor="middle" font-family="var(--font-mono)" font-size="10" font-weight="${isSelected ? 700 : 600}" fill="var(--deep-navy)">
              ${esc(node.label.length > 22 ? node.label.slice(0, 20) + '…' : node.label)}
            </text>
          </g>
        `;
      }).join('');

      svg.innerHTML = `
        <defs>
          <radialGradient id="graph-bg-grad" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#F2FDFF" stop-opacity="0.8"/>
            <stop offset="100%" stop-color="#FFFFFF" stop-opacity="1"/>
          </radialGradient>
          <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#7BB8FF" />
          </marker>
        </defs>
        <rect id="graph-canvas-bg" width="900" height="560" fill="url(#graph-bg-grad)"/>
        <g id="graph-transform-group" transform="translate(${panX}, ${panY}) scale(${zoomLevel})">
          <g id="edges-group">${edgesHTML}</g>
          <g id="nodes-group">${nodesHTML}</g>
        </g>
      `;

      // Attach pointer events to each node for dragging and selection
      svg.querySelectorAll('.graph-node').forEach(g => {
        g.addEventListener('pointerdown', (e) => {
          e.stopPropagation();
          e.preventDefault();
          const nodeId = g.dataset.nodeId;
          const node = nodeMap.get(nodeId);
          if (!node) return;

          isDraggingNode = true;
          dragNode = node;
          startPointerX = e.clientX;
          startPointerY = e.clientY;

          container.classList.add('is-dragging');
          g.classList.add('is-dragging');
          try { container.setPointerCapture(e.pointerId); } catch {}

          if (selectedNodeId !== nodeId) {
            selectNode(nodeId);
          }
        });
      });
    }

    function selectNode(nodeId) {
      if (!nodeId) {
        selectedNodeId = null;
        renderScene(activeFilter, searchQuery, null);
        const inspectorName = $('#inspector-name');
        const inspectorType = $('#inspector-type');
        const inspectorCount = $('#inspector-count');
        const inspectorDesc = $('#inspector-desc');
        const inspectorRelations = $('#inspector-relations');
        const inspectorActions = $('#inspector-actions');
        if (inspectorName) inspectorName.textContent = 'No Entity Selected';
        if (inspectorType) inspectorType.textContent = 'ENTITY INSPECTOR';
        if (inspectorCount) inspectorCount.textContent = 'Click or drag node to inspect';
        if (inspectorDesc) inspectorDesc.textContent = 'Click or drag any node in the topology above to examine its evidence relationships, connected processes, and linked database events.';
        if (inspectorRelations) inspectorRelations.innerHTML = '';
        if (inspectorActions) inspectorActions.style.display = 'none';
        return;
      }

      const node = nodeMap.get(nodeId);
      if (!node) return;

      renderScene(activeFilter, searchQuery, nodeId);

      const inspectorName = $('#inspector-name');
      const inspectorType = $('#inspector-type');
      const inspectorCount = $('#inspector-count');
      const inspectorDesc = $('#inspector-desc');
      const inspectorRelations = $('#inspector-relations');
      const inspectorActions = $('#inspector-actions');

      if (inspectorName) inspectorName.textContent = node.label;
      if (inspectorType) inspectorType.textContent = `${node.type.toUpperCase()} ARTEFACT`;
      if (inspectorCount) inspectorCount.innerHTML = `<span class="severity ${severityClass(node.max_severity || 'Low')}">${esc(node.max_severity || 'Low')}</span>`;

      const connectedEdges = edges.filter(e => e.source === nodeId || e.target === nodeId);
      if (inspectorDesc) {
        inspectorDesc.textContent = `Identified in SQLite evidence records across ${connectedEdges.length} distinct correlation links.`;
      }

      if (inspectorRelations) {
        if (!connectedEdges.length) {
          inspectorRelations.innerHTML = '<span style="color:var(--text-muted);font-style:italic;">No direct connected entities recorded in SQLite.</span>';
        } else {
          inspectorRelations.innerHTML = `
            <div style="font-weight:700;color:var(--deep-navy);margin-bottom:6px;">Connected Linkages (${connectedEdges.length}):</div>
            <ul style="padding-left:16px;display:flex;flex-direction:column;gap:6px;">
              ${connectedEdges.map(e => {
                const otherId = e.source === nodeId ? e.target : e.source;
                const other = nodeMap.get(otherId);
                const otherLabel = other ? other.label : otherId;
                const otherType = other ? other.type : 'artefact';
                const reason = e.reason || e.events?.[0]?.details || `${node.label} ${e.relation} ${otherLabel}`;
                return `
                  <li style="line-height:1.4;">
                    <div style="display:flex;align-items:center;gap:6px;">
                      <span class="badge-source" style="font-size:10px;padding:2px 6px;">${esc(e.relation)}</span>
                      <strong style="color:var(--deep-navy);">${esc(otherLabel)}</strong>
                      <span style="font-size:10px;color:var(--text-muted);">(${esc(otherType)})</span>
                    </div>
                    <div style="font-size:11px;color:var(--text-secondary);margin-top:2px;">${esc(reason)}</div>
                  </li>
                `;
              }).join('')}
            </ul>
          `;
        }
      }

      if (inspectorActions) {
        inspectorActions.style.display = 'flex';
        const timelineBtn = $('#inspector-timeline-btn');
        if (timelineBtn) {
          timelineBtn.onclick = () => {
            activeSearch = node.label;
            setPage('timeline');
          };
        }
        const deselectBtn = $('#inspector-deselect-btn');
        if (deselectBtn) {
          deselectBtn.onclick = () => selectNode(null);
        }
      }
    }

    // Panning & Dragging event handlers on container
    container.addEventListener('pointerdown', (e) => {
      // Background click
      if (e.target.id === 'graph-canvas-bg' || e.target === svg || e.target === container) {
        isPanning = true;
        startPointerX = e.clientX;
        startPointerY = e.clientY;
        startPanX = panX;
        startPanY = panY;
        container.classList.add('is-panning');
        try { container.setPointerCapture(e.pointerId); } catch {}
      }
    });

    container.addEventListener('pointermove', (e) => {
      if (isDraggingNode && dragNode) {
        const pt = getLocalCoords(e.clientX, e.clientY);
        dragNode.x = Math.max(30, Math.min(870, Math.round(pt.x)));
        dragNode.y = Math.max(30, Math.min(530, Math.round(pt.y)));

        // Update node position
        const nodeEl = svg.querySelector(`#node-${CSS.escape(dragNode.id)}`);
        if (nodeEl) {
          nodeEl.setAttribute('transform', `translate(${dragNode.x}, ${dragNode.y})`);
        }

        // Update connected edges
        edges.forEach(edge => {
          if (edge.source === dragNode.id || edge.target === dragNode.id) {
            const edgeEl = svg.querySelector(`#edge-${CSS.escape(edge.id)}`);
            if (edgeEl) {
              const src = nodeMap.get(edge.source);
              const tgt = nodeMap.get(edge.target);
              if (src && tgt) {
                const line = edgeEl.querySelector('line');
                if (line) {
                  line.setAttribute('x1', src.x);
                  line.setAttribute('y1', src.y);
                  line.setAttribute('x2', tgt.x);
                  line.setAttribute('y2', tgt.y);
                }
                const tag = edgeEl.querySelector('.edge-tag');
                if (tag) {
                  tag.setAttribute('transform', `translate(${(src.x + tgt.x) / 2}, ${(src.y + tgt.y) / 2})`);
                }
              }
            }
          }
        });
      } else if (isPanning) {
        panX = startPanX + (e.clientX - startPointerX);
        panY = startPanY + (e.clientY - startPointerY);
        updateTransform();
      }
    });

    const endDragOrPan = (e) => {
      if (isDraggingNode) {
        isDraggingNode = false;
        dragNode = null;
        container.classList.remove('is-dragging');
        svg.querySelectorAll('.graph-node.is-dragging').forEach(n => n.classList.remove('is-dragging'));
        try { container.releasePointerCapture(e.pointerId); } catch {}
      }
      if (isPanning) {
        isPanning = false;
        container.classList.remove('is-panning');
        try { container.releasePointerCapture(e.pointerId); } catch {}
      }
    };

    container.addEventListener('pointerup', endDragOrPan);
    container.addEventListener('pointercancel', endDragOrPan);

    // Mouse wheel zoom
    container.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
      const newZoom = Math.min(2.5, Math.max(0.4, zoomLevel * zoomFactor));
      if (newZoom !== zoomLevel) {
        const rect = container.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;
        panX = mouseX - (mouseX - panX) * (newZoom / zoomLevel);
        panY = mouseY - (mouseY - panY) * (newZoom / zoomLevel);
        zoomLevel = newZoom;
        updateTransform();
      }
    }, { passive: false });

    // Fit to Screen
    function fitToScreen() {
      if (!positionedNodes.length) return;
      const pad = 65;
      const minX = Math.min(...positionedNodes.map(n => n.x));
      const maxX = Math.max(...positionedNodes.map(n => n.x));
      const minY = Math.min(...positionedNodes.map(n => n.y));
      const maxY = Math.max(...positionedNodes.map(n => n.y));

      const spanX = Math.max(100, maxX - minX + pad * 2);
      const spanY = Math.max(100, maxY - minY + pad * 2);

      const scaleX = 900 / spanX;
      const scaleY = 560 / spanY;
      zoomLevel = Math.min(1.7, Math.max(0.45, Math.min(scaleX, scaleY)));

      const midX = (minX + maxX) / 2;
      const midY = (minY + maxY) / 2;

      panX = Math.round((900 / 2) - (midX * zoomLevel));
      panY = Math.round((560 / 2) - (midY * zoomLevel));

      updateTransform();
      toast('Graph fitted to viewport');
    }

    // Reset Layout
    function resetLayout() {
      positionedNodes.forEach(n => {
        n.x = n.defaultX;
        n.y = n.defaultY;
      });
      zoomLevel = 1;
      panX = 0;
      panY = 0;
      renderScene(activeFilter, searchQuery, selectedNodeId);
      toast('Node positions and viewport reset');
    }

    // Generate Standalone Exhibit SVG (White background, Title, Timestamp, Integrity Notice)
    function generateExhibitSVG() {
      const nowStr = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
      const exportWidth = 1200;
      const exportHeight = 820;

      // Fit nodes nicely into 1100x600 canvas area inside 1200x820 document
      const minX = Math.min(...positionedNodes.map(n => n.x));
      const maxX = Math.max(...positionedNodes.map(n => n.x));
      const minY = Math.min(...positionedNodes.map(n => n.y));
      const maxY = Math.max(...positionedNodes.map(n => n.y));

      const spanX = Math.max(100, maxX - minX + 80);
      const spanY = Math.max(100, maxY - minY + 80);
      const s = Math.min(1.3, Math.min(1080 / spanX, 580 / spanY));

      const centerX = (minX + maxX) / 2;
      const centerY = (minY + maxY) / 2;
      const tx = 600 - (centerX * s);
      const ty = 430 - (centerY * s);

      const edgesSVG = edges.map(edge => {
        const src = nodeMap.get(edge.source);
        const tgt = nodeMap.get(edge.target);
        if (!src || !tgt) return '';
        const x1 = Math.round(src.x * s + tx);
        const y1 = Math.round(src.y * s + ty);
        const x2 = Math.round(tgt.x * s + tx);
        const y2 = Math.round(tgt.y * s + ty);
        const mx = Math.round((x1 + x2) / 2);
        const my = Math.round((y1 + y2) / 2);
        return `
          <g>
            <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#7BB8FF" stroke-width="2" marker-end="url(#exhibit-arrow)"/>
            <g transform="translate(${mx}, ${my})">
              <rect x="-32" y="-10" width="64" height="20" rx="4" fill="#050F2A"/>
              <text y="4" text-anchor="middle" fill="#7BB8FF" font-size="10" font-family="'JetBrains Mono', monospace" font-weight="bold">${esc(edge.relation)}</text>
            </g>
          </g>
        `;
      }).join('');

      const nodesSVG = positionedNodes.map(node => {
        const x = Math.round(node.x * s + tx);
        const y = Math.round(node.y * s + ty);
        const baseColor = typeColors[node.type] || '#050F2A';
        const icon = typeIcons[node.type] || '•';
        return `
          <g transform="translate(${x}, ${y})">
            <circle r="22" fill="#FFFFFF" stroke="${baseColor}" stroke-width="3" />
            <circle r="18" fill="${baseColor}" opacity="0.12" />
            <text y="5" text-anchor="middle" font-size="13" fill="${baseColor}">${icon}</text>
            <text y="36" text-anchor="middle" font-family="'Plus Jakarta Sans', Arial, sans-serif" font-size="11" font-weight="bold" fill="#050F2A">${esc(node.label)}</text>
            <text y="48" text-anchor="middle" font-family="'JetBrains Mono', monospace" font-size="9" fill="#64748B">${esc(node.type.toUpperCase())}</text>
          </g>
        `;
      }).join('');

      return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${exportWidth} ${exportHeight}" width="${exportWidth}" height="${exportHeight}">
  <defs>
    <style>
      text { font-family: 'Plus Jakarta Sans', system-ui, -apple-system, Arial, sans-serif; }
      .mono { font-family: 'JetBrains Mono', 'Courier New', monospace; }
    </style>
    <marker id="exhibit-arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#7BB8FF" />
    </marker>
  </defs>

  <!-- Solid White Background -->
  <rect width="${exportWidth}" height="${exportHeight}" fill="#FFFFFF"/>

  <!-- Forensic Header -->
  <rect x="0" y="0" width="${exportWidth}" height="84" fill="#050F2A"/>
  <rect x="0" y="80" width="${exportWidth}" height="4" fill="#7BB8FF"/>
  <text x="32" y="32" fill="#7BB8FF" font-size="11" font-weight="bold" letter-spacing="1.5">SECURESCAN DIGITAL FORENSIC PLATFORM</text>
  <text x="32" y="60" fill="#FFFFFF" font-size="20" font-weight="bold">Case Evidence Exhibit — Entity Correlation Topology</text>
  <text x="${exportWidth - 32}" y="36" text-anchor="end" fill="#94A3B8" font-size="11" class="mono">Generated: ${nowStr}</text>
  <text x="${exportWidth - 32}" y="56" text-anchor="end" fill="#7BB8FF" font-size="11" class="mono">SQLite Database Integrity Verified</text>

  <!-- Topology Graph Content -->
  <g id="exhibit-graph">
    ${edgesSVG}
    ${nodesSVG}
  </g>

  <!-- Forensic Footer -->
  <rect x="0" y="${exportHeight - 64}" width="${exportWidth}" height="64" fill="#F8FAFC" stroke="#E2E8F0" stroke-width="1"/>
  <text x="32" y="${exportHeight - 38}" fill="#0F172A" font-size="11" font-weight="bold">EVIDENCE INTEGRITY NOTICE:</text>
  <text x="32" y="${exportHeight - 22}" fill="#64748B" font-size="10.5">Topological connections represent recorded events in SQLite database. Correlation does not imply or prove malicious activity.</text>
  <text x="${exportWidth - 32}" y="${exportHeight - 30}" text-anchor="end" fill="#050F2A" font-size="11" font-weight="bold">Entities: ${positionedNodes.length} • Relationships: ${edges.length} • Exhibit v2.5</text>
</svg>`;
    }

    // Export SVG
    function exportSVG() {
      if (!positionedNodes.length) {
        toast('No evidence entities to export', true);
        return;
      }
      const svgStr = generateExhibitSVG();
      const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securescan-evidence-exhibit-${Date.now()}.svg`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast('Evidence exhibit exported as SVG (.svg)');
      addNotification('Evidence Exhibit Exported', 'Downloaded SVG topology exhibit.', 'info');
    }

    // Export PNG
    function exportPNG() {
      if (!positionedNodes.length) {
        toast('No evidence entities to export', true);
        return;
      }
      const svgStr = generateExhibitSVG();
      const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const img = new Image();

      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = 1200;
        canvas.height = 820;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#FFFFFF';
        ctx.fillRect(0, 0, 1200, 820);
        ctx.drawImage(img, 0, 0, 1200, 820);
        URL.revokeObjectURL(url);

        canvas.toBlob((pngBlob) => {
          if (!pngBlob) {
            toast('Failed to create PNG image', true);
            return;
          }
          const pngUrl = URL.createObjectURL(pngBlob);
          const a = document.createElement('a');
          a.href = pngUrl;
          a.download = `securescan-evidence-exhibit-${Date.now()}.png`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(pngUrl);
          toast('Evidence exhibit exported as PNG (.png)');
          addNotification('Evidence Exhibit Exported', 'Downloaded PNG topology exhibit.', 'info');
        }, 'image/png');
      };

      img.onerror = () => {
        URL.revokeObjectURL(url);
        toast('Could not render PNG from SVG vector', true);
      };

      img.src = url;
    }

    // Wire up buttons
    $('#reset-layout-btn')?.addEventListener('click', resetLayout);
    $('#fit-screen-btn')?.addEventListener('click', fitToScreen);
    $('#graph-zoom-reset')?.addEventListener('click', resetLayout);
    $('#graph-zoom-fit')?.addEventListener('click', fitToScreen);

    $('#export-svg-btn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      exportMenu?.classList.remove('show');
      exportSVG();
    });

    $('#export-png-btn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      exportMenu?.classList.remove('show');
      exportPNG();
    });

    $('#graph-zoom-in')?.addEventListener('click', () => {
      zoomLevel = Math.min(2.5, Math.round((zoomLevel + 0.25) * 100) / 100);
      updateTransform();
    });

    $('#graph-zoom-out')?.addEventListener('click', () => {
      zoomLevel = Math.max(0.4, Math.round((zoomLevel - 0.25) * 100) / 100);
      updateTransform();
    });

    $$('[data-graph-filter]').forEach(btn => {
      btn.addEventListener('click', () => {
        $$('[data-graph-filter]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const filter = btn.dataset.graphFilter;
        renderScene(filter, $('#graph-search')?.value || '', selectedNodeId);
      });
    });

    $('#graph-search')?.addEventListener('input', (e) => {
      renderScene(activeFilter, e.target.value, selectedNodeId);
    });

    // Initial render
    renderScene('all', '', null);
  }

  // =========================================================================
  // INTERACTIVE EVENT INSPECTION MODAL
  // =========================================================================
  function showEventInspectionModal(event) {
    if (!event) return;
    const modalRoot = $('#modal-root');
    if (!modalRoot) return;

    let payloadFormatted = '';
    try {
      if (event.raw_payload) {
        const parsed = JSON.parse(event.raw_payload);
        payloadFormatted = JSON.stringify(parsed, null, 2);
      }
    } catch {
      payloadFormatted = String(event.raw_payload || 'No raw payload stored.');
    }

    modalRoot.innerHTML = `
      <div class="modal-backdrop" id="event-modal-backdrop">
        <div class="modal-dialog" role="dialog" aria-modal="true">
          <div class="modal-header">
            <div>
              <span class="page-eyebrow">${esc(event.source || 'EVIDENCE')} OBSERVATION</span>
              <h3 style="margin-top:4px;">${esc(event.title || 'Event Details')}</h3>
            </div>
            <button class="icon-button" id="close-modal-btn" aria-label="Close dialog">✕</button>
          </div>

          <div class="modal-body">
            <div style="display:flex;gap:8px;margin-bottom:18px;align-items:center;">
              ${severityBadge(event.severity)}
              ${sourceBadge(event.source)}
              <span class="badge-source">Category: ${esc(event.category || 'General')}</span>
              ${event.is_demo ? '<span class="badge-demo">DEMO SYNTHETIC</span>' : ''}
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px;background:var(--surface-alt);padding:14px;border-radius:var(--radius-md);border:1px solid var(--border-light);">
              <div>
                <small style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">Timestamp (UTC)</small>
                <div class="mono-cell" style="font-weight:700;">${esc(formatDate(event.event_time))}</div>
              </div>
              <div>
                <small style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">Evidence Reference</small>
                <div class="mono-cell" style="font-weight:700;">${esc(event.evidence_reference || 'N/A')}</div>
              </div>
              <div>
                <small style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">Source Endpoint / IP</small>
                <div class="mono-cell">${esc(event.source_ip || 'Local / System')}</div>
              </div>
              <div>
                <small style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">Destination Endpoint / IP</small>
                <div class="mono-cell">${esc(event.destination_ip || 'N/A')}</div>
              </div>
              <div>
                <small style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">Target User Account</small>
                <div><strong>${esc(event.username || 'N/A')}</strong></div>
              </div>
              <div>
                <small style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">Protocol / Command</small>
                <div class="mono-cell">${esc(event.protocol || event.command || 'N/A')}</div>
              </div>
            </div>

            <div style="margin-bottom:18px;">
              <h4 style="font-size:12px;font-weight:700;color:var(--deep-navy);margin-bottom:6px;">Investigation Narrative & Rule Explanation</h4>
              <p style="font-size:12px;color:var(--text-secondary);line-height:1.5;background:#FFFFFF;padding:12px;border-radius:var(--radius-sm);border:1px solid var(--border-light);">
                ${esc(event.details || 'No additional details provided.')}
              </p>
            </div>

            ${payloadFormatted ? `
              <div>
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                  <h4 style="font-size:12px;font-weight:700;color:var(--deep-navy);">Raw Telemetry Payload</h4>
                  <button class="button button-secondary button-small" id="copy-payload-btn" style="padding:2px 8px;font-size:10px;">Copy Payload</button>
                </div>
                <pre class="payload-pre">${esc(payloadFormatted)}</pre>
              </div>
            ` : ''}
          </div>

          <div class="modal-footer">
            <button class="button button-secondary" id="close-modal-footer-btn">Close</button>
          </div>
        </div>
      </div>
    `;

    const close = () => { modalRoot.innerHTML = ''; };
    $('#close-modal-btn')?.addEventListener('click', close);
    $('#close-modal-footer-btn')?.addEventListener('click', close);
    $('#event-modal-backdrop')?.addEventListener('click', (e) => {
      if (e.target.id === 'event-modal-backdrop') close();
    });
    $('#copy-payload-btn')?.addEventListener('click', () => {
      navigator.clipboard?.writeText(payloadFormatted).then(() => toast('Payload copied to clipboard'));
    });
  }

  function showConfirmModal(title, message, onConfirm) {
    const modalRoot = $('#modal-root');
    if (!modalRoot) return;

    modalRoot.innerHTML = `
      <div class="modal-backdrop" id="confirm-modal-backdrop">
        <div class="modal-dialog" role="dialog" aria-modal="true" style="max-width:440px;">
          <div class="modal-header">
            <h3>${esc(title)}</h3>
            <button class="icon-button" id="close-confirm-btn">✕</button>
          </div>
          <div class="modal-body">
            <p style="font-size:12px;color:var(--text-secondary);line-height:1.6;">${esc(message)}</p>
          </div>
          <div class="modal-footer">
            <button class="button button-secondary" id="cancel-confirm-btn">Cancel</button>
            <button class="button button-danger" id="ok-confirm-btn">Confirm Action</button>
          </div>
        </div>
      </div>
    `;

    const close = () => { modalRoot.innerHTML = ''; };
    $('#close-confirm-btn')?.addEventListener('click', close);
    $('#cancel-confirm-btn')?.addEventListener('click', close);
    $('#ok-confirm-btn')?.addEventListener('click', () => {
      close();
      onConfirm();
    });
  }

  function showAboutModal() {
    const modalRoot = $('#modal-root');
    if (!modalRoot) return;

    modalRoot.innerHTML = `
      <div class="modal-backdrop" id="about-modal-backdrop">
        <div class="modal-dialog" role="dialog" aria-modal="true">
          <div class="modal-header">
            <div>
              <span class="page-eyebrow">ABOUT THE PLATFORM</span>
              <h3 style="margin-top:4px;">SecureScan — Forensic Command Centre</h3>
            </div>
            <button class="icon-button" id="close-about-btn">✕</button>
          </div>
          <div class="modal-body" style="font-size:12px;line-height:1.6;color:var(--text-secondary);">
            <p style="margin-bottom:12px;">
              <strong>SecureScan</strong> is a unified cybersecurity system auditing and digital forensic investigation platform designed to correlate multi-source evidence into a single authoritative workspace.
            </p>
            <div style="background:var(--surface-alt);padding:14px;border-radius:var(--radius-md);border:1px solid var(--border-light);margin-bottom:14px;">
              <strong style="color:var(--deep-navy);display:block;margin-bottom:6px;">Supported Tool Integrations:</strong>
              <ul style="padding-left:18px;">
                <li><strong>Windows 11 Security Log:</strong> Authentication (4624/4625), Privileges (4672), Accounts (4720/4726).</li>
                <li><strong>Microsoft Sysmon:</strong> Process Create (1), Network Connect (3), File Create (11), DNS Queries (22).</li>
                <li><strong>Wireshark & TShark:</strong> Packet dissections, IPv4/IPv6 socket tracing, and direct PCAP/PCAPNG parsing.</li>
                <li><strong>Autopsy:</strong> Digital forensic artefacts, deleted files, web history, and staging paths.</li>
                <li><strong>Linux auditd:</strong> System call monitoring, user logins, and privilege escalation records.</li>
              </ul>
            </div>
            <p>
              <strong>Architecture:</strong> Single-page reactive frontend communicating with a local Python Flask backend (<code>127.0.0.1:5000</code>) backed by parameterised SQLite queries (<code>instance/securescan.db</code>).
            </p>
          </div>
          <div class="modal-footer">
            <button class="button button-sky" id="close-about-footer-btn">Close</button>
          </div>
        </div>
      </div>
    `;

    const close = () => { modalRoot.innerHTML = ''; };
    $('#close-about-btn')?.addEventListener('click', close);
    $('#close-about-footer-btn')?.addEventListener('click', close);
  }

  // =========================================================================
  // DATA CONTROLLER (FETCH & REFRESH)
  // =========================================================================
  async function loadCurrentPage() {
    isLoading = true;
    const content = $('#page-content');
    if (!content) return;

    try {
      // Telemetry refresh
      API.getStats().then(s => {
        dashboardStats = s;
        updateSidebarBadges();
      }).catch(console.warn);

      API.getHealth().then(h => {
        systemHealth = h;
        const text = $('#backend-status-text');
        if (text) text.textContent = h.status === 'ok' ? 'FLASK + SQLITE ACTIVE' : 'DATABASE OFFLINE';
      }).catch(console.warn);

      if (currentPage === 'overview') {
        const [stats, events, net] = await Promise.all([
          API.getStats(),
          API.getEvents({ limit: 12 }),
          API.getNetworkStats().catch(() => null)
        ]);
        dashboardStats = stats;
        currentEvents = events;
        networkStats = net;
        content.innerHTML = renderOverviewHTML();

      } else if (currentPage === 'system') {
        const params = { search: activeSearch, severity: activeFilter, source: 'Windows audit,Linux audit,System audit' };
        if (activeSubfilter !== 'all') params.search = (activeSearch ? activeSearch + ' ' : '') + activeSubfilter;
        currentEvents = await API.getEvents(params);
        content.innerHTML = renderWindowsAuditHTML();

      } else if (currentPage === 'process') {
        const params = { category: 'Process', search: activeSearch, severity: activeFilter };
        if (activeSubfilter !== 'all') params.search = (activeSearch ? activeSearch + ' ' : '') + activeSubfilter;
        currentEvents = await API.getEvents(params);
        content.innerHTML = renderProcessIntelligenceHTML();

      } else if (currentPage === 'network') {
        const [events, netStats] = await Promise.all([
          API.getEvents({ source: 'Wireshark,Sysmon', search: activeSearch, severity: activeFilter }),
          API.getNetworkStats().catch(() => null)
        ]);
        currentEvents = events;
        networkStats = netStats;
        content.innerHTML = renderNetworkIntelligenceHTML();

      } else if (currentPage === 'forensic') {
        const params = { source: 'Autopsy', severity: activeFilter };
        const terms = [];
        if (activeSearch) terms.push(activeSearch);
        if (activeSubfilter && activeSubfilter !== 'all') terms.push(activeSubfilter);
        if (terms.length > 0) params.search = terms.join(' ');
        currentEvents = await API.getEvents(params);
        content.innerHTML = renderEvidenceExplorerHTML();
        initForensicInlineDropzone();

      } else if (currentPage === 'audit') {
        const [latest, capture, autopsy] = await Promise.all([
          API.json('/api/audit/host/latest').catch(() => ({ available: false })),
          API.json('/api/capture/interfaces').catch(() => ({ tshark: { available: false }, interfaces: [] })),
          API.json('/api/autopsy/status').catch(() => ({ available: false, jobs: [] }))
        ]);
        auditState = { latest, capture, autopsy };
        content.innerHTML = renderAuditConsoleHTML();
        const running = (autopsy.jobs || []).find(j => j.status === 'running');
        if (running) pollAutopsyJob(running.id);

      } else if (currentPage === 'detections') {
        detectionsData = await API.getDetections();
        content.innerHTML = renderDetectionsHTML();

      } else if (currentPage === 'timeline') {
        currentEvents = await API.getTimeline({ search: activeSearch, severity: activeFilter, limit: 300 });
        content.innerHTML = renderTimelineHTML();

      } else if (currentPage === 'graph') {
        const [graphData, events] = await Promise.all([
          API.getGraph().catch(() => ({ nodes: [], edges: [] })),
          API.getEvents({ limit: 100 })
        ]);
        currentGraphData = graphData;
        currentEvents = events;
        content.innerHTML = renderGraphHTML();
        initGraphCanvas();

      } else if (currentPage === 'reports') {
        reportData = await API.getReportSummary();
        content.innerHTML = renderReportsHTML();

      } else if (currentPage === 'settings') {
        const [h, net] = await Promise.all([
          API.getHealth().catch(() => ({ status: 'error' })),
          API.getNetworkStats().catch(() => null)
        ]);
        systemHealth = h;
        networkStats = net;
        content.innerHTML = renderSettingsHTML();
      }

      bindPageEvents();
      updateSidebarBadges();
      animateCounters();
      initScrollReveal();

    } catch (err) {
      console.error('[SecureScan] Render failed:', err);
      content.innerHTML = renderErrorState(err);
    } finally {
      isLoading = false;
    }
  }

  function setPage(page) {
    if (!pageMeta[page]) return;
    currentPage = page;
    activeSearch = '';
    activeFilter = 'all';
    activeSubfilter = 'all';

    $$('.nav-link').forEach(b => b.classList.toggle('active', b.dataset.page === page));

    $('#breadcrumb-current').textContent = pageMeta[page][1];
    $('#page-eyebrow').textContent = pageMeta[page][0];
    $('#page-title').textContent = pageMeta[page][1];
    $('#page-description').textContent = pageMeta[page][2];

    const primaryAction = $('#primary-action');
    if (primaryAction) {
      if (page === 'overview') {
        primaryAction.innerHTML = '<span>＋</span> Generate Demo Events';
        primaryAction.style.display = 'inline-flex';
      } else if (page === 'reports') {
        primaryAction.innerHTML = '<span>⎙</span> Print Report';
        primaryAction.style.display = 'inline-flex';
      } else if (page === 'audit') {
        primaryAction.innerHTML = '<span>▶</span> Run System Audit';
        primaryAction.style.display = 'inline-flex';
      } else if (page === 'detections') {
        primaryAction.innerHTML = '<span>⚑</span> Load Attack Scenario';
        primaryAction.style.display = 'inline-flex';
      } else if (page === 'graph') {
        primaryAction.innerHTML = '<span>⟲</span> Reset Graph View';
        primaryAction.style.display = 'inline-flex';
      } else {
        primaryAction.innerHTML = '<span>＋</span> Ingest Evidence';
        primaryAction.style.display = 'inline-flex';
      }
    }

    window.location.hash = page;
    loadCurrentPage();
  }

  // =========================================================================
  // INTERACTIVE BINDINGS & LISTENERS
  // =========================================================================
  function bindPageEvents() {
    // Search input with debouncing
    const searchInput = $('#table-search');
    if (searchInput) {
      searchInput.addEventListener('input', e => {
        clearTimeout(searchDebounceTimer);
        searchDebounceTimer = setTimeout(() => {
          activeSearch = e.target.value.trim();
          loadCurrentPage();
        }, 220);
      });
    }

    // Dashboard in-line recent search
    const recentSearchInput = $('#dashboard-recent-search');
    if (recentSearchInput) {
      recentSearchInput.addEventListener('input', e => {
        recentSearchFilter = e.target.value.trim();
        const content = $('#page-content');
        if (content && currentPage === 'overview') {
          content.innerHTML = renderOverviewHTML();
          bindPageEvents();
          animateCounters();
          initScrollReveal();
        }
      });
    }

    // Severity filter
    $('#severity-filter')?.addEventListener('change', e => {
      activeFilter = e.target.value;
      loadCurrentPage();
    });

    // Timeline source filter
    $('#timeline-source-filter')?.addEventListener('change', e => {
      const src = e.target.value;
      API.getTimeline({ search: activeSearch, severity: activeFilter, source: src, limit: 300 })
        .then(ev => {
          currentEvents = ev;
          $('#page-content').innerHTML = renderTimelineHTML();
          bindPageEvents();
          initScrollReveal();
        });
    });

    // Timeline date range filter
    $('#timeline-date-filter')?.addEventListener('change', e => {
      timelineDateRange = e.target.value;
      $('#page-content').innerHTML = renderTimelineHTML();
      bindPageEvents();
      initScrollReveal();
    });

    // Subfilter pills
    $$('.filter-pill[data-subfilter]').forEach(pill => {
      pill.addEventListener('click', () => {
        activeSubfilter = pill.dataset.subfilter;
        $$('.filter-pill[data-subfilter]').forEach(p => p.classList.toggle('active', p === pill));
        loadCurrentPage();
      });
    });

    // Clear filters
    $('#clear-filters')?.addEventListener('click', () => {
      activeSearch = '';
      activeFilter = 'all';
      activeSubfilter = 'all';
      recentSearchFilter = '';
      timelineDateRange = 'all';
      loadCurrentPage();
    });

    // Timeline sort toggle
    $('#toggle-timeline-sort')?.addEventListener('click', () => {
      timelineSortOrder = timelineSortOrder === 'desc' ? 'asc' : 'desc';
      $('#page-content').innerHTML = renderTimelineHTML();
      bindPageEvents();
      initScrollReveal();
    });

    // Navigation jumps
    $$('[data-go]').forEach(b => b.addEventListener('click', () => setPage(b.dataset.go)));

    // Smart Import triggers
    $$('[data-import]').forEach(b => b.addEventListener('click', () => showSmartImportModal(b.dataset.import)));

    // Report buttons
    $('#print-report')?.addEventListener('click', () => window.print());

    // Settings actions
    $('#settings-generate-demo')?.addEventListener('click', handleGenerateDemo);
    $('#settings-clear-demo')?.addEventListener('click', () => {
      showConfirmModal('Purge Demo Records', 'Are you sure you want to delete all synthetic demo records? Real imported evidence will be preserved.', handleClearDemo);
    });

    $('#recheck-health-btn')?.addEventListener('click', async () => {
      toast('Rechecking system health...');
      try {
        const [h, net] = await Promise.all([API.getHealth(), API.getNetworkStats()]);
        systemHealth = h;
        networkStats = net;
        $('#page-content').innerHTML = renderSettingsHTML();
        bindPageEvents();
        toast('Health check complete: SQLite and APIs responsive.');
      } catch (err) {
        toast(err.message, true);
      }
    });

    bindRowClickEvents();
  }

  function bindRowClickEvents() {
    // Table rows
    $$('.interactive-event-row').forEach(row => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('button') || e.target.closest('.timeline-expand-toggle')) return;
        const id = row.dataset.eventId;
        
        // If on overview, toggle inline details row
        if (currentPage === 'overview') {
          const detailRow = $(`#recent-details-${id}`);
          if (detailRow) {
            detailRow.style.display = detailRow.style.display === 'none' ? 'table-row' : 'none';
          }
        }

        const ev = currentEvents.find(item => item.id === id);
        if (ev && currentPage !== 'overview') showEventInspectionModal(ev);
      });
    });

    // Timeline node click (updates side panel)
    $$('.storyline-node-item').forEach(card => {
      card.addEventListener('click', (e) => {
        if (e.target.closest('button')) return;
        const id = card.dataset.eventId;
        const ev = currentEvents.find(item => item.id === id);
        if (ev) {
          selectedTimelineEvent = ev;
          $$('.storyline-node-item').forEach(c => c.classList.toggle('selected-node', c === card));
          const sidePanel = $('#timeline-side-panel');
          if (sidePanel) {
            sidePanel.innerHTML = `
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                <span class="page-eyebrow">SELECTED TIMELINE EVENT</span>
                ${severityBadge(ev.severity)}
              </div>
              <h3 style="font-family:var(--font-display);font-size:15px;color:var(--deep-navy);margin-bottom:6px;">${esc(ev.title || 'Event Observation')}</h3>
              <div style="font-size:11px;color:var(--text-muted);margin-bottom:14px;">${esc(formatDate(ev.event_time))}</div>

              <div style="background:var(--surface-alt);border:1px solid var(--border-light);border-radius:var(--radius-sm);padding:10px;margin-bottom:14px;font-size:11.5px;display:flex;flex-direction:column;gap:6px;">
                <div><strong>Source Engine:</strong> ${esc(ev.source || '—')}</div>
                <div><strong>Category:</strong> ${esc(ev.category || 'General')}</div>
                <div><strong>User Account:</strong> ${esc(ev.username || 'System')}</div>
                <div><strong>Endpoint / IP:</strong> ${esc(ev.source_ip || ev.destination_ip || 'Local / System')}</div>
                <div><strong>Evidence Tag:</strong> <code>${esc(ev.evidence_reference || 'N/A')}</code></div>
              </div>

              <div style="margin-bottom:14px;">
                <strong style="font-size:11px;color:var(--deep-navy);display:block;margin-bottom:4px;">Forensic Narrative:</strong>
                <p style="font-size:11.5px;color:var(--text-secondary);line-height:1.5;background:#FFFFFF;border:1px solid var(--border-light);border-radius:var(--radius-sm);padding:10px;">
                  ${esc(ev.details || 'No additional details logged.')}
                </p>
              </div>

              ${ev.command ? `
                <div style="margin-bottom:14px;">
                  <strong style="font-size:11px;color:var(--deep-navy);display:block;margin-bottom:4px;">Command Line:</strong>
                  <pre class="payload-pre" style="font-size:10.5px;max-height:120px;">${esc(ev.command)}</pre>
                </div>
              ` : ''}

              <div style="border-top:1px dashed var(--border-light);padding-top:12px;margin-top:14px;">
                <strong style="font-size:11px;color:var(--deep-navy);display:block;margin-bottom:4px;">Correlation Context:</strong>
                <p style="font-size:11px;color:var(--text-muted);line-height:1.4;">
                  Correlated with surrounding audit events via matching identifier <code>${esc(ev.username || ev.source_ip || 'local-host')}</code>.
                </p>
              </div>

              <div style="display:flex;gap:8px;margin-top:14px;">
                <button class="button button-sky button-small open-modal-btn" data-event-id="${esc(ev.id)}" style="flex:1;">Full Inspection Modal</button>
              </div>
            `;
            sidePanel.querySelector('.open-modal-btn')?.addEventListener('click', () => showEventInspectionModal(ev));
          }
        }
      });
    });

    // Timeline drawer toggle buttons
    $$('[data-toggle-drawer]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const card = btn.closest('.timeline-card');
        if (card) {
          card.classList.toggle('is-expanded');
          const toggleText = btn.querySelector('.toggle-text');
          if (toggleText) {
            toggleText.textContent = card.classList.contains('is-expanded') ? 'Collapse Details' : 'Toggle Inline Details';
          }
        }
      });
    });

    // Timeline full modal buttons
    $$('.open-modal-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = btn.dataset.eventId;
        const ev = currentEvents.find(item => item.id === id);
        if (ev) showEventInspectionModal(ev);
      });
    });
  }

  // =========================================================================
  // DEMO & IMPORT HANDLERS
  // =========================================================================
  async function handleGenerateDemo() {
    try {
      const primaryBtn = $('#primary-action');
      primaryBtn?.classList.add('is-loading');
      toast('Generating demo records in SQLite...');
      const res = await API.generateDemo();
      addNotification('Demo Data Generated', res.message || '6 synthetic demonstration events written to SQLite.', 'info');
      toast(res.message || 'Demo records created in SQLite.');
      loadCurrentPage();
    } catch (err) {
      toast(err.message, true);
      addNotification('Demo Generation Error', err.message, 'error');
    } finally {
      $('#primary-action')?.classList.remove('is-loading');
    }
  }

  async function handleLoadScenario() {
    try {
      $('#primary-action')?.classList.add('is-loading');
      toast('Loading multi-source attack scenario through the real parsers...');
      const res = await API.loadScenario();
      addNotification('Attack Scenario Loaded', res.message, 'info');
      toast(res.message);
      if (currentPage !== 'detections') setPage('detections'); else loadCurrentPage();
    } catch (err) {
      toast(err.message, true);
      addNotification('Scenario Load Error', err.message, 'error');
    } finally {
      $('#primary-action')?.classList.remove('is-loading');
    }
  }

  async function handleClearDemo() {
    try {
      toast('Purging demo records from SQLite...');
      const res = await API.clearDemo();
      addNotification('Demo Records Cleared', res.message || 'Purged demo records. Genuine evidence preserved.', 'info');
      toast(res.message || 'Demo records deleted. Real evidence preserved.');
      loadCurrentPage();
    } catch (err) {
      toast(err.message, true);
      addNotification('Demo Purge Error', err.message, 'error');
    }
  }

  async function handleFileUpload(file, targetModule, onProgress) {
    if (!file) return;

    // File validation
    const fname = file.name.toLowerCase();
    const validExts = ['.json', '.csv', '.tsv', '.pcap', '.pcapng', '.log', '.txt'];
    const hasValidExt = validExts.some(ext => fname.endsWith(ext));

    if (!hasValidExt) {
      toast(`Invalid file format: ${file.name}. Supported: ${validExts.join(', ')}`, true);
      addNotification('Import Rejected', `File "${file.name}" has an unsupported format.`, 'error');
      throw new Error(`File format not supported. Valid: ${validExts.join(', ')}`);
    }

    if (file.size > 10 * 1024 * 1024) {
      toast('File exceeds maximum size limit (10 MB).', true);
      throw new Error('File exceeds maximum allowable size (10 MB).');
    }

    let endpoint = '/api/import/windows-audit';
    if (targetModule === 'pcap' || fname.endsWith('.pcap') || fname.endsWith('.pcapng')) {
      endpoint = '/api/import/pcap';
    } else if (targetModule === 'sysmon') {
      endpoint = '/api/import/sysmon';
    } else if (targetModule === 'windows' || targetModule === 'windows-audit') {
      endpoint = '/api/import/windows-audit';
    } else if (targetModule === 'linux') {
      endpoint = '/api/import/linux-audit';
    } else if (targetModule === 'network') {
      endpoint = (fname.endsWith('.pcap') || fname.endsWith('.pcapng')) ? '/api/import/pcap' : '/api/import/wireshark';
    } else if (targetModule === 'forensic' || fname.endsWith('.tsv')) {
      endpoint = '/api/import/autopsy';
    } else if (fname.endsWith('.json')) {
      endpoint = (targetModule === 'forensic') ? '/api/import/autopsy' : '/api/import/windows-audit';
    } else if (fname.endsWith('.txt')) {
      endpoint = (targetModule === 'forensic') ? '/api/import/autopsy' : '/api/import/linux-audit';
    } else if (fname.endsWith('.log')) {
      endpoint = '/api/import/linux-audit';
    }

    const fileSizeKB = (file.size / 1024).toFixed(1);
    toast(`Ingesting ${file.name} (${fileSizeKB} KB)...`);

    try {
      const res = await API.uploadEvidence(endpoint, file, onProgress);
      const importedCount = res.successful_records ?? res.imported_packets ?? res.imported_records ?? 0;
      const duplicatesCount = res.duplicate_records ?? res.duplicates ?? 0;
      const failedCount = res.failed_records ?? 0;

      sessionImportHistory.unshift({
        time: new Date().toISOString(),
        filename: file.name,
        targetModule: endpoint.replace('/api/import/', ''),
        status: 'Ingested',
        records: importedCount,
        duplicates: duplicatesCount,
        failed: failedCount
      });

      addNotification(
        'Evidence Ingest Complete',
        `${file.name} parsed successfully: ${importedCount} records added (${duplicatesCount} duplicates prevented).`,
        'success'
      );

      toast(res.message || `Successfully imported ${importedCount} records (${duplicatesCount} duplicates skipped).`);
      loadCurrentPage();
      return res;
    } catch (err) {
      toast(`Import failed: ${err.message}`, true);
      addNotification('Import Ingest Failed', `Failed to import ${file.name}: ${err.message}`, 'error');
      throw err;
    }
  }

  // =========================================================================
  // BOOTSTRAP INITIALIZATION
  // =========================================================================
  $$('.nav-link').forEach(b => b.addEventListener('click', () => setPage(b.dataset.page)));

  $('#brand-link')?.addEventListener('click', (e) => {
    e.preventDefault();
    setPage('overview');
  });

  $('#primary-action')?.addEventListener('click', () => {
    if (currentPage === 'overview') handleGenerateDemo();
    else if (currentPage === 'audit') handleHostAudit($('[data-action="run-host-audit"]'));
    else if (currentPage === 'detections') handleLoadScenario();
    else if (currentPage === 'reports') window.print();
    else if (currentPage === 'graph') {
      initGraphCanvas();
      toast('Graph view reset');
    }
    else showSmartImportModal(currentPage === 'process' ? 'windows' : currentPage);
  });

  $('#export-button')?.addEventListener('click', () => {
    window.location.href = '/api/reports/export.csv';
  });

  $('#clear-demo-banner-btn')?.addEventListener('click', () => {
    showConfirmModal('Purge Demo Records', 'Clear all synthetic demo records? Real imported evidence will be preserved.', handleClearDemo);
  });

  $('#file-input')?.addEventListener('change', e => {
    const target = e.target.dataset.targetModule || currentPage;
    handleFileUpload(e.target.files?.[0], target);
  });

  $('#menu-toggle')?.addEventListener('click', () => $('#sidebar')?.classList.toggle('open'));
  $('#help-button')?.addEventListener('click', showAboutModal);
  $('#dismiss-banner')?.addEventListener('click', () => $('#demo-banner')?.style.setProperty('display', 'none'));

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      $('#sidebar')?.classList.remove('open');
      const modal = $('#modal-root');
      if (modal) modal.innerHTML = '';
      toggleNotificationDrawer(false);
    }
  });

  window.addEventListener('hashchange', () => {
    const hash = window.location.hash.replace(/^#/, '');
    if (hash && pageMeta[hash]) setPage(hash);
  });

  // Initialize interactive sub-engines
  initScrollTracking();
  initNotificationListeners();
  initCommandSearch();
  initDragAndDrop();

  const initialHash = window.location.hash.replace(/^#/, '');
  setPage(initialHash && pageMeta[initialHash] ? initialHash : 'overview');

  // Authoritative global contract
  // Delegated handlers for buttons rendered inside templates.
  // (Replaces inline onclick="" attributes so a strict Content-Security-Policy can be enforced.)
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    if (action === 'retry-load') loadCurrentPage();
    else if (action === 'open-import') showSmartImportModal();
    else if (action === 'load-scenario') handleLoadScenario();
    else if (action === 'goto-detections') setPage('detections');
    else if (action === 'goto-network') setPage('network');
    else if (action === 'goto-forensic') setPage('forensic');
    else if (action === 'run-host-audit') handleHostAudit(btn);
    else if (action === 'run-capture') handleCapture(btn);
    else if (action === 'run-autopsy') handleAutopsyAnalyze(btn);
    else if (action === 'import-autopsy-case') handleAutopsyImport(btn);
  });

  // Severity filter chips on the Threat Detections page (client-side filter).
  document.addEventListener('click', (e) => {
    const chip = e.target.closest('[data-det-filter]');
    if (!chip || currentPage !== 'detections') return;
    activeFilter = chip.dataset.detFilter;
    $('#page-content').innerHTML = renderDetectionsHTML();
    initScrollReveal();
  });

  window.SecureScan = {
    version: '2.5.0-forensic-motion',
    setPage,
    loadCurrentPage,
    generateDemo: handleGenerateDemo,
    clearDemo: handleClearDemo,
    showSmartImportModal,
    API
  };
})();
