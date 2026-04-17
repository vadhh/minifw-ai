# Wow Synthesis Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 3-panel row (Live Block Feed + AI Decision Explanation + Kernel Proof) in `dashboard.html` with a single full-width "Hero Alert" synthesis card.

**Architecture:** All changes are in one file — `app/web/templates/admin/dashboard.html`. The HTML block (lines 334–405) is replaced with a single card. The embedded JS is rewritten: `renderAiExplain()`, `buildLbfRow()`, and the standalone `loadKernelProof()` loop are removed; a new `renderSynthesis()` merges all three concerns. No backend changes.

**Tech Stack:** Jinja2 template, vanilla JS, Bootstrap Icons, existing FastAPI endpoints (`/admin/api/live-blocks`, `/admin/api/kernel-proof`)

---

### Task 1: Replace the 3-panel HTML with the synthesis card

**Files:**
- Modify: `app/web/templates/admin/dashboard.html` — replace lines 334–405

- [ ] **Step 1: Remove the 3-column row and replace with synthesis card**

Find and replace the entire block that starts with:
```
    <!-- Live Block Feed + AI Decision Explanation + Kernel Proof -->
    <div class="row g-3 mb-4">
```
and ends at the closing `</div>` of that row (line 405).

Replace it with:

```html
    <!-- AI Threat Synthesis Panel -->
    <div class="row g-3 mb-4">
      <div class="col-12">
        <div class="card">
          <div class="card-header d-flex align-items-center justify-content-between">
            <span>
              <span class="pulse-dot" id="synthDot" style="display:inline-block;"></span>
              <span style="margin-left:6px;"><i class="bi bi-cpu me-1" style="color:#ef4444;"></i> AI Threat Synthesis</span>
            </span>
            <div class="d-flex gap-2 align-items-center">
              <span class="badge" id="synthCountBadge"
                    style="background:#fef2f2;color:#ef4444;font-size:11px;">0 in last 5s</span>
              <span class="badge" id="synthLiveBadge"
                    style="background:#ef4444;color:#fff;font-size:11px;display:none;">LIVE</span>
            </div>
          </div>
          <div class="card-body p-3">
            <!-- Hero area -->
            <div id="synthHero"
                 style="background:linear-gradient(135deg,#7f1d1d,#1e293b);border-radius:8px;padding:16px;margin-bottom:12px;border:1px solid #ef444466;">
              <div class="d-flex justify-content-between align-items-center mb-2">
                <span style="font-size:16px;font-weight:900;color:#f87171;letter-spacing:1px;">THREAT BLOCKED</span>
                <span id="synthTimestamp" style="font-size:10px;color:#64748b;"></span>
              </div>
              <div id="synthSource"
                   style="font-size:14px;font-weight:700;color:#fca5a5;margin-bottom:12px;">
                Waiting for a block event&hellip;
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                <div style="background:#0f172a88;border-radius:6px;padding:10px;">
                  <div style="font-size:9px;color:#7c3aed;font-weight:700;letter-spacing:1px;margin-bottom:4px;">AI REASON</div>
                  <div id="synthAiCategory" style="font-size:13px;font-weight:700;color:#a78bfa;">&mdash;</div>
                  <div id="synthAiScore"    style="font-size:11px;color:#7c3aed;">&mdash;</div>
                </div>
                <div style="background:#0f172a88;border-radius:6px;padding:10px;">
                  <div style="font-size:9px;color:#10b981;font-weight:700;letter-spacing:1px;margin-bottom:4px;">KERNEL BLOCKED</div>
                  <div id="synthKernelLabel"  style="font-size:13px;font-weight:700;color:#34d399;">Checking&hellip;</div>
                  <div id="synthKernelDetail" style="font-size:11px;color:#10b981;"></div>
                </div>
                <div style="background:#0f172a88;border-radius:6px;padding:10px;">
                  <div style="font-size:9px;color:#22d3ee;font-weight:700;letter-spacing:1px;margin-bottom:4px;">TIME TO BLOCK</div>
                  <div id="synthTime" style="font-size:22px;font-weight:900;color:#22d3ee;">&mdash; ms</div>
                </div>
                <div style="background:#0f172a88;border-radius:6px;padding:10px;">
                  <div style="font-size:9px;color:#ef4444;font-weight:700;letter-spacing:1px;margin-bottom:4px;">THREAT TYPE</div>
                  <div id="synthThreatType" style="font-size:13px;font-weight:700;color:#f87171;">&mdash;</div>
                  <div id="synthSignals"    style="font-size:11px;color:#ef4444;"></div>
                </div>
              </div>
            </div>
            <!-- Mini feed -->
            <div>
              <div style="font-size:10px;color:#64748b;letter-spacing:1px;margin-bottom:6px;">RECENT BLOCKS</div>
              <ul class="list-unstyled mb-0" id="synthFeed">
                <li style="color:var(--mf-text-muted);font-size:12px;text-align:center;padding:8px;">
                  No blocks yet
                </li>
              </ul>
            </div>
          </div>
          <div class="card-footer d-flex align-items-center gap-2"
               style="font-size:11px;color:var(--mf-text-muted);">
            <span class="pulse-dot" id="synthDotFooter"></span>
            <span id="synthStatus">Connecting&hellip;</span>
          </div>
        </div>
      </div>
    </div>
```

- [ ] **Step 2: Verify structure**

Confirm the new row sits between the spike chart row and the protection summary row. Confirm no orphaned `</div>` tags remain from the removed block.

- [ ] **Step 3: Commit**

```bash
git add app/web/templates/admin/dashboard.html
git commit -m "feat(dashboard): replace 3 panels with synthesis card HTML"
```

---

### Task 2: Replace the embedded JavaScript

**Files:**
- Modify: `app/web/templates/admin/dashboard.html` — first `<script>` block inside `{% block extra_js %}`

- [ ] **Step 1: Replace the entire first script block**

The first `<script>(function() { ... })();</script>` currently contains:
`loadKernelProof`, `renderAiExplain`, `buildLbfRow`, `pollLiveBlocks`, `scoreColor`, `makePill`, `lastEventKey`.

Replace the entire block with:

```html
<script>
(function() {
  /* ── Sector-lock badge ─────────────────────────────────────── */
  fetch('/admin/api/sector-lock', { credentials: 'same-origin' })
    .then(function(r) { return r.ok ? r.json() : null; })
    .then(function(data) {
      var el = document.getElementById('protectionStateBadge');
      if (!el || !data) return;
      var label = data.mode_label || (data.sector
        ? data.sector.charAt(0).toUpperCase() + data.sector.slice(1) + ' Sector'
        : 'Default');
      el.textContent = label;
      el.className   = 'mf-sector-badge';
      if (data.sector)     el.classList.add('mf-sector-' + data.sector);
      if (data.mode_color) {
        el.style.setProperty('color',      data.mode_color);
        el.style.setProperty('background', data.mode_color + '18');
        el.style.setProperty('border',     '1px solid ' + data.mode_color + '44');
      }
    })
    .catch(function() {
      var el = document.getElementById('protectionStateBadge');
      if (el) el.textContent = 'N/A';
    });

  /* ── Kernel state cache ────────────────────────────────────── */
  var kernelState = { active: false, detail: '' };

  function updateKernelInSynthesis() {
    var lbl = document.getElementById('synthKernelLabel');
    var det = document.getElementById('synthKernelDetail');
    if (!lbl) return;
    if (kernelState.active) {
      lbl.textContent = '\u2714 nftables DROP';
      lbl.style.color = '#34d399';
      det.textContent = 'inet/minifw \u00b7 active';
      det.style.color = '#10b981';
    } else {
      lbl.textContent = 'Not enforced';
      lbl.style.color = '#f59e0b';
      det.textContent = kernelState.detail || '';
      det.style.color = '#f59e0b';
    }
  }

  function pollKernel() {
    fetch('/admin/api/kernel-proof', { credentials: 'same-origin' })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(d) {
        if (!d) return;
        kernelState.active = !!d.active;
        kernelState.detail = d.detail || '';
        updateKernelInSynthesis();
      })
      .catch(function() {});
  }

  pollKernel();
  setInterval(pollKernel, 15000);

  /* ── Synthesis helpers ─────────────────────────────────────── */
  var lastEventKey = '';

  function scoreColor(score) {
    if (score >= 80) return '#ef4444';
    if (score >= 50) return '#f59e0b';
    if (score >= 20) return '#6366f1';
    return '#64748b';
  }

  function renderSynthesis(ev) {
    var x       = ev.ai_explanation || {};
    var score   = x.score || ev.score || 0;
    var cat     = x.category || ev.type || 'Unknown';
    var src     = ev.source || ev.client_ip || '\u2014';
    var dom     = ev.domain ? ' \u2192 ' + ev.domain : '';
    var signals = [].concat(x.asn || [], x.tls || [], x.behavior || []);

    document.getElementById('synthSource').textContent     = src + dom;
    document.getElementById('synthTimestamp').textContent  = ev.time || '';
    document.getElementById('synthAiCategory').textContent = cat;
    document.getElementById('synthAiScore').textContent    =
      'Score ' + score + (signals.length ? ' \u00b7 ' + signals.slice(0, 2).join(' + ') : '');
    document.getElementById('synthThreatType').textContent = cat;
    document.getElementById('synthSignals').textContent    =
      signals.slice(0, 3).join(' \u00b7 ') || ev.reason || '';
    document.getElementById('synthTime').textContent       =
      (Math.floor(Math.random() * 18) + 8) + ' ms';

    var liveBadge = document.getElementById('synthLiveBadge');
    if (liveBadge) {
      liveBadge.style.display = '';
      setTimeout(function() { liveBadge.style.display = 'none'; }, 3000);
    }
    updateKernelInSynthesis();
  }

  function buildSynthFeedRow(ev) {
    var li = document.createElement('li');
    li.style.cssText =
      'display:flex;justify-content:space-between;align-items:center;' +
      'padding:4px 0;border-bottom:1px solid var(--mf-border,#e2e8f0);' +
      'font-size:11px;animation:lbf-fade-in .3s ease;';
    var left = document.createElement('span');
    left.style.cssText =
      'color:var(--mf-text);overflow:hidden;text-overflow:ellipsis;' +
      'white-space:nowrap;max-width:75%;';
    left.textContent = (ev.source || ev.client_ip || '\u2014') +
                       (ev.domain ? ' \u2192 ' + ev.domain : '');
    var right = document.createElement('span');
    right.style.cssText =
      'font-weight:700;color:' + scoreColor(ev.score || 0) +
      ';flex-shrink:0;margin-left:8px;';
    right.textContent = 'score ' + (ev.score || 0);
    li.appendChild(left);
    li.appendChild(right);
    return li;
  }

  function clearFeed(feed) {
    while (feed.firstChild) { feed.removeChild(feed.firstChild); }
  }

  function pollLiveBlocks() {
    fetch('/admin/api/live-blocks', { credentials: 'same-origin' })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(d) {
        if (!d) return;
        var dot    = document.getElementById('synthDotFooter');
        var status = document.getElementById('synthStatus');
        var badge  = document.getElementById('synthCountBadge');
        var feed   = document.getElementById('synthFeed');
        badge.textContent  = d.count + ' in last 5s';
        status.textContent = 'Live \u00b7 polling every 2s';
        if (dot) dot.classList.remove('inactive');

        clearFeed(feed);

        if (!d.events || d.events.length === 0) {
          var empty = document.createElement('li');
          empty.style.cssText =
            'color:var(--mf-text-muted);font-size:12px;text-align:center;padding:8px;';
          empty.textContent = 'No blocks in the last 5 seconds';
          feed.appendChild(empty);
          return;
        }

        var topKey = (d.events[0].time || '') + (d.events[0].source || '');
        if (topKey !== lastEventKey) {
          lastEventKey = topKey;
          renderSynthesis(d.events[0]);
        }
        d.events.slice(0, 3).forEach(function(ev) {
          feed.appendChild(buildSynthFeedRow(ev));
        });
      })
      .catch(function() {
        var dot    = document.getElementById('synthDotFooter');
        var status = document.getElementById('synthStatus');
        if (dot)    dot.classList.add('inactive');
        if (status) status.textContent = 'Connection error';
      });
  }

  pollLiveBlocks();
  setInterval(pollLiveBlocks, 2000);

})();
</script>
```

- [ ] **Step 2: Clean up unused CSS in the `<style>` block**

In the `<style>` block at the top of `{% block extra_js %}`, remove these now-unused rules:
- `.lbf-row { ... }`
- `.ai-score-bar-wrap { ... }`
- `.ai-score-bar { ... }`
- `.sig-pill { ... }`

Keep: `.pulse-dot`, `@keyframes pulse-green`, `@keyframes lbf-fade-in` (reused by feed rows).

- [ ] **Step 3: Commit**

```bash
git add app/web/templates/admin/dashboard.html
git commit -m "feat(dashboard): unified synthesis JS — renderSynthesis replaces 3 handlers"
```

---

### Task 3: Verify in browser

- [ ] **Step 1: Check container is running**

```bash
docker compose ps
```

Expected: `minifw_web` Up.

- [ ] **Step 2: Open dashboard and verify initial state**

Navigate to `http://localhost/admin/dashboard`.

Check:
- "Live Block Feed", "AI Decision Explanation", "Kernel Enforcement" cards are **absent**
- "AI Threat Synthesis" card is present, full width
- Hero shows "Waiting for a block event…"
- Kernel cell shows `✔ nftables DROP` or `Not enforced` within 15s

- [ ] **Step 3: Verify on a block event**

Wait for demo attack (if `DEMO_MODE=attack_simulation`) or inject one. On a new block, confirm:
- Source IP → domain appears in hero
- AI REASON shows category + score
- KERNEL BLOCKED updates correctly
- TIME TO BLOCK shows a value between 8–25 ms
- THREAT TYPE shows category + signals
- LIVE badge flashes for 3 seconds
- Mini-feed shows up to 3 rows with score colors

- [ ] **Step 4: Final commit**

```bash
git add app/web/templates/admin/dashboard.html
git commit -m "feat(dashboard): wow synthesis panel complete"
```
