// ========================================
// API AUTH WRAPPER
// ========================================
// Backend optionally requires an API token (Bearer / X-Api-Token).
// We wrap window.fetch so every same-origin /api/* call attaches whatever
// token the user has entered. Three properties this needs to handle:
//
//   1. Persistence across reloads + tabs — store in localStorage so a
//      page refresh doesn't re-prompt.
//   2. Single-flight prompt — when the dashboard fires N concurrent
//      requests on first load and all N hit 401, only ONE prompt should
//      appear; the rest queue on the same in-flight token promise.
//   3. Surface a 401 once and stop prompting if the user cancels —
//      otherwise we'd loop forever.
(function () {
    const TOKEN_KEY = 'webvizApiToken';
    const origFetch = window.fetch.bind(window);

    const isApiUrl = (input) => {
        const url = typeof input === 'string' ? input : (input && input.url) || '';
        return url.indexOf('/api/') === 0;
    };

    // sessionStorage only: a long-lived localStorage token is what an XSS
    // would steal. Storage can throw (blocked site data), so guard it.
    const safe = (fn, fallback) => { try { return fn(); } catch (_e) { return fallback; } };
    // One-time migration: drop any token an older build left in localStorage.
    const legacy = safe(() => localStorage.getItem(TOKEN_KEY), null);
    if (legacy) {
        safe(() => { if (!sessionStorage.getItem(TOKEN_KEY)) sessionStorage.setItem(TOKEN_KEY, legacy); });
        safe(() => localStorage.removeItem(TOKEN_KEY));
    }

    const readToken = () => (safe(() => sessionStorage.getItem(TOKEN_KEY), '') || '').trim();

    const writeToken = (value) => {
        if (!value) {
            safe(() => sessionStorage.removeItem(TOKEN_KEY));
            return;
        }
        safe(() => sessionStorage.setItem(TOKEN_KEY, value));
    };

    const attachToken = (init, token) => {
        init = init || {};
        init.headers = new Headers(init.headers || {});
        if (token && !init.headers.has('Authorization')) {
            init.headers.set('Authorization', 'Bearer ' + token);
        }
        return init;
    };

    // Single-flight prompt. Concurrent 401s all await the same promise
    // instead of stacking up `window.prompt` dialogs.
    let pendingPrompt = null;
    // If the user cancels, remember it for this page lifetime so further
    // 401s pass through cleanly and let the caller's UI render its error.
    let promptCancelled = false;

    const promptForToken = () => {
        if (promptCancelled) return Promise.resolve('');
        if (pendingPrompt) return pendingPrompt;
        pendingPrompt = new Promise((resolve) => {
            // Defer so the prompt doesn't compete with the current micro-task
            // (avoids weird stacking when 4 fetches all hit 401 simultaneously).
            setTimeout(() => {
                const entered = (window.prompt(
                    'Enter Fleet Hound API token (WEBVIZ_API_TOKEN). Leave blank to cancel.'
                ) || '').trim();
                if (entered) {
                    writeToken(entered);
                } else {
                    promptCancelled = true;
                }
                pendingPrompt = null;
                resolve(entered);
            }, 0);
        });
        return pendingPrompt;
    };

    window.fetch = function (input, init) {
        if (!isApiUrl(input)) return origFetch(input, init);
        const url = typeof input === 'string' ? input : (input && input.url) || '';
        const token = readToken();
        const initWithToken = attachToken(init, token);

        return origFetch(input, initWithToken).then((response) => {
            if (response.status !== 401 || (init && init.__webvizAuthRetry)) {
                return response;
            }
            // /api/health is always public; a 401 there means something
            // genuinely broke — surface it instead of prompting.
            if (url.indexOf('/api/health') === 0) return response;
            if (promptCancelled) return response;

            return promptForToken().then((entered) => {
                if (!entered) return response;
                const retryInit = attachToken(
                    { ...(init || {}), __webvizAuthRetry: true },
                    entered,
                );
                retryInit.headers.set('Authorization', 'Bearer ' + entered);
                return origFetch(input, retryInit);
            });
        });
    };

    // Expose a "forget token" hook so admins can reset from devtools.
    window.fleetHoundClearToken = () => {
        writeToken('');
        promptCancelled = false;
        console.log('Fleet Hound token cleared. Reload to be re-prompted.');
    };
})();

// ========================================
// CSS VAR HELPER
// ========================================
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// ========================================
// HOUND — shared motion / format / UI primitives
// ========================================
// No framework, no build step: plain functions on one namespace so new
// code doesn't add more globals to an already-global file.
const HOUND = window.HOUND = (() => {
    const reduceQuery = window.matchMedia
        ? window.matchMedia('(prefers-reduced-motion: reduce)')
        : null;
    const reduceMotion = () => !!(reduceQuery && reduceQuery.matches);

    // ---- formatting ----
    const int = (n) => Number(n || 0).toLocaleString();
    const compact = (n) => {
        const v = Number(n || 0);
        if (Math.abs(v) < 1000) return String(v);
        try {
            return new Intl.NumberFormat(undefined, {
                notation: 'compact', maximumFractionDigits: 1,
            }).format(v);
        } catch (e) { return int(v); }
    };
    const relativeTime = (iso) => {
        if (!iso) return '—';
        const then = new Date(iso).getTime();
        if (!Number.isFinite(then)) return '—';
        const secs = Math.round((Date.now() - then) / 1000);
        if (secs < 60) return `${secs}s ago`;
        const mins = Math.round(secs / 60);
        if (mins < 90) return `${mins}m ago`;
        const hours = Math.round(mins / 60);
        if (hours < 36) return `${hours}h ago`;
        return `${Math.round(hours / 24)}d ago`;
    };
    const percent = (part, whole) => {
        const w = Number(whole || 0);
        if (!w) return 0;
        return Math.round((Number(part || 0) / w) * 100);
    };

    // ---- motion ----
    // Count-up animates the visible digits; the caller keeps an
    // aria-live element with the final value so screen readers don't
    // hear every frame.
    const countUp = (el, to, opts) => {
        if (!el) return;
        const o = opts || {};
        const format = o.format || int;
        const duration = o.duration == null ? 500 : o.duration;
        const target = Number(to) || 0;
        const from = Number(el.dataset.countValue || 0);
        el.dataset.countValue = String(target);
        if (el._houndRAF) { cancelAnimationFrame(el._houndRAF); el._houndRAF = null; }
        if (reduceMotion() || from === target || duration === 0) {
            el.textContent = format(target);
            return;
        }
        const start = performance.now();
        const ease = (t) => 1 - Math.pow(1 - t, 3);
        const step = (now) => {
            const p = Math.min(1, (now - start) / duration);
            el.textContent = format(Math.round(from + (target - from) * ease(p)));
            if (p < 1) el._houndRAF = requestAnimationFrame(step);
            else { el._houndRAF = null; el.textContent = format(target); }
        };
        el._houndRAF = requestAnimationFrame(step);
    };

    // ---- storage (private mode safe) ----
    const store = {
        get(k, fallback) {
            try {
                const v = window.localStorage.getItem(k);
                return v === null ? (fallback === undefined ? null : fallback) : v;
            } catch (e) { return fallback === undefined ? null : fallback; }
        },
        set(k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* ignore */ } },
    };

    // ---- toasts ----
    const TOAST_ICON = {
        info: 'i-info', success: 'i-check', warning: 'i-alert', error: 'i-alert',
    };
    let toastSeq = 0;

    const dismissToast = (el) => {
        if (!el || !el.isConnected || el.classList.contains('leaving')) return;
        el.classList.add('leaving');
        const done = () => el.remove();
        if (reduceMotion()) done();
        else setTimeout(done, 170);
    };

    const toast = (message, opts) => {
        const root = document.getElementById('toast-root');
        if (!root) return null;
        const o = opts || {};
        const type = o.type || 'info';
        const duration = o.duration === undefined
            ? (type === 'error' ? 8000 : 4000)
            : o.duration;
        while (root.children.length >= 3) root.removeChild(root.firstElementChild);

        const el = document.createElement('div');
        el.className = 'toast';
        el.dataset.type = type;
        el.dataset.id = String(++toastSeq);
        el.innerHTML = `
            <svg class="toast-icon" aria-hidden="true" focusable="false"><use href="#${TOAST_ICON[type] || 'i-info'}"></use></svg>
            <div class="toast-body"></div>
            <button class="toast-close" type="button" aria-label="Dismiss notification">
                <svg width="12" height="12" aria-hidden="true" focusable="false"><use href="#i-x"></use></svg>
            </button>`;
        el.querySelector('.toast-body').textContent = String(message);
        el.querySelector('.toast-close').addEventListener('click', () => dismissToast(el));

        if (duration > 0) {
            const bar = document.createElement('div');
            bar.className = 'toast-progress';
            bar.style.animationDuration = duration + 'ms';
            el.appendChild(bar);

            let remaining = duration;
            let startedAt = Date.now();
            let timer = null;
            const startTimer = () => {
                startedAt = Date.now();
                timer = setTimeout(() => dismissToast(el), remaining);
            };
            const pause = () => {
                if (!timer) return;
                clearTimeout(timer);
                timer = null;
                remaining -= Date.now() - startedAt;
            };
            el.addEventListener('mouseenter', pause);
            el.addEventListener('mouseleave', () => { if (remaining > 0) startTimer(); });
            el.addEventListener('focusin', pause);
            el.addEventListener('focusout', () => { if (remaining > 0) startTimer(); });
            startTimer();
        }

        root.appendChild(el);
        return el;
    };

    // ---- tooltip (one shared layer) ----
    const tooltip = (() => {
        let el = null;
        const node = () => {
            if (!el) el = document.getElementById('tooltip-root');
            return el;
        };
        const hide = () => {
            const n = node();
            if (!n) return;
            n.classList.remove('visible');
            n.setAttribute('aria-hidden', 'true');
        };
        const place = (clientX, clientY, anchorRect) => {
            const n = node();
            if (!n) return;
            const pad = 12;
            const rect = n.getBoundingClientRect();
            let x = clientX + pad;
            let y = clientY + pad;
            if (anchorRect) { x = anchorRect.left; y = anchorRect.bottom + 8; }
            if (x + rect.width > window.innerWidth - 8) x = window.innerWidth - rect.width - 8;
            if (y + rect.height > window.innerHeight - 8) {
                y = anchorRect ? anchorRect.top - rect.height - 8 : clientY - rect.height - pad;
            }
            n.style.left = Math.max(8, x) + 'px';
            n.style.top = Math.max(8, y) + 'px';
        };
        const show = (clientX, clientY, html, anchorRect) => {
            const n = node();
            if (!n) return;
            if (html != null) n.innerHTML = `<div class="tooltip-card">${html}</div>`;
            n.classList.add('visible');
            n.setAttribute('aria-hidden', 'false');
            place(clientX, clientY, anchorRect);
        };
        const move = (clientX, clientY) => place(clientX, clientY);
        return { show, move, hide };
    })();

    // ---- modal focus management ----
    // Existing modals are toggled by adding `.visible`. Rather than
    // rewriting every call site, observe the class and handle focus,
    // Escape and Tab here so all of them behave consistently.
    let lastFocused = null;
    const focusables = (root) => Array.from(root.querySelectorAll(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), ' +
        'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )).filter((n) => n.offsetParent !== null || n === document.activeElement);

    const installModalBehaviour = () => {
        document.addEventListener('keydown', (e) => {
            const open = document.querySelector('.modal-overlay.visible');
            if (!open) return;
            if (e.key === 'Escape') {
                open.classList.remove('visible');
                e.preventDefault();
                return;
            }
            if (e.key !== 'Tab') return;
            const items = focusables(open);
            if (items.length === 0) return;
            const first = items[0];
            const last = items[items.length - 1];
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault(); last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault(); first.focus();
            }
        });

        const observer = new MutationObserver((mutations) => {
            mutations.forEach((m) => {
                const target = m.target;
                if (!target.classList || !target.classList.contains('modal-overlay')) return;
                const isOpen = target.classList.contains('visible');
                if (isOpen && !target.dataset.houndOpened) {
                    target.dataset.houndOpened = '1';
                    lastFocused = document.activeElement;
                    requestAnimationFrame(() => {
                        if (target.contains(document.activeElement)) return;
                        const items = focusables(target);
                        (items[0] || target).focus();
                    });
                } else if (!isOpen && target.dataset.houndOpened) {
                    delete target.dataset.houndOpened;
                    if (lastFocused && lastFocused.isConnected) lastFocused.focus();
                }
            });
        });
        document.querySelectorAll('.modal-overlay').forEach((m) =>
            observer.observe(m, { attributes: true, attributeFilter: ['class'] }));
    };

    // ---- skeletons ----
    const skeletonLines = (count, widths) => {
        const w = widths || ['w-75', 'w-60', 'w-40'];
        return Array.from({ length: count }, (_, i) =>
            `<div class="skeleton skeleton-line ${w[i % w.length]}"></div>`).join('');
    };

    // ---- donut ----
    // Segments are [{value, color}]. The ring draws in on first paint;
    // reduced motion gets the final ring immediately. Size, stroke and
    // label size derive from the SVG viewBox so one helper covers the
    // 64px overview rings and the 128px Shadow IT ring.
    const donut = (svg, segments, total, label, opts) => {
        if (!svg) return;
        const o = opts || {};
        const vb = svg.viewBox && svg.viewBox.baseVal;
        const size = o.size || (vb && vb.width) || svg.clientWidth || 64;
        const stroke = o.stroke || Math.max(5, size * 0.11);
        const r = (size - stroke) / 2 - 1;
        const c = 2 * Math.PI * r;
        const mid = size / 2;
        const ns = 'http://www.w3.org/2000/svg';

        svg.innerHTML = '';

        const track = document.createElementNS(ns, 'circle');
        track.setAttribute('cx', mid); track.setAttribute('cy', mid);
        track.setAttribute('r', r);
        track.setAttribute('fill', 'none');
        track.style.stroke = 'var(--bg-tertiary)';
        track.setAttribute('stroke-width', stroke);
        svg.appendChild(track);

        const sum = segments.reduce((acc, s) => acc + Number(s.value || 0), 0);
        let offset = 0;
        segments.forEach((seg) => {
            const value = Number(seg.value || 0);
            if (!value || !sum) return;
            const len = (value / sum) * c;
            const arc = document.createElementNS(ns, 'circle');
            arc.setAttribute('cx', mid); arc.setAttribute('cy', mid);
            arc.setAttribute('r', r);
            arc.setAttribute('fill', 'none');
            arc.style.stroke = seg.color;
            arc.setAttribute('stroke-width', stroke);
            arc.setAttribute('stroke-linecap', 'butt');
            const finalDash = `${len} ${c - len}`;
            arc.setAttribute('stroke-dashoffset', String(-offset));
            arc.setAttribute('transform', `rotate(-90 ${mid} ${mid})`);
            arc.style.transition = reduceMotion()
                ? 'none'
                : 'stroke-dasharray 700ms var(--ease-out)';
            if (reduceMotion()) {
                arc.setAttribute('stroke-dasharray', finalDash);
            } else {
                // Start empty, then grow each arc into place. Offset is
                // fixed per segment, so every arc expands from its own
                // start instead of all of them growing from 12 o'clock.
                arc.setAttribute('stroke-dasharray', `0 ${c}`);
                requestAnimationFrame(() => arc.setAttribute('stroke-dasharray', finalDash));
            }
            svg.appendChild(arc);
            offset += len;
        });

        if (!sum) track.style.stroke = 'var(--border)';

        if (!o.noLabel) {
            const text = document.createElementNS(ns, 'text');
            text.setAttribute('x', mid);
            text.setAttribute('y', mid + size * 0.06);
            text.setAttribute('text-anchor', 'middle');
            text.setAttribute('fill', 'var(--text-primary)');
            text.setAttribute('font-family', 'var(--font-mono)');
            text.setAttribute('font-size', String(Math.round(size * 0.2)));
            text.textContent = total > 999 ? compact(total) : String(total);
            svg.appendChild(text);
        }

        if (label) svg.setAttribute('aria-label', label);
    };

    return {
        reduceMotion,
        fmt: { int, compact, relativeTime, percent },
        countUp,
        donut,
        store,
        toast,
        tooltip,
        skeletonLines,
        installModalBehaviour,
    };
})();

// showStatus() predates toasts. Keep the name as a shim so the ~40
// existing call sites keep working; new code should call HOUND.toast.
function showStatus(message, isError) {
    HOUND.toast(message, { type: isError ? 'error' : 'info' });
}

// ========================================
// CONSTANTS & STATE
// ========================================
const DEFAULT_ACCOUNTS = ['root', 'Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount'];
let customExclusions = [];

let currentData = { nodes: [], links: [] };
// Payload handed to renderGraph() while #graph was hidden (0×0).
let _graphPending = null;
let _graphSize = null;
// A fresh layout is fitted once it settles; tab re-entry restarts the
// simulation but must keep the operator's own zoom.
let _graphNeedsFit = false;
let allGraphData = { nodes: [], links: [] };
let simulation;
let _graphZoomTransform = null;
let _graphZoom = null;
let _graphSelected = null;
let _graphFocusId = null;

// Search mode state
let searchMode = 'wildcard';
let caseSensitive = false;

// ========================================
// SEARCH CONTROLS
// ========================================
function toggleCaseSensitive() {
    caseSensitive = !caseSensitive;
    const btn = document.getElementById('toggle-case');
    btn.classList.toggle('active', caseSensitive);
    const searchTerm = document.getElementById('search-input').value.trim();
    if (searchTerm) searchNodes();
}

function setSearchMode(mode) {
    searchMode = mode;
    document.getElementById('mode-wildcard').classList.toggle('active', mode === 'wildcard');
    document.getElementById('mode-exact').classList.toggle('active', mode === 'exact');
    const searchTerm = document.getElementById('search-input').value.trim();
    if (searchTerm) searchNodes();
}

function matchesSearch(value, searchTerm) {
    if (!value || !searchTerm) return !searchTerm;

    const testValue = caseSensitive ? value : value.toLowerCase();
    const testTerm = caseSensitive ? searchTerm : searchTerm.toLowerCase();

    switch (searchMode) {
        case 'exact':
            return testValue === testTerm;
        case 'regex':
            try {
                const re = new RegExp(searchTerm, caseSensitive ? '' : 'i');
                return re.test(value);
            } catch (e) {
                console.warn('Invalid regex:', e);
                return false;
            }
        case 'wildcard':
        default:
            return testValue.includes(testTerm);
    }
}

// ========================================
// THEME
// ========================================
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    const apply = () => {
        html.setAttribute('data-theme', newTheme);
        HOUND.store.set('theme', newTheme);
        const meta = document.querySelector('meta[name="theme-color"]');
        if (meta) meta.setAttribute('content', newTheme === 'light' ? '#f8f9fa' : '#0c0d10');
        if (currentData.nodes.length > 0) renderGraph(currentData);
        // The constellation and blast diagrams bake colours at draw
        // time, so re-render whichever is on screen. Donuts and CSS
        // swatches use var(--…) and repaint on their own.
        const overviewActive = document.getElementById('overview-view').classList.contains('active');
        if (overviewActive && HOUND.overview) HOUND.overview.reload();
        if (typeof _blastLastData !== 'undefined' && _blastLastData
            && typeof renderBlastDiagram === 'function') {
            renderBlastDiagram(_blastLastData);
        }
    };
    if (HOUND.reduceMotion()) {
        apply();
        return;
    }
    // Short colour crossfade on the big surfaces only. Doing this on
    // every element would repaint the whole dashboard for a toggle.
    html.classList.add('theme-fade');
    apply();
    setTimeout(() => html.classList.remove('theme-fade'), 260);
}

function loadThemePreference() {
    // The saved value was already applied pre-paint by the inline head
    // script; this only fills in the default for first-time visitors.
    if (!document.documentElement.getAttribute('data-theme')) {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
}

// ========================================
// GRAPH
// ========================================
// Build the URL params for /api/graph/full from the visible Graph view
// controls (team filter dropdown) + the cross-view SessionLabelScope.
// The graph view doesn't have its own label widget; it inherits the
// scope from whatever the user picked on Blast Radius / Shadow IT,
// surfaced via the Active Scope banner. This is how the "the apps
// shown aren't part of the label" bug got fixed (May 2026).
function _buildGraphScopeParams() {
    const params = new URLSearchParams();
    const teamEl = document.getElementById('team-filter');
    if (teamEl && teamEl.value && teamEl.value !== 'all') {
        params.set('team', teamEl.value);
    }
    const scope = SessionLabelScope.get();
    if (scope.labels && scope.labels.length > 0) {
        params.set('labels', scope.labels.join(','));
        params.set('label_op', scope.label_op || 'AND');
    }
    return params;
}

function loadGraph() {
    showStatus('Loading data...');

    const params = _buildGraphScopeParams();
    const qs = params.toString();
    const url = qs ? `/api/graph/full?${qs}` : '/api/graph/full';

    fetch(url)
        .then(response => {
            if (!response.ok) {
                return response.json().then(errorData => {
                    throw new Error(errorData.message || errorData.error || `HTTP ${response.status}`);
                }).catch(() => {
                    throw new Error(`HTTP ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.error) throw new Error(data.message || data.error);
            allGraphData = data;
            // Performance guardrail: SVG-based force layouts melt at ~800
            // nodes. Beyond that we render the most-connected slice and
            // surface a clear status so the user knows it's a partial view.
            let renderData = data;
            if (data.nodes.length > GRAPH_RENDER_BUDGET) {
                renderData = capGraphForRender(data, GRAPH_RENDER_BUDGET);
                showStatus(`Loaded ${data.nodes.length} nodes — showing top ${renderData.nodes.length} by connections. Use search to drill in.`, false);
            } else {
                showStatus(`Loaded ${data.nodes.length} nodes, ${data.links.length} relationships`);
            }
            currentData = renderData;
            renderGraph(renderData);
        })
        .catch(error => {
            console.error('Error loading graph:', error);
            let errorMsg = error.message;
            if (errorMsg.includes('Memory limit exceeded') || errorMsg.includes('too large')) {
                errorMsg = 'Dataset too large: ' + errorMsg + ' Please increase Memgraph memory limit in docker-compose.yml';
            }
            showStatus('Error loading data: ' + errorMsg, true);
        });
}

/**
 * Reduce a graph to its `budget` most-connected nodes plus the links
 * between them. Used as a soft cap for the initial overview render so
 * SVG force layouts stay smooth on real-world fleets (≥1k nodes).
 */
const GRAPH_RENDER_BUDGET = 800;  // SVG force layouts degrade beyond this

function capGraphForRender(data, budget) {
    const degree = new Map();
    data.links.forEach(l => {
        const src = typeof l.source === 'object' ? l.source.id : l.source;
        const tgt = typeof l.target === 'object' ? l.target.id : l.target;
        degree.set(src, (degree.get(src) || 0) + 1);
        degree.set(tgt, (degree.get(tgt) || 0) + 1);
    });
    const ranked = [...data.nodes].sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0));
    const keep = new Set(ranked.slice(0, budget).map(n => n.id));
    const nodes = data.nodes.filter(n => keep.has(n.id));
    const links = data.links.filter(l => {
        const src = typeof l.source === 'object' ? l.source.id : l.source;
        const tgt = typeof l.target === 'object' ? l.target.id : l.target;
        return keep.has(src) && keep.has(tgt);
    });
    return { nodes, links, capped: true, original_count: data.nodes.length };
}

function renderGraph(data, filterDisconnected = true) {
    const container = d3.select("#graph");
    const width = container.node().clientWidth;
    const height = container.node().clientHeight;

    // Graph loads at boot while its view is still hidden, so the
    // container measures 0×0 and every node gets pinned to the
    // top-left corner of an invisible canvas. Remember the payload
    // and let switchView('graph') draw it once the view has size.
    if (!width || !height) {
        _graphPending = { data, filterDisconnected };
        return;
    }
    _graphPending = null;
    _graphSize = { w: width, h: height };

    container.selectAll("*").remove();

    let nodesToRender;

    if (filterDisconnected && data.links.length > 0) {
        const connectedNodeIds = new Set();
        data.links.forEach(link => {
            connectedNodeIds.add(typeof link.source === 'object' ? link.source.id : link.source);
            connectedNodeIds.add(typeof link.target === 'object' ? link.target.id : link.target);
        });
        nodesToRender = data.nodes.filter(node => connectedNodeIds.has(node.id));
    } else {
        nodesToRender = data.nodes;
    }

    // Defensive dedupe by node id. Server endpoints should already
    // return unique node ids, but if any payload slips through with
    // duplicates (e.g. an unfixed endpoint, or duplicate INSTALLED_ON
    // edges hitting a non-DISTINCT cypher), D3 happily renders one
    // SVG <g> per array entry — so 4 entries with the same id become
    // 4 stacked circles with identical labels. Coalesce here so the
    // viz can't lie about cardinality.
    const _seen = new Map();
    for (const n of nodesToRender) {
        if (n && n.id != null && !_seen.has(n.id)) _seen.set(n.id, n);
    }
    if (_seen.size !== nodesToRender.length) {
        console.warn(
            `renderGraph: deduped ${nodesToRender.length - _seen.size} duplicate node id(s); ` +
            `the API payload should not contain duplicates.`
        );
    }
    nodesToRender = Array.from(_seen.values());

    // Client-side display_name fallback. Endpoints that emit
    // display_name (graph/full, search, software/hosts) already
    // disambiguate hostname collisions. For payloads that don't
    // (older snapshots, unfixed endpoints), synthesize the same
    // `name #fleet_host_id` label here so distinct hosts sharing a
    // hostname remain visually distinguishable in any view.
    const _nameCounts = new Map();
    for (const n of nodesToRender) {
        if (n.type === 'host' && n.name) {
            _nameCounts.set(n.name, (_nameCounts.get(n.name) || 0) + 1);
        }
    }
    for (const n of nodesToRender) {
        if (n.type !== 'host') continue;
        if (n.display_name) continue;
        if (n.name && _nameCounts.get(n.name) > 1 && n.fleet_host_id != null) {
            n.display_name = `${n.name} #${n.fleet_host_id}`;
        } else {
            n.display_name = n.name;
        }
    }

    const svg = container.append("svg")
        .attr("width", width)
        .attr("height", height)
        .attr("role", "application")
        .attr("aria-label", "Fleet graph. Scroll to zoom, drag to pan, click a node to inspect.");

    // Zoom/pan lives on one root group. Node drag stops propagation so
    // dragging a node doesn't pan the canvas under it.
    const root = svg.append("g").attr("class", "graph-root");

    // Degree drives size: hub hosts and widely-installed software read
    // as the important things without needing a label on every node.
    const degree = new Map();
    nodesToRender.forEach((n) => degree.set(n.id, 0));
    data.links.forEach((l) => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        if (degree.has(s)) degree.set(s, degree.get(s) + 1);
        if (degree.has(t)) degree.set(t, degree.get(t) + 1);
    });
    const maxDegree = Math.max(1, ...degree.values());

    function nodeRadius(d) {
        const deg = degree.get(d.id) || 0;
        const base = 4 + Math.sqrt(deg / maxDegree) * 17;
        return Math.max(5, Math.min(22, base + (d.type === 'host' ? 2 : 0)));
    }

    if (simulation) simulation.stop();
    simulation = d3.forceSimulation(nodesToRender)
        .force("link", d3.forceLink(data.links).id(d => d.id).distance(90).strength(0.2))
        .force("charge", d3.forceManyBody().strength(-320).distanceMax(600))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(d => nodeRadius(d) + 8))
        .alphaDecay(0.035)
        .velocityDecay(0.65);

    // A 204-node cloud can extend past the SVG box, and a phone-sized
    // viewport reshapes it after the fact. Once a fresh layout settles,
    // zoom to its actual bounds; re-entering the tab doesn't refit, so
    // the operator's zoom survives tab switches.
    _graphNeedsFit = true;
    simulation.on("end", () => {
        if (_graphNeedsFit) {
            _graphNeedsFit = false;
            fitGraph();
        }
        // fitGraph animates the zoom for 400ms; measure labels once
        // the transform has landed.
        setTimeout(declutterGraphLabels, 450);
    });

    // Read theme-aware colors. Type is identity; risk is a halo.
    const typeHost = cssVar('--type-host');
    const typeUser = cssVar('--type-user');
    const typeSoftware = cssVar('--type-software');
    const textTertiary = cssVar('--text-tertiary');
    const bgPrimary = cssVar('--bg-primary');

    const link = root.append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(data.links)
        .enter().append("line")
        .attr("class", "link")
        .attr("stroke", d => d.type === 'uses' ? typeUser : textTertiary)
        .attr("stroke-width", d => d.type === 'uses' ? 1.2 : 0.9)
        .attr("stroke-opacity", d => d.type === 'uses' ? 0.22 : 0.10);

    const node = root.append("g")
        .attr("class", "nodes")
        .selectAll("g")
        .data(nodesToRender)
        .enter().append("g")
        .attr("class", "node")
        .attr("tabindex", 0)
        .attr("role", "button")
        .on("click", (event, d) => {
            if (typeof pathfinder !== 'undefined' && pathfinder.active) return;
            selectGraphNode(d);
        })
        .on("dblclick", (event, d) => {
            if (typeof pathfinder !== 'undefined' && pathfinder.active) return;
            event.preventDefault();
            expandNodeConnections(d);
        })
        .on("keydown", (event, d) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                selectGraphNode(d);
            }
        })
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));

    node.append("circle")
        .attr("class", "node-core")
        .attr("r", nodeRadius)
        .attr("fill", d => {
            if (d.type === 'host') return typeHost;
            if (d.type === 'user') return typeUser;
            return typeSoftware;
        })
        .attr("fill-opacity", 0.92)
        .attr("stroke", bgPrimary)
        .attr("stroke-width", 2);

    // Labels: only the busiest nodes at overview zoom. Everything else
    // labels on hover/selection, which is what kills the hairball.
    const labelled = new Set(
        [...nodesToRender]
            .sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0))
            .slice(0, 12)
            .map((n) => n.id)
    );

    // A separate layer drawn after the nodes: labels are inside the
    // node radius field, and a sibling circle would otherwise paint
    // over them. The 3px halo makes text legible on a node fill.
    const labelLayer = root.append("g").attr("class", "node-labels");
    const graphLabels = labelLayer.selectAll("text")
        .data(nodesToRender)
        .enter().append("text")
        .attr("class", "node-label")
        .attr("text-anchor", "middle")
        .attr("paint-order", "stroke")
        .attr("stroke", "var(--bg-primary)")
        .attr("stroke-linejoin", "round")
        .attr("pointer-events", "none")
        .style("display", d => labelled.has(d.id) ? null : 'none')
        .text(d => {
            const name = d.display_name || d.name || '';
            return name.length > 18 ? name.slice(0, 17) + '…' : name;
        });

    // Zooming out shrinks the graph but not the screen, so a 10px
    // label at k=0.5 was a 5px smudge with a halo thicker than its
    // stems. Counter-scale the type (and its offset) to keep every
    // label 10 screen pixels tall at any zoom level.
    function sizeGraphLabels() {
        const k = (_graphZoomTransform && _graphZoomTransform.k) || 1;
        graphLabels
            .attr('font-size', 11 / k)
            .attr('stroke-width', 2 / k)
            .attr('dy', (d) => -(nodeRadius(d) + 6 / k));
    }
    sizeGraphLabels();

    // The busiest nodes are not always neighbours: on the Fleet graph
    // a dozen indexers can share one 100px cluster, where twelve
    // labels stack into an unreadable block. Keep the highest-degree
    // labels and drop only the ones that physically collide. Zooming
    // in buys the space back, so this reruns when a zoom ends.
    function declutterGraphLabels() {
        const candidates = [...nodesToRender]
            .filter((d) => labelled.has(d.id))
            .sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0));
        const byId = new Map(graphLabels.nodes().map((el) => [d3.select(el).datum().id, el]));
        graphLabels.style('display', (d) => labelled.has(d.id) ? null : 'none');
        const placed = [];
        candidates.forEach((d) => {
            const el = byId.get(d.id);
            if (!el) return;
            el.style.display = '';
            const box = el.getBoundingClientRect();
            // Display bounds already include the node transform, so a
            // zero-size box means the label is off-layer and unmeasured.
            const clash = placed.some((p) =>
                box.left < p.right + 2 && box.right > p.left - 2 &&
                box.top < p.bottom + 2 && box.bottom > p.top - 2);
            if (clash) el.style.display = 'none';
            else placed.push(box);
        });
    }

    // Hover: light the neighbourhood, dim the rest. One shared tooltip
    // layer instead of per-node <title> (slow and invisible to AT).
    const neighbours = new Map();
    data.links.forEach((l) => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        if (!neighbours.has(s)) neighbours.set(s, new Set());
        if (!neighbours.has(t)) neighbours.set(t, new Set());
        neighbours.get(s).add(t);
        neighbours.get(t).add(s);
    });

    function clearGraphHover() {
        node.style('opacity', null);
        graphLabels.style('opacity', null);
        link.attr('stroke-opacity', d => d.type === 'uses' ? 0.22 : 0.10);
        link.attr('stroke-width', d => d.type === 'uses' ? 1.2 : 0.9);
        HOUND.tooltip.hide();
    }

    node
        .on('mouseenter', function (event, d) {
            const near = neighbours.get(d.id) || new Set();
            node.style('opacity', n => (n.id === d.id || near.has(n.id) ? 1 : 0.12));
            graphLabels.style('opacity', n => (n.id === d.id || near.has(n.id) ? 1 : 0.12));
            link.attr('stroke-opacity', l => {
                const s = typeof l.source === 'object' ? l.source.id : l.source;
                const t = typeof l.target === 'object' ? l.target.id : l.target;
                return (s === d.id || t === d.id) ? 0.85 : 0.03;
            });
            link.attr('stroke-width', l => {
                const s = typeof l.source === 'object' ? l.source.id : l.source;
                const t = typeof l.target === 'object' ? l.target.id : l.target;
                return (s === d.id || t === d.id) ? 1.8 : 0.6;
            });
            HOUND.tooltip.show(event.clientX, event.clientY, graphTooltipHtml(d, degree.get(d.id) || 0));
        })
        .on('mousemove', (event) => {
            HOUND.tooltip.move(event.clientX, event.clientY);
        })
        .on('mouseleave', clearGraphHover)
        .on('focus', function (event, d) {
            HOUND.tooltip.show(0, 0, graphTooltipHtml(d, degree.get(d.id) || 0), this.getBoundingClientRect());
        })
        .on('blur', () => HOUND.tooltip.hide());

    simulation.on("tick", () => {
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        node.attr("transform", d => `translate(${d.x},${d.y})`);
        labelLayer.selectAll('text').attr("transform", d => `translate(${d.x},${d.y})`);
    });

    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.1).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = event.x;
        d.fy = event.y;
    }

    // ---- zoom / pan ----
    // Without this, an 800-node graph on a 1440px screen is a fixed
    // postage stamp. Wheel zooms, drag pans, double-click is reserved
    // for expanding a node.
    _graphZoom = d3.zoom()
        .scaleExtent([0.15, 4])
        .on('zoom', (event) => {
            root.attr('transform', event.transform);
            _graphZoomTransform = event.transform;
            sizeGraphLabels();
        })
        .on('end', () => {
            if (typeof declutterGraphLabels === 'function') declutterGraphLabels();
        });

    svg.call(_graphZoom).on('dblclick.zoom', null);
    if (_graphZoomTransform) svg.call(_graphZoom.transform, _graphZoomTransform);

    svg.on('click', (event) => {
        if (event.target !== svg.node()) return;
        clearGraphSelection();
    });

    // Re-attach pathfinder click binding after re-render so the
    // click.pathfinder namespace stays alive across legitimate
    // re-renders (cluster toggle, host expand outside pick mode,
    // etc.). See debug/pathfinder-broken.md.
    if (typeof pathfinder !== 'undefined' && pathfinder.active) {
        _bindPathfinderClicks();
    }

    // Preserve selection across re-renders when the node survived.
    if (_graphSelected) {
        const still = nodesToRender.find((n) => n.id === _graphSelected.id);
        if (still) selectGraphNode(still);
        else clearGraphSelection();
    }
}

// ---- graph selection / focus ----

function graphTooltipHtml(d, deg) {
    const name = d.display_name || d.name || d.id;
    let html = `<div class="tooltip-title">${escapeHtml(name)}</div>`;
    html += `<div class="tooltip-row"><span>Type</span><strong>${escapeHtml(d.type)}</strong></div>`;
    html += `<div class="tooltip-row"><span>Connections</span><strong>${HOUND.fmt.int(deg || 0)}</strong></div>`;
    if (d.category && d.category.length) {
        html += `<div class="tooltip-row"><span>Category</span><strong>${escapeHtml(String(d.category).slice(0, 40))}</strong></div>`;
    }
    return html;
}

function showGraphSelection(d) {
    const card = document.getElementById('graph-selection');
    if (!card) return;
    const name = d.display_name || d.name || d.id;
    const typeLabel = d.type === 'host' ? 'Host' : d.type === 'user' ? 'Identity' : 'Software';
    document.getElementById('graph-selection-name').textContent = name;
    document.getElementById('graph-selection-type').textContent = typeLabel;
    document.getElementById('graph-selection-details').textContent = d.details || d.description || '—';
    card.hidden = false;
    card.dataset.nodeId = d.id;
    card.dataset.nodeName = name;
    card.dataset.nodeType = d.type;
}

function clearGraphSelection() {
    _graphSelected = null;
    _graphFocusId = null;
    const card = document.getElementById('graph-selection');
    if (card) card.hidden = true;
    d3.selectAll('#graph .node').classed('focus-dim', false).classed('selected', false);
    d3.selectAll('#graph .node-label').classed('focus-dim', false);
    d3.selectAll('#graph .link').classed('focus-dim', false);
}

function selectGraphNode(d) {
    _graphSelected = d;
    d3.selectAll('#graph .node').classed('selected', n => n.id === d.id);
    showGraphSelection(d);
    if (_graphFocusId) applyGraphFocus(d.id);
}

function applyGraphFocus(id) {
    _graphFocusId = id;
    const near = new Set([id]);
    (currentData.links || []).forEach((l) => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        if (s === id) near.add(t);
        if (t === id) near.add(s);
    });
    d3.selectAll('#graph .node').classed('focus-dim', n => !near.has(n.id));
    d3.selectAll('#graph .node-label').classed('focus-dim', (n) => !near.has(n.id));
    d3.selectAll('#graph .link').classed('focus-dim', (l) => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        return !(s === id || t === id);
    });
}

function clearGraphFocus() {
    _graphFocusId = null;
    d3.selectAll('#graph .node').classed('focus-dim', false);
    d3.selectAll('#graph .node-label').classed('focus-dim', false);
    d3.selectAll('#graph .link').classed('focus-dim', false);
}

function zoomGraphBy(factor) {
    const svgEl = document.querySelector('#graph svg');
    if (!svgEl || !_graphZoom) return;
    d3.select(svgEl).transition().duration(200).call(_graphZoom.scaleBy, factor);
}

function fitGraph() {
    const svgEl = document.querySelector('#graph svg');
    if (!svgEl || !_graphZoom || !simulation) return;
    const nodes = simulation.nodes().filter((n) => Number.isFinite(n.x) && Number.isFinite(n.y));
    if (!nodes.length) return;
    const pad = 56;
    const minX = Math.min(...nodes.map((n) => n.x));
    const maxX = Math.max(...nodes.map((n) => n.x));
    const minY = Math.min(...nodes.map((n) => n.y));
    const maxY = Math.max(...nodes.map((n) => n.y));
    const w = svgEl.clientWidth;
    const h = svgEl.clientHeight;
    const scale = Math.max(0.15, Math.min(2.5,
        Math.min((w - pad * 2) / Math.max(1, maxX - minX), (h - pad * 2) / Math.max(1, maxY - minY))
    ));
    const tx = w / 2 - scale * (minX + (maxX - minX) / 2);
    const ty = h / 2 - scale * (minY + (maxY - minY) / 2);
    const t = d3.zoomIdentity.translate(tx, ty).scale(scale);
    d3.select(svgEl).transition().duration(400).call(_graphZoom.transform, t);
}

function expandNodeConnections(clickedNode) {
    // Pathfinder mode owns node clicks — don't re-render the graph
    // mid-pick or the .click.pathfinder binding gets wiped along
    // with the old DOM. See debug/pathfinder-broken.md.
    if (typeof pathfinder !== 'undefined' && pathfinder.active) return;
    d3.selectAll('.node').classed('highlight-node', false);
    d3.selectAll('.link').classed('highlight-link', false);

    const isLatestExpand = beginRequest('expand');
    if (clickedNode.type === 'host') {
        showStatus(`Loading software for ${clickedNode.name}...`);
        const fidQS = clickedNode.fleet_host_id != null ? `?fleet_host_id=${encodeURIComponent(clickedNode.fleet_host_id)}` : '';
        fetch(`/api/host/${encodeURIComponent(clickedNode.name)}/software${fidQS}`)
            .then(response => response.ok ? response.json() : Promise.reject(new Error(`HTTP ${response.status}`)))
            .then(hostData => {
                if (!isLatestExpand()) return;
                hostData = hostData.nodes.length > GRAPH_RENDER_BUDGET ? capGraphForRender(hostData, GRAPH_RENDER_BUDGET) : hostData;
                currentData = hostData;
                renderGraph(hostData);
                setTimeout(() => {
                    d3.selectAll('.node').classed('highlight-node', d => d.id === clickedNode.id);
                }, 100);
                showStatus(`${clickedNode.name}: ${hostData.nodes.filter(n => n.type === 'software').length} software packages`);
            })
            .catch(error => {
                console.error('Error loading host data:', error);
                showStatus('Error loading host details', true);
                findAndShowConnections(clickedNode, allGraphData);
            });

    } else if (clickedNode.type === 'software') {
        const softwareLabel = clickedNode.display_name || clickedNode.name;
        showStatus(`Loading hosts with ${softwareLabel}...`);
        fetch(`/api/software/${encodeURIComponent(clickedNode.name)}/hosts`)
            .then(response => response.ok ? response.json() : Promise.reject(new Error(`HTTP ${response.status}`)))
            .then(softwareData => {
                if (!isLatestExpand()) return;
                softwareData = softwareData.nodes.length > GRAPH_RENDER_BUDGET ? capGraphForRender(softwareData, GRAPH_RENDER_BUDGET) : softwareData;
                currentData = softwareData;
                renderGraph(softwareData);
                setTimeout(() => {
                    d3.selectAll('.node').classed('highlight-node', d => d.id === clickedNode.id);
                }, 100);
                const hostCount = softwareData.nodes.filter(n => n.type === 'host').length;
                showStatus(`${softwareLabel} on ${hostCount} hosts`);
            })
            .catch(error => {
                console.error('Error loading software data:', error);
                showStatus('Error loading software details', true);
                findAndShowConnections(clickedNode, allGraphData);
            });

    } else {
        findAndShowConnections(clickedNode, allGraphData);
    }
}

function findAndShowConnections(clickedNode, dataSource) {
    const connectedLinks = dataSource.links.filter(link => {
        const sourceId = (typeof link.source === 'object') ? link.source.id : link.source;
        const targetId = (typeof link.target === 'object') ? link.target.id : link.target;
        return sourceId === clickedNode.id || targetId === clickedNode.id;
    });

    const connectedNodeIds = new Set([clickedNode.id]);
    connectedLinks.forEach(link => {
        connectedNodeIds.add((typeof link.source === 'object') ? link.source.id : link.source);
        connectedNodeIds.add((typeof link.target === 'object') ? link.target.id : link.target);
    });

    const connectedNodes = dataSource.nodes.filter(node => connectedNodeIds.has(node.id));

    if (connectedNodes.length > 1 && connectedLinks.length > 0) {
        const expandedData = { nodes: connectedNodes, links: connectedLinks };
        currentData = expandedData;
        renderGraph(expandedData);
        setTimeout(() => {
            d3.selectAll('.node').classed('highlight-node', d => d.id === clickedNode.id);
        }, 100);
        showStatus(`${connectedNodes.length} nodes, ${connectedLinks.length} connections for ${clickedNode.name}`);
    } else {
        highlightNode(clickedNode);
        showStatus(`${clickedNode.name} has no connections in current data`);
    }
}

function highlightNode(targetNode) {
    d3.selectAll('.node').classed('highlight-node', false);
    d3.selectAll('.link').classed('highlight-link', false);

    const connectedLinks = currentData.links.filter(link =>
        (link.source.id || link.source) === targetNode.id ||
        (link.target.id || link.target) === targetNode.id
    );

    const connectedNodeIds = new Set([targetNode.id]);
    connectedLinks.forEach(link => {
        connectedNodeIds.add(link.source.id || link.source);
        connectedNodeIds.add(link.target.id || link.target);
    });

    d3.selectAll('.node').classed('highlight-node', d => connectedNodeIds.has(d.id));
    d3.selectAll('.link').classed('highlight-link', d =>
        (d.source.id || d.source) === targetNode.id ||
        (d.target.id || d.target) === targetNode.id
    );
}

// ========================================
// SEARCH & FILTER
// ========================================
function searchNodes() {
    const searchTerm = document.getElementById('search-input').value.trim();
    const nodeTypeFilter = document.getElementById('node-type-filter').value;
    const platformFilter = document.getElementById('platform-filter').value;
    const teamFilter = document.getElementById('team-filter').value;

    // Cross-view label scope. Read FIRST so the early-return below
    // can include it — otherwise a user with active label scope
    // but no other filter would hit clearSearch and lose the scope.
    const _scope = SessionLabelScope.get();
    const _hasLabelScope = _scope.labels && _scope.labels.length > 0;

    if (!searchTerm && nodeTypeFilter === 'all'
        && platformFilter === 'all' && teamFilter === 'all'
        && !_hasLabelScope) {
        clearSearch();
        return;
    }

    if (nodeTypeFilter !== 'all' || searchTerm || teamFilter !== 'all' || _hasLabelScope) {
        const searchParam = searchTerm ? `q=${encodeURIComponent(searchTerm)}` : 'q=';
        const typeParam = `&type=${encodeURIComponent(nodeTypeFilter)}`;
        const platformParam = platformFilter !== 'all' ? `&platform=${encodeURIComponent(platformFilter)}` : '';
        const teamParam = teamFilter !== 'all' ? `&team=${encodeURIComponent(teamFilter)}` : '';
        const labelsParam = _hasLabelScope
            ? `&labels=${encodeURIComponent(_scope.labels.join(','))}&label_op=${encodeURIComponent(_scope.label_op || 'AND')}`
            : '';
        const modeParam = `&mode=${searchMode}`;
        const caseParam = `&case=${caseSensitive}`;

        let statusMsg = searchTerm ? `Searching for "${searchTerm}"` : `Loading ${nodeTypeFilter}s`;
        if (searchMode !== 'wildcard') statusMsg += ` (${searchMode})`;
        if (caseSensitive) statusMsg += ` (case sensitive)`;
        if (nodeTypeFilter !== 'all' && searchTerm) statusMsg += ` in ${nodeTypeFilter}s`;
        if (platformFilter !== 'all') statusMsg += ` on ${platformFilter}`;
        if (_hasLabelScope) statusMsg += ` (scoped to ${_scope.labels.length} label${_scope.labels.length === 1 ? '' : 's'})`;
        showStatus(statusMsg + '...');

        const isLatest = beginRequest('graph');
        fetch(`/api/search?${searchParam}${typeParam}${platformParam}${teamParam}${labelsParam}${modeParam}${caseParam}`)
            .then(response => response.json())
            .then(data => {
                if (!isLatest()) return;
                if (data.error) {
                    showStatus(`Search Error: ${data.message || data.error}`, true);
                    return;
                }

                if (data.nodes && data.nodes.length > 0) {
                    currentData = { nodes: data.nodes, links: data.links };
                    renderGraph(currentData, false);
                    let msg = `Found ${data.node_count} nodes`;
                    if (searchTerm) msg += ` matching "${searchTerm}"`;
                    msg += ` with ${data.link_count} connections`;
                    showStatus(msg);
                } else {
                    currentData = { nodes: [], links: [] };
                    renderGraph(currentData);
                    let msg = 'No results found';
                    if (searchTerm) msg += ` for "${searchTerm}"`;
                    showStatus(msg);
                }
            })
            .catch(error => {
                console.error('Error searching:', error);
                showStatus('Error searching, using local data', true);
                performLocalFiltering(searchTerm, nodeTypeFilter, platformFilter);
            });
    } else {
        performLocalFiltering(searchTerm, nodeTypeFilter, platformFilter);
    }
}

function performLocalFiltering(searchTerm, nodeTypeFilter, platformFilter) {
    let platformFilteredHosts = allGraphData.nodes.filter(node => {
        if (node.type !== 'host') return false;
        return platformFilter === 'all' || (node.details && node.details.toLowerCase().includes(platformFilter));
    });

    const platformFilteredHostIds = new Set(platformFilteredHosts.map(h => h.id));
    let connectedNodeIds = new Set(platformFilteredHostIds);

    allGraphData.links.forEach(link => {
        const sourceId = link.source.id || link.source;
        const targetId = link.target.id || link.target;
        if (link.type === 'uses' && platformFilteredHostIds.has(targetId)) connectedNodeIds.add(sourceId);
        if (link.type === 'installed' && platformFilteredHostIds.has(targetId)) connectedNodeIds.add(sourceId);
    });

    let matchingNodes = allGraphData.nodes.filter(node => {
        if (platformFilter !== 'all' && !connectedNodeIds.has(node.id)) return false;
        return !searchTerm || matchesSearch(node.name, searchTerm) || matchesSearch(node.display_name, searchTerm) || (node.details && matchesSearch(node.details, searchTerm));
    });

    let filteredNodes;
    if (nodeTypeFilter === 'all') {
        filteredNodes = matchingNodes;
    } else if (nodeTypeFilter === 'host') {
        filteredNodes = matchingNodes.filter(node =>
            node.type === 'host' || node.type === 'user' || node.type === 'software'
        );
    } else if (nodeTypeFilter === 'software') {
        const platformHostIds = new Set(platformFilteredHosts.map(h => h.id));
        const connectedSoftwareIds = new Set();
        allGraphData.links.forEach(link => {
            const sourceId = link.source.id || link.source;
            const targetId = link.target.id || link.target;
            if (link.type === 'installed' && platformHostIds.has(targetId)) connectedSoftwareIds.add(sourceId);
        });

        let matchingSoftware = searchTerm
            ? allGraphData.nodes.filter(node =>
                node.type === 'software' && connectedSoftwareIds.has(node.id) &&
                (matchesSearch(node.name, searchTerm) || matchesSearch(node.display_name, searchTerm) || (node.details && matchesSearch(node.details, searchTerm))))
            : allGraphData.nodes.filter(node => node.type === 'software' && connectedSoftwareIds.has(node.id));

        const softwareIds = new Set(matchingSoftware.map(s => s.id));
        const hostsConnectedToSoftware = new Set();
        allGraphData.links.forEach(link => {
            const sourceId = link.source.id || link.source;
            const targetId = link.target.id || link.target;
            if (link.type === 'installed' && softwareIds.has(sourceId) && platformHostIds.has(targetId)) {
                hostsConnectedToSoftware.add(targetId);
            }
        });
        filteredNodes = allGraphData.nodes.filter(node => softwareIds.has(node.id) || hostsConnectedToSoftware.has(node.id));
    } else if (nodeTypeFilter === 'user') {
        const platformHostIds = new Set(platformFilteredHosts.map(h => h.id));
        const connectedUserIds = new Set();
        allGraphData.links.forEach(link => {
            const sourceId = link.source.id || link.source;
            const targetId = link.target.id || link.target;
            if (link.type === 'uses' && platformHostIds.has(targetId)) connectedUserIds.add(sourceId);
        });

        let matchingUsers = allGraphData.nodes.filter(node => {
            if (node.type !== 'user' || !connectedUserIds.has(node.id)) return false;
            if (!searchTerm) return true;
            return matchesSearch(node.name, searchTerm) || (node.details && matchesSearch(node.details, searchTerm));
        });

        const userIds = new Set(matchingUsers.map(u => u.id));
        const hostsConnectedToUsers = new Set();
        allGraphData.links.forEach(link => {
            const sourceId = link.source.id || link.source;
            const targetId = link.target.id || link.target;
            if (link.type === 'uses' && userIds.has(sourceId) && platformHostIds.has(targetId)) {
                hostsConnectedToUsers.add(targetId);
            }
        });
        filteredNodes = allGraphData.nodes.filter(node => userIds.has(node.id) || hostsConnectedToUsers.has(node.id));
    } else {
        filteredNodes = matchingNodes.filter(node => node.type === nodeTypeFilter);
    }

    const nodeIds = new Set(filteredNodes.map(n => n.id));
    let filteredLinks = allGraphData.links.filter(link =>
        nodeIds.has(link.source.id || link.source) && nodeIds.has(link.target.id || link.target)
    );

    currentData = { nodes: filteredNodes, links: filteredLinks };
    renderGraph(currentData, false);
    showStatus(`Found ${filteredNodes.length} nodes, ${filteredLinks.length} connections`);
}

function clearSearch() {
    document.getElementById('search-input').value = '';
    document.getElementById('node-type-filter').value = 'all';
    document.getElementById('platform-filter').value = 'all';
    document.getElementById('team-filter').value = 'all';
    d3.selectAll('.node').classed('highlight-node', false);
    d3.selectAll('.link').classed('highlight-link', false);
    currentData = allGraphData;
    renderGraph(allGraphData);
    showStatus(`All data: ${allGraphData.nodes.length} nodes, ${allGraphData.links.length} connections`);
}

function centerGraph() {
    if (simulation) {
        simulation.nodes().forEach(node => {
            if (!node.fx && !node.fy) {
                node.x = 400 + (Math.random() - 0.5) * 200;
                node.y = 300 + (Math.random() - 0.5) * 200;
                node.vx = 0;
                node.vy = 0;
            }
        });
        simulation.alpha(0.3).restart();
        showStatus('Graph centered');
    }
}

function resetToOverview() {
    clearSearch();
    loadGraph();
}

function resetPositions() {
    if (simulation) {
        simulation.nodes().forEach(node => {
            node.x = 400 + (Math.random() - 0.5) * 400;
            node.y = 300 + (Math.random() - 0.5) * 400;
            node.vx = 0;
            node.vy = 0;
            node.fx = null;
            node.fy = null;
        });
        simulation.alpha(0.5).restart();
        showStatus('Positions reset');
    }
}

// ========================================
// EXPORT
// ========================================
function exportAsJSON() {
    if (!currentData || currentData.nodes.length === 0) { showStatus('No data to export', true); return; }
    const dataStr = JSON.stringify(currentData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `fleet-hound-export-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showStatus(`Exported ${currentData.nodes.length} nodes as JSON`);
}

function exportAsCSV() {
    if (!currentData || currentData.nodes.length === 0) { showStatus('No data to export', true); return; }
    let csv = '# NODES\nid,name,type,details\n';
    currentData.nodes.forEach(node => {
        const details = (node.details || '').replace(/"/g, '""');
        csv += `"${node.id}","${node.name}","${node.type}","${details}"\n`;
    });
    csv += '\n# RELATIONSHIPS\nsource,target,type\n';
    currentData.links.forEach(link => {
        const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
        const targetId = typeof link.target === 'object' ? link.target.id : link.target;
        csv += `"${sourceId}","${targetId}","${link.type || 'CONNECTED'}"\n`;
    });
    const dataBlob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `fleet-hound-export-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showStatus(`Exported ${currentData.nodes.length} nodes as CSV`);
}

// ========================================
// VIEW ROUTER
// ========================================
// Single source of truth for tab state. Each view declares its own
// enter/exit work; nothing monkey-patches switchView from the bottom
// of the file anymore (that pattern silently broke whenever a tab was
// added). Adding a view = add a tab with data-view + an entry here.
const VIEWS = {
    overview: {
        onEnter() { if (HOUND.overview) HOUND.overview.enter(); },
        onExit() { if (HOUND.overview) HOUND.overview.exit(); },
    },
    graph: {
        onEnter() {
            if (_graphPending) {
                const pending = _graphPending;
                _graphPending = null;
                renderGraph(pending.data, pending.filterDisconnected);
            } else if (simulation) {
                const host = document.getElementById('graph');
                const resized = !_graphSize || !host
                    || host.clientWidth !== _graphSize.w
                    || host.clientHeight !== _graphSize.h;
                // SVG coordinates are absolute, so a container sized on
                // a desktop viewport clips the graph on a phone until
                // it is laid out again.
                if (resized) renderGraph(currentData);
                else simulation.alpha(0.1).restart();
            }
            // If the cross-view label scope changed while the user was
            // on another tab, flush the stale graph now.
            if (typeof _graphScopeStale !== 'undefined' && _graphScopeStale) {
                _graphScopeStale = false;
                if (typeof loadGraph === 'function') loadGraph();
            }
        },
        onExit() { if (simulation) simulation.stop(); },
    },
    'blast-radius': {
        onEnter() {
            if (typeof _blastEntitiesStale !== 'undefined' && _blastEntitiesStale) {
                _blastEntitiesStale = false;
                if (typeof loadBlastEntities === 'function') loadBlastEntities();
            }
            const list = document.getElementById('blast-entity-list');
            if (list && list.children.length <= 1) loadBlastEntities();
        },
    },
    'shadow-it': {
        onEnter() {
            if (!window.shadowITLoaded) {
                window.shadowITLoaded = true;
                loadShadowITDetections();
            }
        },
    },
    extensions: {
        onEnter() {
            if (!window._extensionsLoaded) {
                window._extensionsLoaded = true;
                loadExtensions();
            }
        },
    },
    changes: {
        onEnter() {
            if (!window._changesLoaded) {
                window._changesLoaded = true;
                loadSnapshots().then(_populateSnapshotPickers);
                const btn = document.getElementById('diff-run-btn');
                if (btn) btn.addEventListener('click', runDiff);
                _wireChangesFilterUI();
            }
        },
    },
};

let activeView = null;

function switchView(view) {
    const target = document.getElementById(view + '-view');
    if (!target) return;

    if (activeView === view) {
        if (VIEWS[view] && VIEWS[view].onEnter) VIEWS[view].onEnter();
        return;
    }

    const previous = activeView;
    if (previous && VIEWS[previous] && VIEWS[previous].onExit) {
        try { VIEWS[previous].onExit(); } catch (e) { console.warn('view exit failed', e); }
    }

    document.querySelectorAll('.view-container').forEach((el) => el.classList.remove('active'));
    target.classList.add('active');

    document.querySelectorAll('[role="tab"][data-view]').forEach((tab) => {
        const active = tab.dataset.view === view;
        tab.classList.toggle('active', active);
        tab.setAttribute('aria-selected', active ? 'true' : 'false');
        tab.setAttribute('tabindex', active ? '0' : '-1');
    });

    const graphToolbar = document.getElementById('graph-toolbar');
    if (graphToolbar) graphToolbar.style.display = view === 'graph' ? 'flex' : 'none';
    const graphView = document.getElementById('graph-view');
    if (graphView) graphView.classList.toggle('with-toolbar', view === 'graph');

    activeView = view;
    HOUND.store.set('hound.lastView', view);

    if (VIEWS[view] && VIEWS[view].onEnter) {
        try { VIEWS[view].onEnter(); } catch (e) { console.error('view enter failed', e); }
    }
}

// ========================================
// BLAST RADIUS
// ========================================
let blastEntities = [];
let blastSeedLabel = '';
let searchTimeout;

// Build the team + label scope params shared by both
// loadBlastEntities and filterBlastEntities. Without this the
// Blast Radius sidebar listed every software/user in the graph
// even when the operator had scoped to "Domain Controllers" —
// making the list useless for picking entities that are actually
// in the active scope. (May 2026 fix.)
function _blastScopeQS() {
    const params = new URLSearchParams();
    const teamEl = document.getElementById('blast-team-filter');
    if (teamEl && teamEl.value && teamEl.value !== 'all') {
        params.set('team', teamEl.value);
    }
    const scope = SessionLabelScope.get();
    if (scope.labels && scope.labels.length > 0) {
        params.set('labels', scope.labels.join(','));
        params.set('label_op', scope.label_op || 'AND');
    }
    return params;
}

function loadBlastEntities() {
    const type = document.getElementById('blast-type-selector').value;
    const listContainer = document.getElementById('blast-entity-list');
    listContainer.innerHTML = '<div class="loading-state">Loading...</div>';
    document.getElementById('blast-search').value = '';

    const scopeQs = _blastScopeQS();
    scopeQs.set('type', type);
    scopeQs.set('limit', '1000');

    const isLatest = beginRequest('blastList');
    fetch(`/api/search?${scopeQs.toString()}`)
        .then(res => res.json())
        .then(data => {
            if (!isLatest()) return;
            blastEntities = data.nodes.filter(n => n.type === type);
            renderBlastList(blastEntities, true);
        })
        .catch(err => {
            console.error("Error loading entities:", err);
            listContainer.innerHTML = '<div class="loading-state" style="color: var(--danger);">Error loading entities</div>';
        });
}

function renderBlastList(entities, autoSelect) {
    const listContainer = document.getElementById('blast-entity-list');
    listContainer.innerHTML = '';

    if (entities.length === 0) {
        listContainer.innerHTML = '<div class="loading-state">No entities found</div>';
        return;
    }

    entities.sort((a, b) => a.name.localeCompare(b.name));

    entities.forEach(entity => {
        const item = document.createElement('div');
        item.className = 'entity-item';
        item.innerHTML = `
            <div class="flex-1">
                <div class="entity-name">${escapeHtml(entity.name)}</div>
                <div class="entity-meta">${escapeHtml(entity.details || '')}</div>
            </div>
        `;
        item.onclick = () => selectBlastEntity(entity, item);
        listContainer.appendChild(item);
    });

    // Opening Blast Radius used to land on 1,000 entities and an empty
    // diagram until something was clicked. Seed the first entity on
    // the initial load; an explicit pick (Graph → Blast radius) has
    // already set selectedEntityId and wins.
    if (autoSelect && !selectedEntityId) {
        // Skip UUIDs and names with no visible letter/digit (Fleet reports
        // some software named just U+200E).
        const starter = entities.find((e) => /[\p{L}\p{N}]/u.test(e.name) && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(e.name)) || entities[0];
        const item = listContainer.querySelectorAll('.entity-item')[entities.indexOf(starter)];
        if (item && starter) selectBlastEntity(starter, item);
    }
}

function filterBlastEntities() {
    const term = document.getElementById('blast-search').value.toLowerCase();
    const type = document.getElementById('blast-type-selector').value;

    clearTimeout(searchTimeout);
    if (!term) { loadBlastEntities(); return; }

    searchTimeout = setTimeout(() => {
        const listContainer = document.getElementById('blast-entity-list');
        listContainer.innerHTML = '<div class="loading-state">Searching...</div>';

        const scopeQs = _blastScopeQS();
        scopeQs.set('type', type);
        scopeQs.set('q', term);
        scopeQs.set('limit', '100');
        const isLatest = beginRequest('blastList');
        fetch(`/api/search?${scopeQs.toString()}`)
            .then(res => res.json())
            .then(data => {
                if (!isLatest()) return;
                const results = data.nodes.filter(n => n.type === type);
                renderBlastList(results);
            })
            .catch(err => {
                listContainer.innerHTML = '<div class="loading-state" style="color: var(--danger);">Error searching</div>';
            });
    }, 300);
}

let selectedEntityId = null;

function selectBlastEntity(entity, domElement) {
    document.querySelectorAll('.entity-item').forEach(el => el.classList.remove('active'));
    domElement.classList.add('active');
    selectedEntityId = entity.name;
    blastSeedLabel = entity.display_name || entity.name;
    calculateBlastRadius(entity.type, entity.name, blastSeedLabel);
}

function calculateBlastRadius(type, id, label) {
    if (!type || !id) {
        if (!selectedEntityId) return;
        type = document.getElementById('blast-type-selector').value;
        id = selectedEntityId;
    }
    // The API returns no name for the seed, so remember the label the
    // operator picked; falling back to the id would show a raw UUID.
    blastSeedLabel = label || id;
    selectedEntityId = id;

    const teamFilter = document.getElementById('blast-team-filter').value;
    const ignoreDefaults = document.getElementById('ignore-defaults-toggle').checked;
    const blastWidget = document.querySelector('.label-widget[data-view="blast"]');
    const labelScope = readLabelFilter(blastWidget);

    showStatus(`Calculating blast radius for ${id}...`);

    let exclusionParams = '';
    if (ignoreDefaults) {
        const allExcluded = [...new Set([...DEFAULT_ACCOUNTS, ...customExclusions])];
        if (allExcluded.length > 0) exclusionParams = `&excluded_users=${encodeURIComponent(allExcluded.join(','))}`;
    }

    const labelParams = labelScope.labels
        ? `&labels=${encodeURIComponent(labelScope.labels)}&label_op=${encodeURIComponent(labelScope.label_op)}`
        : '';

    const isLatest = beginRequest('blast');
    fetch(`/api/blast-radius?type=${encodeURIComponent(type)}&id=${encodeURIComponent(id)}&team=${encodeURIComponent(teamFilter)}&ignore_defaults=${ignoreDefaults}${exclusionParams}${labelParams}`)
        .then(res => res.json())
        .then(data => {
            if (!isLatest()) return;
            if (data.error) throw new Error(data.error);
            updateBlastMetrics(data);
            renderBlastDiagram(data);
            updateBlastDetails(data);
            showStatus(`Blast radius calculated for ${id}`);
        })
        .catch(err => {
            console.error("Blast radius error:", err);
            showStatus("Error calculating blast radius", true);
        });
}

function openExclusionSettings() {
    document.getElementById('custom-exclusion-list').value = customExclusions.join(', ');
    document.getElementById('exclusion-modal').classList.add('visible');
}

function closeExclusionSettings() {
    document.getElementById('exclusion-modal').classList.remove('visible');
}

function saveExclusionSettings() {
    const input = document.getElementById('custom-exclusion-list').value;
    customExclusions = input.split(',').map(s => s.trim()).filter(s => s.length > 0);
    localStorage.setItem('customExclusions', JSON.stringify(customExclusions));
    closeExclusionSettings();
    if (document.getElementById('ignore-defaults-toggle').checked) calculateBlastRadius();
    showStatus(`Saved ${customExclusions.length} custom exclusions`);
}

function loadExclusionSettings() {
    // Storage can be blocked entirely (Safari "block all cookies",
    // private windows, enterprise policy). A throw here would abort
    // the whole DOMContentLoaded handler and leave a blank shell.
    try {
        const saved = localStorage.getItem('customExclusions');
        if (saved) {
            try { customExclusions = JSON.parse(saved); }
            catch (e) { customExclusions = []; }
        }
    } catch (e) {
        customExclusions = [];
    }
}

// ========================================
// TEAMS & PLATFORMS
// ========================================
function loadTeams() {
    fetch('/api/teams')
        .then(response => {
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        })
        .then(teams => {
            const teamFilter = document.getElementById('team-filter');
            const blastTeamFilter = document.getElementById('blast-team-filter');
            const shadowTeamFilter = document.getElementById('shadow-team-filter-new');

            if (!teamFilter) return;

            while (teamFilter.options.length > 1) teamFilter.remove(1);
            if (blastTeamFilter) while (blastTeamFilter.options.length > 1) blastTeamFilter.remove(1);
            if (shadowTeamFilter) {
                // Default to the whole fleet: an empty Scope on first
                // visit reads as a broken panel, and "All Teams" is a
                // real, labelled scope — never inferred data.
                shadowTeamFilter.innerHTML = `<option value="" disabled>Select Team (${teams.length})</option><option value="all" selected>All Teams</option>`;
            }

            teams.forEach(team => {
                const option = document.createElement('option');
                option.value = team.id;
                option.textContent = team.name;
                teamFilter.appendChild(option);
                if (blastTeamFilter) blastTeamFilter.appendChild(option.cloneNode(true));
                if (shadowTeamFilter) shadowTeamFilter.appendChild(option.cloneNode(true));
            });

            // Deep-link straight into Shadow IT: its first load ran
            // before the team list arrived and saw no scope.
            if (activeView === 'shadow-it') loadShadowITDetections();
        })
        .catch(error => console.error('Error loading teams:', error));
}

// ========================================
// LABELS — Variant C widget (plan-design-review approved 2026-05-07)
// ========================================
// Searchable checkbox list + segmented AND/OR + scope readout with
// pre-flight host count. Replaces the prior <select multiple> impl.
//
// The module exports:
//   - createLabelWidget(container, opts)  — bind one widget to a
//     `.label-widget` container; returns an instance with getScope()
//     and refresh() methods.
//   - readLabelFilter(widget)             — backward-compat helper
//     used by calculateBlastRadius / loadShadowITDetections to
//     produce the {labels, label_op} pair for URL params.
//   - loadLabels()                        — fetches /api/labels and
//     refreshes every widget on the page.
//
// State per widget instance: { labels[], selected:Set, mode, search,
// hostCount, altCount, altMode, lastLabelLoad }. State is local —
// selection does NOT persist cross-view (per existing team/platform
// pattern; cross-view persistence is TODO-3).
// ========================================

const _labelWidgetRegistry = new Map();
let _labelDataCache = null;
let _labelDataLoadedAt = 0;

// ========================================
// SessionLabelScope (TODO-3) — cross-view label selection
// ========================================
// Single source of truth for the active label scope across views.
// Backed by sessionStorage so the scope survives in-SPA tab switches
// but resets on a fresh page load (intentional — full reload =
// clean slate). Each `.label-widget` reads on mount, writes on
// change, and subscribes to changes from sibling widgets so all
// instances stay in lockstep.
// ========================================
const SessionLabelScope = (function () {
    const KEY = 'fleethound.labelScope';
    let listeners = [];
    function read() {
        try {
            const raw = sessionStorage.getItem(KEY);
            if (raw) {
                const parsed = JSON.parse(raw);
                if (parsed && Array.isArray(parsed.labels)) {
                    return {
                        labels: parsed.labels,
                        label_op: parsed.label_op === 'OR' ? 'OR' : 'AND',
                    };
                }
            }
        } catch (e) { /* ignore — fall through to default */ }
        return { labels: [], label_op: 'AND' };
    }
    function write(scope) {
        try {
            if (!scope.labels || scope.labels.length === 0) {
                sessionStorage.removeItem(KEY);
            } else {
                sessionStorage.setItem(KEY, JSON.stringify(scope));
            }
        } catch (e) { /* sessionStorage may be disabled — degrade gracefully */ }
        notify(scope);
    }
    function notify(scope) {
        listeners.forEach(fn => {
            try { fn(scope); } catch (e) { console.warn('SessionLabelScope listener:', e); }
        });
    }
    return {
        get() { return read(); },
        set(scope) { write(scope); },
        clear() { write({ labels: [], label_op: 'AND' }); },
        subscribe(fn) {
            listeners.push(fn);
            return () => { listeners = listeners.filter(l => l !== fn); };
        },
    };
})();

// ========================================
// ActiveScopeBanner (TODO-3) — visible cross-view scope indicator
// ========================================
function _initActiveScopeBanner() {
    const banner = document.getElementById('active-scope-banner');
    const labelsEl = document.getElementById('active-scope-labels');
    const modeEl = document.getElementById('active-scope-mode');
    const clearBtn = document.getElementById('active-scope-clear');
    if (!banner || !labelsEl || !modeEl || !clearBtn) return;

    function render(scope) {
        const hasScope = scope && scope.labels && scope.labels.length > 0;
        if (!hasScope) {
            // Empty state — banner stays in DOM with muted styling
            // so toolbar position stays stable (no layout shift on
            // clear, which was reading as "everything reset").
            banner.classList.add('empty');
            labelsEl.textContent = 'none';
            modeEl.textContent = 'pick labels on Graph / Blast Radius / Shadow IT to scope this view';
            clearBtn.hidden = true;
            return;
        }
        banner.classList.remove('empty');
        clearBtn.hidden = false;
        const previewMax = 3;
        const display = scope.labels.length <= previewMax
            ? scope.labels.join(', ')
            : `${scope.labels.slice(0, previewMax).join(', ')} +${scope.labels.length - previewMax} more`;
        labelsEl.textContent = display;
        const modeText = scope.label_op === 'OR' ? 'Match any' : 'Match all';
        modeEl.textContent = `(${modeText} · ${scope.labels.length} label${scope.labels.length === 1 ? '' : 's'})`;
    }
    clearBtn.addEventListener('click', () => {
        // CONTRACT: Clear scope removes LABEL scope only.
        // Team / platform / type / search filters in the toolbar
        // are independent and stay exactly as the user set them.
        // The cascade fetches (loadGraph, loadBlastEntities,
        // calculateBlastRadius, loadShadowITDetections) all read
        // the toolbar values fresh on each call.
        SessionLabelScope.clear();
        if (typeof showStatus === 'function') {
            showStatus('Label scope cleared. Team / platform / type filters preserved.');
        }
    });
    SessionLabelScope.subscribe(render);
    render(SessionLabelScope.get());
}
// Wire the banner once at module-load time. Safe to call multiple times
// — early-returns when DOM is not yet present.
if (document.readyState !== 'loading') {
    _initActiveScopeBanner();
} else {
    document.addEventListener('DOMContentLoaded', _initActiveScopeBanner);
}

// Graph view auto-refresh: when the cross-view label scope changes
// (e.g., user picks labels on Shadow IT, switches to Graph), re-fetch
// the graph so node/edge visibility matches the active scope.
//
// The visibility check uses .classList.contains('active') because
// the view-container hide mechanism is CSS-class-based (`.active`
// toggles `display: block`). The earlier `style.display === 'none'`
// check read inline style — which is empty regardless — so it always
// reported "visible" and refreshed even when the user wasn't on the
// Graph view. Worse, when the user later SWITCHED to Graph, no
// refresh fired because the scope-change event was already
// consumed. Result: stale unfiltered graph.
//
// Fix is two-fold:
//   1. Use the right visibility check.
//   2. Track a `_graphScopeStale` flag when scope changes while
//      Graph view is hidden, and force a reload on switchView('graph').
let _graphRefreshTimer = null;
let _graphScopeStale = false;
function _isGraphViewActive() {
    const graphView = document.getElementById('graph-view');
    return !!(graphView && graphView.classList.contains('active'));
}
function _scheduleGraphRefresh(reason) {
    if (typeof loadGraph !== 'function') return;
    if (!_isGraphViewActive()) {
        // Defer: mark stale so the next switch-to-Graph picks it up.
        _graphScopeStale = true;
        return;
    }
    if (_graphRefreshTimer) clearTimeout(_graphRefreshTimer);
    _graphRefreshTimer = setTimeout(() => {
        _graphRefreshTimer = null;
        _graphScopeStale = false;
        loadGraph();
    }, 250);
}
// Subscribe Graph-view refresh to SessionLabelScope changes.
// SessionLabelScope is defined earlier in this module; safe to call
// at module load time.
SessionLabelScope.subscribe(() => _scheduleGraphRefresh('label-scope-change'));

// Graph view label picker — popover toggled from the toolbar
// "Labels" button. Closes on outside click and Escape.
function toggleGraphLabelsPopover(forceState) {
    const pop = document.getElementById('graph-labels-popover');
    const btn = document.getElementById('graph-labels-toggle');
    if (!pop || !btn) return;
    const willOpen = (forceState !== undefined)
        ? !!forceState
        : pop.hidden;
    pop.hidden = !willOpen;
    btn.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
}
document.addEventListener('click', e => {
    const pop = document.getElementById('graph-labels-popover');
    const btn = document.getElementById('graph-labels-toggle');
    if (!pop || pop.hidden) return;
    if (pop.contains(e.target) || (btn && btn.contains(e.target))) return;
    toggleGraphLabelsPopover(false);
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') toggleGraphLabelsPopover(false);
});

// Toolbar count badge — shows the active label count next to the
// "Labels" button so the user sees scope state at a glance even
// when the popover is closed.
function _updateGraphLabelsCount(scope) {
    const badge = document.getElementById('graph-labels-count');
    if (!badge) return;
    const n = (scope && scope.labels && scope.labels.length) || 0;
    if (n === 0) {
        badge.hidden = true;
    } else {
        badge.hidden = false;
        badge.textContent = String(n);
    }
}
SessionLabelScope.subscribe(_updateGraphLabelsCount);
if (document.readyState !== 'loading') {
    _updateGraphLabelsCount(SessionLabelScope.get());
} else {
    document.addEventListener('DOMContentLoaded', () =>
        _updateGraphLabelsCount(SessionLabelScope.get()));
}

// Blast Radius sidebar: reload the entity list when label scope or
// team filter changes so the picker reflects only entities actually
// in scope. Without this, the operator picks "Domain Controllers"
// and still sees `acl`, `adduser`, `Adobe Refresh Manager`, etc. —
// none of which are on a DC. Debounced; only fires when the entity
// list is actually mounted.
let _blastEntitiesRefreshTimer = null;
let _blastEntitiesStale = false;
function _isBlastViewActive() {
    const view = document.getElementById('blast-radius-view');
    return !!(view && view.classList.contains('active'));
}
function _scheduleBlastEntitiesRefresh() {
    if (typeof loadBlastEntities !== 'function') return;
    if (!document.getElementById('blast-entity-list')) return;
    // Same fix as the Graph view: visibility is class-based, not
    // inline-style-based. Mark stale and flush on next switchView.
    if (!_isBlastViewActive()) {
        _blastEntitiesStale = true;
        return;
    }
    if (_blastEntitiesRefreshTimer) clearTimeout(_blastEntitiesRefreshTimer);
    _blastEntitiesRefreshTimer = setTimeout(() => {
        _blastEntitiesRefreshTimer = null;
        _blastEntitiesStale = false;
        loadBlastEntities();
    }, 250);
}
SessionLabelScope.subscribe(_scheduleBlastEntitiesRefresh);
function _wireBlastTeamRefresh() {
    const teamEl = document.getElementById('blast-team-filter');
    if (teamEl && !teamEl.dataset.wiredBlastRefresh) {
        teamEl.addEventListener('change', _scheduleBlastEntitiesRefresh);
        teamEl.dataset.wiredBlastRefresh = '1';
    }
}
if (document.readyState !== 'loading') {
    _wireBlastTeamRefresh();
} else {
    document.addEventListener('DOMContentLoaded', _wireBlastTeamRefresh);
}

// Wire the team-filter dropdown to also trigger a Graph refresh when
// the user changes selection. The team-filter is the Graph view's
// primary scope control today; without this hook, switching teams
// didn't actually re-query the graph.
function _wireGraphFilterRefresh() {
    const teamEl = document.getElementById('team-filter');
    if (teamEl && !teamEl.dataset.wiredGraphRefresh) {
        teamEl.addEventListener('change', () => _scheduleGraphRefresh('team-filter-change'));
        teamEl.dataset.wiredGraphRefresh = '1';
    }
}
if (document.readyState !== 'loading') {
    _wireGraphFilterRefresh();
} else {
    document.addEventListener('DOMContentLoaded', _wireGraphFilterRefresh);
}


async function _fetchLabels(force) {
    const now = Date.now();
    if (!force && _labelDataCache && (now - _labelDataLoadedAt) < 30000) {
        return _labelDataCache;
    }
    const resp = await fetch('/api/labels');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    _labelDataCache = await resp.json();
    _labelDataLoadedAt = now;
    return _labelDataCache;
}

async function _fetchScopeCount(scope) {
    // Pre-flight count for zero-host UX. Returns
    // {count, alt_count, alt_label_op} so the widget can render
    // the "Switch to OR (matches N hosts)" CTA without a 2nd round-trip.
    const params = new URLSearchParams();
    if (scope.labels) {
        params.set('labels', scope.labels);
        params.set('label_op', scope.label_op);
        params.set('include_alt', 'true');
    }
    const resp = await fetch(`/api/labels/scope-count?${params}`);
    if (!resp.ok) return null;
    return await resp.json();
}

function createLabelWidget(container, opts) {
    const onChange = (opts && opts.onChange) || function () {};
    const view = container.dataset.view || 'unknown';

    // Restore from cross-view session scope (TODO-3) on mount.
    const sessionScope = SessionLabelScope.get();

    const state = {
        labels: [],
        selected: new Set(sessionScope.labels || []),
        mode: sessionScope.label_op || 'AND',
        search: '',
        count: null,
        altCount: null,
        altMode: null,
        error: null,
        loading: true,
        _suppressNextSessionWrite: false,
    };

    // Lookup elements once.
    const elList = container.querySelector('.label-list');
    const elSearch = container.querySelector('.label-search');
    const elSegmented = container.querySelector('.segmented');
    const elSegBtns = elSegmented
        ? Array.from(elSegmented.querySelectorAll('button[data-op]'))
        : [];
    const elReadout = container.querySelector('.scope-readout');
    const elClear = container.querySelector('.label-widget-clear');
    const elStaleBanner = container.querySelector('.label-stale-banner');
    const elAnnouncer = container.querySelector('.sr-only');

    function getScope() {
        const names = Array.from(state.selected);
        return {
            labels: names.join(','),
            label_op: state.mode,
            count: names.length,
        };
    }

    function announce(msg) {
        if (elAnnouncer) elAnnouncer.textContent = msg;
    }

    function renderList() {
        if (state.loading) {
            elList.innerHTML = `
                <div class="label-skeleton">
                    <div class="label-skeleton-row"></div>
                    <div class="label-skeleton-row" style="width:80%"></div>
                    <div class="label-skeleton-row" style="width:65%"></div>
                    <div class="label-skeleton-row" style="width:90%"></div>
                </div>`;
            return;
        }
        if (state.error) {
            elList.innerHTML = `
                <div class="label-stale-banner" style="border-left-color:var(--danger);background:rgba(229,72,77,0.1);">
                    <strong style="color:var(--danger);">Backend unavailable.</strong><br>
                    ${escapeHtml(state.error)}
                </div>`;
            return;
        }
        if (state.labels.length === 0) {
            elList.innerHTML = `
                <div class="label-empty">
                    <strong>No labels yet</strong>
                    Define labels in Fleet to scope investigations by Shadow IT, asset criticality, or any custom grouping.
                </div>`;
            return;
        }
        const q = state.search.trim().toLowerCase();
        const filtered = q
            ? state.labels.filter(l => l.name.toLowerCase().includes(q))
            : state.labels;
        if (filtered.length === 0) {
            elList.innerHTML = `
                <div class="label-search-empty">
                    No labels match &ldquo;${escapeHtml(state.search)}&rdquo;.
                    <button type="button" class="label-search-clear">Clear search</button>
                </div>`;
            return;
        }
        elList.innerHTML = filtered.map(lbl => {
            const sel = state.selected.has(lbl.name);
            const stale = lbl.last_label_sync_status &&
                          lbl.last_label_sync_status !== 'ok';
            const staleAria = stale
                ? ` Sync stale; last successful sync ${escapeHtml(lbl.last_synced_iso || 'unknown')}.`
                : '';
            return `
                <li class="label-row${sel ? ' selected' : ''}"
                    role="option"
                    aria-selected="${sel ? 'true' : 'false'}"
                    tabindex="0"
                    data-name="${escapeHtml(lbl.name)}"
                    title="${escapeHtml(lbl.name)}${staleAria}">
                    <span class="label-cb" aria-hidden="true"></span>
                    <span class="label-name">${escapeHtml(lbl.name)}</span>
                    <span class="label-count">${lbl.host_count || 0}</span>
                    ${stale
                        ? `<span class="stale-dot" role="img" aria-label="Sync stale; last sync ${escapeHtml(lbl.last_synced_iso || 'unknown')}"></span>`
                        : ''}
                </li>`;
        }).join('');
    }

    function renderClear() {
        if (!elClear) return;
        elClear.hidden = state.selected.size === 0;
    }

    function renderSegmented() {
        if (!elSegmented) return;
        elSegmented.hidden = state.selected.size < 2;
        elSegBtns.forEach(b => {
            const active = b.dataset.op === state.mode;
            b.classList.toggle('active', active);
            b.setAttribute('aria-checked', active ? 'true' : 'false');
            b.tabIndex = active ? 0 : -1;
        });
    }

    function renderReadout() {
        if (!elReadout) return;

        if (state.selected.size === 0) {
            elReadout.classList.add('empty');
            elReadout.innerHTML = `
                <strong>Pick labels to scope this view.</strong><br>
                Match all = narrow (AND), Match any = broad (OR).`;
            return;
        }

        elReadout.classList.remove('empty');
        const total = state.labels.length;
        const sel = state.selected.size;
        const modeLabel = state.mode === 'AND' ? 'AND mode' : 'OR mode';

        if (state.count === 0 && state.altCount && state.altCount > 0) {
            // Zero-host result with non-zero alt
            const altLabel = state.altMode === 'AND' ? 'all' : 'any';
            elReadout.innerHTML = `
                <strong>0 hosts</strong> match this filter.
                Try <strong>${state.altMode}</strong> to broaden the scope.
                <button type="button" class="switch-cta">
                    Switch to Match ${altLabel} (${state.altCount} hosts)
                </button>`;
            return;
        }

        const countText = state.count == null
            ? '…'
            : `${state.count} host${state.count === 1 ? '' : 's'}`;

        elReadout.innerHTML = `
            <strong>${sel} of ${total} labels</strong> selected, ${modeLabel}
            <span class="count-pill">${countText}</span>`;
    }

    function renderStaleBanner() {
        if (!elStaleBanner) return;
        const failedCount = state.labels.filter(
            l => l.last_label_sync_status === 'failed' &&
                 (l.consecutive_failures || 0) >= 3
        ).length;
        if (failedCount > 0) {
            elStaleBanner.hidden = false;
            elStaleBanner.innerHTML = `
                <strong>Label data may be stale.</strong>
                ${failedCount} label${failedCount === 1 ? '' : 's'} failed to sync recently.
                Selections still work; refreshes on next ETL.`;
        } else {
            elStaleBanner.hidden = true;
        }
    }

    function renderAll() {
        renderList();
        renderClear();
        renderSegmented();
        renderReadout();
        renderStaleBanner();
    }

    async function refreshCount() {
        state.count = null;
        state.altCount = null;
        state.altMode = null;
        renderReadout();
        if (state.selected.size === 0) {
            return;
        }
        try {
            const data = await _fetchScopeCount(getScope());
            if (data) {
                state.count = data.count;
                state.altCount = data.alt_count;
                state.altMode = data.alt_label_op;
            }
        } catch (e) {
            // Non-fatal — readout falls back to "…" placeholder.
            console.warn('scope-count fetch failed:', e);
        }
        renderReadout();
    }

    async function commitChange() {
        renderAll();
        // Push to cross-view session scope (TODO-3). Skip when the
        // change came FROM a session-scope event (avoids infinite
        // notify loop).
        if (!state._suppressNextSessionWrite) {
            SessionLabelScope.set({
                labels: Array.from(state.selected),
                label_op: state.mode,
            });
        } else {
            state._suppressNextSessionWrite = false;
        }
        await refreshCount();
        renderReadout();
        onChange(getScope(), { source: view });
    }

    function toggleLabel(name) {
        if (state.selected.has(name)) {
            state.selected.delete(name);
            announce(`${name} unselected. ${state.selected.size} of ${state.labels.length} labels selected.`);
        } else {
            state.selected.add(name);
            announce(`${name} selected. ${state.selected.size} of ${state.labels.length} labels selected, ${state.mode} mode.`);
        }
        commitChange();
    }

    function setMode(newMode) {
        if (newMode !== 'AND' && newMode !== 'OR') return;
        if (newMode === state.mode) return;
        state.mode = newMode;
        announce(`${newMode} mode.`);
        commitChange();
    }

    function clearAll() {
        if (state.selected.size === 0) return;
        state.selected.clear();
        announce('All labels cleared.');
        commitChange();
    }

    // Event wiring (delegated on the list to handle dynamic rows).
    elList.addEventListener('click', e => {
        const row = e.target.closest('.label-row');
        if (row) {
            toggleLabel(row.dataset.name);
            return;
        }
        if (e.target.classList.contains('label-search-clear')) {
            state.search = '';
            if (elSearch) elSearch.value = '';
            renderList();
        }
    });
    elList.addEventListener('keydown', e => {
        const row = e.target.closest('.label-row');
        if (!row) return;
        if (e.key === ' ' || e.key === 'Enter') {
            e.preventDefault();
            toggleLabel(row.dataset.name);
            return;
        }
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            const next = row.nextElementSibling;
            if (next && next.classList.contains('label-row')) next.focus();
        }
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            const prev = row.previousElementSibling;
            if (prev && prev.classList.contains('label-row')) prev.focus();
        }
    });

    if (elSearch) {
        elSearch.addEventListener('input', e => {
            state.search = e.target.value;
            renderList();
        });
    }

    elSegBtns.forEach(b => {
        b.addEventListener('click', () => setMode(b.dataset.op));
        b.addEventListener('keydown', e => {
            if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
                e.preventDefault();
                const idx = elSegBtns.indexOf(b);
                const next = elSegBtns[(idx + 1) % elSegBtns.length];
                next.focus();
                setMode(next.dataset.op);
            }
        });
    });

    if (elClear) {
        elClear.addEventListener('click', clearAll);
    }

    if (elReadout) {
        elReadout.addEventListener('click', e => {
            if (e.target.classList.contains('switch-cta')) {
                setMode(state.altMode || (state.mode === 'AND' ? 'OR' : 'AND'));
            }
        });
    }

    async function refresh() {
        state.loading = true;
        state.error = null;
        renderList();
        try {
            state.labels = await _fetchLabels(false);
            state.loading = false;
            // Drop selections for labels that no longer exist (Fleet
            // deletion / 7-day reap).
            const live = new Set(state.labels.map(l => l.name));
            Array.from(state.selected).forEach(n => {
                if (!live.has(n)) state.selected.delete(n);
            });
        } catch (e) {
            state.loading = false;
            state.error = 'Memgraph is unreachable. Retry shortly.';
        }
        renderAll();
        refreshCount();
    }

    // Subscribe to cross-view scope changes. When another widget
    // (or the active-scope banner's "Clear" button) mutates the
    // session scope, mirror the change here without re-broadcasting.
    const _unsub = SessionLabelScope.subscribe((scope) => {
        const newSelected = new Set(scope.labels || []);
        const newMode = scope.label_op || 'AND';
        // Skip if our state already matches — this widget is the source.
        const sameLabels =
            newSelected.size === state.selected.size &&
            Array.from(newSelected).every(n => state.selected.has(n));
        const sameMode = newMode === state.mode;
        if (sameLabels && sameMode) return;
        state.selected = newSelected;
        state.mode = newMode;
        state._suppressNextSessionWrite = true;
        commitChange();
    });

    const inst = {
        refresh,
        getScope,
        getElement: () => container,
        destroy: () => _unsub(),
    };
    _labelWidgetRegistry.set(container, inst);
    refresh();
    return inst;
}

// Backward-compat shim used by calculateBlastRadius and
// loadShadowITDetections — they still call readLabelFilter().
// The new signature accepts EITHER (selectEl, opEl) tuple (legacy)
// OR a single `.label-widget` container element. Resolve via the
// registry when given a container.
function readLabelFilter(elOrContainer, _opEl_unused) {
    // Legacy: passed a <select> element directly. Read selectedOptions.
    if (elOrContainer && elOrContainer.tagName === 'SELECT') {
        const names = Array.from(elOrContainer.selectedOptions)
            .map(o => o.value).filter(v => v);
        const opEl = _opEl_unused;
        return {
            labels: names.join(','),
            label_op: (opEl && opEl.value) ? opEl.value : 'AND',
        };
    }
    // New: passed the .label-widget container.
    if (elOrContainer && elOrContainer.classList &&
        elOrContainer.classList.contains('label-widget')) {
        const inst = _labelWidgetRegistry.get(elOrContainer);
        return inst
            ? inst.getScope()
            : { labels: '', label_op: 'AND' };
    }
    return { labels: '', label_op: 'AND' };
}

function loadLabels() {
    // Discovery + binding. Each `.label-widget` container becomes its
    // own widget instance bound to its parent view's data fetch.
    document.querySelectorAll('.label-widget').forEach(container => {
        if (_labelWidgetRegistry.has(container)) {
            _labelWidgetRegistry.get(container).refresh();
            return;
        }
        const view = container.dataset.view;
        createLabelWidget(container, {
            onChange: () => {
                if (view === 'blast') {
                    if (typeof calculateBlastRadius === 'function') {
                        calculateBlastRadius();
                    }
                } else if (view === 'shadow') {
                    if (typeof loadShadowITDetections === 'function') {
                        loadShadowITDetections();
                    }
                }
            },
        });
    });
}

function loadPlatforms() {
    fetch('/api/platforms')
        .then(response => {
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        })
        .then(platforms => {
            const graphPlatformFilter = document.getElementById('platform-filter');
            const shadowPlatformFilter = document.getElementById('shadow-platform-filter-new');

            if (graphPlatformFilter) {
                while (graphPlatformFilter.options.length > 1) graphPlatformFilter.remove(1);
                platforms.forEach(platform => {
                    const option = document.createElement('option');
                    option.value = platform;
                    option.textContent = platform.charAt(0).toUpperCase() + platform.slice(1);
                    graphPlatformFilter.appendChild(option);
                });
            }

            if (shadowPlatformFilter) {
                shadowPlatformFilter.innerHTML = `<option value="all">All Platforms (${platforms.length})</option>`;
                platforms.forEach(platform => {
                    const option = document.createElement('option');
                    option.value = platform;
                    option.textContent = platform.charAt(0).toUpperCase() + platform.slice(1);
                    shadowPlatformFilter.appendChild(option);
                });
            }
        })
        .catch(error => console.error('Error loading platforms:', error));
}

function updateBlastMetrics(data) {
    const metrics = data.metrics || {};
    const totals = (data.scope && data.scope.totals) || {};
    const setMetric = (id, value, denom, unit) => {
        const valueEl = document.getElementById(id);
        HOUND.countUp(valueEl, value);
        const sub = document.getElementById(id + '-sub');
        if (sub && denom !== undefined) {
            sub.textContent = `${value} of ${denom} ${unit}`;
        }
        const bar = document.getElementById(id + '-bar');
        if (bar) {
            const pct = denom ? Math.min(100, Math.round((value / denom) * 100)) : 0;
            // Start from 0 so the bar always animates, even on a re-select.
            bar.style.width = '0%';
            requestAnimationFrame(() => { bar.style.width = pct + '%'; });
        }
    };
    setMetric('metric-host-reach', metrics.host_reach || 0, totals.hosts, 'hosts impacted');
    setMetric('metric-user-impact', metrics.user_impact || 0, totals.users, 'users affected');
    // Lateral movement uses GLOBAL host count for normalization (cross-team danger).
    setMetric('metric-lateral-movement', metrics.lateral_movement || 0, totals.hosts, '2nd-degree hosts');
    // Platform diversity caps at 3 conceptually (windows/darwin/linux).
    setMetric('metric-platform-diversity', metrics.platform_diversity || 0, 3, 'OS platforms');
}

// ========================================
// IMPACT CASCADE
// ========================================
// Replaces the abstract four-axis radar as the default diagram. It
// shows what was actually reached: seed → impacted hosts → impacted
// identities → platform arcs. The radar stays available because some
// analysts prefer the shape, but it is no longer the first thing a
// newcomer sees.
let _blastChartMode = 'cascade';
let _blastLastData = null;

function renderBlastDiagram(data) {
    // No-arg calls re-render the last payload (e.g. theme toggle).
    // Without this fallback they used to blank the cache and crash.
    data = data || _blastLastData || {};
    _blastLastData = data;
    const radar = document.getElementById('radar-chart');
    const cascade = document.getElementById('impact-cascade');
    if (!radar || !cascade) return;
    if (_blastChartMode === 'radar') {
        cascade.hidden = true;
        radar.hidden = false;
        drawRadarChart(data.scores || {});
    } else {
        radar.hidden = true;
        cascade.hidden = false;
        drawImpactCascade(data);
    }
}

function setBlastChartMode(mode) {
    _blastChartMode = mode === 'radar' ? 'radar' : 'cascade';
    document.querySelectorAll('.chart-switch-btn').forEach((btn) => {
        btn.classList.toggle('active', btn.dataset.chart === _blastChartMode);
    });
    if (_blastLastData) renderBlastDiagram(_blastLastData);
}

function drawImpactCascade(data) {
    data = data || {};
    const host = document.getElementById('impact-cascade');
    if (!host) return;
    host.innerHTML = '';

    const details = data.details || {};
    const metrics = data.metrics || {};
    const hosts = details.hosts || [];
    const users = details.users || [];
    const platforms = details.platforms || [];
    const seedName = (metrics.display_name || metrics.name || data.id || details.name || blastSeedLabel || 'Selected entity');
    const seedType = (metrics.type || data.type || (String(data.id || '').startsWith('user_') ? 'user' : 'software'));

    const rect = host.getBoundingClientRect();
    const w = Math.max(320, rect.width || 520);
    const h = Math.max(360, rect.height || 440);
    const cx = w / 2;
    const cy = h / 2;
    const reduce = HOUND.reduceMotion();

    const svg = d3.select(host).append('svg')
        .attr('viewBox', `0 0 ${w} ${h}`)
        .attr('preserveAspectRatio', 'xMidYMid meet')
        .attr('aria-hidden', 'true');

    const root = svg.append('g');
    const unit = Math.min(w, h);
    const r1 = unit * 0.24;
    const r2 = unit * 0.39;
    // 0.44, not 0.47: the platform captions orbit outside r3+10, and at
    // 0.47 their text ran past the card edge on a 680px pane.
    const r3 = unit * 0.44;
    const hostColor = cssVar('--type-host');
    const userColor = cssVar('--type-user');

    // Ghost rings are always drawn, so an empty result still reads as
    // a diagram rather than a blank card.
    [r1, r2, r3].forEach((r, i) => {
        root.append('circle')
            .attr('cx', cx).attr('cy', cy).attr('r', r)
            .attr('fill', 'none')
            .attr('stroke', 'var(--border)')
            .attr('stroke-width', 1)
            .attr('stroke-dasharray', i === 2 ? '3 6' : '2 5')
            .attr('opacity', i === 2 ? 0.55 : 0.9);
    });

    // Ring captions, placed at the top of each ring.
    const caption = (r, text, color) => {
        root.append('text')
            .attr('x', cx)
            .attr('y', cy - r - 6)
            .attr('text-anchor', 'middle')
            .attr('class', 'cascade-ring-label')
            .attr('fill', color || 'var(--text-tertiary)')
            .text(text);
    };
    caption(r1, `HOSTS · ${HOUND.fmt.int(hosts.length)}`, cssVar('--text-tertiary'));
    caption(r2, `IDENTITIES · ${HOUND.fmt.int(users.length)}`, cssVar('--text-tertiary'));

    // Platform arcs: one segment per distinct platform. Never fake
    // proportions — segment count is the data.
    if (platforms.length) {
        const arcSpan = Math.PI / Math.max(2, platforms.length) * 0.9;
        const startBase = -Math.PI * 0.75;
        platforms.slice(0, 6).forEach((platform, i) => {
            const a0 = startBase + i * (Math.PI * 2 / Math.max(2, platforms.length));
            const a1 = a0 + arcSpan;
            const arc = d3.arc()
                .innerRadius(r3 + 4)
                .outerRadius(r3 + 10)
                .startAngle(a0)
                .endAngle(a1);
            root.append('path')
                .attr('transform', `translate(${cx},${cy})`)
                .attr('d', arc())
                .attr('fill', 'var(--accent)')
                .attr('opacity', 0.55);
            const mid = (a0 + a1) / 2;
            // d3.arc measures angles from 12 o'clock clockwise; the
            // trig caption has to use the same convention or the
            // platform name lands on the opposite side of the ring.
            // Sit just inside the arc: at r3+22 a left-side caption
            // ran off the card edge.
            const labelR = r3 - 14;
            root.append('text')
                .attr('x', cx + Math.sin(mid) * labelR)
                .attr('y', cy - Math.cos(mid) * labelR)
                .attr('text-anchor', 'middle')
                .attr('dominant-baseline', 'middle')
                .attr('class', 'cascade-ring-label')
                .attr('font-size', 7.5)
                .text(String(platform).toUpperCase());
        });
    }

    // Lateral halo: the API returns a count, not names, so show a
    // numeric halo rather than inventing nodes.
    const lateral = Number(metrics.lateral_movement || 0);
    if (lateral > 0) {
        const haloR = r3 + 26;
        root.append('circle')
            .attr('cx', cx).attr('cy', cy).attr('r', haloR)
            .attr('fill', 'none')
            .attr('stroke', 'var(--warning)')
            .attr('stroke-width', 1)
            .attr('stroke-dasharray', '1 7')
            .attr('opacity', 0.6);
        root.append('text')
            .attr('x', cx)
            // Inside the halo: below it, the dashed ring sat on the
            // card's bottom edge and the caption was clipped.
            .attr('y', cy + haloR - 10)
            .attr('text-anchor', 'middle')
            .attr('class', 'cascade-ring-label')
            .attr('fill', 'var(--warning)')
            .text(`+${HOUND.fmt.int(lateral)} reachable next`);
    }

    const hasReach = hosts.length || users.length || lateral;
    if (!hasReach) {
        root.append('text')
            .attr('x', cx).attr('y', cy + 74)
            .attr('text-anchor', 'middle')
            .attr('class', 'cascade-ring-label')
            .text('NO REACH IN THIS SCOPE');
    }

    // Seed.
    const seedGroup = root.append('g').attr('class', 'cascade-seed');
    seedGroup.append('circle')
        .attr('cx', cx).attr('cy', cy).attr('r', 30)
        .attr('fill', 'var(--accent-muted)')
        .attr('stroke', 'var(--accent)')
        .attr('stroke-width', 1.5);
    seedGroup.append('text')
        .attr('x', cx).attr('y', cy - 3)
        .attr('text-anchor', 'middle')
        .attr('class', 'cascade-center-type')
        .text(String(seedType).toUpperCase());
    seedGroup.append('text')
        .attr('x', cx).attr('y', cy + 15)
        .attr('text-anchor', 'middle')
        .attr('class', 'cascade-center-name')
        .text(seedName.length > 18 ? seedName.slice(0, 17) + '…' : seedName);

    // Spokes + nodes. Cap at 24 per ring so labels stay readable; the
    // remainder is reported as a +N chip.
    const CAP = 24;
    const spokeLayer = root.append('g');
    const nodeLayer = root.append('g');

    const drawRing = (items, radius, color, typeLabel, delayBase) => {
        const shown = items.slice(0, CAP);
        shown.forEach((name, i) => {
            const angle = (i / Math.max(1, shown.length)) * Math.PI * 2 - Math.PI / 2;
            const x = cx + Math.cos(angle) * radius;
            const y = cy + Math.sin(angle) * radius;

            const spoke = spokeLayer.append('line')
                .attr('x1', cx).attr('y1', cy).attr('x2', x).attr('y2', y)
                .attr('stroke', color)
                .attr('stroke-width', 1)
                .attr('opacity', 0.28);

            if (!reduce) {
                const len = Math.hypot(x - cx, y - cy);
                spoke.attr('stroke-dasharray', `${len} ${len}`)
                    .attr('stroke-dashoffset', len)
                    .transition().delay(delayBase).duration(420)
                    .attr('stroke-dashoffset', 0);
            }

            const g = nodeLayer.append('g')
                .attr('class', 'cascade-node')
                .attr('transform', `translate(${x},${y})`);
            g.append('circle')
                .attr('r', 3.5)
                .attr('fill', color)
                .attr('fill-opacity', 0.9)
                .attr('stroke', 'var(--bg-secondary)')
                .attr('stroke-width', 1);
            g.append('title').text(`${typeLabel}: ${name}`);

            if (!reduce) {
                g.style('opacity', 0);
                g.transition().delay(delayBase + i * 18).duration(240).style('opacity', 1);
            }
        });

        if (items.length > CAP) {
            // Bottom of the ring, not the top: the ring caption and
            // the platform arcs already live there.
            const angle = Math.PI / 2;
            nodeLayer.append('text')
                .attr('x', cx + Math.cos(angle) * (radius + 14))
                .attr('y', cy + Math.sin(angle) * (radius + 14))
                .attr('text-anchor', 'middle')
                .attr('class', 'cascade-ring-label')
                .text(`+${items.length - CAP}`);
        }
    };

    drawRing(hosts, r1, hostColor, 'Host', 120);
    drawRing(users, r2, userColor, 'Identity', 260);

    host.setAttribute('aria-label',
        `Impact cascade for ${seedName}: ${hosts.length} hosts, ${users.length} identities, ` +
        `${platforms.length} platforms, ${lateral} reachable next.`);
}

function updateBlastDetails(data) {
    const details = data.details;
    const metrics = data.metrics;
    const container = document.getElementById('blast-details-content');
    container.innerHTML = '';

    if (metrics.category || metrics.description) {
        const infoSection = document.createElement('div');
        infoSection.className = 'detail-section';
        infoSection.innerHTML = `<h4>Entity Info</h4>`;

        const infoContent = document.createElement('div');
        infoContent.className = 'info-block';

        if (metrics.category && metrics.category.length > 0) {
            infoContent.innerHTML += `
                <div style="margin-bottom: var(--space-2);">
                    <div class="info-label">Categories</div>
                    <div style="display: flex; flex-wrap: wrap; gap: var(--space-1); margin-top: var(--space-1);">
                        ${metrics.category.map(cat => `<span class="tag">${escapeHtml(cat)}</span>`).join('')}
                    </div>
                </div>
            `;
        }

        if (metrics.description) {
            infoContent.innerHTML += `
                <div>
                    <div class="info-label">Description</div>
                    <div style="font-size: var(--text-xs); margin-top: 2px; line-height: 1.4;">${escapeHtml(metrics.description)}</div>
                </div>
            `;
        }

        infoSection.appendChild(infoContent);
        container.appendChild(infoSection);
    }

    const addSection = (title, items) => {
        if (!items || items.length === 0) return;
        const section = document.createElement('div');
        section.className = 'detail-section';
        section.innerHTML = `<h4>${title} <span class="count-badge">${items.length}</span></h4>`;

        const list = document.createElement('div');
        list.className = 'detail-list';
        const displayItems = items.slice(0, 50);

        displayItems.forEach(item => {
            const el = document.createElement('div');
            el.className = 'detail-item';
            el.textContent = item;
            list.appendChild(el);
        });

        if (items.length > 50) {
            const more = document.createElement('div');
            more.className = 'detail-item';
            more.style.fontStyle = 'italic';
            more.style.color = 'var(--text-tertiary)';
            more.textContent = `...and ${items.length - 50} more`;
            list.appendChild(more);
        }

        section.appendChild(list);
        container.appendChild(section);
    };

    addSection('Impacted Teams', details.teams);
    addSection('Impacted Platforms', details.platforms);
    addSection('Impacted Hosts', details.hosts);
    addSection('Impacted Users', details.users);
}

function drawRadarChart(scores) {
    const container = d3.select("#radar-chart");
    container.selectAll("*").remove();

    const containerEl = document.getElementById('radar-chart');
    const fullWidth = containerEl.clientWidth;
    const maxSize = 720;
    const width = Math.min(fullWidth, maxSize);
    const height = Math.min(containerEl.clientHeight, maxSize);
    // Room for the axis captions: they sit outside the outer ring, so
    // a 60px margin clipped "User Impact" on a 700px-wide pane.
    const margin = 84;
    const radius = Math.min(width, height) / 2 - margin;
    const labelRadius = radius + 18;

    const svg = container.append("svg")
        .attr("width", "100%")
        .attr("height", height)
        .attr("class", "radar-chart")
        .append("g")
        .attr("transform", `translate(${fullWidth / 2},${height / 2})`);

    const features = Object.keys(scores);
    const rScale = d3.scaleLinear().range([0, radius]).domain([0, 100]);
    const angleSlice = Math.PI * 2 / features.length;

    const levels = 5;
    for (let i = 0; i < levels; i++) {
        const levelFactor = radius * ((i + 1) / levels);
        svg.append("circle")
            .attr("r", levelFactor)
            .style("fill", "none")
            .style("stroke", "var(--border)")
            .style("stroke-opacity", "0.5");
    }

    for (let i = 0; i < levels; i++) {
        const levelFactor = radius * ((i + 1) / levels);
        svg.append("text")
            .attr("x", 4)
            .attr("y", -levelFactor)
            .attr("dy", "0.4em")
            .style("font-size", "10px")
            .attr("fill", "var(--text-tertiary)")
            .text(Math.round((i + 1) * 100 / levels));
    }

    const axis = svg.selectAll(".axis")
        .data(features)
        .enter()
        .append("g")
        .attr("class", "axis");

    axis.append("line")
        .attr("x1", 0).attr("y1", 0)
        .attr("x2", (d, i) => rScale(100) * Math.cos(angleSlice * i - Math.PI / 2))
        .attr("y2", (d, i) => rScale(100) * Math.sin(angleSlice * i - Math.PI / 2))
        .style("stroke", "var(--border)")
        .style("stroke-width", "1px");

    axis.append("text")
        .style("font-size", "11px")
        .attr("text-anchor", "middle")
        .attr("dy", "0.35em")
        .attr("x", (d, i) => labelRadius * Math.cos(angleSlice * i - Math.PI / 2))
        .attr("y", (d, i) => labelRadius * Math.sin(angleSlice * i - Math.PI / 2))
        .text(d => d)
        .style("fill", "var(--text-primary)")
        .style("font-weight", "600")
        // The axis line ends at the data vertex, which is inside a
        // wide label such as "Lateral Movement"; a page-coloured
        // halo keeps the caption readable where the line crosses it.
        .style("paint-order", "stroke")
        .style("stroke", "var(--bg-secondary)")
        .style("stroke-width", "4px")
        .style("stroke-linejoin", "round");

    const radarLine = d3.lineRadial()
        .curve(d3.curveLinearClosed)
        .radius(d => rScale(d.value))
        .angle((d, i) => i * angleSlice);

    const data = Object.keys(scores).map(key => ({ axis: key, value: scores[key] }));

    svg.append("path")
        .datum(data)
        .attr("d", radarLine)
        .style("fill", "var(--accent)")
        .style("fill-opacity", 0.15)
        .style("stroke", "var(--accent)")
        .style("stroke-width", 2);

    svg.selectAll(".radar-circle")
        .data(data)
        .enter()
        .append("circle")
        .attr("r", 4)
        .attr("cx", (d, i) => rScale(d.value) * Math.cos(angleSlice * i - Math.PI / 2))
        .attr("cy", (d, i) => rScale(d.value) * Math.sin(angleSlice * i - Math.PI / 2))
        .style("fill", "var(--accent)")
        .style("fill-opacity", 0.8)
        .append("title")
        .text(d => `${d.value}%`);

    // The filled polygon is appended after the axes and otherwise
    // paints straight through the captions at 100%. Raise the whole
    // axis group (its texts alone stay under a later sibling).
    axis.raise();
}

// ========================================
// SHADOW IT
// ========================================
let shadowITData = null;
// ========================================
// SHADOW IT — CSV export of currently-loaded detections
// ========================================
function _csvCell(value) {
    if (value === null || value === undefined) return '';
    const s = Array.isArray(value) ? value.join('; ') : String(value);
    // RFC 4180 quoting: every cell wrapped in quotes, embedded quotes doubled.
    return '"' + s.replace(/"/g, '""') + '"';
}

function exportShadowDetectionsCsv() {
    if (!shadowITData || !Array.isArray(shadowITData.detections) || shadowITData.detections.length === 0) {
        showStatus('Nothing to export.', true);
        return;
    }
    // Honor any per-column filtering the user applied (filterShadowTable hides rows).
    const tbody = document.getElementById('shadow-detections-tbody');
    const visibleSoftware = new Set();
    if (tbody) {
        tbody.querySelectorAll('tr').forEach((tr) => {
            if (tr.style.display === 'none') return;
            const cell = tr.querySelector('td strong');
            if (cell && cell.textContent) visibleSoftware.add(cell.textContent.trim());
        });
    }
    const rows = visibleSoftware.size > 0
        ? shadowITData.detections.filter(d => visibleSoftware.has(softwareTitle(d)))
        : shadowITData.detections;

    const headers = [
        'software_name', 'display_name', 'software_type', 'risk_level', 'category',
        'detection_type', 'host_count', 'user_count', 'version',
        'recommendation', 'affected_hosts', 'affected_users', 'platforms',
    ];
    const lines = [headers.join(',')];
    rows.forEach((d) => {
        lines.push([
            _csvCell(d.software_name),
            _csvCell(softwareTitle(d)),
            _csvCell(d.software_type),
            _csvCell(d.risk_level),
            _csvCell(d.category),
            _csvCell(d.detection_type),
            _csvCell(d.host_count),
            _csvCell((d.affected_users || []).length),
            _csvCell(d.version),
            _csvCell(d.recommendation),
            _csvCell(d.affected_hosts),
            _csvCell(d.affected_users),
            _csvCell(d.platforms),
        ].join(','));
    });
    const csv = lines.join('\r\n');
    // BOM so Excel detects UTF-8 correctly on first open.
    const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const today = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `fleet-hound-shadow-it-${today}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showStatus(`Exported ${rows.length} detection${rows.length === 1 ? '' : 's'} to CSV`);
}

async function loadShadowITDetections() {
    const teamFilter = document.getElementById('shadow-team-filter-new').value;

    if (!teamFilter) {
        // No scope = no numbers. Zero the composition too, otherwise
        // the ring keeps the last team's counts while the table says
        // "select a team".
        renderShadowComposition({ summary: {}, detections: [] });
        const tbody = document.getElementById('shadow-detections-tbody');
        tbody.innerHTML = `
            <tr><td colspan="8">
                <div class="empty-state">
                    <div class="empty-state-icon">&#8592;</div>
                    <div>Select a Team to view detections</div>
                </div>
            </td></tr>`;
        return;
    }

    const platformFilter = document.getElementById('shadow-platform-filter-new').value;
    const riskFilter = document.getElementById('shadow-risk-filter').value;
    const detectionTypeFilter = document.getElementById('shadow-detection-type-filter').value;
    const softwareTypeFilter = document.getElementById('shadow-software-type-filter').value;
    const hostCountFilter = document.getElementById('shadow-host-count-filter').value;
    const userCountFilter = document.getElementById('shadow-user-count-filter').value;

    const shadowWidget = document.querySelector('.label-widget[data-view="shadow"]');
    const labelScope = readLabelFilter(shadowWidget);

    const params = new URLSearchParams({
        team: teamFilter, platform: platformFilter, risk: riskFilter,
        detection_type: detectionTypeFilter, software_type: softwareTypeFilter,
        host_count: hostCountFilter, user_count: userCountFilter
    });
    if (labelScope.labels) {
        params.set('labels', labelScope.labels);
        params.set('label_op', labelScope.label_op);
    }

    try {
        const isLatest = beginRequest('shadow');
        const response = await fetch(`/api/shadow-it?${params}`);
        const data = await response.json();
        if (!isLatest()) return;
        if (!response.ok || data.error) throw new Error(data.error || `HTTP ${response.status}`);
        shadowITData = data;

        renderShadowComposition(data);
        renderShadowITTable(data.detections);
        filterShadowTable();
        const exportBtn = document.getElementById('shadow-export-csv-btn');
        if (exportBtn) exportBtn.disabled = !(data.detections && data.detections.length > 0);
    } catch (error) {
        console.error('Error loading Shadow IT detections:', error);
        showEmptyState('Error loading detections. Please try again.');
        const exportBtn = document.getElementById('shadow-export-csv-btn');
        if (exportBtn) exportBtn.disabled = true;
    }
}

// ---- Shadow IT composition ----
// Severity ring + detection-mix ribbon. Counts come from the same
// payload as the table, so the diagram and the rows can never disagree.
const SHADOW_MIX = [
    { key: 'outlier', label: 'Outlier software', color: 'var(--accent)' },
    { key: 'high_risk', label: 'High-risk categories', color: 'var(--danger)' },
    { key: 'version_sprawl', label: 'Version sprawl', color: 'var(--caution)' },
];

function renderShadowComposition(data) {
    const summary = (data && data.summary) || {};
    const detections = (data && data.detections) || [];
    const total = Number(summary.total_detections || 0);
    const high = Number(summary.high_risk || 0);
    const medium = Number(summary.medium_risk || 0);
    const low = Number(summary.low_risk || 0);

    HOUND.countUp(document.getElementById('shadow-total-detections'), total);
    HOUND.countUp(document.getElementById('shadow-high-risk'), high);
    HOUND.countUp(document.getElementById('shadow-medium-risk'), medium);
    HOUND.countUp(document.getElementById('shadow-low-risk'), low);
    HOUND.countUp(document.getElementById('shadow-affected-hosts'), Number(summary.affected_hosts || 0));
    HOUND.countUp(document.getElementById('shadow-affected-users'), Number(summary.affected_users || 0));

    HOUND.donut(document.getElementById('shadow-sev-donut'), [
        { value: high, color: 'var(--danger)' },
        { value: medium, color: 'var(--warning)' },
        { value: low, color: 'var(--caution)' },
    ], total, `${total} detections: ${high} high, ${medium} medium, ${low} low`, { noLabel: true });

    // ---- detection-mix ribbon ----
    const known = new Set(SHADOW_MIX.map((m) => m.key));
    const segments = SHADOW_MIX.map((m) => ({
        ...m,
        count: detections.filter((d) => (d.detection_type || '') === m.key).length,
    }));
    const other = detections.filter((d) => !known.has(d.detection_type || '')).length;
    if (other) segments.push({ key: 'other', label: 'Other', color: 'var(--text-tertiary)', count: other });

    const bar = document.getElementById('shadow-mix-bar');
    const legend = document.getElementById('shadow-mix-legend');
    const totalEl = document.getElementById('shadow-mix-total');
    const shown = segments.reduce((acc, s) => acc + s.count, 0);

    if (totalEl) totalEl.textContent = shown ? `${HOUND.fmt.int(shown)} shown` : '';

    if (bar) {
        bar.innerHTML = '';
        if (!shown) {
            bar.setAttribute('aria-label', 'No detections in this scope');
        } else {
            bar.setAttribute('aria-label', segments
                .filter((s) => s.count)
                .map((s) => `${s.label}: ${s.count}`)
                .join(', '));
            segments.forEach((seg) => {
                if (!seg.count) return;
                const el = document.createElement('div');
                el.className = 'mix-seg';
                el.style.background = seg.color;
                bar.appendChild(el);
                const pct = (seg.count / shown) * 100;
                requestAnimationFrame(() => { el.style.width = pct + '%'; });
            });
        }
    }

    if (legend) {
        legend.innerHTML = segments
            .filter((s) => s.count)
            .map((s) => `
                <span class="mix-legend-item">
                    <span class="comp-swatch" style="background: ${s.color}"></span>
                    ${escapeHtml(s.label)} <strong>${HOUND.fmt.int(s.count)}</strong>
                </span>`)
            .join('') || '<span class="mix-legend-item">No detections in this scope</span>';
    }
}

function softwareTitle(detection) {            return detection.display_name || detection.software_name || '';
}

async function authorizeSoftware(softwareName, displayName) {
    const title = displayName || softwareName;
    if (!confirm(`Authorize "${title}"?\nIt will be whitelisted and excluded from future scans.`)) return;

    try {
        const response = await fetch('/api/authorize-software', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ software_name: softwareName })
        });
        const result = await response.json();
        if (response.ok) {
            closeDetectionDetails();
            loadShadowITDetections();
            showStatus(`${title} authorized`);
        } else {
            alert('Error: ' + result.error);
        }
    } catch (error) {
        console.error('Error authorizing software:', error);
        alert('Error authorizing software');
    }
}

function renderShadowITTable(detections) {
    const tbody = document.getElementById('shadow-detections-tbody');

    if (!detections || detections.length === 0) {
        tbody.innerHTML = `
            <tr><td colspan="8">
                <div class="empty-state">
                    <div class="empty-state-icon">&#10003;</div>
                    <div>No Shadow IT detections found</div>
                    <div class="empty-state-text">Your environment looks clean.</div>
                </div>
            </td></tr>`;
        return;
    }

    tbody.innerHTML = '';
    detections.forEach(detection => {
        const row = document.createElement('tr');
        row.onclick = () => showDetectionDetails(detection);
        const riskClass = ['high','medium','low'].includes(detection.risk_level) ? detection.risk_level : 'low';
        row.innerHTML = `
            <td><strong>${escapeHtml(softwareTitle(detection))}</strong></td>
            <td class="text-sm" style="color: var(--text-secondary);">${escapeHtml(detection.software_type || 'Unknown')}</td>
            <td><span class="badge badge-${riskClass}">${escapeHtml((detection.risk_level || '').toUpperCase())}</span></td>
            <td><span class="detection-category">${escapeHtml(detection.category || '')}</span></td>
            <td class="text-sm">${escapeHtml((detection.detection_type || '').replace('_', ' ').toUpperCase())}</td>
            <td>${Number(detection.host_count) || 0}</td>
            <td>${(detection.affected_users || []).length}</td>
            <td class="text-sm">${escapeHtml(truncateText(detection.version, 30))}</td>
        `;
        tbody.appendChild(row);
    });
    filterShadowTable();
}

function filterShadowTable() {
    const table = document.getElementById("shadow-detections-table");
    if (!table) return;
    const tr = table.getElementsByTagName("tr");
    const inputs = document.getElementsByClassName("table-filter-input");

    for (let i = 2; i < tr.length; i++) {
        if (tr[i].cells.length < inputs.length) continue;
        let showRow = true;
        for (let j = 0; j < inputs.length; j++) {
            const filter = inputs[j].value.toUpperCase();
            if (filter === "") continue;
            // Numeric columns (hosts/users) have no filter box, so the
            // input's data-col is the real cell index.
            const col = inputs[j].dataset.col === undefined ? j : Number(inputs[j].dataset.col);
            const td = tr[i].getElementsByTagName("td")[col];
            if (td) {
                const txtValue = td.textContent || td.innerText;
                if (txtValue.toUpperCase().indexOf(filter) === -1) { showRow = false; break; }
            }
        }
        tr[i].style.display = showRow ? "" : "none";
    }
}

function showDetectionDetails(detection) {
    const modal = document.getElementById('detection-details-modal');
    const body = document.getElementById('detection-details-body');

    const safeRiskClass = ['high','medium','low'].includes(detection.risk_level) ? detection.risk_level : 'low';
    const platforms = (detection.platforms || []).filter(Boolean).map(escapeHtml).join(', ');
    const hostsHtml = (detection.affected_hosts || []).map(h => `<div style="padding: 1px 0;">&#8226; ${escapeHtml(h)}</div>`).join('');
    const usersList = detection.affected_users || [];
    const usersHtml = usersList.length > 0
        ? usersList.map(u => `<div style="padding: 1px 0;">&#8226; ${escapeHtml(u)}</div>`).join('')
        : '<span style="color: var(--text-tertiary);">No user data</span>';

    body.innerHTML = `
        <div class="detail-row">
            <div class="detail-label">Software Name</div>
            <div class="detail-value"><strong>${escapeHtml(softwareTitle(detection))}</strong></div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Risk Level</div>
            <div class="detail-value"><span class="badge badge-${safeRiskClass}">${escapeHtml((detection.risk_level || '').toUpperCase())}</span></div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Risk Reason</div>
            <div class="detail-value risk-quote">${escapeHtml(detection.risk_reason || 'Reason not available')}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Detection Category</div>
            <div class="detail-value">${escapeHtml(detection.category || '')}</div>
        </div>
        ${detection.db_category && detection.db_category.length > 0 ? `
        <div class="detail-row">
            <div class="detail-label">Wikidata Categories</div>
            <div class="detail-value" style="display: flex; flex-wrap: wrap; gap: var(--space-1); margin-top: var(--space-1);">
                ${detection.db_category.map(cat => `<span class="tag">${escapeHtml(cat)}</span>`).join('')}
            </div>
        </div>` : ''}
        ${detection.wikidata_description ? `
        <div class="detail-row">
            <div class="detail-label">Description</div>
            <div class="detail-value" style="font-size: var(--text-sm); color: var(--text-secondary); line-height: 1.5;">${escapeHtml(detection.wikidata_description)}</div>
        </div>` : ''}
        <div class="detail-row">
            <div class="detail-label">Detection Type</div>
            <div class="detail-value">${escapeHtml((detection.detection_type || '').replace('_', ' '))}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Version</div>
            <div class="detail-value">${escapeHtml(detection.version)}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Affected Hosts (${Number(detection.host_count) || 0})</div>
            <div class="detail-value scroll-y">${hostsHtml}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Affected Users (${usersList.length})</div>
            <div class="detail-value scroll-y">${usersHtml}</div>
        </div>
        ${platforms ? `
        <div class="detail-row">
            <div class="detail-label">Platforms</div>
            <div class="detail-value">${platforms}</div>
        </div>` : ''}
        <div class="detail-row">
            <div class="detail-label">Details</div>
            <div class="detail-value">${escapeHtml(detection.details)}</div>
        </div>
        <div class="recommendation-box">
            <div class="rec-title">Recommendation</div>
            <div>${escapeHtml(detection.recommendation)}</div>
        </div>
        <div style="margin-top: var(--space-5); text-align: right;">
            <button class="btn btn-success" id="authorize-btn">
                Authorize Software
            </button>
            <div style="font-size: var(--text-xs); color: var(--text-tertiary); margin-top: var(--space-1);">
                Whitelists this software from future alerts
            </div>
        </div>
    `;

    // Attach the click handler programmatically so the software name is
    // never spliced into a JS string literal (no inline-handler injection).
    const authorizeBtn = body.querySelector('#authorize-btn');
    if (authorizeBtn) {
        authorizeBtn.onclick = () => authorizeSoftware(detection.software_name, softwareTitle(detection));
    }

    modal.classList.add('visible');
}

function closeDetectionDetails(event) {
    document.getElementById('detection-details-modal').classList.remove('visible');
}

function showEmptyState(message) {
    const tbody = document.getElementById('shadow-detections-tbody');
    tbody.innerHTML = `
        <tr><td colspan="8">
            <div class="empty-state">
                <div class="empty-state-icon">!</div>
                <div>${message}</div>
            </div>
        </td></tr>`;
}

// ========================================
// UTILITIES
// ========================================
// Per-view request sequencing: a slow earlier response must not paint
// over a newer one. Usage: const isLatest = beginRequest('key');
// then bail out of the response handler when !isLatest().
const _reqSeq = {};
function beginRequest(key) {
    const n = (_reqSeq[key] = (_reqSeq[key] || 0) + 1);
    return () => _reqSeq[key] === n;
}

// Quotes must be escaped too: results land inside attr="..." values.
function escapeHtml(text) {
    if (text == null) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function truncateText(text, maxLength) {
    if (!text || text.length <= maxLength) return text || '';
    return text.substring(0, maxLength) + '...';
}

// ========================================
// TAB / NAV — accessible click + keyboard handling
// ========================================
function wireTabs() {
    const tabs = Array.from(document.querySelectorAll('[role="tab"][data-view]'));
    tabs.forEach((tab, idx) => {
        tab.addEventListener('click', () => switchView(tab.dataset.view));
        tab.addEventListener('keydown', (e) => {
            if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') return;
            e.preventDefault();
            let next;
            if (e.key === 'Home') next = tabs[0];
            else if (e.key === 'End') next = tabs[tabs.length - 1];
            else {
                const dir = e.key === 'ArrowRight' ? 1 : -1;
                next = tabs[(idx + dir + tabs.length) % tabs.length];
            }
            next.focus();
            switchView(next.dataset.view);
        });
    });
}

// ========================================
// SYNC METADATA PILL — total nodes + last health-check time
// ========================================
async function refreshTopbarMeta() {
    const pill = document.getElementById('topbar-meta');
    if (!pill) return;
    try {
        const r = await fetch('/api/meta');
        if (!r.ok) { pill.hidden = true; return; }
        const data = await r.json();
        if (!data || typeof data.hosts !== 'number') { pill.hidden = true; return; }
        pill.innerHTML = `
            <strong>${escapeHtml(String(data.hosts))}</strong> hosts ·
            <strong>${escapeHtml(String(data.users))}</strong> users ·
            <strong>${escapeHtml(String(data.software))}</strong> software`;
        pill.hidden = false;
    } catch (_e) {
        pill.hidden = true;
    }
}

// ========================================
// PATHFINDER + CLUSTERS + HOVER CORRELATION
// ========================================
const _reduceMotion = window.matchMedia
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
    : false;

const pathfinder = {
    active: false,
    pickedFrom: null,
    pickedTo: null,
};
let _pathfinderClickHandler = null;
let _hoverDebounceTimer = null;
let _correlationFetchToken = 0;
let _clustersOn = false;

function _pathStatus(msg) {
    const el = document.getElementById('pathfinder-status');
    if (!el) return;
    if (!msg) { el.hidden = true; el.textContent = ''; return; }
    el.hidden = false;
    el.textContent = msg;
}

function togglePathfinder() {
    pathfinder.active = !pathfinder.active;
    pathfinder.pickedFrom = null;
    pathfinder.pickedTo = null;
    const btn = document.getElementById('pathfinder-toggle');
    if (btn) btn.classList.toggle('active', pathfinder.active);
    if (pathfinder.active) {
        _pathStatus('Click two nodes to animate the shortest path (Esc to cancel)');
        _bindPathfinderClicks();
        _bindPathfinderEsc();
    } else {
        _pathStatus(null);
        _unbindPathfinderClicks();
        _unbindPathfinderEsc();
        _clearPathHighlights();
        d3.selectAll('#graph .node').classed('path-pick', false);
    }
}

function _bindPathfinderClicks() {
    _unbindPathfinderClicks();
    _pathfinderClickHandler = function (event, d) {
        if (!pathfinder.active || !d || !d.id) return;
        event.stopPropagation();
        event.preventDefault();
        // No pick yet → set first.
        if (!pathfinder.pickedFrom) {
            pathfinder.pickedFrom = d;
            d3.selectAll('#graph .node')
                .classed('path-pick', n => n.id === d.id);
            _pathStatus(`From: ${d.name} — pick destination (click again or Esc to cancel)`);
            return;
        }
        // Re-click same node → cancel selection.
        if (d.id === pathfinder.pickedFrom.id) {
            pathfinder.pickedFrom = null;
            pathfinder.pickedTo = null;
            d3.selectAll('#graph .node').classed('path-pick', false);
            _pathStatus('Click two nodes to animate the shortest path (Esc to cancel)');
            return;
        }
        // Different node → second pick → run pathfinder.
        if (!pathfinder.pickedTo) {
            pathfinder.pickedTo = d;
            _runPathfinder(pathfinder.pickedFrom, pathfinder.pickedTo);
        }
    };
    d3.selectAll('#graph .node').on('click.pathfinder', _pathfinderClickHandler);
}

function _unbindPathfinderClicks() {
    d3.selectAll('#graph .node').on('click.pathfinder', null);
    _pathfinderClickHandler = null;
}

let _pathfinderEscHandler = null;
function _bindPathfinderEsc() {
    _unbindPathfinderEsc();
    _pathfinderEscHandler = function (e) {
        if (e.key !== 'Escape' || !pathfinder.active) return;
        pathfinder.pickedFrom = null;
        pathfinder.pickedTo = null;
        d3.selectAll('#graph .node').classed('path-pick', false);
        _clearPathHighlights();
        _pathStatus('Click two nodes to animate the shortest path (Esc to cancel)');
    };
    document.addEventListener('keydown', _pathfinderEscHandler);
}

function _unbindPathfinderEsc() {
    if (_pathfinderEscHandler) {
        document.removeEventListener('keydown', _pathfinderEscHandler);
        _pathfinderEscHandler = null;
    }
}

async function _runPathfinder(a, b) {
    _pathStatus(`Querying path: ${a.name} → ${b.name}…`);
    try {
        const url = `/api/path?from=${encodeURIComponent(a.id)}&to=${encodeURIComponent(b.id)}&max_hops=4`;
        const r = await fetch(url);
        if (!r.ok) {
            _pathStatus('No path found');
            return;
        }
        const data = await r.json();
        if (!data.ordered_ids || data.ordered_ids.length < 2) {
            _pathStatus('No path between selected nodes');
            return;
        }
        _animatePath(data);
        _pathStatus(`Path: ${data.ordered_ids.length} nodes, ${data.links.length} edges`);
    } catch (e) {
        console.error('pathfinder error', e);
        _pathStatus('Path lookup failed');
    } finally {
        pathfinder.pickedFrom = null;
        pathfinder.pickedTo = null;
    }
}

// Top-layer pathfinder overlay — drawn as fresh elements ABOVE base
// links so the highlight is unaffected by base-link CSS lifecycle,
// theme-overrides, or cluster-mode renders. Tick handler keeps the
// overlay aligned with the moving simulation. See debug/pathfinder-broken.md.
function _animatePath(data) {
    _clearPathHighlights();
    const orderedIds = (data.ordered_ids || []).slice();
    if (orderedIds.length < 2) return;
    const orderedSet = new Set(orderedIds);

    // Backdrop: dim everything off-path so the overlay reads clearly.
    d3.selectAll('#graph .node').classed('dim', d => !orderedSet.has(d.id));
    d3.selectAll('#graph .node-label').classed('dim', d => !orderedSet.has(d.id));
    d3.selectAll('#graph .link').classed('dim', true);
    // Mark ALL path nodes (including intermediate hops) with path-pick
    // so the entire chain glows red, not just the picked endpoints.
    d3.selectAll('#graph .node').classed('path-pick', d => orderedSet.has(d.id));

    // Resolve ordered_ids -> rendered node objects (carries .x/.y from sim).
    const nodeById = new Map();
    d3.selectAll('#graph .node').each(function (d) {
        if (d && d.id) nodeById.set(d.id, d);
    });
    const orderedNodes = orderedIds.map(id => nodeById.get(id)).filter(Boolean);
    if (orderedNodes.length < 2) {
        // Couldn't resolve at least two endpoints in current view; fall
        // back to status only — no overlay possible without coords.
        return;
    }

    const svg = d3.select('#graph svg');
    if (svg.empty()) return;
    // Insert overlay LAST so it sits on top of <g class="links"> and
    // <g class="nodes">. d3 append on the svg root achieves this.
    const overlay = svg.append('g').attr('class', 'path-overlay');

    // Edges between consecutive path nodes.
    const edges = [];
    for (let i = 0; i < orderedNodes.length - 1; i++) {
        edges.push({ a: orderedNodes[i], b: orderedNodes[i + 1] });
    }
    const edgeSel = overlay.selectAll('line.path-overlay-edge')
        .data(edges)
        .enter().append('line')
        .attr('class', 'path-overlay-edge');

    // Numeric hop badges on intermediate nodes (skip endpoints — they
    // already have the .path-pick glow + are visually anchored by the user's clicks).
    const intermediates = orderedNodes.slice(1, -1).map((n, idx) => ({ node: n, order: idx + 1 }));
    const badgeG = overlay.selectAll('g.path-overlay-hop-badge-g')
        .data(intermediates)
        .enter().append('g')
        .attr('class', 'path-overlay-hop-badge-g');
    badgeG.append('circle')
        .attr('class', 'path-overlay-hop-badge')
        .attr('r', 9);
    badgeG.append('text')
        .attr('class', 'path-overlay-hop-badge-text')
        .attr('dy', '0.35em')
        .text(d => String(d.order));

    const _positionOverlay = () => {
        edgeSel
            .attr('x1', d => d.a.x || 0)
            .attr('y1', d => d.a.y || 0)
            .attr('x2', d => d.b.x || 0)
            .attr('y2', d => d.b.y || 0);
        badgeG.attr('transform', d => {
            // Offset badge slightly up-right of the node so it doesn't
            // sit on top of the node label.
            const x = (d.node.x || 0) + 14;
            const y = (d.node.y || 0) - 14;
            return `translate(${x},${y})`;
        });
    };

    // Initial paint and ongoing tick alignment.
    _positionOverlay();
    if (typeof simulation !== 'undefined' && simulation) {
        simulation.on('tick.path-overlay', _positionOverlay);
    }
}

function _clearPathHighlights() {
    d3.selectAll('#graph .node').classed('dim', false).classed('path-pick', false);
    d3.selectAll('#graph .node-label').classed('dim', false);
    d3.selectAll('#graph .link').classed('dim', false).classed('path-edge', false);
    d3.selectAll('#graph .pulse-ring').remove();
    d3.select('#graph svg .path-overlay').remove();
    if (typeof simulation !== 'undefined' && simulation) {
        simulation.on('tick.path-overlay', null);
    }
}

// ---- Hover correlation overlay ----
function _wireHoverCorrelation() {
    d3.selectAll('#graph .node')
        .on('mouseenter.correlate', function (event, d) {
            if (pathfinder.active) return;
            if (_hoverDebounceTimer) clearTimeout(_hoverDebounceTimer);
            const token = ++_correlationFetchToken;
            _hoverDebounceTimer = setTimeout(() => _fetchCorrelation(d, token), 250);
            _addPulseRing(d);
        })
        .on('mouseleave.correlate', function () {
            if (_hoverDebounceTimer) {
                clearTimeout(_hoverDebounceTimer);
                _hoverDebounceTimer = null;
            }
            _correlationFetchToken++;
            d3.selectAll('#graph .pulse-ring').remove();
            if (!pathfinder.active && !_clustersOn) {
                d3.selectAll('#graph .node').classed('highlight-node', false);
                d3.selectAll('#graph .link').classed('highlight-link', false);
            }
        });
}

function _addPulseRing(d) {
    d3.selectAll('#graph .pulse-ring').remove();
    const svg = d3.select('#graph svg');
    if (svg.empty()) return;
    svg.append('circle')
        .attr('class', 'pulse-ring')
        .attr('cx', d.x || 0)
        .attr('cy', d.y || 0)
        .attr('r', 12);
}

async function _fetchCorrelation(d, token) {
    if (!d || !d.id) return;
    try {
        const r = await fetch(`/api/correlate?id=${encodeURIComponent(d.id)}&depth=2`);
        if (!r.ok) return;
        if (token !== _correlationFetchToken) return; // stale hover
        const data = await r.json();
        const ids = new Set((data.nodes || []).map(n => n.id));
        d3.selectAll('#graph .node').classed('highlight-node', n => ids.has(n.id));
        d3.selectAll('#graph .link').classed('highlight-link', l => {
            const sId = (l.source && l.source.id) || l.source;
            const tId = (l.target && l.target.id) || l.target;
            return ids.has(sId) && ids.has(tId);
        });
    } catch (_e) { /* swallow */ }
}

// ---- Cluster grouping ----
function toggleClusters() {
    _clustersOn = !_clustersOn;
    const btn = document.getElementById('clusters-toggle');
    if (btn) btn.classList.toggle('active', _clustersOn);
    if (!simulation || !currentData) return;
    if (_clustersOn) {
        _applyClusterForces(currentData);
    } else {
        _removeClusterForces();
    }
    // Groups land somewhere new; refit once the layout settles.
    _graphNeedsFit = true;
    simulation.alpha(0.6).restart();
}

function _clusterKey(node) {
    if (node.type === 'host') {
        return `team:${node.team_name || node.team_id || 'no-team'}`;
    }
    if (node.type === 'software') {
        const cat = Array.isArray(node.category) && node.category.length ? node.category[0] : 'uncategorized';
        return `cat:${cat}`;
    }
    return 'users';
}

// Display text for a _clusterKey(); the raw key stays the d3 data key.
function _clusterLabel(key) {
    if (key === 'users') return 'Users';
    const [kind, ...rest] = key.split(':');
    const name = rest.join(':');
    if (kind === 'team') return name === 'no-team' ? 'Hosts · No team' : `Hosts · ${name}`;
    if (kind === 'cat') return `Software · ${name === 'uncategorized' ? 'Uncategorized' : name}`;
    return key;
}

function _applyClusterForces(data) {
    // Group the nodes the simulation actually renders. data.nodes also
    // holds nodes dropped by filterDisconnected, whose stale x/y from an
    // earlier layout drew hulls around empty space.
    const groups = new Map();
    simulation.nodes().forEach(n => {
        const k = _clusterKey(n);
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(n);
    });
    const groupKeys = Array.from(groups.keys());
    // One colour per team, assigned by sorted name so a team keeps its
    // colour across re-renders. Category, user and no-team hulls stay
    // on the neutral accent from app.css.
    const teamKeys = groupKeys.filter(k => k.startsWith('team:') && k !== 'team:no-team').sort();
    const teamColor = k => {
        const i = teamKeys.indexOf(k);
        return i < 0 ? null : `var(--team-${(i % 6) + 1})`;
    };
    const cols = Math.ceil(Math.sqrt(groupKeys.length || 1));
    const rows = Math.ceil((groupKeys.length || 1) / cols);
    const container = document.getElementById('graph');
    const w = container ? container.clientWidth : 1000;
    const h = container ? container.clientHeight : 700;
    // Size cells to the largest group, not the viewport: a 100-node
    // group packed by forceCollide needs far more room than a
    // viewport/3 cell, and undersized cells made neighbours overlap.
    // fitGraph() zooms to whatever extent this produces.
    // Packed area ~ sum of collision discs; 1.2 covers packing slack.
    const collide = simulation.force('collision');
    const collideR = collide ? collide.radius() : () => 20;
    const groupRadius = nodes => 1.2 * Math.sqrt(d3.sum(nodes, n => collideR(n) ** 2));
    const maxR = Math.max(1, ...Array.from(groups.values(), groupRadius));
    const cell = Math.max(200, 2 * maxR + 120);

    const centroids = new Map();
    groupKeys.forEach((k, idx) => {
        const cx = w / 2 + ((idx % cols) - (cols - 1) / 2) * cell;
        const cy = h / 2 + (Math.floor(idx / cols) - (rows - 1) / 2) * cell;
        centroids.set(k, { x: cx, y: cy });
    });

    simulation
        .force('clusterX', d3.forceX(d => (centroids.get(_clusterKey(d)) || { x: w / 2 }).x).strength(0.3))
        .force('clusterY', d3.forceY(d => (centroids.get(_clusterKey(d)) || { y: h / 2 }).y).strength(0.3));
    // Global repulsion at -320 spreads each group wider than its cell;
    // forceCollide alone keeps nodes from stacking.
    const chargeForce = simulation.force('charge');
    if (chargeForce) chargeForce.strength(-40);
    // Host-software links span groups and strength is per edge, so a
    // host with 100 installs out-pulls its cluster even at 0.03. Edges
    // still draw; they just stop shaping the layout while grouped.
    const linkForce = simulation.force('link');
    if (linkForce) linkForce.strength(0);

    // Hulls + labels — recomputed on tick but throttled to ~10fps so the
    // O(N + group_count * pts log pts) hull pass doesn't shadow the main
    // d3 simulation tick at 60fps. Reduced-motion: render hulls once,
    // skip subsequent recomputes to avoid jitter.
    // Hulls live inside the zoom root so they pan and zoom with the
    // nodes; on the bare <svg> they stayed in screen space and drifted
    // off their nodes after fitGraph() or any zoom.
    const root = d3.select('#graph svg .graph-root');
    root.selectAll('.cluster-hull-layer').remove();
    root.selectAll('.cluster-label-layer').remove();
    const hullLayer = root.insert('g', ':first-child').attr('class', 'cluster-hull-layer');
    const labelLayer = root.append('g').attr('class', 'cluster-label-layer');

    const _renderHulls = () => {
        const polygons = [];
        groups.forEach((nodes, key) => {
            const placed = nodes.filter(n => Number.isFinite(n.x) && Number.isFinite(n.y));
            if (!placed.length) return;
            // Ring each node with 8 points so the hull wraps the circles
            // instead of running through their centres, and so 1-2 node
            // groups still get an outline. collideR is radius + 8, so big
            // hub circles stay inside too.
            const pts = [];
            placed.forEach(n => {
                const pad = collideR(n) + 4;
                for (let i = 0; i < 8; i++) {
                    const a = (i / 8) * 2 * Math.PI;
                    pts.push([n.x + pad * Math.cos(a), n.y + pad * Math.sin(a)]);
                }
            });
            const hull = d3.polygonHull(pts);
            polygons.push({ key, hull, pts });
        });
        const sel = hullLayer.selectAll('path.cluster-hull').data(polygons.filter(p => p.hull), p => p.key);
        sel.exit().remove();
        sel.enter().append('path').attr('class', 'cluster-hull')
            .merge(sel)
            .style('fill', p => teamColor(p.key))
            .style('fill-opacity', p => (teamColor(p.key) ? 0.12 : null))
            .style('stroke', p => teamColor(p.key))
            .attr('d', p => 'M' + p.hull.map(c => c.join(',')).join('L') + 'Z');

        const lblSel = labelLayer.selectAll('text.cluster-label').data(polygons, p => p.key);
        lblSel.exit().remove();
        lblSel.enter().append('text').attr('class', 'cluster-label')
            .merge(lblSel)
            .attr('x', p => d3.mean(p.pts, c => c[0]))
            .style('fill', p => teamColor(p.key))
            .text(p => _clusterLabel(p.key));
        _sizeClusterLabels();
    };
    // Labels sit in the zoom root, so counter-scale them like node
    // labels: fitGraph() zooms a large layout out to ~0.4 and 11px
    // headings shrank to 4px.
    const _clusterZoomK = () => (_graphZoomTransform && _graphZoomTransform.k) || 1;
    const _sizeClusterLabels = () => {
        const k = _clusterZoomK();
        labelLayer.selectAll('text.cluster-label')
            // 16 screen px clears the top node's own label (r + 6/k up);
            // set here because fitGraph() zooms after the last tick.
            .attr('y', p => d3.min(p.pts, c => c[1]) - 16 / k)
            .style('font-size', `${12 / k}px`)
            .style('stroke-width', `${3 / k}px`);
    };
    if (_graphZoom) _graphZoom.on('zoom.cluster', _sizeClusterLabels);

    // Initial render so hulls are visible immediately.
    _renderHulls();

    if (_reduceMotion) {
        // Reduced-motion: don't re-render hulls during simulation, only on demand.
        simulation.on('tick.cluster', null);
    } else {
        let _lastHullTick = 0;
        const _hullThrottleMs = 100; // ~10fps
        simulation.on('tick.cluster', () => {
            const now = (typeof performance !== 'undefined' && performance.now)
                ? performance.now()
                : Date.now();
            if (now - _lastHullTick < _hullThrottleMs) return;
            _lastHullTick = now;
            _renderHulls();
        });
    }
}

function _removeClusterForces() {
    if (!simulation) return;
    simulation.force('clusterX', null);
    simulation.force('clusterY', null);
    simulation.on('tick.cluster', null);
    if (_graphZoom) _graphZoom.on('zoom.cluster', null);
    const linkForce = simulation.force('link');
    if (linkForce) linkForce.strength(0.2); // renderGraph's default
    const chargeForce = simulation.force('charge');
    if (chargeForce) chargeForce.strength(-320); // renderGraph's default
    const root = d3.select('#graph svg .graph-root');
    root.selectAll('.cluster-hull-layer').remove();
    root.selectAll('.cluster-label-layer').remove();
}

// Re-wire correlation hover after every renderGraph(); patch the global.
const _origRenderGraph = renderGraph;
renderGraph = function (data, filterDisconnected) {
    _origRenderGraph(data, filterDisconnected);
    _wireHoverCorrelation();
    if (pathfinder.active) _bindPathfinderClicks();
    if (_clustersOn) {
        _applyClusterForces(data);
        if (simulation) simulation.alpha(0.4).restart();
    }
};

// ========================================
// CHANGES TAB — snapshot diff
// ========================================
async function loadSnapshots() {
    try {
        // Recent history only: the picker and timeline never show more,
        // and the endpoint returns every snapshot otherwise.
        const r = await fetch('/api/snapshots?limit=60');
        if (!r.ok) return [];
        return await r.json();
    } catch (_e) { return []; }
}

// ---- snapshot timeline ----
let _timelineSnaps = [];

function renderSnapshotTimeline(snaps) {
    const panel = document.getElementById('snapshot-timeline');
    const track = document.getElementById('timeline-track');
    const hint = document.getElementById('timeline-hint');
    if (!panel || !track) return;

    _timelineSnaps = (snaps || []).slice().reverse();  // oldest → newest
    if (!_timelineSnaps.length) {
        panel.hidden = true;
        return;
    }
    panel.hidden = false;
    if (hint) {
        hint.textContent = `${_timelineSnaps.length} snapshots · click a point to diff it against the next newer one`;
    }

    const totals = _timelineSnaps.map((s) =>
        Number(s.hosts || 0) + Number(s.users || 0) + Number(s.software || 0));
    const max = Math.max(1, ...totals);

    track.innerHTML = '';
    _timelineSnaps.forEach((s, i) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'timeline-bar';
        btn.dataset.index = String(i);
        btn.setAttribute('role', 'option');
        btn.setAttribute('aria-selected', 'false');
        btn.setAttribute('tabindex', i === _timelineSnaps.length - 1 ? '0' : '-1');
        btn.style.setProperty('--h', Math.round(18 + (totals[i] / max) * 82) + '%');
        const label = `${s.ts} — ${HOUND.fmt.int(s.hosts)} hosts, `
            + `${HOUND.fmt.int(s.users)} identities, ${HOUND.fmt.int(s.software)} software`;
        btn.title = label;
        btn.setAttribute('aria-label', label);
        track.appendChild(btn);
    });

    track.onclick = (event) => {
        const btn = event.target.closest('.timeline-bar');
        if (btn) _pickTimelineSnapshot(Number(btn.dataset.index));
    };

    track.onkeydown = (event) => {
        const btn = event.target.closest('.timeline-bar');
        if (!btn) return;
        const i = Number(btn.dataset.index);
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            _pickTimelineSnapshot(i);
            return;
        }
        const step = event.key === 'ArrowLeft' ? -1 : (event.key === 'ArrowRight' ? 1 : 0);
        if (!step) return;
        event.preventDefault();
        const next = track.children[Math.min(track.children.length - 1, Math.max(0, i + step))];
        if (!next) return;
        Array.from(track.children).forEach((el) => el.setAttribute('tabindex', '-1'));
        next.setAttribute('tabindex', '0');
        next.focus();
    };

    _syncTimelineSelection();
}

function _syncTimelineSelection() {
    const track = document.getElementById('timeline-track');
    const fromSel = document.getElementById('diff-from-select');
    const toSel = document.getElementById('diff-to-select');
    if (!track) return;
    const from = fromSel ? fromSel.value : '';
    const to = toSel ? toSel.value : '';
    Array.from(track.children).forEach((el) => {
        const snap = _timelineSnaps[Number(el.dataset.index)];
        const slug = snap ? (snap.slug || snap.ts) : '';
        const isFrom = !!slug && slug === from;
        const isTo = !!slug && slug === to;
        el.classList.toggle('is-from', isFrom);
        el.classList.toggle('is-to', isTo);
        el.setAttribute('aria-selected', isFrom || isTo ? 'true' : 'false');
    });
}

function _pickTimelineSnapshot(index) {
    const fromSel = document.getElementById('diff-from-select');
    const toSel = document.getElementById('diff-to-select');
    if (!fromSel || !toSel || !_timelineSnaps[index]) return;
    // Diff this snapshot against the next newer one. Clicking the
    // newest point has no "after", so it diffs the previous snapshot
    // into it — the interval ending at the click, never a self-diff.
    let older = _timelineSnaps[index];
    let newer = _timelineSnaps[index + 1];
    if (!newer) {
        newer = _timelineSnaps[index];
        older = _timelineSnaps[index - 1] || newer;
    }
    fromSel.value = older.slug || older.ts;
    toSel.value = newer.slug || newer.ts;
    _syncTimelineSelection();
    runDiff();
}

function _populateSnapshotPickers(snaps) {
    const fromSel = document.getElementById('diff-from-select');
    const toSel = document.getElementById('diff-to-select');
    if (!fromSel || !toSel) return;
    fromSel.innerHTML = '';
    toSel.innerHTML = '';
    if (!snaps || snaps.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No snapshots yet';
        fromSel.appendChild(opt.cloneNode(true));
        toSel.appendChild(opt);
        return;
    }
    snaps.forEach(s => {
        const o = document.createElement('option');
        o.value = s.slug || s.ts;
        o.textContent = `${s.ts} — ${s.hosts}h ${s.users}u ${s.software}s`;
        fromSel.appendChild(o.cloneNode(true));
        toSel.appendChild(o);
    });
    // Default: from = previous (idx 1), to = latest (idx 0).
    toSel.selectedIndex = 0;
    fromSel.selectedIndex = Math.min(1, snaps.length - 1);

    renderSnapshotTimeline(snaps);
    // The pickers are the source of truth for the interval; keep the
    // timeline marks in sync when they change.
    if (!fromSel.dataset.timelineWired) {
        fromSel.dataset.timelineWired = '1';
        fromSel.addEventListener('change', _syncTimelineSelection);
        toSel.addEventListener('change', _syncTimelineSelection);
    }

    // The pickers already default to previous → latest, so show that
    // interval instead of an empty panel demanding a second click.
    runDiff();
}

async function runDiff() {
    const fromSel = document.getElementById('diff-from-select');
    const toSel = document.getElementById('diff-to-select');
    const results = document.getElementById('changes-results');
    const bar = document.getElementById('changes-filter-bar');
    if (!fromSel || !toSel || !results) return;
    const from = fromSel.value;
    const to = toSel.value;
    if (!from || !to) {
        results.innerHTML = '<div class="changes-empty">Pick two snapshots first.</div>';
        if (bar) bar.hidden = true;
        _lastDiffData = null;
        return;
    }
    results.innerHTML = '<div class="changes-empty">Computing diff…</div>';
    if (bar) bar.hidden = true;
    _lastDiffData = null;
    try {
        const r = await fetch(`/api/diff?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
        if (!r.ok) {
            results.innerHTML = `<div class="changes-empty">Diff failed (${r.status})</div>`;
            return;
        }
        const data = await r.json();
        _renderDiff(data);
    } catch (e) {
        console.error(e);
        results.innerHTML = '<div class="changes-empty">Diff request failed</div>';
    }
}

let _changesFilterDebounce = null;
function _wireChangesFilterUI() {
    const input = document.getElementById('changes-search-input');
    const clearBtn = document.getElementById('changes-search-clear');
    const cs = document.getElementById('changes-case-sensitive');
    const rx = document.getElementById('changes-regex-mode');
    const sd = document.getElementById('changes-search-drift-values');
    const bucketGroup = document.getElementById('changes-bucket-chips');
    const typeGroup = document.getElementById('changes-type-chips');
    if (!input || !bucketGroup || !typeGroup) return;

    input.addEventListener('input', () => {
        _changesFilter.text = input.value;
        clearTimeout(_changesFilterDebounce);
        _changesFilterDebounce = setTimeout(_applyChangesFilter, 120);
    });
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            input.value = '';
            _changesFilter.text = '';
            _applyChangesFilter();
        }
    });
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            _resetChangesFilter();
            _applyChangesFilter();
        });
    }
    if (cs) cs.addEventListener('change', () => {
        _changesFilter.caseSensitive = cs.checked;
        _applyChangesFilter();
    });
    if (rx) rx.addEventListener('change', () => {
        _changesFilter.regex = rx.checked;
        _applyChangesFilter();
    });
    if (sd) sd.addEventListener('change', () => {
        _changesFilter.searchDriftValues = sd.checked;
        _applyChangesFilter();
    });
    bucketGroup.addEventListener('click', (e) => {
        const chip = e.target.closest('.changes-chip[data-bucket]');
        if (!chip) return;
        const key = chip.getAttribute('data-bucket');
        _changesFilter.buckets[key] = !_changesFilter.buckets[key];
        chip.classList.toggle('active', _changesFilter.buckets[key]);
        _applyChangesFilter();
    });
    typeGroup.addEventListener('click', (e) => {
        const chip = e.target.closest('.changes-chip[data-type]');
        if (!chip) return;
        const key = chip.getAttribute('data-type');
        _changesFilter.types[key] = !_changesFilter.types[key];
        chip.classList.toggle('active', _changesFilter.types[key]);
        _applyChangesFilter();
    });
}

// Holds the most recent /api/diff payload so the filter UI can re-render
// without refetching. Reset whenever runDiff() fires a new fetch.
let _lastDiffData = null;
const _CHANGES_DEFAULT_CAP = 200;
const _changesFilter = {
    text: '',
    caseSensitive: false,
    regex: false,
    searchDriftValues: false,
    buckets: { added: true, removed: true, changed: true },
    types: { hosts: true, users: true, software: true, edges: true },
};

function _resetChangesFilter() {
    _changesFilter.text = '';
    _changesFilter.caseSensitive = false;
    _changesFilter.regex = false;
    _changesFilter.searchDriftValues = false;
    _changesFilter.buckets = { added: true, removed: true, changed: true };
    _changesFilter.types = { hosts: true, users: true, software: true, edges: true };
    const input = document.getElementById('changes-search-input');
    if (input) input.value = '';
    const cs = document.getElementById('changes-case-sensitive');
    if (cs) cs.checked = false;
    const rx = document.getElementById('changes-regex-mode');
    if (rx) rx.checked = false;
    const sd = document.getElementById('changes-search-drift-values');
    if (sd) sd.checked = false;
    document.querySelectorAll('#changes-bucket-chips .changes-chip').forEach(c => c.classList.add('active'));
    document.querySelectorAll('#changes-type-chips .changes-chip').forEach(c => c.classList.add('active'));
}

function _changesFilterIsActive() {
    if (_changesFilter.text.trim()) return true;
    if (!_changesFilter.buckets.added || !_changesFilter.buckets.removed || !_changesFilter.buckets.changed) return true;
    if (!_changesFilter.types.hosts || !_changesFilter.types.users
        || !_changesFilter.types.software || !_changesFilter.types.edges) return true;
    return false;
}

function _buildChangesMatcher() {
    const raw = _changesFilter.text.trim();
    if (!raw) return { ok: true, match: () => true, error: null };
    if (_changesFilter.regex) {
        try {
            const re = new RegExp(raw, _changesFilter.caseSensitive ? '' : 'i');
            return { ok: true, match: (s) => re.test(String(s)), error: null };
        } catch (e) {
            return { ok: false, match: () => false, error: e.message };
        }
    }
    const needle = _changesFilter.caseSensitive ? raw : raw.toLowerCase();
    const fn = _changesFilter.caseSensitive
        ? (s) => String(s).includes(needle)
        : (s) => String(s).toLowerCase().includes(needle);
    return { ok: true, match: fn, error: null };
}

function _highlight(text, matcher) {
    const raw = _changesFilter.text.trim();
    if (!raw) return escapeHtml(text);
    try {
        let re;
        if (_changesFilter.regex) {
            re = new RegExp(raw, _changesFilter.caseSensitive ? 'g' : 'gi');
        } else {
            const esc = raw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            re = new RegExp(esc, _changesFilter.caseSensitive ? 'g' : 'gi');
        }
        const str = String(text);
        let out = '';
        let last = 0;
        for (const m of str.matchAll(re)) {
            out += escapeHtml(str.slice(last, m.index));
            out += `<mark class="match-hit">${escapeHtml(m[0])}</mark>`;
            last = m.index + m[0].length;
            if (!m[0].length) break; // guard against zero-width regex
        }
        out += escapeHtml(str.slice(last));
        return out;
    } catch (_e) {
        return escapeHtml(text);
    }
}

// Totals for the interval, independent of the active filter. The
// sections below can be filtered down to nothing, so without this the
// page can look empty while 900 nodes actually changed.
function _changesDeltaRibbon(data) {
    const countBucket = (b) => {
        if (!b) return 0;
        return ['hosts', 'users', 'software']
            .reduce((acc, k) => acc + ((b[k] || []).length), 0)
            + (b.edges || []).length;
    };
    const added = countBucket(data.added);
    const removed = countBucket(data.removed);
    const changed = (data.changed || []).length;
    const total = added + removed + changed;
    const pct = (n) => (total ? (n / total) * 100 : 0);
    const seg = (n, color) => (n > 0
        ? `<div class="delta-ribbon-seg" data-width="${pct(n).toFixed(2)}" style="background: ${color}"></div>`
        : '');

    return `<div class="delta-ribbon" role="group"
                 aria-label="${added} added, ${removed} removed, ${changed} changed">
        <div class="delta-ribbon-cell added"><span>Added</span><strong>${HOUND.fmt.int(added)}</strong></div>
        <div class="delta-ribbon-cell removed"><span>Removed</span><strong>${HOUND.fmt.int(removed)}</strong></div>
        <div class="delta-ribbon-cell changed"><span>Property drift</span><strong>${HOUND.fmt.int(changed)}</strong></div>
        <div class="delta-ribbon-bar">${seg(added, 'var(--success)')}${seg(removed, 'var(--danger)')}${seg(changed, 'var(--warning)')}</div>
    </div>`;
}

let _animateDeltaRibbon = false;

function _renderDiff(data) {
    _lastDiffData = data || null;
    _resetChangesFilter();
    _animateDeltaRibbon = true;
    const bar = document.getElementById('changes-filter-bar');
    if (bar) bar.hidden = !_lastDiffData;
    _applyChangesFilter();
}

function _applyChangesFilter() {
    const results = document.getElementById('changes-results');
    if (!results) return;
    if (!_lastDiffData) {
        results.innerHTML = '<div class="changes-empty">Pick two snapshots and run diff.</div>';
        return;
    }
    const matcherInfo = _buildChangesMatcher();
    const summary = document.getElementById('changes-filter-summary');
    const data = _lastDiffData;
    const filterActive = _changesFilterIsActive();
    const cap = filterActive ? Infinity : _CHANGES_DEFAULT_CAP;

    const sections = [
        { key: 'added', label: 'Added', badge: 'badge-added' },
        { key: 'removed', label: 'Removed', badge: 'badge-removed' },
    ];
    let html = '';
    let totalShown = 0;
    let totalMatched = 0;

    sections.forEach(({ key, label, badge }) => {
        if (!_changesFilter.buckets[key]) return;
        const bucket = data[key] || {};
        let sectionMatched = 0;
        let sectionShown = 0;
        let sectionTotal = 0;
        let body = '';

        ['hosts', 'users', 'software'].forEach(k => {
            const items = bucket[k] || [];
            sectionTotal += items.length;
            if (!_changesFilter.types[k]) return;
            const filtered = matcherInfo.ok
                ? items.filter(id => matcherInfo.match(id))
                : [];
            if (!filtered.length) return;
            sectionMatched += filtered.length;
            const slice = filtered.slice(0, cap);
            sectionShown += slice.length;
            body += `<div style="padding:8px 14px;color:var(--text-tertiary);font-size:12px;text-transform:uppercase;letter-spacing:0.05em;">${k} (${filtered.length}${filtered.length !== items.length ? ` of ${items.length}` : ''})</div>`;
            body += '<ul class="changes-list">';
            slice.forEach(id => {
                body += `<li>
                    <span class="id-badge">${_highlight(id, matcherInfo)}</span>
                    <span class="view-link" data-jump-id="${escapeHtml(id)}">View on graph →</span>
                </li>`;
            });
            if (filtered.length > slice.length) {
                body += `<li><span class="id-badge">… ${filtered.length - slice.length} more</span></li>`;
            }
            body += '</ul>';
        });

        if (_changesFilter.types.edges) {
            const edges = bucket.edges || [];
            sectionTotal += edges.length;
            const filteredEdges = matcherInfo.ok
                ? edges.filter(e => matcherInfo.match(e.label) || matcherInfo.match(e.from) || matcherInfo.match(e.to))
                : [];
            if (filteredEdges.length) {
                sectionMatched += filteredEdges.length;
                const slice = filteredEdges.slice(0, cap);
                sectionShown += slice.length;
                body += `<div style="padding:8px 14px;color:var(--text-tertiary);font-size:12px;text-transform:uppercase;letter-spacing:0.05em;">edges (${filteredEdges.length}${filteredEdges.length !== edges.length ? ` of ${edges.length}` : ''})</div>`;
                body += '<ul class="changes-list">';
                slice.forEach(e => {
                    body += `<li><span class="id-badge">${_highlight(e.label, matcherInfo)}: ${_highlight(e.from, matcherInfo)} → ${_highlight(e.to, matcherInfo)}</span></li>`;
                });
                if (filteredEdges.length > slice.length) {
                    body += `<li><span class="id-badge">… ${filteredEdges.length - slice.length} more</span></li>`;
                }
                body += '</ul>';
            }
        }

        html += `<section class="changes-section">
            <header>${label}
                <span class="badge ${badge}">${filterActive ? `${sectionMatched} of ${sectionTotal}` : `${sectionTotal}`} match${sectionMatched === 1 && filterActive ? '' : 'es'}</span>
            </header>`;
        if (sectionMatched === 0) {
            html += filterActive
                ? '<div class="changes-empty">No matches in this bucket.</div>'
                : '<div class="changes-empty">Nothing.</div>';
        } else {
            html += body;
        }
        html += '</section>';

        totalMatched += sectionMatched;
        totalShown += sectionShown;
    });

    if (_changesFilter.buckets.changed) {
        const changed = data.changed || [];
        let changedMatched = 0;
        let body = '';
        const filtered = matcherInfo.ok
            ? changed.filter(c => {
                if (matcherInfo.match(c.id)) return true;
                if (!_changesFilter.searchDriftValues) return false;
                const props = c.props_changed || {};
                for (const k of Object.keys(props)) {
                    if (matcherInfo.match(k)) return true;
                    const v = props[k] || {};
                    try {
                        if (matcherInfo.match(JSON.stringify(v.old))) return true;
                        if (matcherInfo.match(JSON.stringify(v.new))) return true;
                    } catch (_e) { /* skip */ }
                }
                return false;
            })
            : [];
        changedMatched = filtered.length;
        const slice = filtered.slice(0, cap);
        if (slice.length) {
            body += '<ul class="changes-list">';
            slice.forEach(c => {
                const propKeys = Object.keys(c.props_changed || {});
                const summaryStr = propKeys.slice(0, 3).map(k => {
                    const v = c.props_changed[k];
                    return `${_highlight(k, matcherInfo)}: ${_highlight(JSON.stringify(v.old), matcherInfo)} → ${_highlight(JSON.stringify(v.new), matcherInfo)}`;
                }).join(' · ');
                body += `<li>
                    <div>
                        <div class="id-badge">${_highlight(c.id, matcherInfo)}</div>
                        <div style="font-size:11px;color:var(--text-tertiary);margin-top:2px;">${summaryStr}</div>
                    </div>
                    <span class="view-link" data-jump-id="${escapeHtml(c.id)}">View on graph →</span>
                </li>`;
            });
            if (filtered.length > slice.length) {
                body += `<li><span class="id-badge">… ${filtered.length - slice.length} more</span></li>`;
            }
            body += '</ul>';
        }
        html += `<section class="changes-section">
            <header>Property drift
                <span class="badge badge-changed">${filterActive ? `${changedMatched} of ${changed.length}` : `${changed.length}`} nodes</span>
            </header>`;
        if (!changedMatched) {
            html += filterActive
                ? '<div class="changes-empty">No matches in property drift.</div>'
                : '<div class="changes-empty">No property drift detected.</div>';
        } else {
            html += body;
        }
        html += '</section>';
        totalMatched += changedMatched;
        totalShown += slice.length;
    }

    results.innerHTML = _changesDeltaRibbon(data) + html;

    // Grow the ribbon only for a freshly computed diff. A filter
    // keystroke re-renders the same numbers, so animating there would
    // flash the bar on every character typed.
    const ribbonSegs = results.querySelectorAll('.delta-ribbon-seg');
    if (_animateDeltaRibbon) {
        requestAnimationFrame(() => {
            ribbonSegs.forEach((el) => {
                el.style.width = (el.dataset.width || 0) + '%';
            });
        });
    } else {
        ribbonSegs.forEach((el) => {
            el.style.width = (el.dataset.width || 0) + '%';
        });
    }
    _animateDeltaRibbon = false;

    if (summary) {
        if (!matcherInfo.ok) {
            summary.innerHTML = `<span class="changes-filter-error">Regex error: ${escapeHtml(matcherInfo.error || '')}</span>`;
        } else if (filterActive) {
            summary.innerHTML = `Showing <strong>${totalShown}</strong> of <strong>${totalMatched}</strong> match${totalMatched === 1 ? '' : 'es'}.`;
        } else {
            summary.innerHTML = `No filter. Each list capped at <strong>${_CHANGES_DEFAULT_CAP}</strong> — type to search all.`;
        }
    }

    results.querySelectorAll('[data-jump-id]').forEach(el => {
        el.addEventListener('click', () => {
            const id = el.getAttribute('data-jump-id');
            if (typeof switchView === 'function') switchView('graph');
            setTimeout(() => _jumpToCorrelation(id), 60);
        });
    });
}

async function _jumpToCorrelation(typedId) {
    try {
        const r = await fetch(`/api/correlate?id=${encodeURIComponent(typedId)}&depth=1`);
        if (!r.ok) return;
        const data = await r.json();
        if (!data.nodes || !data.nodes.length) return;
        currentData = data;
        renderGraph(data);
        setTimeout(() => {
            d3.selectAll('#graph .node').classed('highlight-node', d => d.id === typedId);
        }, 80);
    } catch (_e) { /* swallow */ }
}

// ========================================
// ENRICHER STATUS PILL
// ========================================
let _enricherTimer = null;

async function refreshEnricherStatus() {
    const pill = document.getElementById('enricher-pill');
    if (!pill) return;
    try {
        const r = await fetch('/api/enricher/status');
        if (!r.ok) { pill.hidden = true; return; }
        const s = await r.json();
        pill.hidden = false;
        pill.classList.remove('is-running', 'is-error', 'is-disabled');
        if (!s.enabled) pill.classList.add('is-disabled');
        else if (s.last_error) pill.classList.add('is-error');
        else if (s.running) pill.classList.add('is-running');
        const text = document.getElementById('enricher-pill-text');
        if (text) {
            const total = s.items_categorized_total || 0;
            const queue = s.queue_remaining || 0;
            text.textContent = `${total.toLocaleString()} enriched · ${queue.toLocaleString()} left`;
        }
        document.getElementById('enricher-last-tick').textContent = s.last_tick_iso || '—';
        document.getElementById('enricher-total').textContent = (s.items_categorized_total || 0).toLocaleString();
        document.getElementById('enricher-queue').textContent = (s.queue_remaining || 0).toLocaleString();
        const errRow = document.getElementById('enricher-error-row');
        const errSpan = document.getElementById('enricher-error');
        if (s.last_error) {
            errRow.hidden = false;
            errSpan.textContent = s.last_error;
        } else {
            errRow.hidden = true;
        }
    } catch (_e) {
        pill.hidden = true;
    }
}

function _wireEnricherUI() {
    const pill = document.getElementById('enricher-pill');
    const popover = document.getElementById('enricher-popover');
    const runBtn = document.getElementById('enricher-run-now-btn');
    if (!pill || !popover || !runBtn) return;
    pill.addEventListener('click', (e) => {
        e.stopPropagation();
        popover.hidden = !popover.hidden;
    });
    document.addEventListener('click', (e) => {
        if (popover.hidden) return;
        if (e.target === pill || pill.contains(e.target)) return;
        if (!popover.contains(e.target)) popover.hidden = true;
    });
    runBtn.addEventListener('click', async () => {
        runBtn.disabled = true;
        runBtn.textContent = 'Triggering…';
        try {
            const r = await fetch('/api/enricher/trigger', { method: 'POST' });
            if (r.status === 204) {
                runBtn.textContent = 'Triggered';
                setTimeout(refreshEnricherStatus, 800);
            } else if (r.status === 429) {
                runBtn.textContent = 'Cooldown — try later';
            } else {
                runBtn.textContent = `Failed (${r.status})`;
            }
        } catch (_e) {
            runBtn.textContent = 'Failed';
        }
        setTimeout(() => {
            runBtn.disabled = false;
            runBtn.textContent = 'Run now';
        }, 4000);
    });
}

// ========================================
// EXTENSIONS VIEW
// ========================================
const _EXT_SIGNAL_GOOD = new Set([
    'browser-builtin', 'reputable-publisher', 'store-listed',
    'verified-developer', 'manifest-v3', 'crx-hash-verified',
    'install-popularity', 'store-rating', 'store-updated',
    'low-installs-reputable-publisher',
]);

function _extSignalClass(signal) {
    const code = signal.code || '';
    if (_EXT_SIGNAL_GOOD.has(code)) return 'good';
    const weight = Number(signal.weight) || 0;
    if (weight >= 25) return 'bad';
    if (weight > 0) return 'warn';
    return '';
}

function _extBadge(band) {
    const safe = ['critical', 'high', 'medium', 'low'].includes(band) ? band : 'unassessed';
    return `<span class="badge badge-${safe}">${escapeHtml((band || 'unassessed').toUpperCase())}</span>`;
}

async function loadExtensions() {
    const searchEl = document.getElementById('ext-search-input');
    const params = new URLSearchParams({
        risk: document.getElementById('ext-risk-filter').value,
        store: document.getElementById('ext-store-filter').value,
        search: searchEl ? searchEl.value.trim() : '',
        include_builtin: document.getElementById('ext-include-builtin').checked ? '1' : '0',
    });

    try {
        const isLatest = beginRequest('extensions');
        const resp = await fetch(`/api/extensions?${params}`);
        const data = await resp.json();
        if (!isLatest()) return;
        if (!resp.ok) throw new Error(data.error || 'query failed');

        const summary = data.summary || {};
        HOUND.countUp(document.getElementById('ext-critical'), Number(summary.critical ?? 0));
        HOUND.countUp(document.getElementById('ext-high'), Number(summary.high ?? 0));
        HOUND.countUp(document.getElementById('ext-medium'), Number(summary.medium ?? 0));
        HOUND.countUp(document.getElementById('ext-low'), Number(summary.low ?? 0));
        HOUND.countUp(document.getElementById('ext-total'), Number(summary.total ?? 0));
        HOUND.countUp(document.getElementById('ext-hosts'), Number(summary.affected_hosts ?? 0));

        _renderExtensionWorkerLine(data.worker);
        _renderExtensionsTable(data.extensions || []);
        _renderExtensionMatrix(data.extensions || []);
    } catch (error) {
        console.error('Error loading extensions:', error);
        const tbody = document.getElementById('extensions-tbody');
        tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><div class="empty-state-icon">&#9888;</div><div>${escapeHtml(error.message || 'Failed to load extensions')}</div></div></td></tr>`;
    }
}

// ---- prevalence × risk matrix ----
// Rows are risk bands, columns are host-count buckets. A cell is a
// count of extensions, not a score: "3 high-risk extensions are each on
// 5–9 hosts" is the fact an operator needs to prioritise a sweep.
const EXT_BANDS = [
    { key: 'critical', label: 'Critical', tone: 'var(--danger)' },
    { key: 'high', label: 'High', tone: 'var(--warning)' },
    { key: 'medium', label: 'Medium', tone: 'var(--caution)' },
    { key: 'low', label: 'Low', tone: 'var(--success)' },
    { key: 'unassessed', label: 'Unassessed', tone: 'var(--text-tertiary)' },
];

const EXT_PREVALENCE = [
    { key: 'one', label: '1 host', match: (n) => n === 1 },
    { key: 'few', label: '2–4 hosts', match: (n) => n >= 2 && n <= 4 },
    { key: 'some', label: '5–9 hosts', match: (n) => n >= 5 && n <= 9 },
    { key: 'many', label: '10+ hosts', match: (n) => n >= 10 },
];

function _renderExtensionMatrix(extensions) {
    const host = document.getElementById('ext-matrix');
    if (!host) return;
    host.innerHTML = '';

    if (!extensions.length) {
        host.innerHTML = '<div class="ext-matrix-label" style="padding:8px 0;">No extensions match the current filters</div>';
        return;
    }

    const counts = new Map();
    let unknownHosts = 0;
    extensions.forEach((ext) => {
        const band = EXT_BANDS.some((b) => b.key === ext.risk_band) ? ext.risk_band : 'unassessed';
        const hosts = Number(ext.host_count || 0);
        const bucket = EXT_PREVALENCE.find((p) => p.match(hosts));
        if (!bucket) { unknownHosts += 1; return; }
        const key = `${band}:${bucket.key}`;
        counts.set(key, (counts.get(key) || 0) + 1);
    });

    const hintEl = document.getElementById('ext-matrix-hint');
    if (hintEl) {
        hintEl.textContent = unknownHosts
            ? `How widely each risk band has spread · ${HOUND.fmt.int(unknownHosts)} with no host count omitted`
            : 'How widely each risk band has spread';
    }

    const max = Math.max(1, ...counts.values());

    // Header row.
    const head = document.createElement('div');
    head.className = 'ext-matrix-row';
    head.setAttribute('role', 'row');
    const riskHead = Object.assign(document.createElement('div'), { className: 'ext-matrix-headcell', textContent: 'Risk' });
    riskHead.setAttribute('role', 'columnheader');
    head.appendChild(riskHead);
    EXT_PREVALENCE.forEach((p) => {
        const cell = Object.assign(document.createElement('div'), {
            className: 'ext-matrix-headcell',
            textContent: p.label,
        });
        cell.setAttribute('role', 'columnheader');
        head.appendChild(cell);
    });
    host.appendChild(head);

    EXT_BANDS.forEach((band) => {
        const rowTotal = EXT_PREVALENCE.reduce(
            (acc, p) => acc + (counts.get(`${band.key}:${p.key}`) || 0), 0
        );
        if (!rowTotal) return;

        const row = document.createElement('div');
        row.className = 'ext-matrix-row';
        row.setAttribute('role', 'row');

        const label = document.createElement('div');
        label.className = 'ext-matrix-label';
        label.innerHTML = `<span class="comp-swatch" style="background: ${band.tone}"></span>${band.label}`
            + ` <span class="ext-cell-note">${HOUND.fmt.int(rowTotal)}</span>`;
        row.appendChild(label);

        EXT_PREVALENCE.forEach((p) => {
            const n = counts.get(`${band.key}:${p.key}`) || 0;
            const cell = document.createElement('div');
            cell.className = 'ext-cell' + (n ? ' has-value' : '');
            cell.setAttribute('role', 'cell');
            cell.setAttribute('aria-label', `${n} ${band.label} extensions on ${p.label}`);
            if (n) {
                cell.style.setProperty('--cell-tone', band.tone);
                cell.style.setProperty('--cell-alpha', String(Math.min(0.9, 0.14 + (n / max) * 0.7)));
                cell.textContent = HOUND.fmt.int(n);
            } else {
                cell.textContent = '·';
            }
            row.appendChild(cell);
        });

        host.appendChild(row);
    });
}


function _renderExtensionWorkerLine(worker) {
    const line = document.getElementById('ext-worker-line');
    if (!line) return;
    if (!worker) { line.textContent = 'Worker: unavailable'; return; }
    const state = worker.enabled ? (worker.running ? 'running' : 'idle') : 'disabled';
    const tick = worker.last_tick_iso ? worker.last_tick_iso.replace('T', ' ').slice(0, 16) : 'never';
    const err = worker.last_error ? ` · last error: ${worker.last_error}` : '';
    const feeds = (worker.threat_feeds || []).map(f =>
        `${f.name} ${Number(f.entries || 0).toLocaleString()} IDs${f.error ? ` (${f.error})` : ''}`).join(', ');
    // Fill rates per store: a store whose numbers drop is a broken adapter.
    const cov = (worker.coverage || []).filter(c => c.total).map(c =>
        `${c.store} ${c.with_users}/${c.total} installs, ${c.manifest_parsed}/${c.total} manifests` +
        (c.uninspected ? `, ${c.uninspected} uninspected` : '') + (c.feed_hits ? `, ${c.feed_hits} feed hits` : ''));
    line.textContent = `Worker: ${state} · last run ${tick}${err}` +
        (feeds ? ` · feeds: ${feeds}` : ' · feeds: none configured');
    line.title = cov.length ? `Enrichment coverage\n${cov.join('\n')}` : '';
}

function _renderExtensionsTable(extensions) {
    const tbody = document.getElementById('extensions-tbody');
    if (!extensions.length) {
        tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><div class="empty-state-icon">&#10003;</div><div>No browser extensions match the filters</div></div></td></tr>`;
        return;
    }
    tbody.innerHTML = '';
    extensions.forEach(ext => {
        const row = document.createElement('tr');
        row.onclick = () => showExtensionDetail(ext.extension_key);
        const signals = (ext.risk_signals || []).slice(0, 4).map(s =>
            `<span class="extension-signal ${_extSignalClass(s)}">${escapeHtml(s.code)}${s.weight ? ` +${s.weight}` : ''}</span>`
        ).join(' ');
        const installs = ext.install_users == null ? '—' : Number(ext.install_users).toLocaleString();
        const publisher = ext.publisher || ext.vendor || '—';
        row.innerHTML = `
            <td><strong>${escapeHtml(ext.display_name || ext.name || ext.extension_key)}</strong>
                <div class="text-sm" style="color: var(--text-tertiary);">${escapeHtml(truncateText(ext.extension_id || '', 34))}</div></td>
            <td class="text-sm">${escapeHtml(ext.store || '—')}</td>
            <td>${_extBadge(ext.risk_band)}${ext.risk_score != null ? ` <span class="text-sm text-secondary">${ext.risk_score}</span>` : ''}</td>
            <td class="text-sm">${installs}</td>
            <td>${ext.host_count || 0}</td>
            <td class="text-sm">${escapeHtml(truncateText(publisher, 28))}${ext.publisher_reputable ? ' <span class="extension-signal good">known</span>' : ''}</td>
            <td class="text-sm">${signals || '<span style="color: var(--text-tertiary);">—</span>'}</td>
        `;
        tbody.appendChild(row);
    });
}

async function showExtensionDetail(key) {
    if (!key) return;
    const modal = document.getElementById('extension-details-modal');
    const body = document.getElementById('extension-details-body');
    try {
        const resp = await fetch(`/api/extensions/detail?key=${encodeURIComponent(key)}`);
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'not found');
        const ext = data.extension || {};
        document.getElementById('ext-modal-title').textContent = ext.display_name || ext.name || key;

        const signals = (ext.risk_signals || []).map(s => {
            const cls = _extSignalClass(s);
            return `<div class="signal-row">
                <span class="extension-signal ${cls}">${cls || 'info'}</span>
                <span class="signal-weight">${s.weight != null ? (s.weight > 0 ? `+${s.weight}` : s.weight) : '0'}</span>
                <strong>${escapeHtml(s.code)}</strong> — <span class="text-sm" style="color: var(--text-secondary);">${escapeHtml(s.detail || '')}</span>
            </div>`;
        }).join('') || '<p class="text-secondary">No signals recorded yet. Run "Refresh intel".</p>';

        const vulns = (ext.vulnerabilities || []).map(v =>
            `<div class="signal-row"><span class="extension-signal ${Number(v.cvss_score) >= 7 ? 'bad' : 'warn'}">${escapeHtml(v.cve || 'CVE')}</span>
             CVSS ${v.cvss_score != null ? escapeHtml(String(v.cvss_score)) : '?'} ${v.details ? `— ${escapeHtml(truncateText(v.details, 120))}` : ''}</div>`
        ).join('') || '<p class="text-secondary">No Fleet-reported vulnerabilities.</p>';

        const hosts = (data.hosts || []).map(h => `
            <tr>
                <td class="text-sm">${escapeHtml(h.hostname || '')}</td>
                <td class="text-sm">${escapeHtml(h.version || '')}</td>
                <td class="text-sm" style="color: var(--text-tertiary);">${escapeHtml(truncateText(h.installed_path || h.source || '', 60))}</td>
            </tr>`).join('');

        body.innerHTML = `
            <div class="detail-row">
                <div class="detail-label">Risk</div>
                <div class="detail-value">${_extBadge(ext.risk_band)} <strong style="margin-left:6px;">${ext.risk_score != null ? ext.risk_score : 'unassessed'}</strong>
                    <span class="text-sm" style="color: var(--text-secondary); margin-left:8px;">
                        capability ${ext.capability_score ?? '—'} · trust ${ext.trust_score ?? '—'} · threat ${ext.threat_score ?? '—'} · exposure ${ext.exposure_score ?? '—'}
                    </span></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Identity</div>
                <div class="detail-value text-sm">
                    key <code>${escapeHtml(ext.extension_key || key)}</code><br>
                    store <strong>${escapeHtml(ext.store || '—')}</strong> (${escapeHtml(ext.store_status || 'unknown')}) ·
                    latest ${escapeHtml(ext.latest_version || '—')} · MV${ext.manifest_version ?? '—'}<br>
                    publisher <strong>${escapeHtml(ext.publisher || ext.vendor || '—')}</strong>${ext.publisher_reputable ? ' <span class="extension-signal good">known vendor</span>' : ''}
                    ${ext.install_users != null ? ` · ${Number(ext.install_users).toLocaleString()} installs` : ' · install count unavailable'}
                </div>
            </div>
            ${/^https:\/\//i.test(ext.store_url || '') ? `<div class="detail-row"><div class="detail-label">Store listing</div><div class="detail-value"><a href="${escapeHtml(ext.store_url)}" target="_blank" rel="noopener noreferrer" class="text-sm">${escapeHtml(ext.store_url)}</a></div></div>` : ''}
            ${_extReputationRow(ext)}
            <div class="detail-row">
                <div class="detail-label">Why this score</div>
                <div class="detail-value">${signals}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Capabilities</div>
                <div class="detail-value">
                    ${(ext.permissions || []).map(p => `<span class="extension-signal">${escapeHtml(p)}</span>`).join(' ') || '<span class="text-secondary text-sm">no permissions recorded</span>'}
                    ${(ext.host_permissions || []).map(p => `<span class="extension-signal warn">${escapeHtml(p)}</span>`).join(' ')}
                </div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Vulnerabilities</div>
                <div class="detail-value">${vulns}</div>
            </div>
            <div class="detail-row" style="border-bottom:none;">
                <div class="detail-label">Hosts (${data.host_count || 0})</div>
                <div class="detail-value" style="max-height: 200px; overflow-y: auto;">
                    <table class="detections-table"><thead><tr><th>Host</th><th>Version</th><th>Path / source</th></tr></thead><tbody>${hosts || '<tr><td colspan="3" class="text-sm text-secondary">No hosts</td></tr>'}</tbody></table>
                </div>
            </div>
        `;
        modal.classList.add('visible');
    } catch (error) {
        showStatus(`Extension detail failed: ${error.message}`, true);
    }
}

function _extReputationRow(ext) {
    const link = u => /^https?:\/\//i.test(u || '')
        ? `<a href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer">${escapeHtml(truncateText(u, 48))}</a>` : '';
    const badges = [
        ext.store_featured ? '<span class="extension-signal good">featured</span>' : '',
        ext.established_publisher ? '<span class="extension-signal good">no history of violations</span>' : '',
        ext.developer_verified ? '<span class="extension-signal good">verified developer</span>' : '',
        ext.trader === true ? '<span class="extension-signal">EU trader</span>' : '',
        ext.trader === false ? '<span class="extension-signal">non-trader</span>' : '',
    ].filter(Boolean).join(' ');
    const parts = [
        ext.rating != null ? `rated <strong>${Number(ext.rating).toFixed(1)}</strong>/5${ext.rating_count != null ? ` (${Number(ext.rating_count).toLocaleString()} ratings)` : ''}` : '',
        ext.store_updated_at ? `updated ${escapeHtml(String(ext.store_updated_at).slice(0, 10))}` : '',
        ext.developer_email ? `email <a href="mailto:${escapeHtml(ext.developer_email)}">${escapeHtml(ext.developer_email)}</a>` : '',
        link(ext.developer_website) ? `website ${link(ext.developer_website)}` : '',
        ext.privacy_disclosure ? escapeHtml(ext.privacy_disclosure) : '',
        link(ext.privacy_policy_url) ? `privacy policy ${link(ext.privacy_policy_url)}` : '',
    ].filter(Boolean);
    if (!badges && !parts.length) return '';
    return `<div class="detail-row"><div class="detail-label">Reputation</div>
        <div class="detail-value text-sm">${badges}${badges && parts.length ? '<br>' : ''}${parts.join(' · ')}</div></div>`;
}

function closeExtensionDetails(event) {
    const modal = document.getElementById('extension-details-modal');
    if (event && event.target !== modal) return;
    modal.classList.remove('visible');
}

function _wireExtensionsUI() {
    ['ext-risk-filter', 'ext-store-filter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('change', loadExtensions);
    });
    const builtin = document.getElementById('ext-include-builtin');
    if (builtin) builtin.addEventListener('change', loadExtensions);
    const search = document.getElementById('ext-search-input');
    if (search) search.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') loadExtensions();
    });
    const refresh = document.getElementById('ext-refresh-btn');
    if (refresh) refresh.addEventListener('click', async () => {
        try {
            const resp = await fetch('/api/extensions/refresh', { method: 'POST' });
            if (resp.status === 429) {
                const data = await resp.json();
                showStatus(`Already refreshing — retry in ${data.retry_after_sec}s`);
            } else if (resp.ok) {
                showStatus('Extension intel refresh queued');
            } else {
                const data = await resp.json();
                showStatus(data.error || 'Refresh failed', true);
            }
            loadExtensions();
        } catch (error) {
            showStatus('Refresh failed', true);
        }
    });
}

// ========================================
// OVERVIEW / COMMAND DECK
// ========================================
// Summary view. Fans out to the endpoints that already exist, caches
// for 60s, and fails per-card so one dead query can't blank the page.
(function () {
    const CACHE_TTL = 60000;
    const cache = new Map();
    const inflight = new Map();
    let pollTimer = null;
    let constellationData = null;
    let riskSoftware = new Set();
    let mounted = false;

    const $ = (id) => document.getElementById(id);

    async function getJSON(url, ttl) {
        const hit = cache.get(url);
        if (hit && Date.now() - hit.at < (ttl || CACHE_TTL)) return hit.data;
        if (inflight.has(url)) return inflight.get(url);
        const p = fetch(url)
            .then(async (res) => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json();
                cache.set(url, { at: Date.now(), data });
                return data;
            })
            .finally(() => inflight.delete(url));
        inflight.set(url, p);
        return p;
    }

    // ---- stat / delta helpers ----
    function setStat(id, value) {
        const node = $(id);
        if (!node) return;
        if (value === null || value === undefined) {
            node.textContent = '—';
            return;
        }
        HOUND.countUp(node, value);
    }

    function setDelta(key, diff) {
        const node = document.querySelector(`[data-delta="${key}"]`);
        if (!node) return;
        if (diff === null || diff === undefined) {
            node.textContent = '—';
            node.className = 'flat';
            return;
        }
        const sign = diff > 0 ? '+' : '';
        node.textContent = `${sign}${diff}`;
        node.className = diff > 0 ? 'up' : (diff < 0 ? 'down' : 'flat');
    }

    // ---- constellation ----
    // Deterministic radial layout, not the force simulation: the hero
    // must be stable, cheap, and visually distinct from the working
    // graph. Rings are ordered software → identities → hosts.
    const RING = { software: 0.36, user: 0.58, host: 0.80 };
    const TYPE_LABEL = { host: 'Hosts', user: 'Identities', software: 'Software' };
    const TYPE_COLOR = {
        host: () => cssVar('--type-host') || '#8b9cff',
        user: () => cssVar('--type-user') || '#6ee7d8',
        software: () => cssVar('--type-software') || '#9aa3b8',
    };

    function renderConstellation(payload) {
        const host = $('fleet-constellation');
        const caption = $('constellation-caption');
        if (!host) return;
        constellationData = payload;

        const nodes = (payload.nodes || []);
        const links = (payload.links || []);
        const totalNodes = payload.total_nodes || nodes.length;

        if (caption) {
            caption.textContent = payload.sample
                ? `Sample · ${nodes.length} of ${HOUND.fmt.int(totalNodes)} nodes · all teams`
                : `${HOUND.fmt.int(nodes.length)} nodes · all teams`;
        }

        host.innerHTML = '';
        if (!nodes.length) {
            host.innerHTML = '<div class="constellation-empty">No fleet data yet.<br>Connect Fleet to populate the graph.</div>';
            return;
        }

        const rect = host.getBoundingClientRect();
        const w = Math.max(280, rect.width || 420);
        const h = Math.max(230, rect.height || 320);
        const cx = w / 2;
        const cy = h / 2;
        const R = Math.min(w, h) * 0.44;

        const idOf = (v) => (v && typeof v === 'object' ? v.id : v);
        const degree = new Map();
        nodes.forEach((n) => degree.set(n.id, 0));
        links.forEach((l) => {
            const s = idOf(l.source), t = idOf(l.target);
            if (degree.has(s)) degree.set(s, degree.get(s) + 1);
            if (degree.has(t)) degree.set(t, degree.get(t) + 1);
        });

        // Cap each ring so 300 nodes can't turn the hero back into a
        // hairball. Highest degree survives.
        const perType = { host: 44, user: 40, software: 40 };
        const placed = [];
        ['software', 'user', 'host'].forEach((type, ringIdx) => {
            const bucket = nodes
                .filter((n) => n.type === type)
                .sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0))
                .slice(0, perType[type]);
            const count = bucket.length;
            bucket.forEach((n, i) => {
                const angle = (i / Math.max(1, count)) * Math.PI * 2 + ringIdx * 0.4;
                const jitter = Math.sin(i * 1.7) * 4;
                const r = R * RING[type] + jitter;
                placed.push({
                    ...n,
                    x: cx + Math.cos(angle) * r,
                    y: cy + Math.sin(angle) * r,
                    degree: degree.get(n.id) || 0,
                });
            });
        });

        const byId = new Map(placed.map((n) => [n.id, n]));
        // 1.3k edges between 120 nodes is a hairball, not a hero. Keep
        // identity edges first, then fill with software edges, and cap
        // the total so the diagram stays a composition.
        const keptLinks = links
            .filter((l) => byId.has(idOf(l.source)) && byId.has(idOf(l.target)))
            .sort((a, b) => (a.type === 'uses' ? 0 : 1) - (b.type === 'uses' ? 0 : 1))
            .slice(0, 320);
        const maxDeg = Math.max(1, ...placed.map((n) => n.degree));
        const radius = (n) => Math.max(3, Math.min(9, 3 + Math.sqrt(n.degree / maxDeg) * 6.5 + (n.type === 'host' ? 1.5 : 0)));

        const svg = d3.select(host).append('svg')
            .attr('viewBox', `0 0 ${w} ${h}`)
            .attr('preserveAspectRatio', 'xMidYMid meet')
            .attr('aria-hidden', 'true')
            .attr('focusable', 'false');

        const reduce = HOUND.reduceMotion();
        const gRoot = svg.append('g');

        // Orbit rings + mono tick labels.
        const rings = gRoot.append('g').attr('class', 'ring-group');
        [
            { type: 'software', r: R * RING.software, label: 'SOFTWARE' },
            { type: 'user', r: R * RING.user, label: 'IDENTITIES' },
            { type: 'host', r: R * RING.host, label: 'HOSTS' },
        ].forEach((ring) => {
            rings.append('circle')
                .attr('cx', cx).attr('cy', cy).attr('r', ring.r)
                .attr('fill', 'none')
                .attr('stroke', 'var(--border)')
                .attr('stroke-width', 1)
                .attr('stroke-dasharray', '2 5')
                .attr('opacity', 0.75);
            rings.append('text')
                .attr('x', cx + 4)
                .attr('y', cy - ring.r + 11)
                .attr('fill', 'var(--text-tertiary)')
                .attr('font-family', 'var(--font-mono)')
                .attr('font-size', 8)
                .attr('letter-spacing', '0.12em')
                .text(ring.label);
        });

        // Edges: quadratic curves bowed toward the centre so links read
        // as chord lines, not a spider web of straight spokes.
        const linkLayer = gRoot.append('g').attr('class', 'link-layer');
        const linkSel = linkLayer.selectAll('path')
            .data(keptLinks)
            .join('path')
            .attr('d', (d) => {
                const s = byId.get(idOf(d.source));
                const t = byId.get(idOf(d.target));
                if (!s || !t) return null;
                const mx = (s.x + t.x) / 2;
                const my = (s.y + t.y) / 2;
                const qx = mx + (cx - mx) * 0.22;
                const qy = my + (cy - my) * 0.22;
                return `M${s.x},${s.y} Q${qx},${qy} ${t.x},${t.y}`;
            })
            .attr('fill', 'none')
            .attr('stroke', (d) => (d.type === 'uses' ? cssVar('--type-user') : cssVar('--type-software')))
            .attr('stroke-width', (d) => (d.type === 'uses' ? 1.1 : 0.8))
            .attr('opacity', (d) => (d.type === 'uses' ? 0.22 : 0.10));

        if (!reduce) {
            linkSel.attr('opacity', 0)
                .transition().delay(360).duration(420)
                .attr('opacity', (d) => (d.type === 'uses' ? 0.22 : 0.10));
        }

        // Nodes.
        const nodeLayer = gRoot.append('g').attr('class', 'node-layer');
        const nodeSel = nodeLayer.selectAll('g')
            .data(placed)
            .join('g')
            .attr('class', 'constellation-node')
            .attr('transform', (d) => `translate(${d.x},${d.y})`)
            .attr('tabindex', 0)
            .attr('role', 'button')
            .attr('aria-label', (d) => `${d.type} ${d.display_name || d.name || d.id}`);

        nodeSel.append('circle')
            .attr('class', 'halo')
            .attr('r', (d) => radius(d) + 5)
            .attr('fill', 'none')
            .attr('stroke', 'var(--danger)')
            .attr('stroke-width', 1)
            .attr('opacity', (d) => (riskSoftware.has(String(d.name || '').toLowerCase()) ? 0.55 : 0));

        nodeSel.append('circle')
            .attr('class', 'core')
            .attr('r', radius)
            .attr('fill', (d) => (TYPE_COLOR[d.type] || TYPE_COLOR.software)())
            .attr('fill-opacity', 0.9)
            .attr('stroke', 'var(--bg-primary)')
            .attr('stroke-width', 1);

        if (!reduce) {
            nodeSel.style('opacity', 0);
            nodeSel.each(function (d) {
                const ringDelay = d.type === 'software' ? 120 : (d.type === 'user' ? 210 : 300);
                const order = placed.filter((p) => p.type === d.type).indexOf(d);
                d3.select(this)
                    .transition()
                    .delay(ringDelay + Math.min(order * 12, 260))
                    .duration(320)
                    .style('opacity', 1);
            });
        }

        // Labels: only the eight busiest nodes, plus hover, and skip
        // any that would collide with a label already placed.
        const labelText = (d) => {
            const name = d.display_name || d.name || d.id;
            return name.length > 18 ? name.slice(0, 17) + '…' : name;
        };
        const labelBoxes = [];
        // Six desktop / three phone: the hero is a 300px-wide graphic,
        // and a label per hub turned the outer ring into noise.
        const maxLabels = w < 420 ? 3 : 6;
        const labelled = [...placed]
            .sort((a, b) => b.degree - a.degree)
            .filter((d) => {
                const text = labelText(d);
                const bw = text.length * 5.2;
                const box = { x: d.x - bw / 2, y: d.y - radius(d) - 17, w: bw, h: 13 };
                const hit = labelBoxes.some(
                    (b) => box.x < b.x + b.w && box.x + box.w > b.x
                        && box.y < b.y + b.h && box.y + box.h > b.y
                );
                if (!hit) labelBoxes.push(box);
                return !hit;
            })
            .slice(0, maxLabels);
        nodeLayer.selectAll('text.constellation-label')
            .data(labelled)
            .join('text')
            .attr('class', 'constellation-label')
            .attr('x', (d) => d.x)
            .attr('y', (d) => d.y - radius(d) - 6)
            .attr('text-anchor', 'middle')
            .attr('font-family', 'var(--font-mono)')
            .attr('font-size', 9)
            .attr('fill', 'var(--text-secondary)')
            .attr('paint-order', 'stroke')
            .attr('stroke', 'var(--bg-secondary)')
            .attr('stroke-width', 3)
            .attr('stroke-linejoin', 'round')
            .attr('opacity', reduce ? 1 : 0)
            .text(labelText);
        if (!reduce) {
            nodeLayer.selectAll('text.constellation-label')
                .transition().delay(680).duration(280).attr('opacity', 1);
        }

        // Hover: dim everything, light the neighbours.
        const neighbours = new Map();
        keptLinks.forEach((l) => {
            const s = idOf(l.source), t = idOf(l.target);
            if (!neighbours.has(s)) neighbours.set(s, new Set());
            if (!neighbours.has(t)) neighbours.set(t, new Set());
            neighbours.get(s).add(t);
            neighbours.get(t).add(s);
        });

        const clearHover = () => {
            nodeSel.style('opacity', 1);
            linkSel.attr('opacity', (d) => (d.type === 'uses' ? 0.22 : 0.10));
            HOUND.tooltip.hide();
        };

        nodeSel
            .on('mouseenter', function (event, d) {
                const near = neighbours.get(d.id) || new Set();
                nodeSel.style('opacity', (n) => (n.id === d.id || near.has(n.id) ? 1 : 0.18));
                linkSel.attr('opacity', (l) => {
                    const s = idOf(l.source), t = idOf(l.target);
                    return (s === d.id || t === d.id) ? 0.75 : 0.04;
                });
                const name = d.display_name || d.name || d.id;
                HOUND.tooltip.show(event.clientX, event.clientY, `
                    <div class="tooltip-title">${escapeHtml(name)}</div>
                    <div class="tooltip-row"><span>Type</span><strong>${escapeHtml(TYPE_LABEL[d.type] || d.type)}</strong></div>
                    <div class="tooltip-row"><span>Connections</span><strong>${HOUND.fmt.int(d.degree)}</strong></div>`);
            })
            .on('mousemove', (event) => {
                HOUND.tooltip.move(event.clientX, event.clientY);
            })
            .on('mouseleave', clearHover)
            .on('focus', function (event, d) {
                const name = d.display_name || d.name || d.id;
                HOUND.tooltip.show(0, 0, `
                    <div class="tooltip-title">${escapeHtml(name)}</div>
                    <div class="tooltip-row"><span>Type</span><strong>${escapeHtml(TYPE_LABEL[d.type] || d.type)}</strong></div>`,
                    this.getBoundingClientRect());
            })
            .on('blur', clearHover)
            .on('click', (event, d) => {
                const name = d.display_name || d.name || '';
                jumpToGraph(name);
            })
            .on('keydown', function (event, d) {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    jumpToGraph(d.display_name || d.name || '');
                }
            });
    }

    function jumpToGraph(name) {
        switchView('graph');
        const input = document.getElementById('search-input');
        if (input && name) {
            input.value = name;
            if (typeof searchNodes === 'function') searchNodes();
        }
    }

    // ---- OODA ----
    function renderOoda(status) {
        const steps = document.querySelectorAll('#ooda-steps .ooda-step');
        const meta = $('ooda-meta');
        const runBtn = $('ooda-run-btn');
        if (!meta) return;

        const enabled = !!status.enabled;
        const cycle = status.last_cycle || null;
        const phases = (cycle && cycle.phases) || [];
        const doneNames = new Set(phases.filter((p) => p.ok).map((p) => p.name));
        const failed = phases.find((p) => !p.ok) || null;

        steps.forEach((step) => {
            const name = step.dataset.phase;
            step.className = 'ooda-step';
            const icon = step.querySelector('.ooda-icon');
            if (icon) icon.remove();
            if (!enabled) {
                step.classList.add('off');
                return;
            }
            if (failed && failed.name === name) {
                step.classList.add('failed');
            } else if (doneNames.has(name)) {
                step.classList.add(status.running && name === 'act' ? 'active' : 'done');
            } else if (status.running && phases.length && name === phases[phases.length - 1].name) {
                step.classList.add('active');
            }
        });

        if (!enabled) {
            meta.textContent = 'Autonomy off — enable OODA_ENABLED to run cycles.';
            if (runBtn) runBtn.disabled = true;
            return;
        }

        if (runBtn) runBtn.disabled = !!status.running;
        if (runBtn) runBtn.textContent = status.running ? 'Running…' : 'Run now';

        if (!cycle) {
            meta.textContent = `Cycle #${status.next_cycle_id || 1} queued · interval ${Math.round((status.interval_sec || 0) / 60)}m`;
            return;
        }

        const parts = [];
        if (status.running) parts.push('cycle running');
        parts.push(`cycle #${HOUND.fmt.int(cycle.cycle_id)}`);
        if (cycle.duration_sec != null) parts.push(`${cycle.duration_sec.toFixed(1)}s`);
        if (cycle.finished_iso) parts.push(HOUND.fmt.relativeTime(cycle.finished_iso));
        if (status.cycles_failed) parts.push(`${status.cycles_failed} failed`);
        meta.textContent = parts.join(' · ');
    }

    async function loadOoda() {
        try {
            const status = await getJSON('/api/ooda/status', 15000);
            renderOoda(status);
        } catch (e) {
            const meta = $('ooda-meta');
            if (meta) meta.textContent = 'Autonomy status unavailable.';
        }
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(() => {
            if (document.visibilityState !== 'visible') return;
            loadOoda();
        }, 30000);
    }

    function stopPolling() {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    // ---- main load ----
    async function load() {
        const results = await Promise.allSettled([
            getJSON('/api/meta'),
            getJSON('/api/shadow-it?team=all&risk=all'),
            getJSON('/api/extensions?limit=1'),
            getJSON('/api/snapshots?limit=8'),
            getJSON('/api/graph/full?sample=120', 30000),
            getJSON('/api/ooda/status', 15000),
        ]);

        const [metaR, shadowR, extR, snapR, graphR, oodaR] = results;

        // ---- meta / header ----
        if (metaR.status === 'fulfilled' && metaR.value && typeof metaR.value.hosts === 'number') {
            setStat('ov-stat-hosts', metaR.value.hosts);
            setStat('ov-stat-users', metaR.value.users);
            setStat('ov-stat-software', metaR.value.software);
        }

        // ---- shadow IT ----
        let shadowTotal = null;
        if (shadowR.status === 'fulfilled' && shadowR.value) {
            const s = shadowR.value.summary || {};
            shadowTotal = Number(s.total_detections || 0);
            const high = Number(s.high_risk || 0);
            const medium = Number(s.medium_risk || 0);
            const low = Number(s.low_risk || 0);
            setStat('ov-stat-findings', shadowTotal);
            const totalEl = $('ov-shadow-total');
            if (totalEl) HOUND.countUp(totalEl, shadowTotal);
            const legend = $('ov-shadow-legend');
            if (legend) {
                legend.querySelector('[data-sev="high"]').textContent = HOUND.fmt.int(high);
                legend.querySelector('[data-sev="medium"]').textContent = HOUND.fmt.int(medium);
                legend.querySelector('[data-sev="low"]').textContent = HOUND.fmt.int(low);
            }
            HOUND.donut($('ov-shadow-donut'), [
                { value: high, color: 'var(--danger)' },
                { value: medium, color: 'var(--warning)' },
                { value: low, color: 'var(--caution)' },
            ], shadowTotal, `${shadowTotal} Shadow IT detections: ${high} high, ${medium} medium, ${low} low`);

            // Real risk signal for the constellation halos.
            riskSoftware = new Set(
                (shadowR.value.detections || [])
                    .map((d) => String(d.software_name || d.software || '').toLowerCase())
                    .filter(Boolean)
            );
        } else {
            setStat('ov-stat-findings', null);
        }

        // ---- extensions ----
        if (extR.status === 'fulfilled' && extR.value) {
            const summary = extR.value.summary || {};
            const total = Number(summary.total || extR.value.total || 0);
            const totalEl = $('ov-ext-total');
            if (totalEl) HOUND.countUp(totalEl, total);
            const legend = $('ov-ext-legend');
            if (legend) {
                legend.querySelector('[data-band="critical"]').textContent = HOUND.fmt.int(summary.critical || 0);
                legend.querySelector('[data-band="high"]').textContent = HOUND.fmt.int(summary.high || 0);
                legend.querySelector('[data-band="medium"]').textContent = HOUND.fmt.int(summary.medium || 0);
                legend.querySelector('[data-band="low"]').textContent = HOUND.fmt.int(summary.low || 0);
            }
            const hostsEl = $('ov-ext-hosts');
            if (hostsEl) hostsEl.textContent = `on ${HOUND.fmt.int(summary.affected_hosts || 0)} hosts`;
            HOUND.donut($('ov-ext-donut'), [
                { value: Number(summary.critical || 0), color: 'var(--danger)' },
                { value: Number(summary.high || 0), color: 'var(--warning)' },
                { value: Number(summary.medium || 0), color: 'var(--caution)' },
                { value: Number(summary.low || 0), color: 'var(--text-tertiary)' },
            ], total, `${total} extensions: ${summary.critical || 0} critical, ${summary.high || 0} high`);
        }

        // ---- fleet delta ----
        if (snapR.status === 'fulfilled' && Array.isArray(snapR.value) && snapR.value.length) {
            const snaps = snapR.value;
            const latest = snaps[0];
            const previous = snaps[1] || null;
            const ageEl = $('ov-delta-age');
            if (ageEl) ageEl.textContent = HOUND.fmt.relativeTime(latest.ts);
            ['hosts', 'users', 'software'].forEach((key) => {
                setDelta(key, previous ? Number(latest[key] || 0) - Number(previous[key] || 0) : null);
            });

            // Staleness is a truth signal: amber dot after 3h, grey if
            // there is no snapshot at all.
            const dot = $('overview-live-dot');
            const eye = $('overview-eyebrow-text');
            const ageMs = latest.ts ? Date.now() - new Date(latest.ts).getTime() : Infinity;
            const offline = metaR.status !== 'fulfilled' || !metaR.value || metaR.value.connected === false;
            if (dot) dot.className = 'live-dot' + (offline ? ' offline' : (ageMs > 3 * 3600 * 1000 ? ' stale' : ''));
            if (eye) {
                eye.textContent = offline ? 'Graph disconnected'
                    : (ageMs > 3 * 3600 * 1000 ? `Fleet snapshot · ${HOUND.fmt.relativeTime(latest.ts)}` : 'Live fleet graph');
            }
        }

        // ---- constellation ----
        if (graphR.status === 'fulfilled' && graphR.value) {
            renderConstellation(graphR.value);
        } else {
            const host = $('fleet-constellation');
            if (host) host.innerHTML = '<div class="constellation-empty">Graph sample unavailable.<br>Check the API token and connection.</div>';
            const caption = $('constellation-caption');
            if (caption) caption.textContent = 'Sample unavailable';
        }

        // ---- OODA ----
        if (oodaR.status === 'fulfilled' && oodaR.value) renderOoda(oodaR.value);
        else {
            const meta = $('ooda-meta');
            if (meta) meta.textContent = 'Autonomy status unavailable.';
        }
    }

    // ---- lifecycle ----
    const enter = () => {
        if (!mounted) {
            mounted = true;
            document.querySelectorAll('[data-jump]').forEach((node) => {
                node.addEventListener('click', (event) => {
                    const target = node.dataset.jump;
                    if (!target) return;
                    if (node.tagName === 'A') event.preventDefault();
                    switchView(target);
                });
            });
            const runBtn = $('ooda-run-btn');
            if (runBtn) runBtn.addEventListener('click', async () => {
                runBtn.disabled = true;
                runBtn.textContent = 'Queuing…';
                try {
                    const res = await fetch('/api/ooda/trigger', { method: 'POST' });
                    if (res.status === 429) {
                        const data = await res.json();
                        HOUND.toast(`Cycle already running — retry in ${data.retry_after_sec}s`, { type: 'warning' });
                    } else if (res.ok) {
                        HOUND.toast('OODA cycle queued', { type: 'success' });
                    } else {
                        const data = await res.json().catch(() => ({}));
                        HOUND.toast(data.error || 'Could not queue cycle', { type: 'error' });
                    }
                } catch (e) {
                    HOUND.toast('Could not queue cycle', { type: 'error' });
                }
                cache.delete('/api/ooda/status');
                loadOoda();
            });
            // Re-render on resize (the SVG viewBox is cheap to redraw).
            let resizeRAF = null;
            window.addEventListener('resize', () => {
                if (!constellationData) return;
                cancelAnimationFrame(resizeRAF);
                resizeRAF = requestAnimationFrame(() => renderConstellation(constellationData));
            });

            // The graph is laid out in pixel coordinates, so it needs a
            // real re-render (not a viewBox scale) after a viewport
            // change; otherwise nodes sit outside a phone-sized SVG.
            let graphResizeTimer = null;
            window.addEventListener('resize', () => {
                if (activeView !== 'graph' || !currentData.nodes.length) return;
                clearTimeout(graphResizeTimer);
                graphResizeTimer = setTimeout(() => {
                    if (activeView === 'graph') renderGraph(currentData);
                }, 250);
            });
        }
        load();
        startPolling();
    };

    const exit = () => {
        stopPolling();
        HOUND.tooltip.hide();
    };

    HOUND.overview = { enter, exit, reload: load };
})();

// ========================================
// INIT
// ========================================
document.addEventListener('DOMContentLoaded', function () {
    loadThemePreference();
    loadExclusionSettings();
    wireTabs();
    HOUND.installModalBehaviour();

    const brand = document.getElementById('brand-home');
    if (brand) brand.addEventListener('click', () => switchView('overview'));

    // Cascade / Radar toggle. Delegated so the buttons can be
    // re-rendered without rebinding.
    const chartSwitch = document.querySelector('.chart-switch');
    if (chartSwitch) chartSwitch.addEventListener('click', (event) => {
        const btn = event.target.closest('.chart-switch-btn');
        if (!btn || !btn.dataset.chart) return;
        setBlastChartMode(btn.dataset.chart);
    });

    const themeBtn = document.getElementById('theme-toggle-btn');
    if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

    const exportBtn = document.getElementById('shadow-export-csv-btn');
    if (exportBtn) exportBtn.addEventListener('click', exportShadowDetectionsCsv);

    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') searchNodes();
        });
    }

    const nodeTypeFilter = document.getElementById('node-type-filter');
    const platformFilter = document.getElementById('platform-filter');
    const teamFilter = document.getElementById('team-filter');
    if (nodeTypeFilter) nodeTypeFilter.addEventListener('change', searchNodes);
    if (platformFilter) platformFilter.addEventListener('change', searchNodes);
    if (teamFilter) teamFilter.addEventListener('change', searchNodes);

    // Esc also closes popovers (modals are handled by HOUND).
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        const pop = document.getElementById('enricher-popover');
        if (pop) pop.hidden = true;
        HOUND.tooltip.hide();
        if (activeView === 'graph') {
            if (_graphFocusId) clearGraphFocus();
            else clearGraphSelection();
        }
    });

    // Graph keyboard shortcuts: + / - zoom, 0 fits. Ignored while
    // typing so the search box keeps its characters.
    document.addEventListener('keydown', (e) => {
        if (activeView !== 'graph') return;
        const tag = (e.target && e.target.tagName || '').toLowerCase();
        if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.metaKey || e.ctrlKey) return;
        if (e.key === '+' || e.key === '=') { e.preventDefault(); zoomGraphBy(1.35); }
        else if (e.key === '-') { e.preventDefault(); zoomGraphBy(1 / 1.35); }
        else if (e.key === '0') { e.preventDefault(); fitGraph(); }
    });

    const copyBtn = document.getElementById('graph-selection-copy');
    if (copyBtn) copyBtn.addEventListener('click', async () => {
        const card = document.getElementById('graph-selection');
        const id = card && card.dataset.nodeId;
        if (!id) return;
        try {
            await navigator.clipboard.writeText(id);
            HOUND.toast('Node ID copied', { type: 'success', duration: 2400 });
        } catch (err) {
            HOUND.toast('Copy failed — clipboard blocked', { type: 'error' });
        }
    });

    loadTeams();
    loadPlatforms();
    loadLabels();
    loadGraph();
    refreshTopbarMeta();

    _wireEnricherUI();
    refreshEnricherStatus();
    _enricherTimer = setInterval(refreshEnricherStatus, 30000);

    _wireExtensionsUI();

    // First visit lands on the Command Deck; returning operators get
    // the tab they left. `hound.lastView` is written by switchView().
    const saved = HOUND.store.get('hound.lastView', null);
    const initial = saved && document.getElementById(saved + '-view') ? saved : 'overview';
    switchView(initial);
});

// ========================================
// EVENT BINDINGS (were inline on* attributes; CSP forbids inline script)
// ========================================
(function bindInlineHandlers() {
    const bind = (ev, id, fn) => {
        const el = document.querySelector(`[data-bind-${ev}="${id}"]`);
        if (el) el.addEventListener(ev, fn);
        else console.error('missing bind target', ev, id);
    };
    bind('click', 'b0', function (event) { toggleCaseSensitive(); });
    bind('click', 'b1', function (event) { setSearchMode('wildcard'); });
    bind('click', 'b2', function (event) { setSearchMode('exact'); });
    bind('click', 'b3', function (event) { searchNodes(); });
    bind('click', 'b4', function (event) { clearSearch(); });
    bind('click', 'b5', function (event) { resetToOverview(); });
    bind('click', 'b6', function (event) { centerGraph(); });
    bind('click', 'b7', function (event) { resetPositions(); });
    bind('click', 'b8', function (event) { loadGraph(); });
    bind('click', 'b9', function (event) { togglePathfinder(); });
    bind('click', 'b10', function (event) { toggleClusters(); });
    bind('click', 'b11', function (event) { toggleGraphLabelsPopover(); });
    bind('click', 'b12', function (event) { exportAsJSON(); });
    bind('click', 'b13', function (event) { exportAsCSV(); });
    bind('click', 'b14', function (event) { zoomGraphBy(1.35); });
    bind('click', 'b15', function (event) { zoomGraphBy(1/1.35); });
    bind('click', 'b16', function (event) { fitGraph(); });
    bind('click', 'b17', function (event) { clearGraphSelection(); });
    bind('click', 'b18', function (event) { applyGraphFocus(document.getElementById('graph-selection').dataset.nodeId); });
    bind('click', 'b19', function (event) { clearGraphFocus(); });
    bind('click', 'b20', function (event) { expandNodeConnections(_graphSelected); });
    bind('click', 'b21', function (event) { const c=document.getElementById('graph-selection');calculateBlastRadius(c.dataset.nodeType,c.dataset.nodeName);switchView('blast-radius'); });
    bind('change', 'b22', function (event) { calculateBlastRadius(); });
    bind('change', 'b23', function (event) { loadBlastEntities(); });
    bind('keyup', 'b24', function (event) { filterBlastEntities(); });
    bind('click', 'b25', function (event) { openExclusionSettings(); });
    bind('change', 'b26', function (event) { calculateBlastRadius(); });
    bind('click', 'b27', function (event) { loadShadowITDetections(); });
    bind('keyup', 'b28', function (event) { filterShadowTable(); });
    bind('keyup', 'b29', function (event) { filterShadowTable(); });
    bind('keyup', 'b30', function (event) { filterShadowTable(); });
    bind('keyup', 'b31', function (event) { filterShadowTable(); });
    bind('keyup', 'b32', function (event) { filterShadowTable(); });
    bind('keyup', 'b33', function (event) { filterShadowTable(); });
    bind('click', 'b34', function (event) { closeDetectionDetails(event); });
    bind('click', 'b35', function (event) { event.stopPropagation(); });
    bind('click', 'b36', function (event) { closeDetectionDetails(); });
    bind('click', 'b37', function (event) { closeExclusionSettings(); });
    bind('click', 'b38', function (event) { event.stopPropagation(); });
    bind('click', 'b39', function (event) { closeExclusionSettings(); });
    bind('click', 'b40', function (event) { closeExclusionSettings(); });
    bind('click', 'b41', function (event) { saveExclusionSettings(); });
    bind('click', 'b42', function (event) { closeExtensionDetails(event); });
    bind('click', 'b43', function (event) { event.stopPropagation(); });
    bind('click', 'b44', function (event) { closeExtensionDetails(); });
})();

