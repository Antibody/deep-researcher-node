
(function initViewportAndComposerAnchoring(){
  function setVh() {
    const vh = window.innerHeight || document.documentElement.clientHeight;
    document.documentElement.style.setProperty('--app-vh', `${vh}px`);
  }
  function setSidebarWidthVar() {
    const sidebar = document.querySelector('.sidebar');
    const w = sidebar && getComputedStyle(sidebar).display !== 'none'
      ? sidebar.getBoundingClientRect().width
      : 0;
    document.documentElement.style.setProperty('--sidebar-w', `${Math.round(w)}px`);
  }
  function setComposerHeightVar() {
    const composer = document.getElementById('composer');
    if (!composer) return;
    const h = composer.getBoundingClientRect().height;
    document.documentElement.style.setProperty('--composer-h', `${Math.ceil(h)}px`);
  }
  function refreshLayoutVars() {
    setVh();
    setSidebarWidthVar();
    setComposerHeightVar();
  }
  window.addEventListener('resize', refreshLayoutVars, { passive: true });
  window.addEventListener('orientationchange', refreshLayoutVars, { passive: true });
  window.addEventListener('load', refreshLayoutVars);
  document.addEventListener('DOMContentLoaded', refreshLayoutVars);
})();

/* ------------------------------------------------------------- global DOM references ------------------------------------------------------------- */
const conversationHistory = document.getElementById('conversation');
const composerForm = document.getElementById('composer');
const userInputEl = document.getElementById('user-input');
const depthSelect = document.getElementById('depth-select');
const sseStatusEl = document.getElementById('sse-status');
const sessionListEl = document.getElementById('session-list');
const newSessionBtn = document.getElementById('new-session');
const clearAllBtn = document.getElementById('clear-all');
const heroBanner = document.getElementById('GPT-chatly-message');
const activeTitleEl = document.getElementById('active-session-title');

/* API key panel elements  */
const apiKeyPanel = document.querySelector('.api-key-panel.emphasize');
const apiKeyForm = document.getElementById('api-key-form');
const apiKeyInput = document.getElementById('api-key-input');
const apiKeyToggleBtn = document.getElementById('api-key-toggle-visibility');
const apiKeySaveBtn = document.getElementById('api-key-save');
const apiKeyClearBtn = document.getElementById('api-key-clear');
const apiKeyStatus = document.getElementById('api-key-status');

/*  input lock element */
const composerLock = document.getElementById('composer-lock');

/*  Depth tooltip refs */
const depthField = document.getElementById('depth-field');
const depthTooltip = document.getElementById('depth-tip');

/* API panel tooltip ref */
const apiKeyCostTip = document.getElementById('api-key-cost-tip');

/* ------------------------------------------------------------- App constants / endpoints ------------------------------------------------------------- */
const ENDPOINT_SSE = '/deep-research-FOSS-events';
const ENDPOINT_POST = '/deep-research';
const ENDPOINT_JWT = '/jwt-token';
const ENDPOINT_TITLE = '/fetch-titles';

const PLACEHOLDER_TITLE = 'New Chat';

/* ------------------------------------ PER-USER OPENAI KEY (HTML panel + HEADER FORWARDING) ------------------------- */
const OPENAI_KEY_STORAGE_KEY = 'user_openai_api_key';

/* Return current key (string or '') */
function getOpenAIKey() {
  try {
    return localStorage.getItem(OPENAI_KEY_STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

/* Set/remove key in storage */
function setOpenAIKey(value) {
  try {
    if (value && typeof value === 'string' && value.trim()) {
      localStorage.setItem(OPENAI_KEY_STORAGE_KEY, value.trim());
    } else {
      localStorage.removeItem(OPENAI_KEY_STORAGE_KEY);
    }
  } catch {}
}

/* a key assessment to style status pill */
function isLikelyOpenAIKey(v) {
  if (!v) return false;
  const s = String(v).trim();
  if (!/^sk-/.test(s)) return false;
  if (s.length < 20) return false;
  return true;
}

/* Toast utility */
function showToast(message, kind = 'error', ttl = 3600) {
  const root = document.getElementById('toast-root');
  if (!root) return;
  const el = document.createElement('div');
  el.className = `toast ${kind === 'ok' ? 'ok' : kind === 'warn' ? 'warn' : 'error'}`;
  el.textContent = message;
  root.appendChild(el);
  setTimeout(() => { try { el.remove(); } catch {} }, ttl);
}

/* Validate key against OpenAI without spending tokens */
async function validateOpenAIKey(key, { timeoutMs = 10000 } = {}) {
  if (!key) return { ok: false, reason: 'empty' };
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const r = await fetch('https://api.openai.com/v1/models?limit=1', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${key}` },
      signal: controller.signal,
    });
    clearTimeout(t);
    if (r.status === 200) return { ok: true };
    if (r.status === 401) return { ok: false, reason: 'unauthorized' };
    if (r.status === 403) return { ok: false, reason: 'forbidden' };
    if (r.status === 429) return { ok: true, reason: 'rate_limited' };
    return { ok: false, reason: `http_${r.status}` };
  } catch (e) {
    clearTimeout(t);
    if (e && e.name === 'AbortError') return { ok: false, reason: 'timeout' };
    return { ok: false, reason: 'network' };
  }
}

/* Toggle the composer enabled/disabled state based on presence of a saved key */
function updateComposerEnabledState() {
  const hasKey = !!getOpenAIKey();
  const needKey = composerForm && composerForm.dataset && composerForm.dataset.requiresKey === 'true';

  if (!composerForm) return;

  if (needKey && !hasKey) {
    composerForm.setAttribute('aria-disabled', 'true');
    if (composerLock) composerLock.setAttribute('aria-hidden', 'false');
    if (userInputEl) userInputEl.setAttribute('disabled', 'true');
    const attachBtn = document.getElementById('attach-btn');
    const sendBtn = document.getElementById('send-btn');
    if (attachBtn) attachBtn.setAttribute('disabled', 'true');
    if (sendBtn) sendBtn.setAttribute('disabled', 'true');
  } else {
    composerForm.removeAttribute('aria-disabled');
    if (composerLock) composerLock.setAttribute('aria-hidden', 'true');
    if (userInputEl) userInputEl.removeAttribute('disabled');
    const attachBtn = document.getElementById('attach-btn');
    const sendBtn = document.getElementById('send-btn');
    if (attachBtn) attachBtn.removeAttribute('disabled');
    if (sendBtn) sendBtn.removeAttribute('disabled');
  }

  requestAnimationFrame(() => {
    const composer = document.getElementById('composer');
    if (composer) {
      const h = composer.getBoundingClientRect().height;
      document.documentElement.style.setProperty('--composer-h', `${Math.ceil(h)}px`);
    }
  });
}

/* Wire up the static API key panel (no dynamic creation) + validation flow */
function bindApiKeyPanel() {
  if (!apiKeyPanel || !apiKeyForm || !apiKeyInput || !apiKeyStatus) return;

  
  const existing = getOpenAIKey();
  if (existing) {
    apiKeyInput.classList.remove('glow-blue');             
    apiKeyInput.value = existing;
    setStatusPill('ok', 'Key set');
    updateComposerEnabledState();
  } else {
    apiKeyInput.classList.add('glow-blue');               
    setStatusPill('warn', 'No key');
    updateComposerEnabledState();
  }

  /* Show/hide api-key panel tooltip via mouse/touch/keyboard */
  if (apiKeyCostTip && apiKeyPanel) {
    const show = () => { apiKeyCostTip.setAttribute('aria-hidden', 'false'); };
    const hide = () => { apiKeyCostTip.setAttribute('aria-hidden', 'true'); };
    apiKeyPanel.addEventListener('mouseenter', show);
    apiKeyPanel.addEventListener('mouseleave', hide);
    apiKeyPanel.addEventListener('focusin', show);
    apiKeyPanel.addEventListener('focusout', hide);
    apiKeyPanel.addEventListener('touchstart', () => { show(); setTimeout(hide, 1500); }, { passive: true });
  }

  /* Toggle visibility of API key characters */
  if (apiKeyToggleBtn) {
    apiKeyToggleBtn.addEventListener('click', () => {
      const type = apiKeyInput.getAttribute('type') === 'password' ? 'text' : 'password';
      apiKeyInput.setAttribute('type', type);
      apiKeyToggleBtn.title = type === 'password' ? 'Show key' : 'Hide key';
      apiKeyToggleBtn.setAttribute('aria-label', type === 'password' ? 'Show API key' : 'Hide API key');
      apiKeyToggleBtn.textContent = type === 'password' ? '👁️' : '🙈';
    });
  }

  /* Save on form submit with validation */
  apiKeyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const v = apiKeyInput.value.trim();

    /* Clear path */
    if (!v) {
      setOpenAIKey('');
      apiKeyInput.classList.add('glow-blue');               
      removeUserInputGlow();                                 
      setStatusPill('warn', 'No key');
      updateComposerEnabledState();
      return;
    }

    /* Quick format hint (does not block) */
    if (!isLikelyOpenAIKey(v)) {
      setStatusPill('warn', 'Checking…');
    } else {
      setStatusPill('warn', 'Validating…');
    }

    /* Temporarily keep composer locked until validation succeeds */
    setOpenAIKey('');
    updateComposerEnabledState();

    /* Validate against OpenAI */
    const res = await validateOpenAIKey(v);

    if (res.ok) {
      setOpenAIKey(v);
      setStatusPill('ok', 'Key set');
      updateComposerEnabledState();

      apiKeyInput.classList.remove('glow-blue');            
      applyUserInputGlowAndFocus();                         

      if (res.reason === 'rate_limited') {
        showToast('API key validated, but rate-limited right now.', 'warn', 3800);
      } else {
        showToast('API key validated.', 'ok', 2200);
      }
      try { userInputEl?.focus(); } catch {}
    } else {
      let msg = 'API key is invalid or not authorized.';
      if (res.reason === 'unauthorized') msg = 'API key is invalid.';
      else if (res.reason === 'forbidden') msg = 'API key is forbidden for this operation.';
      else if (res.reason === 'timeout') msg = 'Something is wrong. Validation timed out. Check your API key, your network and try again.';
      else if (res.reason === 'network') msg = 'Network error during validation. Try again.';
      setStatusPill('danger', 'Invalid key');

      apiKeyInput.classList.add('glow-blue');               
      removeUserInputGlow();                                 

      showToast(msg, 'error', 4600);
    }
  });

  /* Explicit Save button (same as submit) */
  if (apiKeySaveBtn) {
    apiKeySaveBtn.addEventListener('click', (e) => {
      e.preventDefault();
      apiKeyForm.requestSubmit();
    });
  }

  /* Clear button */
  if (apiKeyClearBtn) {
    apiKeyClearBtn.addEventListener('click', (e) => {
      e.preventDefault();
      apiKeyInput.value = '';
      setOpenAIKey('');
      setStatusPill('warn', 'No key');
      apiKeyInput.classList.add('glow-blue');               
      removeUserInputGlow();                                 
      updateComposerEnabledState();
    });
  }

  function setStatusPill(kind, text) {
    apiKeyStatus.textContent = text || '';
    apiKeyStatus.classList.remove('ok', 'warn', 'danger');
    if (kind === 'ok') apiKeyStatus.classList.add('ok');
    else if (kind === 'danger') apiKeyStatus.classList.add('danger');
    else apiKeyStatus.classList.add('warn');
  }
}

/* Helper to glow & focus user input after successful key validation */
function applyUserInputGlowAndFocus() {
  if (!userInputEl) return;
  userInputEl.classList.add('glow-blue');
  try { userInputEl.focus(); } catch {}
  /* Remove the glow on first typing */
  if (!userInputEl.__glowRemoveBound) {
    const remove = () => removeUserInputGlow();
    userInputEl.addEventListener('input', remove, { once: true });
    userInputEl.__glowRemoveBound = true;
  }
}

/* Helper to remove user input glow (used on clear/invalid and after typing) */
function removeUserInputGlow() {
  if (!userInputEl) return;
  userInputEl.classList.remove('glow-blue');
}

/* ------------------------------------------------------------- JWT handling (server-supplied only) ------------------------------------------------------------- */
let jwtToken = '';

async function fetchJwtToken() {
  try {
    const response = await fetch(ENDPOINT_JWT, { credentials: 'include' });
    if (!response.ok) throw new Error(`JWT HTTP ${response.status}`);
    const data = await response.json();
    jwtToken = data?.jwtToken || '';
  } catch (error) {
    console.error('Error fetching JWT token:', error);
    jwtToken = '';
  }
}
async function ensureJwt() {
  try { if (!jwtToken) await fetchJwtToken(); } catch {}
  return !!jwtToken;
}

/* ------------------------------------------------------------- Sessions & Titles Persistence ------------------------------------------------------------- */
function getMaxSessionIndex() {
  const raw = localStorage.getItem('chat_session_index');
  const n = parseInt(raw || '0', 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}
function setMaxSessionIndex(n) { localStorage.setItem('chat_session_index', String(n)); }
function getActiveSessionIndex() {
  const raw = localStorage.getItem('active_session_index');
  const n = parseInt(raw || '0', 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}
function setActiveSessionIndex(n) { localStorage.setItem('active_session_index', String(n)); }

function getSessionTitle(index) { return localStorage.getItem(`session_title_${index}`); }
function getSessionTitleSource(index) { return localStorage.getItem(`session_title_source_${index}`) || ''; }
function setSessionTitle(index, title) {
  if (typeof title === 'string') localStorage.setItem(`session_title_${index}`, title.trim());
}
function setSessionTitleSource(index, source) {
  if (source === 'pending' || source === 'server' || source === 'placeholder') {
    localStorage.setItem(`session_title_source_${index}`, source);
  }
}

/* -------------------------------------- Title sanitization & request builder -------------------------------------- */
function sanitizeTitle(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let t = raw.trim();
  t = t.replace(/^```[\s\S]*?```$/g, '')
       .replace(/^[`"'“”‘’]+|[`"'“”‘’]+$/g, '')
       .replace(/\u200B/g, '');
  t = t.replace(/\s+/g, ' ').trim();
  t = t.replace(/[.,;:!?]+$/g, '').trim();
  const MAX_LEN = 60;
  if (t.length > MAX_LEN) {
    const cut = t.slice(0, MAX_LEN + 1);
    const lastSpace = cut.lastIndexOf(' ');
    t = (lastSpace > 0 ? cut.slice(0, lastSpace) : cut.slice(0, MAX_LEN)).trim();
  }
  return t;
}
function buildTitleMessages(userInput) {
  return [
    {
      role: 'system',
      content:
        'Generate a very short, clear 3–7 word title that summarizes the user’s request. Rules: return ONLY the title text, no quotes, no trailing punctuation, no emojis, no code blocks, no markdown. Use the same language as the user input.'
    },
    { role: 'user', content: userInput }
  ];
}

/* -------------------------------------- Sidebar helpers -------------------------------------- */
function ensureSidebarItem(index) {
  let li = sessionListEl.querySelector(`li[data-index="${index}"]`);
  if (!li) {
    li = document.createElement('li');
    li.dataset.index = String(index);

    const titleSpan = document.createElement('span');
    titleSpan.className = 'session-title';
    titleSpan.textContent = getSessionTitle(index) || `Chat ${index}`;
    li.appendChild(titleSpan);

    const actions = document.createElement('div');
    actions.className = 'actions';

    const del = document.createElement('button');
    del.className = 'icon-btn';
    del.title = 'Delete';
    del.textContent = '×';
    del.addEventListener('click', (e) => {
      e.stopPropagation();
      deleteSession(index);
    });

    actions.appendChild(del);
    li.appendChild(actions);

    li.addEventListener('click', () => { loadSessionHistory(index); });

    sessionListEl.insertBefore(li, sessionListEl.firstChild);
  }
  return li;
}
function updateSidebarItemTitle(index, newTitle) {
  const li = ensureSidebarItem(index);
  const span = li.querySelector('.session-title');
  if (span) span.textContent = newTitle;
}
function updateSidebar(index) {
  const li = document.createElement('li');
  li.dataset.index = String(index);

  const titleSpan = document.createElement('span');
  titleSpan.className = 'session-title';
  titleSpan.textContent = getSessionTitle(index) || `Chat ${index}`;
  li.appendChild(titleSpan);

  const actions = document.createElement('div');
  actions.className = 'actions';

  const del = document.createElement('button');
  del.className = 'icon-btn';
  del.title = 'Delete';
  del.textContent = '×';
  del.addEventListener('click', (e) => {
    e.stopPropagation();
    deleteSession(index);
  });

  actions.appendChild(del);
  li.appendChild(actions);

  li.addEventListener('click', () => { loadSessionHistory(index); });

  sessionListEl.insertBefore(li, sessionListEl.firstChild);
}
function updateAllSidebars() {
  const max = getMaxSessionIndex();
  const active = getActiveSessionIndex();
  sessionListEl.innerHTML = '';
  for (let i = 1; i <= max; i++) {
    if (localStorage.getItem(`past_conversations_${i}`)) {
      updateSidebar(i);
    }
  }
  const activeTitle = active ? (getSessionTitle(active) || PLACEHOLDER_TITLE) : PLACEHOLDER_TITLE;
  activeTitleEl.textContent = activeTitle;
}

/* -------------------------------------- Title generation manager -------------------------------------- */
const titleGenInProgress = new Set();

async function generateAndStoreSessionTitle(sessionIndex, firstUserText) {
  if (!sessionIndex || !firstUserText) return getSessionTitle(sessionIndex) || PLACEHOLDER_TITLE;

  const src = getSessionTitleSource(sessionIndex);
  const existing = getSessionTitle(sessionIndex) || PLACEHOLDER_TITLE;

  if (src === 'server' && existing.trim()) return existing;
  if (titleGenInProgress.has(sessionIndex)) return existing;

  titleGenInProgress.add(sessionIndex);

  ensureSidebarItem(sessionIndex);
  if (!existing || existing === '') {
    setSessionTitle(sessionIndex, PLACEHOLDER_TITLE);
    updateSidebarItemTitle(sessionIndex, PLACEHOLDER_TITLE);
    if (getActiveSessionIndex() === sessionIndex) activeTitleEl.textContent = PLACEHOLDER_TITLE;
  }
  if (src !== 'server') setSessionTitleSource(sessionIndex, 'pending');

  let finalTitle = '';
  try {
    const ok = await ensureJwt();
    if (!ok) throw new Error('JWT unavailable');

    const messages = buildTitleMessages(firstUserText);
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${jwtToken}`
    };

    const userKey = getOpenAIKey();
    if (userKey) headers['x-openai-key'] = userKey;

    const response = await fetch(ENDPOINT_TITLE, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({ past_conversations: messages })
    });
    if (!response.ok) throw new Error(`Title HTTP ${response.status}`);

    const data = await response.json();
    const raw = data && data.chatGPTResponse ? data.chatGPTResponse : '';
    finalTitle = sanitizeTitle(raw);
  } catch (e) {
    finalTitle = '';
  }

  if (finalTitle && finalTitle.toLowerCase() !== PLACEHOLDER_TITLE.toLowerCase()) {
    setSessionTitle(sessionIndex, finalTitle);
    setSessionTitleSource(sessionIndex, 'server');
    updateSidebarItemTitle(sessionIndex, finalTitle);
    if (getActiveSessionIndex() === sessionIndex) activeTitleEl.textContent = finalTitle;
  } else {
    setSessionTitle(sessionIndex, existing || PLACEHOLDER_TITLE);
    setSessionTitleSource(sessionIndex, 'pending');
    updateSidebarItemTitle(sessionIndex, existing || PLACEHOLDER_TITLE);
    if (getActiveSessionIndex() === sessionIndex) activeTitleEl.textContent = existing || PLACEHOLDER_TITLE;
  }

  titleGenInProgress.delete(sessionIndex);
  return getSessionTitle(sessionIndex) || PLACEHOLDER_TITLE;
}

/* ------------------------------------------------------------- Conversation persistence ------------------------------------------------------------- */
function loadConversation(sessionIdx) {
  try {
    const key = `past_conversations_${sessionIdx}`;
    const arr = JSON.parse(localStorage.getItem(key) || '[]');
    return Array.isArray(arr) ? arr : [];
  } catch { return []; }
}
function saveConversation(sessionIdx, arr) {
  try {
    const key = `past_conversations_${sessionIdx}`;
    localStorage.setItem(key, JSON.stringify(arr));
  } catch {}
}

/* ------------------------------------------------------------- Hero visibility (welcome) ------------------------------------------------------------- */
function hasAnyConversation() {
  const max = getMaxSessionIndex();
  for (let i = 1; i <= max; i++) {
    if (localStorage.getItem(`past_conversations_${i}`)) return true;
  }
  return false;
}
function manageGPTChatlyMessageDisplay() {
  if (!heroBanner) return;
  heroBanner.style.display = hasAnyConversation() ? 'none' : 'block';
}

/* ------------------------------------------------------------- Textarea auto-size & keys ------------------------------------------------------------- */
userInputEl.addEventListener('input', () => {
  autoSizeTextArea();
  requestAnimationFrame(() => {
    const composer = document.getElementById('composer');
    if (!composer) return;
    const h = composer.getBoundingClientRect().height;
    document.documentElement.style.setProperty('--composer-h', `${Math.ceil(h)}px`);
  });
});
userInputEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    composerForm.requestSubmit();
  }
});
function autoSizeTextArea() {
  userInputEl.style.height = 'auto';
  userInputEl.style.height = Math.min(userInputEl.scrollHeight, 200) + 'px';
}

/* ------------------------------------------------------------- SSE helpers ------------------------------------------------------------- */
const __SSE_ACTIVE = new Map();
const __SSE_MAX_LINES = 180;
const __RUN_CTX = new Map();

function generateCorrelationId() {
  const ts = Date.now();
  const rand = Math.random().toString(36).slice(2, 10);
  return `${ts}-${rand}`;
}

function ensureSseLogPanel(assistantMessageElement) {
  if (!assistantMessageElement || !assistantMessageElement.isConnected) return null;

  const next = assistantMessageElement.nextElementSibling;
  if (next && next.classList && next.classList.contains('sse-log-panel')) return next;

  const panel = document.createElement('div');
  panel.className = 'sse-log-panel';

  const header = document.createElement('div');
  header.className = 'sse-log-header';
  header.innerHTML = `
    <div class="title">Live research log</div>
    <div class="sse-log-actions">
      <button class="btn small ghost" data-act="collapse">Collapse</button>
      <button class="btn small ghost" data-act="clear">Clear</button>
      <button class="btn small ghost" data-act="close">Close</button>
    </div>
  `;

  const scroller = document.createElement('div');
  scroller.className = 'sse-log-scroller';
  const stream = document.createElement('div');
  stream.className = 'sse-log-stream';
  scroller.appendChild(stream);

  panel.appendChild(header);
  panel.appendChild(scroller);

  assistantMessageElement.insertAdjacentElement('afterend', panel);

  header.addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    const act = btn.getAttribute('data-act');
    if (act === 'collapse') {
      scroller.style.display = scroller.style.display === 'none' ? '' : 'none';
    } else if (act === 'clear') {
      stream.innerHTML = '';
    } else if (act === 'close') {
      panel.remove();
    }
  });

  return panel;
}

function openSSE(correlationId, attachToAssistantEl, sessionIndex) {
  tryCloseSSE(correlationId);

  const url = `${ENDPOINT_SSE}?correlationId=${encodeURIComponent(correlationId)}`;
  const es = new EventSource(url, { withCredentials: true });

  const panel = ensureSseLogPanel(attachToAssistantEl);
  const stream = panel ? panel.querySelector('.sse-log-stream') : null;

  __SSE_ACTIVE.set(correlationId, {
    es,
    node: stream,
    lines: 0,
    attachedTo: attachToAssistantEl,
    sessionIndex
  });

  if (sseStatusEl) sseStatusEl.textContent = `SSE: connecting…`;

  es.addEventListener('open', () => { if (sseStatusEl) sseStatusEl.textContent = `SSE: connected`; });
  es.addEventListener('error', () => { if (sseStatusEl) sseStatusEl.textContent = `SSE: error`; });

  const DEFAULT_EVENTS = [
    'hello','heartbeat','ready','start','done','error',
    'plan_ready','outline_used','outline_final',
    'subq_start','subq_progress','subq_done',
    'queries_ready','queries_seeded','search_start','search_progress','search_results','search_results_urls',
    'fetch_start','fetched','crawl_progress','reranked',
    'synthesis_start','writing_started','writing_chunk','writing_progress','writing_done',
    'message','partial','debug','warn'
  ];

  const subscribed = new Set();

  function appendLine(evt, payload) {
    const rec = __SSE_ACTIVE.get(correlationId);
    if (!rec || !rec.node) return;
    const row = document.createElement('div');
    row.className = 'log-line';

    const tag = document.createElement('div');
    tag.className = 'evt';
    if (evt === 'error') tag.classList.add('err');
    if (evt === 'hello' || evt === 'ready' || evt === 'heartbeat' || evt === 'start') tag.classList.add('ok');
    tag.textContent = `[${evt}]`;

    const text = document.createElement('div');
    text.className = 'txt';
    text.textContent = typeof payload === 'string' ? payload : JSON.stringify(payload);

    row.appendChild(tag);
    row.appendChild(text);
    rec.node.appendChild(row);
    rec.node.parentElement.scrollTop = rec.node.parentElement.scrollHeight;

    rec.lines++;
    if (rec.lines > __SSE_MAX_LINES) {
      const first = rec.node.querySelector('.log-line');
      if (first) first.remove();
      rec.lines--;
    }
  }

  function addEvt(name) {
    if (!name || subscribed.has(name)) return;
    subscribed.add(name);
    if (name === 'message') return;
    es.addEventListener(name, (ev) => {
      let data = ev?.data;
      try { data = JSON.parse(data); } catch {}
      if (name === 'error') {
        handleSseJobError(correlationId, data);
      } else if (name === 'done') {
        handleSseDone(correlationId, data || {});
      }
      const rec = __SSE_ACTIVE.get(correlationId);
      if (rec?.node) appendLine(name, data);
    });
  }

  DEFAULT_EVENTS.forEach(addEvt);

  es.addEventListener('hello', (ev) => {
    try {
      const data = JSON.parse(ev?.data || '{}');
      const advertised =
        data?.allEvents || data?.events || data?.supportedEvents || [];
      if (Array.isArray(advertised)) {
        for (const name of advertised) addEvt(String(name));
      }
      const rec = __SSE_ACTIVE.get(correlationId);
      if (rec?.node) appendLine('hello', data);
    } catch {}
  });

  es.addEventListener('log', (ev) => {
    try {
      const data = JSON.parse(ev?.data || '{}');
      const name = data?.event || 'log';
      const payload = data?.payload;
      addEvt(name);
      const rec = __SSE_ACTIVE.get(correlationId);
      if (rec?.node) appendLine(name, payload);
      if (name === 'error') handleSseJobError(correlationId, payload);
      if (name === 'done') handleSseDone(correlationId, payload || {});
    } catch {}
  });

  es.onmessage = (ev) => {
    try {
      if (!ev?.data) return;
      const data = JSON.parse(ev.data);
      const rec = __SSE_ACTIVE.get(correlationId);
      if (rec?.node) appendLine('message', data);
    } catch {}
  };

  return es;
}

function handleSseDone(correlationId, payload) {
  const ctx = __RUN_CTX.get(correlationId) || {};
  const assistantMessageElement = ctx.assistantEl;
  const sessionIndex = Number(ctx.sessionIndex) || getActiveSessionIndex();

  if (!assistantMessageElement || !assistantMessageElement.isConnected) {
    tryCloseSSE(correlationId);
    __RUN_CTX.delete(correlationId);
    return;
  }

  const contentEl = assistantMessageElement.querySelector('.message-content');
  const text = (payload && typeof payload.chatGPTResponse === 'string') ? payload.chatGPTResponse : '';
  const sources = Array.isArray(payload?.sources) ? payload.sources : [];

  assistantMessageElement.classList.remove('loading');

  if (text && text.trim()) {
    const html = renderMarkdown(text, sources);
    contentEl.innerHTML = html + buildSourcesFooter(sources);
    enhanceCodeBlocks(contentEl);

    const arr = loadConversation(sessionIndex);
    arr.push({ role: 'assistant', content: text, sources });
    saveConversation(sessionIndex, arr);

    if (getSessionTitleSource(sessionIndex) !== 'server') {
      const firstUser = arr.find(m => m.role === 'user');
      if (firstUser) generateAndStoreSessionTitle(sessionIndex, firstUser.content);
    }
  } else {
    return;
  }
  
  tryCloseSSE(correlationId);
  scrollToLatestMessage(conversationHistory);
  __RUN_CTX.delete(correlationId);
}

function handleSseJobError(correlationId, data) {
  const ctx = __RUN_CTX.get(correlationId) || {};
  const assistantMessageElement = ctx.assistantEl;
  if (!assistantMessageElement || !assistantMessageElement.isConnected) {
    tryCloseSSE(correlationId);
    __RUN_CTX.delete(correlationId);
    return;
  }

  assistantMessageElement.classList.remove('loading');
  const contentEl = assistantMessageElement.querySelector('.message-content');
  const msg = (data && (data.message || data.text)) ? String(data.message || data.text) : 'Unknown error';
  contentEl.innerHTML = `<p><strong>Failed:</strong> ${escapeHtml(msg)}</p>`;

  showToast?.(`Research run failed: ${msg}`, 'error', 5200);
  tryCloseSSE(correlationId);
  scrollToLatestMessage(conversationHistory);
  __RUN_CTX.delete(correlationId);
}

function tryCloseSSE(correlationId) {
  const rec = __SSE_ACTIVE.get(correlationId);
  if (!rec) return;
  try { rec.es.close(); } catch {}
  __SSE_ACTIVE.delete(correlationId);
}

/* ------------------------------------------------------------- Markdown & sources rendering ------------------------------------------------------------- */
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
function renderMarkdown(md, sourcesList) {
  if (!md) return '';

  md = md.replace(/```([\s\S]*?)```/g, (m, code) => {
    const safe = escapeHtml(code);
    return `<pre><code>${safe}</code></pre>`;
  });

  md = md.replace(/`([^`]+)`/g, (m, code) => `<code>${escapeHtml(code)}</code>`);

  md = md.replace(/^### (.*)$/gim, '<h3>$1</h3>');
  md = md.replace(/^## (.*)$/gim, '<h2>$1</h2>');
  md = md.replace(/^# (.*)$/gim, '<h1>$1</h1>');

  md = md.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  md = md.replace(/\*([^*]+)\*/g, '<em>$1</em>');

  md = md.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

  md = md.replace(/^\s*-\s+(.*)$/gim, '<li>$1</li>');
  md = md.replace(/(<li>[\s\S]*<\/li>)/gim, '<ul>$1</ul>');

  const lines = md.split(/\n{2,}/).map(p => {
    if (/^<h\d|^<ul|^<pre|^<blockquote|^<table/.test(p.trim())) return p;
    return `<p>${p.trim().replace(/\n/g, '<br>')}</p>`;
  }).join('\n');

  let html = lines;

  if (Array.isArray(sourcesList) && sourcesList.length) {
    html = html.replace(/\[(\d+)\]/g, (m, numStr) => {
      const n = parseInt(numStr, 10);
      if (!Number.isFinite(n)) return m;
      const found = sourcesList.find(s => s.index === n);
      if (!found) return m;
      return `<a href="#src-${n}" class="cite">[${n}]</a>`;
    });
  }

  return html;
}
function buildSourcesFooter(sourcesList) {
  if (!Array.isArray(sourcesList) || sourcesList.length === 0) return '';
  const items = sourcesList.map(s => {
    const title = s.title && s.title !== s.url ? escapeHtml(s.title) : s.url;
    return `<li id="src-${s.index}">[${s.index}] <a href="${s.url}" target="_blank" rel="noopener noreferrer">${title}</a></li>`;
  }).join('');
  return `
    <div class="sources-footer">
      <strong>Sources</strong>
      <ul>${items}</ul>
    </div>
  `;
}
function enhanceCodeBlocks(container) {
  const pres = container.querySelectorAll('pre');
  for (const pre of pres) {
    if (pre.querySelector('.copy-btn')) continue;
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.addEventListener('click', async () => {
      try {
        const code = pre.querySelector('code')?.innerText ?? '';
        await navigator.clipboard.writeText(code);
        const t = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(() => { btn.textContent = t; }, 1200);
      } catch {}
    });
    pre.appendChild(btn);
  }
}

/* ------------------------------------------------------------- Message helpers & history rendering ------------------------------------------------------------- */
function createMessage(role, html) {
  const tpl = document.getElementById('tmpl-message');
  const node = tpl.content.firstElementChild.cloneNode(true);
  node.classList.add(role);
  const content = node.querySelector('.message-content');
  content.innerHTML = html;

  const avatarEl = node.querySelector('.avatar');
  if (avatarEl) avatarEl.textContent = role === 'assistant' ? '🤖' : '👤';

  return node;
}
function scrollToLatestMessage(container) { container.scrollTop = container.scrollHeight; }
function updateConversationHistory(container, pastConversations) {
  container.innerHTML = '';
  for (const msg of pastConversations) {
    if (!msg || typeof msg !== 'object') continue;
    const role = msg.role === 'assistant' ? 'assistant' : 'user';
    const html = role === 'assistant'
      ? renderMarkdown(String(msg.content || ''), msg.sources || []) + buildSourcesFooter(msg.sources || [])
      : `<div class="message-content">${escapeHtml(String(msg.content || ''))}</div>`;
    const node = createMessage(role, html);
    container.appendChild(node);
    if (role === 'assistant') {
      const contentEl = node.querySelector('.message-content');
      enhanceCodeBlocks(contentEl);
    }
  }
  scrollToLatestMessage(container);
}

/* ------------------------------------------------------------- Web search heuristic (placeholder) ------------------------------------------------------------- */
function guessLikelyWebSearch(text) {
  const s = String(text || '').toLowerCase();
  if (/\b(today|latest|recent|this week|this month|202\d|202[0-9]|arxiv|pubmed|lineup|festival|tickets?|schedule)\b/.test(s)) return true;
  if (/\b(gdnf|ret|gfra|meta-analysis|systematic review|randomized trial)\b/.test(s)) return true;
  return false;
}

/* ------------------------------------------------------------- Depth tooltip behavior ------------------------------------------------------------- */
(function bindDepthTooltip(){
  if (!depthSelect || !depthTooltip) return;
  function showTip(){ depthTooltip.setAttribute('aria-hidden', 'false'); }
  function hideTip(){ depthTooltip.setAttribute('aria-hidden', 'true'); }

  depthSelect.addEventListener('mouseenter', showTip);
  depthSelect.addEventListener('mouseleave', hideTip);
  depthSelect.addEventListener('focus', showTip);
  depthSelect.addEventListener('blur', hideTip);

  if (depthField) {
    depthField.addEventListener('mouseenter', showTip);
    depthField.addEventListener('mouseleave', hideTip);
  }
})();

/* ------------------------------------------------------------- Session loading / deletion ------------------------------------------------------------- */
function loadSessionHistory(sessionIndex) {
  const key = `past_conversations_${sessionIndex}`;
  const pastConversations = JSON.parse(localStorage.getItem(key) || '[]');
  updateConversationHistory(conversationHistory, pastConversations);
  setActiveSessionIndex(sessionIndex);
  ensureSidebarItem(sessionIndex);
  const title = getSessionTitle(sessionIndex) || PLACEHOLDER_TITLE;
  activeTitleEl.textContent = title;
  manageGPTChatlyMessageDisplay();
}
function deleteSession(index) {
  localStorage.removeItem(`past_conversations_${index}`);
  localStorage.removeItem(`session_title_${index}`);
  localStorage.removeItem(`session_title_source_${index}`);

  if (getActiveSessionIndex() === index) {
    setActiveSessionIndex(0);
    conversationHistory.innerHTML = '';
    activeTitleEl.textContent = PLACEHOLDER_TITLE;
  }
  updateAllSidebars();
  manageGPTChatlyMessageDisplay();
}
function clearAllSessions() {
  const max = getMaxSessionIndex();
  for (let i = 1; i <= max; i++) {
    localStorage.removeItem(`past_conversations_${i}`);
    localStorage.removeItem(`session_title_${i}`);
    localStorage.removeItem(`session_title_source_${i}`);
  }
  setActiveSessionIndex(0);
  setMaxSessionIndex(0);
  sessionListEl.innerHTML = '';
  conversationHistory.innerHTML = '';
  activeTitleEl.textContent = PLACEHOLDER_TITLE;
  manageGPTChatlyMessageDisplay();
}

/* ------------------------------------------------------------- Compose & send ------------------------------------------------------------- */
composerForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const userPrompt = userInputEl.value.trim();
  if (!userPrompt) return;

  let active = getActiveSessionIndex();
  if (!active) {
    const max = getMaxSessionIndex();
    const next = max + 1;
    setMaxSessionIndex(next);
    setActiveSessionIndex(next);

    setSessionTitle(next, PLACEHOLDER_TITLE);
    setSessionTitleSource(next, 'placeholder');

    active = next;
    updateAllSidebars();
  }

  ensureSidebarItem(active);

  const userNode = createMessage('user', `<div class="message-content">${escapeHtml(userPrompt)}</div>`);
  conversationHistory.appendChild(userNode);

  try {
    const keyInit = `past_conversations_${active}`;
    const existingConv = JSON.parse(localStorage.getItem(keyInit) || '[]');
    const isFirst = existingConv.length === 0;
    existingConv.push({ role: 'user', content: userPrompt });
    localStorage.setItem(keyInit, JSON.stringify(existingConv));

    const src = getSessionTitleSource(active);
    if (isFirst || src !== 'server') {
      setSessionTitleSource(active, 'pending');
      generateAndStoreSessionTitle(active, userPrompt);
    }
  } catch (ePersist) {
    console.warn('Failed to persist user message:', ePersist);
  }

  const likelyWebSearch = guessLikelyWebSearch(userPrompt);
  const assistantMessageElement = document.createElement('div');
  assistantMessageElement.className = 'assistant message-container loading';
  if (likelyWebSearch) {
    assistantMessageElement.innerHTML = `
      <div class="avatar" aria-hidden="true"></div>
      <div class="message">
        <div class="message-content">
          <div class="web-search-wait" role="status" aria-live="polite" style="width:100%">
            <span class="mag-glass" aria-hidden="true"><span class="scan" aria-hidden="true"></span></span>
            <span class="search-msg">Searching the web for fresh sources</span>
          </div>
          <style>
            .web-search-wait{display:flex;align-items:center;gap:10px;padding:6px 0}
            .mag-glass{width:22px;height:22px;display:inline-block;position:relative;color:currentColor;animation:float 1.9s ease-in-out infinite}
            .mag-glass::before{content:"";position:absolute;left:2px;top:2px;width:18px;height:18px;border:2px solid currentColor;border-radius:50%;box-sizing:border-box}
            .mag-glass::after{content:"";position:absolute;width:10px;height:2px;background:currentColor;border-radius:1px;left:16px;top:16px;transform-origin:left center;transform:rotate(45deg)}
            .mag-glass .scan{position:absolute;left:2px;top:2px;width:18px;height:18px;border-radius:50%;overflow:hidden}
            .mag-glass .scan::before{content:"";position:absolute;left:-30%;top:-30%;width:160%;height:160%;background:linear-gradient(135deg, rgba(255,255,255,0) 30%, rgba(255,255,255,.35) 50%, rgba(255,255,255,0) 70%);animation:scan 1.4s ease-in-out infinite}
            .search-msg{position:relative}
            .search-msg::after{content:"";display:inline-block;width:1.25em;margin-left:.15em;text-align:left}
            .search-msg.dots-1::after{content:"."}
            .search-msg.dots-2::after{content:".."}
            .search-msg.dots-3::after{content:"..."}
            @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-2px)}}
            @keyframes scan{0%{transform:translate(-10%, -10%) rotate(0deg)}100%{transform:translate(10%, 10%) rotate(15deg)}}
            @media (prefers-reduced-motion: reduce){.mag-glass,.mag-glass .scan::before{animation:none}}
          </style>
        </div>
      </div>`;
    (function animateDots(){
      const msg = assistantMessageElement.querySelector('.search-msg');
      if (!msg) return;
      let step = 0;
      const id = setInterval(() => {
        step = (step % 3) + 1;
        msg.classList.remove('dots-1','dots-2','dots-3');
        msg.classList.add(`dots-${step}`);
        if (!assistantMessageElement.isConnected || !assistantMessageElement.classList.contains('loading')) {
          clearInterval(id);
        }
      }, 500);
    })();
  } else {
    assistantMessageElement.innerHTML = `
      <div class="avatar" aria-hidden="true"></div>
      <div class="message">
        <div class="message-content">
          <div class="typing-indicator">
            <div class="dot"></div><div class="dot"></div><div class="dot"></div>
          </div>
        </div>
      </div>`;
  }

  const avatarEl = assistantMessageElement.querySelector('.avatar');
  if (avatarEl) avatarEl.textContent = '🤖';

  conversationHistory.appendChild(assistantMessageElement);
  ensureSseLogPanel(assistantMessageElement);
  scrollToLatestMessage(conversationHistory);

  requestAnimationFrame(() => {
    const composer = document.getElementById('composer');
    if (composer) {
      const h = composer.getBoundingClientRect().height;
      document.documentElement.style.setProperty('--composer-h', `${Math.ceil(h)}px`);
    }
  });

  userInputEl.value = '';
  autoSizeTextArea();
  manageGPTChatlyMessageDisplay();

  const correlationId = generateCorrelationId();
  openSSE(correlationId, assistantMessageElement, active);
  __RUN_CTX.set(correlationId, { assistantEl: assistantMessageElement, sessionIndex: active });

  const past = loadConversation(active);
  const body = {
    userPrompt,
    past_conversations: past,
    depth: depthSelect.value,
    correlationId
  };

  const headers = { 'Content-Type': 'application/json' };
  if (await ensureJwt()) headers['Authorization'] = `Bearer ${jwtToken}`;

  const userKey = getOpenAIKey();
  if (userKey) headers['x-openai-key'] = userKey;

  fetch(ENDPOINT_POST, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    credentials: 'include'
  })
    .then(async (r) => {
      if (r.status !== 202) {
        const txt = await r.text().catch(() => '');
        showToast(`Failed to start research: ${r.status} ${txt}`, 'error', 6000);

        assistantMessageElement.classList.remove('loading');
        const contentEl = assistantMessageElement.querySelector('.message-content');
        contentEl.innerHTML = `<p><strong>Failed to submit:</strong> ${escapeHtml(txt || ('HTTP ' + r.status))}</p>`;
        tryCloseSSE(correlationId);
        __RUN_CTX.delete(correlationId);
      }
    })
    .catch((e) => {
      showToast(`Network error starting research: ${e?.message || e}`, 'error', 6000);
      assistantMessageElement.classList.remove('loading');
      const contentEl = assistantMessageElement.querySelector('.message-content');
      contentEl.innerHTML = `<p><strong>Failed to submit:</strong> ${escapeHtml(e?.message || 'Network error')}</p>`;
      tryCloseSSE(correlationId);
      __RUN_CTX.delete(correlationId);
    });

  scrollToLatestMessage(conversationHistory);

  requestAnimationFrame(() => {
    const composer = document.getElementById('composer');
    if (composer) {
      const h = composer.getBoundingClientRect().height;
      document.documentElement.style.setProperty('--composer-h', `${Math.ceil(h)}px`);
    }
  });
});

/* ------------------------------------------------------------- Initial boot ------------------------------------------------------------- */
window.addEventListener('load', async () => {
  await fetchJwtToken();

  bindApiKeyPanel();

  updateAllSidebars();
  manageGPTChatlyMessageDisplay();

  const sidebar = document.querySelector('.sidebar');
  const sW = sidebar && getComputedStyle(sidebar).display !== 'none'
    ? sidebar.getBoundingClientRect().width
    : 0;
  document.documentElement.style.setProperty('--sidebar-w', `${Math.round(sW)}px`);
  const composer = document.getElementById('composer');
  if (composer) {
    const h = composer.getBoundingClientRect().height;
    document.documentElement.style.setProperty('--composer-h', `${Math.ceil(h)}px`);
  }

  const active = getActiveSessionIndex();
  if (active) loadSessionHistory(active);

  newSessionBtn.addEventListener('click', () => {
    const next = getMaxSessionIndex() + 1;
    setMaxSessionIndex(next);
    setActiveSessionIndex(next);

    setSessionTitle(next, PLACEHOLDER_TITLE);
    setSessionTitleSource(next, 'placeholder');

    ensureSidebarItem(next);

    conversationHistory.innerHTML = '';
    activeTitleEl.textContent = PLACEHOLDER_TITLE;
    manageGPTChatlyMessageDisplay();

    const sidebar = document.querySelector('.sidebar');
    const w = sidebar && getComputedStyle(sidebar).display !== 'none'
      ? sidebar.getBoundingClientRect().width : 0;
    document.documentElement.style.setProperty('--sidebar-w', `${Math.round(w)}px`);
    const composer = document.getElementById('composer');
    if (composer) {
      const h = composer.getBoundingClientRect().height;
      document.documentElement.style.setProperty('--composer-h', `${Math.ceil(h)}px`);
    }

    userInputEl.focus();
  });

  clearAllBtn.addEventListener('click', () => {
    clearAllSessions();
    const sidebar = document.querySelector('.sidebar');
    const w = sidebar && getComputedStyle(sidebar).display !== 'none'
      ? sidebar.getBoundingClientRect().width : 0;
    document.documentElement.style.setProperty('--sidebar-w', `${Math.round(w)}px`);
    const composer = document.getElementById('composer');
    if (composer) {
      const h = composer.getBoundingClientRect().height;
      document.documentElement.style.setProperty('--composer-h', `${Math.ceil(h)}px`);
    }
  });
});
