import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import session from 'express-session';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();

//If you have one proxy in front in prod, use 1 otherwise 2. does not matter for dev
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT) || 3000;
const isProd = process.env.NODE_ENV === 'production';

/* ##################################################################################################
 * Security Headers (for production)
 * =============================================================================================== */

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'self'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self'",
      "connect-src 'self' https:",
      "object-src 'none'",
      "upgrade-insecure-requests"
    ].join('; ')
  );

  next();
});

/* ######################################################################################################
 * Session Middleware 
 * =============================================================================================== */

const sessionMw = session({
  secret: process.env.SESSION_SECRET || 'your-strong-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProd,                  
    httpOnly: true,
    sameSite: 'lax'
  }
});

app.use(sessionMw); 

/* ######################################################################################################
 * Static Assets
 * =============================================================================================== */


app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (/\.(js|css|png|jpg|jpeg|svg|webp|ico|woff2?)$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable'); // 1y
    } else {
      res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
    }
  }
}));


app.use(
  '/public',
  express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    immutable: false
  })
);

/* ############################################################################
 * Body Parsers (single set; duplicates removed)
 * =============================================================================================== */

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

/*  Helpers
=============================================================================================== */

function resolveApiKey(req) {
  try {
    const hdrKey =
      (req?.get?.('x-openai-key') || req?.headers?.['x-openai-key'] || '')
        .toString()
        .trim();
    if (!hdrKey) throw new Error('API Key not set. Provide it via X-OpenAI-Key header.');
    return hdrKey;
  } catch (e) {
    throw new Error('API Key not set. Provide it via X-OpenAI-Key header.');
  }
}

// initialize a session for a new user 
function initializeUserSession(req) {
  if (!req.session.userId) {
    req.session.userId = uuidv4();  
    /* console.log(`New session for user: ${req.session.userId}`); */
  }
}

// Secret key for JWT . USE YOUR OWN in produuction!!!
const JWT_SECRET = process.env.JWT_SECRET || '87689278100539879972341165400401175808582';

/* ===============================================================================================
 *  Pages
 * =============================================================================================== */

/* Serve index.html as root */
app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=0, s-maxage=1800, must-revalidate, stale-while-revalidate=60, stale-if-error=86400');
  const primary = path.join(__dirname, 'index.html');
  const fallback = path.join(__dirname, 'public', 'index.html');
  res.sendFile(primary, err => {
    if (err) res.sendFile(fallback);
  });
});

/* I will probably remove this later  */
app.get('/deep-search', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=0, s-maxage=1800, must-revalidate, stale-while-revalidate=60, stale-if-error=86400');
  const primary = path.join(__dirname, 'deep-search.html');
  const fallback = path.join(__dirname, 'public', 'deep-search.html');
  res.sendFile(primary, err => {
    if (err) res.sendFile(fallback);
  });
});

/* ###############################################################################################
 * Protected Paths                       
 * =============================================================================================== */

const protectedPaths = ['/jwt-token', '/fetch-titles', '/deep-research', '/deep-research/status'];

app.use(protectedPaths, (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');

  initializeUserSession(req); 

  if (!req.session.jwt) {
    const payload = {
      sessionID: req.sessionID,
      timestamp: Date.now()
    };
    req.session.jwt = jwt.sign(payload, JWT_SECRET, { expiresIn: '100h' });
  }

  next();
});


// get the jwt-token endpoint
app.get('/jwt-token', (req, res) => {
  if (!req.session.jwt) {
    const payload = { sessionID: req.sessionID, timestamp: Date.now() };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '100h' });
    req.session.jwt = token;
  }
  // Decode the token to get the expiry time
  const decoded = jwt.decode(req.session.jwt);
  console.log('JWT sent to client:', req.session.jwt);
  res.json({
    jwtToken: req.session.jwt,
    expiry: decoded && decoded.exp ? decoded.exp * 1000 : null 
  });
});

/* Validate JWT middleware */
const validateJWT = (req, res, next) => {
  try {
    const raw = req.headers['authorization'] || '';
    const token = raw.startsWith('Bearer ') ? raw.slice(7).trim() : null;
    if (!token) return res.status(403).send('A token is required for authentication');
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch {
    return res.status(401).send('Invalid Token');
  }
};





/* ##################################################################################################
 * SSE LAYER
 * =============================================================================================== */

/* a registry + backlog per correlationId */
const connections = new Map(); 
const backlog = new Map();     

const nowIso = () => new Date().toISOString();

/* named events */
function sendEvent(res, event, payload) {
  try {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(payload || {})}\n\n`);
  } catch {
    // 
  }
}

function getBucket(correlationId) {
  if (!connections.has(correlationId)) connections.set(correlationId, new Set());
  return connections.get(correlationId);
}

function enqueueBacklog(correlationId, event, payload) {
  if (!backlog.has(correlationId)) backlog.set(correlationId, []);
  const buf = backlog.get(correlationId);
  buf.push({ event, payload, ts: Date.now() });
  const MAX = 500;
  if (buf.length > MAX) buf.splice(0, buf.length - MAX);
}

function flushBacklog(res, correlationId) {
  const buf = backlog.get(correlationId);
  if (!Array.isArray(buf) || buf.length === 0) return;
  for (const item of buf) sendEvent(res, item.event, item.payload);
}

/* the broadcaster */
function sseBroadcast(correlationId, event, payload) {
  if (!correlationId) return;
  const bucket = connections.get(correlationId);
  if (!bucket || bucket.size === 0) {
    enqueueBacklog(correlationId, event, payload);
    return;
  }
  for (const res of bucket) sendEvent(res, event, payload);
}

/* Helper used inside your job/pipeline to emit structured logs */
function makeSseLogger(correlationId) {
  return (event, detail) => {
    const payload = {
      t: nowIso(),
      correlationId,
      ...(typeof detail === 'string' ? { text: detail } : (detail || {}))
    };
    sseBroadcast(correlationId, event, payload);
  };
}

/* expose globally if other modules want it */
global.sseBroadcast = sseBroadcast;

/* SSE endpoint */
app.get('/deep-research-FOSS-events', (req, res) => {
  const correlationId = String(req.query.correlationId || '').trim();
  if (!correlationId) return res.status(400).end('missing correlationId');

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  // send initial comment to establish stream quickly on some proxies
  res.write(': ok\n\n');
  res.flushHeaders?.();

  const bucket = getBucket(correlationId);
  bucket.add(res);

  sendEvent(res, 'hello', {
    correlationId,
    t: nowIso(),
    supportedEvents: [
      'hello','heartbeat','ready','start','plan_ready','outline_used','outline_final',
      'subq_start','subq_progress','subq_done','queries_ready','queries_seeded',
      'search_start','search_progress','search_results','search_results_urls',
      'fetch_start','fetched','crawl_progress','reranked',
      'synthesis_start','writing_started','writing_chunk','writing_progress','writing_done',
      'message','partial','debug','warn','error','done'
    ]
  });

  flushBacklog(res, correlationId);

  //FOR prod on ephemeral and for proxied by e.g. Cloudflare
  /* keep the connection active with frequent heartbeats (< 15s) */
  const hb = setInterval(() => {
    sendEvent(res, 'heartbeat', { t: nowIso() });
  }, 15000);

  req.on('close', () => {
    clearInterval(hb);
    const b = getBucket(correlationId);
    b.delete(res);
    if (b.size === 0) connections.delete(correlationId);
  });
});

/* ############
 * Job Queue
 * ############ */

const JOBS = new Map();
const QUEUE = [];
let ACTIVE = 0;
const MAX_CONCURRENCY = Math.max(1, Number(process.env.JOB_CONCURRENCY || 2));
const JOB_TTL_MS = Number(process.env.JOB_TTL_MS || 60 * 60 * 1000);

function enqueueJob(correlationId, requestSnapshot) {
  const now = Date.now();
  let job = JOBS.get(correlationId);
  if (job) {
    job.updatedAt = now;
    return job;
  }
  job = { status: 'queued', createdAt: now, updatedAt: now, requestSnapshot };
  JOBS.set(correlationId, job);
  QUEUE.push(correlationId);
  scheduleWorkers();
  return job;
}

function scheduleWorkers() {
  while (ACTIVE < MAX_CONCURRENCY && QUEUE.length > 0) {
    const corr = QUEUE.shift();
    runJob(corr).catch(() => {});
  }
}

async function runJob(correlationId) {
  const job = JOBS.get(correlationId);
  if (!job || (job.status !== 'queued' && job.status !== 'retry')) return;

  const sseLog = makeSseLogger(correlationId);
  ACTIVE += 1;

  try {
    job.status = 'running';
    job.startedAt = Date.now();
    job.updatedAt = job.startedAt;

    const { userPrompt, depth, apiKey, unpaywallEmail } = job.requestSnapshot || {};
    sseLog('ready', { depth, preview: (userPrompt || '').slice(0, 96) });

    /* The call to the actual main search pipeline */
    const result = await runDeepResearchPipeline({
      correlationId,
      userPrompt,
      depth,
      apiKey,
      unpaywallEmail,
      sseLog
    });

    job.status = 'done';
    job.finishedAt = Date.now();
    job.updatedAt = job.finishedAt;
    job.result = result;

    sseBroadcast(correlationId, 'done', { t: nowIso(), correlationId, ...result });

    setTimeout(() => backlog.delete(correlationId), 30_000);
  } catch (err) {
    job.status = 'error';
    job.finishedAt = Date.now();
    job.updatedAt = job.finishedAt;
    job.reason = err?.message || 'Unknown job error';
    sseBroadcast(correlationId, 'error', { t: nowIso(), correlationId, message: job.reason });
  } finally {
    ACTIVE = Math.max(0, ACTIVE - 1);
    scheduleWorkers();
  }
}


setInterval(() => {
  const now = Date.now();
  for (const [cid, job] of JOBS.entries()) {
    const ref = job.finishedAt || job.updatedAt || now;
    if (['done', 'error', 'aborted'].includes(job.status) && now - ref > JOB_TTL_MS) {
      JOBS.delete(cid);
      backlog.delete(cid);
    }
  }
}, 60_000);



/* Kickoff endpoint */
app.post('/deep-research', async (req, res) => {
  try {
    
    res.type('application/json');

    const {
      userPrompt: rawPrompt,
      past_conversations = [],
      depth = 'standard',
      correlationId: rawCorrId
    } = req.body || {};

    const correlationId =
      String(rawCorrId || `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`).trim();

    if (!correlationId) return res.status(400).json({ error: 'correlationId missing' });

    let userPrompt = (rawPrompt || '').trim();
    if (!userPrompt && Array.isArray(past_conversations)) {
      for (let i = past_conversations.length - 1; i >= 0; i--) {
        const m = past_conversations[i];
        if (m?.role === 'user' && m?.content && String(m.content).trim()) {
          userPrompt = String(m.content).trim();
          break;
        }
      }
    }
    if (!userPrompt) return res.status(400).json({ error: 'userPrompt missing or invalid' });

    /* Strictly require API key from client header only */
    let apiKey = '';
    try {
      apiKey = resolveApiKey(req);
    } catch (e) {
      return res.status(400).json({ error: e.message || 'OpenAI API key missing' });
    }

    /* Accept early; job streams via SSE */
    res.status(202).json({ accepted: true, correlationId });

    
    enqueueJob(correlationId, {
      userPrompt,
      past_conversations,
      depth,
      apiKey,
      unpaywallEmail: process.env.UNPAYWALL_EMAIL || ''
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || 'server error' });
  }
});

/* Status endpoint */
app.get('/deep-research/status', (req, res) => {
  res.type('application/json');
  const correlationId = String(req.query.correlationId || '');
  if (!correlationId) return res.status(400).json({ error: 'Missing correlationId' });
  const job = JOBS.get(correlationId);
  if (!job) return res.status(404).json({ error: 'Not found' });
  res.json({
    correlationId,
    status: job.status,
    startedAt: job.startedAt || null,
    finishedAt: job.finishedAt || null,
    reason: job.reason || null,
    result: job.result || null
  });
});

/* ===============================================================================================
 * Deep Research Pipeline 
 * =============================================================================================== */

async function runDeepResearchPipeline({
  correlationId,
  userPrompt,
  depth = 'standard',
  apiKey,
  unpaywallEmail = process.env.UNPAYWALL_EMAIL
}) {
  /* --- Guards --- */
  const nowIso = () => new Date().toISOString();
  function emit(event, detail = {}) {
    try {
      if (typeof sseBroadcast === 'function') {
        sseBroadcast(correlationId, event, {
          t: nowIso(),
          correlationId,
          ...(typeof detail === 'string' ? { text: detail } : detail)
        });
      }
    } catch {
      // 
    }
  }
  function log(kind, detail) {
    try {
      const pretty = typeof detail === 'string' ? detail : JSON.stringify(detail);
      console.log(`[${nowIso()}] [corr:${correlationId}] ${kind} :: ${pretty}`);
    } catch {
      // 
    }
    emit(kind, detail);
  }
  function assertString(v, name) {
    if (!v || typeof v !== 'string' || !v.trim()) throw new Error(`${name} missing or invalid`);
  }
  assertString(correlationId, 'correlationId');
  assertString(userPrompt, 'userPrompt');
  assertString(apiKey, 'apiKey');

  /* --- Config --- */
  const CFG = {
    MODELS: {
      planner: process.env.DR_PLANNER_MODEL || 'gpt-4o',
      critic: process.env.DR_CRITIC_MODEL || 'gpt-4o',
      synthesizer: process.env.DR_SYNTH_MODEL || 'gpt-4o',
      fast: process.env.DR_FAST_MODEL || 'gpt-4o-mini',
      polish: process.env.DR_POLISH_MODEL || 'gpt-4o',
      embed: process.env.DR_EMBED_MODEL || 'text-embedding-3-small',
      extractor: process.env.DR_EXTRACT_MODEL || 'gpt-4o'
    },

    /* ######################### 
    ### Have not implemented these yet, supposed to take value from "Shallow" etc.. from client ###
     ########################################################################################## */
    /* limits via env or defaults  */
    DEPTH_PRESETS: {
      shallow: {
        maxSteps: Number(process.env.DR_SHALLOW_STEPS || 3),
        maxSearches: Number(process.env.DR_SHALLOW_SEARCHES || 12),
        maxFetches: Number(process.env.DR_SHALLOW_FETCHES || 18),
        deepReads: Number(process.env.DR_SHALLOW_DEEPREADS || 8),
        minPerSubQSources: Number(process.env.DR_SHALLOW_MIN_SRCS || 3),
        timeBudgetMs: Number(process.env.DR_SHALLOW_TIME_MS || 8 * 60 * 1000)
      },
      standard: {
        maxSteps: Number(process.env.DR_STD_STEPS || 6),
        maxSearches: Number(process.env.DR_STD_SEARCHES || 30),
        maxFetches: Number(process.env.DR_STD_FETCHES || 50),
        deepReads: Number(process.env.DR_STD_DEEPREADS || 24),
        minPerSubQSources: Number(process.env.DR_STD_MIN_SRCS || 6),
        timeBudgetMs: Number(process.env.DR_STD_TIME_MS || 24 * 60 * 1000)
      },
      deep: {
        maxSteps: Number(process.env.DR_DEEP_STEPS || 9),
        maxSearches: Number(process.env.DR_DEEP_SEARCHES || 60),
        maxFetches: Number(process.env.DR_DEEP_FETCHES || 90),
        deepReads: Number(process.env.DR_DEEP_DEEPREADS || 36),
        minPerSubQSources: Number(process.env.DR_DEEP_MIN_SRCS || 8),
        timeBudgetMs: Number(process.env.DR_DEEP_TIME_MS || 50 * 60 * 1000)
      }
    },
    SELECT_LIMITS: {
      mmrFrac: 0.5,
      mmrMinPerSubQ: 12,
      fetchHardCapPerSubQ: 22,
      perDomainCapPerSubQ: 3,
      oaTopUpMax: 12
    },
    CONCURRENCY: { total: 16 },
    TTL: { searchMs: 12 * 60 * 60 * 1000, contentMs: 30 * 24 * 60 * 60 * 1000 },
    FLAGS: { enableOAResolver: true },
    CITATION_POLICY:
      'Cite sources in-text using numeric references like [1], [2]. End with "Sources:" listing [n] → URL on separate lines. ' +
      'Every sentence containing a claim must include ≥1 numeric citation.',
    EVENT_TOPIC_PATTERNS:
      /\b(festival|concert|line[- ]?up|tour|gig|venue|tickets?|schedule|setlist|headliners?)\b/i,
    SCHOLAR_TOPIC_PATTERNS:
      /\b(randomi[sz]ed|trial|cohort|case[- ]?control|systematic review|meta[- ]?analysis|confidence interval|95%\s*ci|p\s*[=<>]|odds ratio|hazard ratio|effect size|arxiv|pubmed|clinicaltrials|preprint|dataset|benchmark|algorithm|regression|anova|theorem|proof|doi)\b/i,
    COVERAGE: {
      minCitationCoverage: 0.95,
      minCitesPerParagraph: 3,
      maxCitesPerSentence: 3,
      perSourceMinimumMentions: 8,
      minWordsPerSource: 120,
      minQuantClaimsPerSource: 3,
      triangulationTargetRatio: 0.4
    },
    DYNAMIC_LIMITS: {
      baseSynthTokens: 18000,
      perSourceTokens: 420,
      perSubQTokens: 500,
      hardMaxSynthTokens: 52000,
      baseSynthTimeoutMs: 320000,
      perSourceSynthMs: 3500,
      perSubQSynthMs: 3500
    },
    APPENDIX_OPTS: {
      targetWordCount: 2800,
      perSourceDigestSentences: [6, 8]
    },
    TIERS: { coreCount: 14 }
  };

  const OA_PRIORITY = [
    /pmc\.ncbi\.nlm\.nih\.gov/i,
    /ncbi\.nlm\.nih\.gov\/pmc/i,
    /\.nih\.gov/i,
    /\.gov(\.[a-z]{2})?$/i,
    /\.edu$|\.ac\.[a-z]{2}$/i,
    /nature\.com\/articles/i,
    /plos\.org/i,
    /frontiersin\.org/i,
    /bmc.*biomedcentral\.com/i,
    /springer(?:open)?\.com/i,
    /cell\.com/i,
    /sciencedirect\.com\/science\/article\/pii\/.*-open-access/i
  ];

  const startedAt = Date.now();
  const cfg = CFG.DEPTH_PRESETS[depth] || CFG.DEPTH_PRESETS.standard; //NOt working yet

  
  /* ============================== Small utils ============================== */
  const safeTruncate = (s, n = 1200) => {
    s = String(s ?? '');
    return s.length <= n ? s : s.slice(0, n - 1) + '…';
  };

  const normalizeUrl = (u) => {
    try {
      const url = new URL(u);
      [
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'utm_id',
        'gclid', 'fbclid', 'mc_cid', 'mc_eid', 'igshid', 'si', 'spm'
      ].forEach((p) => url.searchParams.delete(p));
      url.hash = '';
      return url.toString();
    } catch {
      return u;
    }
  };

  const isDynamicOrJunk = (url) => {
    try {
      const h = new URL(url).hostname.replace(/^www\./, '');
      if (/google\.com$/i.test(h) && /\/maps\//i.test(url)) return true;
      if (/facebook|instagram|twitter|x\.com|tiktok/i.test(h)) return true;
      return false;
    } catch {
      return false;
    }
  };

  const stripHtml = (html) => {
    try {
      let t = String(html || '');
      t = t.replace(/<script[\s\S]*?<\/script>/gi, '');
      t = t.replace(/<style[\s\S]*?<\/style>/gi, '');
      t = t.replace(/<!--[\s\S]*?-->/g, '');
      t = t.replace(/<\/(p|div|li|br|h[1-6])>/gi, '\n');
      t = t.replace(/<[^>]+>/g, '');
      t = t.replace(/\n{3,}/g, '\n\n');
      t = t.replace(/[ \t]{2,}/g, ' ');
      return t.trim();
    } catch {
      return '';
    }
  };

  const parseCanonicalFromHtml = (url, html) => {
    try {
      const m1 = html.match(/<link\s+rel=["']canonical["']\s+href=["']([^"']+)["']/i);
      if (m1 && m1[1]) return new URL(m1[1], url).toString();
      const m2 = html.match(/<meta\s+property=["']og:url["']\s+content=["']([^"']+)["']/i);
      if (m2 && m2[1]) return new URL(m2[1], url).toString();
    } catch {
      // 
    }
    return null;
  };

  const parseLikelyDate = (htmlOrText) => {
    const s = String(htmlOrText || '');
    const ld = s.match(/"datePublished"\s*:\s*"([^"]+)"/i);
    if (ld) return ld[1];
    const og = s.match(
      /(article:published_time|pubdate|datePublished)["']?\s*[:=]\s*["']([^"']+)["']/i
    );
    if (og) return og[2];
    const iso = s.match(/\b(20\d{2}|19\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b/);
    if (iso) return iso[0];
    const mdy = s.match(
      /\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?)\s+([12]?\d|3[01]),\s*(19|20)\d{2}\b/i
    );
    if (mdy) return mdy[0];
    const yOnly = s.match(/\b(20\d{2}|19\d{2})\b/);
    if (yOnly) return yOnly[0];
    return null;
  };

  const extractDoiFromTextOrHtml = (s) => {
    const t = String(s || '');
    const m = t.match(/\b10\.\d{4,9}\/[^\s"'<>\]]+/i);
    return m ? m[0].replace(/[)\].,;:]+$/, '') : null;
  };

  const domainName = (u) => {
    try {
      return new URL(u).hostname.replace(/^www\./, '');
    } catch {
      return '';
    }
  };
  const oaPreferred = (u) => OA_PRIORITY.some((rx) => rx.test(u));
  const isLikelyBlocked = (u) =>
    /science\.org/i.test(u) || /nature\.com\/(.*\/)?(doi|abs)\//i.test(u);

  const RESP_WEIGHTS = { gov: 1.0, edu: 0.95, journal: 0.92, standard: 0.9, news: 0.75, web: 0.5 };
  const domainClass = (url) => {
    try {
      const { hostname } = new URL(url);
      if (
        /\.(gov|gov\.[a-z]{2})$/i.test(hostname) ||
        /(^|\.)(sec\.gov|europa\.eu|who\.int|ema\.europa\.eu|data\.gov)$/i.test(hostname)
      )
        return 'gov';
      if (/\.(edu|ac\.[a-z]{2})$/i.test(hostname)) return 'edu';
      if (
        /(arxiv\.org|pubmed\.ncbi\.nlm\.nih\.gov|nature\.com|science\.org|cell\.com|elsevier\.com|springer\.com|plos\.org|biorxiv\.org|frontiersin\.org|nejm\.org|thelancet\.com)/i.test(
          hostname
        )
      )
        return 'journal';
      if (/(w3\.org|iso\.org|ietf\.org|etsi\.org)/i.test(hostname)) return 'standard';
      if (/(reuters\.com|apnews\.com|bloomberg\.com|ft\.com|wsj\.com|guardian\.com)/i.test(hostname))
        return 'news';
      return 'web';
    } catch {
      return 'web';
    }
  };
  const authorityScore = (url) => RESP_WEIGHTS[domainClass(url)] || 0.5;

  const freshnessScore = (publishedAtStr) => {
    if (!publishedAtStr) return 0.4;
    const ts = Date.parse(publishedAtStr);
    if (!Number.isFinite(ts)) return 0.4;
    const ageDays = Math.max(0, (Date.now() - ts) / 86400000);
    if (ageDays <= 7) return 1.0;
    if (ageDays <= 30) return 0.9;
    if (ageDays <= 90) return 0.8;
    if (ageDays <= 365) return 0.6;
    return 0.4;
  };

  const scoreRelevance = (text, q) => {
    const Q = String(q || '').toLowerCase();
    const T = String(text || '').toLowerCase();
    if (!Q || !T) return 0;
    const terms = Q.split(/[^\wα-ωΑ-Ω]+/).filter(Boolean).slice(0, 12);
    let s = 0;
    for (const w of terms) s += (T.match(new RegExp(`\\b${w}\\b`, 'g')) || []).length;
    return s;
  };

  function extractKeyTerms(text, max = 12) {
    const s = (text || '').toLowerCase();
    const tokens = s.replace(/[^a-z0-9\-\s_/]/g, ' ').split(/\s+/).filter(Boolean);
    const stop = new Set([
      'the','and','for','that','with','you','your','what','how','why','can','this','from','into','over','under','between','about','best','good','bad','vs','in','on','to','of','a','an','is','are','be','as','it','by','or','if','at','we','they','i','my','our','their','more','most','less','few','new','latest','update','today','recent'
    ]);
    const freq = new Map();
    for (const t of tokens) {
      if (stop.has(t) || t.length < 3) continue;
      freq.set(t, (freq.get(t) || 0) + 1);
    }
    return [...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, max).map(([t]) => t);
  }

  function extractNumericsWithUnits(s) {
    const out = [];
    const text = String(s || '');
    const reBase =
      /([-+]?\d{1,3}(?:[,\s]\d{3})*(?:\.\d+)?|\d+\.\d+|\d+)\s*(%|percent|USD|EUR|£|\$|million|billion|k|K|°C|°F|km|mi|g|kg|mg|µg|ng|pg|ml|mL|L|µL|nM|µM|mM|GB|MB|TB|bps|ms|s|min|h|hours?|days?|months?|years?)?\b/gi;
    let m;
    while ((m = reBase.exec(text)))
      out.push({
        raw: m[0],
        value: Number(String(m[1]).replace(/[, ]/g, '')),
        unit: (m[2] || '').trim()
      });
    const reP = /\bp\s*[=<>]\s*(0?\.\d+|<\s*0?\.\d+|>\s*0?\.\d+|[0-1](?:\.\d+)?)\b/gi;
    while ((m = reP.exec(text)))
      out.push({ raw: m[0], measure: 'p', value: Number((m[1] || '0').replace(/[^\d.]/g, '')), unit: '' });
    const reES =
      /\b(OR|HR|RR|IRR|IR|\bMD\b|SMD)\s*[:=]?\s*([\-+]?\d+(?:\.\d+)?)\s*(?:\((?:95%CI|95%\s*CI|CI)\s*[:=]?\s*([\-+]?\d+(?:\.\d+)?)[ ,;\u2013-]+([\-+]?\d+(?:\.\d+)?)\))?/gi;
    while ((m = reES.exec(text))) {
      out.push({
        raw: m[0],
        measure: m[1],
        value: Number(m[2]),
        ci_low: m[3] ? Number(m[3]) : null,
        ci_high: m[4] ? Number(m[4]) : null,
        unit: ''
      });
    }
    return out.slice(0, 36);
  }

  async function pMap(items, concurrency, worker) {
    const ret = new Array(items.length);
    let index = 0;
    const active = new Set();
    async function runNext() {
      if (index >= items.length) return;
      const i = index++;
      const p = (async () => {
        try {
          ret[i] = await worker(items[i], i);
        } catch (e) {
          ret[i] = null;
        }
      })().finally(() => active.delete(p));
      active.add(p);
      if (active.size >= concurrency) await Promise.race(active);
      return runNext();
    }
    await Promise.all(new Array(Math.min(concurrency, items.length)).fill(0).map(runNext));
    return ret;
  }

  /* ============================== OpenAI helpers ============================== */
  function extractOutputText(data) {
    if (typeof data?.output_text === 'string' && data.output_text.trim()) return data.output_text.trim();
    if (Array.isArray(data?.output)) {
      const chunks = [];
      for (const item of data.output)
        if (item?.type === 'message' && Array.isArray(item.content))
          for (const c of item.content)
            if ((c?.type === 'output_text' || c?.type === 'text') && typeof c?.text === 'string' && c.text.trim())
              chunks.push(c.text.trim());
      if (chunks.length) return chunks.join('\n\n');
    }
    if (Array.isArray(data?.choices) && data.choices[0]?.message?.content)
      return String(data.choices[0].message.content).trim();
    return '';
  }

  async function openAIRequest(body, timeoutMs = 45000, tries = 4) {
    const jitter = () => Math.floor(200 + Math.random() * 200);
    for (let k = 0; k < tries; k++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new Error('request-timeout')), timeoutMs);
      try {
        const r = await fetch('https://api.openai.com/v1/responses', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`,
            'X-Idempotency-Key': body?.idempotency_key || `${Date.now()}-${Math.random().toString(36).slice(2)}`
          },
          body: JSON.stringify(body),
          signal: controller.signal
        });
        clearTimeout(timer);
        if (r.ok) {
          const data = await r.json();
          return { data };
        }
        const retriable = [429, 500, 502, 503, 504].includes(r.status);
        if (!retriable || k === tries - 1) {
          const payload = await r.text().catch(() => '');
          throw new Error(`OpenAI HTTP ${r.status}: ${payload}`);
        }
      } catch (e) {
        if (k === tries - 1) throw e;
      } finally {
        clearTimeout(timer);
      }
      await new Promise((res) => setTimeout(res, (2 ** k) * 500 + jitter()));
      if (k === tries - 2 && body?.model && /gpt-4o\b/.test(body.model)) {
        body.model = body.model.replace('gpt-4o', 'gpt-4o-mini');
      }
    }
  }
  async function openAIResp(body, timeoutMs) {
    const { data } = await openAIRequest(body, timeoutMs);
    return extractOutputText(data);
  }

  /* Embeddings */
  async function embedTexts(texts, timeoutMs = 100000) {
    if (!texts || !texts.length) return [];
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('request-timeout')), timeoutMs);
    try {
      const r = await fetch('https://api.openai.com/v1/embeddings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({ input: texts, model: CFG.MODELS.embed }),
        signal: controller.signal
      });
      if (!r.ok) throw new Error(`Embedding HTTP ${r.status}`);
      const j = await r.json();
      return (j.data || []).map((d) => d.embedding || []);
    } finally {
      clearTimeout(timer);
    }
  }

  const cosine = (a, b) => {
    let dot = 0, na = 0, nb = 0;
    for (let i = 0; i < a.length && i < b.length; i++) {
      const x = a[i], y = b[i];
      dot += x * y;
      na += x * x;
      nb += y * y;
    }
    return !na || !nb ? 0 : dot / (Math.sqrt(na) * Math.sqrt(nb));
  };

  function mmrSelect(candidates, candEmbeds, K = 8, lambda = 0.6) {
    if (candidates.length <= K) return candidates.map((_, i) => i);
    const selected = [];
    const idxs = candidates.map((_, i) => i);
    const dim = candEmbeds[0]?.length || 0;
    const centroid = new Array(dim).fill(0);
    for (const e of candEmbeds) for (let i = 0; i < dim; i++) centroid[i] += e[i];
    for (let i = 0; i < dim; i++) centroid[i] /= candEmbeds.length;
    while (selected.length < K && idxs.length) {
      let bestIdx = idxs[0], bestScore = -Infinity;
      for (const i of idxs) {
        const rel = cosine(candEmbeds[i], centroid);
        let maxSim = 0;
        if (selected.length) for (const s of selected) maxSim = Math.max(maxSim, cosine(candEmbeds[i], candEmbeds[s]));
        const div = 1 - maxSim;
        const score = lambda * rel + (1 - lambda) * div;
        if (score > bestScore) {
          bestScore = score;
          bestIdx = i;
        }
      }
      selected.push(bestIdx);
      idxs.splice(idxs.indexOf(bestIdx), 1);
    }
    return selected;
  }

  /* ============================== Fetching & OA resolution ============================== */
  const contentCache = new Map();
  async function fetchPage(url, timeoutMs = 9000, deep = false) {
    const cached = contentCache.get(url);
    if (cached && Date.now() - cached.ts < CFG.TTL.contentMs)
      return { ok: true, ...cached.value };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('request-timeout')), timeoutMs);
    try {
      if (isDynamicOrJunk(url)) return { ok: true, status: 200, ctype: 'text/html', text: '', html: null, skipped: true };
      const resp = await fetch(url, {
        signal: controller.signal,
        redirect: 'follow',
        headers: { 'User-Agent': 'ResearchBot/1.8' }
      });
      const status = resp.status;
      const ctype = resp.headers.get('content-type') || '';
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      if (/application\/pdf/i.test(ctype)) {
        const ab = await resp.arrayBuffer();
        const value = { status, ctype, text: '', html: null, binary: Buffer.from(ab) };
        contentCache.set(url, { ts: Date.now(), value });
        return { ok: true, ...value };
      }
      const html = deep ? await resp.text() : (await resp.text()).slice(0, 350000);
      if (/queueittoken=/i.test(resp.url) || /queueittoken=/i.test(url))
        return { ok: false, status, ctype, text: '', error: 'queue-wall', html: null };
      const text = stripHtml(html);
      const value = { status, ctype, text, html };
      contentCache.set(url, { ts: Date.now(), value });
      return { ok: true, ...value };
    } catch (e) {
      return { ok: false, status: 0, ctype: '', text: '', error: e?.message || String(e) };
    } finally {
      clearTimeout(timer);
    }
  }

  async function tryUnpaywall(doi) {
    if (!unpaywallEmail || !doi) return null;
    try {
      const url = `https://api.unpaywall.org/v2/${encodeURIComponent(doi)}?email=${encodeURIComponent(unpaywallEmail)}`;
      const r = await fetch(url, { method: 'GET' });
      if (!r.ok) return null;
      const j = await r.json();
      const best = j?.best_oa_location || j?.oa_locations?.[0] || null;
      if (!best) return null;
      return {
        url: best?.url || null,
        url_for_pdf: best?.url_for_pdf || null,
        version: best?.version || null,
        license: best?.license || null,
        host_type: best?.host_type || null
      };
    } catch {
      return null;
    }
  }

  async function tryDoiResolve(doi) {
    try {
      const doiUrl = `https://doi.org/${encodeURIComponent(doi)}`;
      const r = await fetch(doiUrl, {
        method: 'GET',
        headers: { 'Accept': 'text/html,application/pdf;q=0.9,*/*;q=0.8', 'User-Agent': 'ResearchBot/1.8' },
        redirect: 'follow'
      });
      if (!r.ok) return null;
      const finalUrl = r.url || doiUrl;
      const ctype = r.headers.get('content-type') || '';
      let html = null, binary = null, text = '';
      if (/pdf/i.test(ctype)) {
        const ab = await r.arrayBuffer();
        binary = Buffer.from(ab);
      } else {
        html = await r.text();
        text = stripHtml(html);
      }
      return { url: finalUrl, ctype, html, text, binary };
    } catch {
      return null;
    }
  }

  function extractPmcLinkFromPubMedHtml(html, baseUrl) {
    try {
      const rels = html.match(/<a[^>]+href="([^"]+)"[^>]*>([^<]*?PMC[^<]*?)<\/a>/gi) || [];
      for (const a of rels) {
        const href = (a.match(/href="([^"]+)"/i) || [])[1];
        if (!href) continue;
        if (/ncbi\.nlm\.nih\.gov\/pmc\/articles\//i.test(href) || /pmc\.ncbi\.nlm\.nih\.gov\/articles\//i.test(href)) {
          return new URL(href, baseUrl).toString();
        }
      }
    } catch {
      // 
    }
    return null;
  }

  function isAbstractOnly(doc) {
    const u = ((doc?.url || '') + ' ' + (doc?.canonical_url || '')).toLowerCase();
    const pubmed = /pubmed\.ncbi\.nlm\.nih\.gov/.test(u);
    const shortText = (doc?.text || '').length < 6000;
    return pubmed || shortText;
  }

  async function resolveFullTextForDoc(doc) {
    try {
      if (!CFG.FLAGS.enableOAResolver || !doc) return false;
      const originalUrl = doc.url;
      if (/pubmed\.ncbi\.nlm\.nih\.gov/i.test(originalUrl) && doc.html) {
        const pmcUrl = extractPmcLinkFromPubMedHtml(doc.html, originalUrl);
        if (pmcUrl) {
          const got = await fetchPage(pmcUrl, 15000, true);
          if (got.ok) {
            doc.canonical_url = pmcUrl;
            doc.ctype = got.ctype || doc.ctype;
            doc.html = got.html || doc.html;
            if (got.text && (!doc.text || got.text.length < got.text.length)) doc.text = got.text;
            doc.fetchedAt = nowIso();
            return true;
          }
        }
      }
      const doi = extractDoiFromTextOrHtml(doc.html || doc.text || '') || extractDoiFromTextOrHtml(`${doc.title} ${doc.snippet}`);
      if (doi) {
        const oa = await tryUnpaywall(doi);
        if (oa?.url_for_pdf) {
          const gotPdf = await fetchPage(oa.url_for_pdf, 18000, true);
          if (gotPdf.ok) {
            doc.canonical_url = oa.url_for_pdf;
            doc.ctype = gotPdf.ctype || doc.ctype;
            if (gotPdf.text) doc.text = gotPdf.text;
            doc.html = gotPdf.html || doc.html;
            doc.fetchedAt = nowIso();
            return true;
          }
        }
        if (oa?.url) {
          const gotHtml = await fetchPage(oa.url, 18000, true);
          if (gotHtml.ok) {
            doc.canonical_url = oa.url;
            doc.ctype = gotHtml.ctype || doc.ctype;
            if (gotHtml.text) doc.text = gotHtml.text;
            doc.html = gotHtml.html || doc.html;
            doc.fetchedAt = nowIso();
            return true;
          }
        }
        const doiRes = await tryDoiResolve(doi);
        if (doiRes?.html || doiRes?.binary || doiRes?.text) {
          doc.canonical_url = doiRes.url || doc.canonical_url || originalUrl;
          doc.ctype = doiRes.ctype || doc.ctype;
          doc.html = doiRes.html || doc.html;
          if (doiRes.text && (!doc.text || doiRes.text.length > doc.text.length)) doc.text = doiRes.text;
          doc.fetchedAt = nowIso();
          return true;
        }
      }
    } catch {
      // 
    }
    return false;
  }

  /* ============================== Outline designer (cached) ============================== */
  const outlineStore = new Map();
  const OUTLINE_TTL_MS = 60 * 60 * 1000;

  function normalizeOutlinePayload(payload) {
    try {
      if (!payload) return null;
      if (Array.isArray(payload)) {
        return payload.map((s) => String(s).trim()).filter(Boolean);
      }
      if (typeof payload === 'object') {
        const arr = payload.outline || payload.sections || payload.headings;
        if (Array.isArray(arr)) return arr.map((s) => String(s).trim()).filter(Boolean);
      }
      return null;
    } catch {
      return null;
    }
  }

  function setDynamicOutline(correlationId, outlinePayload, meta = {}) {
    const outline = normalizeOutlinePayload(outlinePayload);
    if (!outline || !outline.length) return false;
    outlineStore.set(correlationId, {
      outline,
      notes: String(meta.notes || meta.style_notes || meta.justification || '').slice(0, 800),
      title: String(meta.title || '').slice(0, 200),
      promptHash: String(meta.promptHash || ''),
      ts: Date.now()
    });
    return true;
  }

  function getStoredOutline(correlationId) {
    const rec = outlineStore.get(correlationId);
    if (!rec) return null;
    if (Date.now() - (rec.ts || 0) > OUTLINE_TTL_MS) {
      outlineStore.delete(correlationId);
      return null;
    }
    return rec;
  }

  async function outlineModelRequest(body, timeoutMs = 120000, tries = 3) {
    const jitter = () => Math.floor(200 + Math.random() * 200);
    for (let k = 0; k < tries; k++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new Error('request-timeout')), timeoutMs);
      try {
        const r = await fetch('https://api.openai.com/v1/responses', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`,
            'X-Idempotency-Key': body?.idempotency_key || `${Date.now()}-${Math.random().toString(36).slice(2)}`
          },
          body: JSON.stringify(body),
          signal: controller.signal
        });
        clearTimeout(timer);
        if (r.ok) return await r.json();
        if (![429, 500, 502, 503, 504].includes(r.status) || k === tries - 1) {
          const txt = await r.text().catch(() => '');
          throw new Error(`Outline HTTP ${r.status}: ${txt}`);
        }
      } catch (e) {
        if (k === tries - 1) throw e;
      } finally {
        clearTimeout(timer);
      }
      await new Promise((res) => setTimeout(res, (2 ** k) * 400 + jitter()));
    }
  }

  async function callOutlineDesigner(prompt) {
    const model = process.env.DR_OUTLINE_MODEL || 'gpt-4o';
    const instructions =
      'Design a publication-quality section outline tailored to the USER PROMPT. ' +
      'Produce 8–12 top-level headings (no subsections), specific to the domain (biomed, ML, economics, law, etc.). ' +
      'Return STRICT JSON like: {"title": string, "outline":[string,...], "notes": string}. ' +
      'Headings must be concise but descriptive (5–10 words). Do NOT include introduction/conclusion unless justified by the prompt.';
    const input = [{ role: 'user', content: `USER PROMPT:\n${String(prompt || '').slice(0, 4000)}` }];
    const { output_text, output, choices } = await outlineModelRequest({
      model,
      input,
      instructions,
      max_output_tokens: 900,
      truncation: 'auto',
      store: false,
      temperature: 0.2
    });

    let txt = '';
    if (typeof output_text === 'string' && output_text.trim()) txt = output_text.trim();
    else if (Array.isArray(output)) {
      const parts = [];
      for (const item of output)
        if (item?.type === 'message' && Array.isArray(item.content))
          for (const c of item.content) if (typeof c?.text === 'string') parts.push(c.text);
      txt = parts.join('\n').trim();
    } else if (Array.isArray(choices) && choices[0]?.message?.content) {
      txt = String(choices[0].message.content).trim();
    }

    let j = null;
    try {
      j = JSON.parse(txt);
    } catch {
      const m = txt.match(/\{[\s\S]*\}$/);
      if (m) {
        try {
          j = JSON.parse(m[0]);
        } catch {
          // 
        }
      }
    }

    const outline =
      normalizeOutlinePayload(j) || [
        'Executive Summary',
        'Background & Key Definitions',
        'Core Questions & Scope',
        'Methods / Theory / Mechanisms',
        'Evidence & Results',
        'Comparisons & Alternatives',
        'Implementation / Practical Considerations',
        'Risks, Limitations & Failure Modes',
        'Ethics / Safety / Regulatory',
        'Open Questions & Future Directions'
      ];
    return { outline, title: j?.title || '', notes: j?.notes || '' };
  }

  async function getDynamicOutline(correlationId, prompt) {
    const cached = getStoredOutline(correlationId);
    if (cached?.outline?.length) return cached.outline;
    const payload = await callOutlineDesigner(prompt).catch(() => null);
    if (payload?.outline?.length) {
      setDynamicOutline(correlationId, payload.outline, { title: payload.title, notes: payload.notes });
      return payload.outline;
    }
    return [
      'Executive Summary',
      'Background & Key Definitions',
      'Methods / Theory / Mechanisms',
      'Evidence & Results',
      'Comparisons & Alternatives',
      'Implementation / Practical Considerations',
      'Risks, Limitations & Failure Modes',
      'Open Questions & Future Directions'
    ];
  }

  /* ============================== Web search (Responses tool) ============================== */
  function parseWebSearchResults(data) {
    const out = [];
    const seen = new Set();
    function pushFrom(r) {
      try {
        const raw = r?.url || r?.link || r?.href || '';
        const url = normalizeUrl(String(raw).trim());
        if (!url || seen.has(url)) return;
        seen.add(url);
        out.push({
          title: String(r?.title || r?.name || '').trim(),
          url,
          snippet: String(r?.snippet || r?.text || r?.description || '').trim(),
          source: r?.source || r?.site || null,
          date: r?.date || r?.published_at || r?.publishedAt || null
        });
      } catch {
        // 
      }
    }
    function walk(node) {
      if (!node) return;
      if (Array.isArray(node)) {
        for (const item of node) walk(item);
        return;
      }
      if (typeof node === 'object') {
        if (Array.isArray(node.results)) for (const r of node.results) pushFrom(r);
        if (
          (node.type === 'web_search_results' || node.type === 'tool_result' || node.type === 'tool') &&
          (node.tool_name === 'web_search_preview' || node.name === 'web_search_preview' || node.tool?.name === 'web_search_preview')
        ) {
          let content = node.content ?? node.result ?? node.data ?? null;
          if (typeof content === 'string') {
            try {
              content = JSON.parse(content);
            } catch {
              // 
            }
          }
          walk(content);
        }
        if (typeof node.url === 'string' || typeof node.link === 'string' || typeof node.href === 'string') pushFrom(node);
        for (const v of Object.values(node)) walk(v);
        return;
      }
      if (typeof node === 'string') {
        const urls = node.match(/\bhttps?:\/\/[^\s"\]]+/g);
        if (urls) for (const u of urls.slice(0, 10)) pushFrom({ url: u });
      }
    }
    walk(data);
    return out;
  }

  async function callWebSearch(query, timeoutMs = 12000) {
    const instructions = 'Use the web_search_preview tool exactly once with the given query and return results.';
    const body = {
      model: CFG.MODELS.fast,
      input: [{ role: 'user', content: `Search for: ${query}` }],
      instructions,
      max_output_tokens: 10000,
      truncation: 'auto',
      store: false,
      tools: [{ type: 'web_search_preview', search_context_size: 'low', user_location: { type: 'approximate' } }],
      max_tool_calls: 1,
      temperature: 0
    };
    const { data } = await openAIRequest(body, timeoutMs);
    return parseWebSearchResults(data);
  }

  /* ============================== Routing & queries ============================== */
  function detectDomainRouting(prompt) {
    const p = String(prompt || '').toLowerCase();
    if (CFG.EVENT_TOPIC_PATTERNS.test(p)) {
      return { domain: 'events', engines: [], is_time_sensitive: true, justification: 'Event-like request detected.' };
    }
    if (CFG.SCHOLAR_TOPIC_PATTERNS.test(p)) {
      return { domain: 'scholarly', engines: ['pubmed', 'arxiv'], is_time_sensitive: /latest|update|today|recent/i.test(p), justification: 'Scholarly markers detected.' };
    }
    return { domain: 'other', engines: [], is_time_sensitive: /latest|update|today|recent/i.test(p), justification: 'Default routing.' };
  }

  function academicSeedQueries(globalPrompt, subQ, engines = []) {
    const keyTerms = extractKeyTerms(`${globalPrompt} ${subQ}`, 8);
    const core = keyTerms.length ? keyTerms.join(' ') : subQ || globalPrompt;
    const base = [
      `${core} review`,
      `${core} systematic review`,
      `${core} meta-analysis`,
      `${core} filetype:pdf`,
      `${core} best practices`
    ];
    if (engines.includes('pubmed') || /trial|patient|cohort|clinical/i.test(`${globalPrompt} ${subQ}`)) {
      base.push(`${core} site:pmc.ncbi.nlm.nih.gov`);
      base.push(`${core} site:pubmed.ncbi.nlm.nih.gov`);
      base.push(`${core} site:who.int OR site:ema.europa.eu OR site:fda.gov`);
      base.push(`${core} site:clinicaltrials.gov`);
    }
    if (engines.includes('arxiv') || /arxiv|preprint|theorem|algorithm|benchmark|dataset/i.test(`${globalPrompt} ${subQ}`)) {
      base.push(`${core} site:arxiv.org`);
      base.push(`${core} site:openreview.net`);
      base.push(`${core} benchmark results`);
      base.push(`${core} dataset site:paperswithcode.com OR site:huggingface.co`);
    }
    base.push(`${core} site:nature.com OR site:science.org`);
    base.push(`${core} site:*.edu`);
    base.push(`${core} site:*.gov`);
    return Array.from(new Set(base)).slice(0, 14);
  }

  /* ============================== Doc card & extraction ============================== */
  async function buildDocCard(doc, subqContext = '') {
    if (!doc?.text) return null;
    const instructions =
      'Extract an extended structured card (strict JSON): ' +
      '{"type":"primary|review|guideline|news|standard|other","design":string,"population":string,"intervention":string,"comparator":string,"outcomes":[string],' +
      '"delivery":{"route":string,"dose":string,"schedule":string,"duration":string},"follow_up":string,"n":string,"species":string,"model":string,' +
      '"methods":string,"comparators":string,"endpoint_types":[string],"risk_of_bias":{"randomization":string,"blinding":string,"confounding":string,"notes":string},' +
      '"key_results":[string], "numerics":[{"measure":string,"value":string,"ci":"string","p":"string"}], "limitations":[string]} ' +
      'Include concrete numbers (effect sizes, CIs, p), dosage/route/duration if present. Arrays ≤6 items. If non-biomedical, adapt fields naturally (e.g., datasets, benchmarks, metrics).';
    const input = [
      { role: 'system', content: 'You build extended doc cards for scientific/technical synthesis.' },
      {
        role: 'user',
        content: `Title: ${doc.title || doc.url}
Context: ${subqContext}

Document text (excerpt, truncated):
${safeTruncate(doc.text, 9000)}`
      }
    ];
    try {
      const body = { model: CFG.MODELS.critic, input, instructions, max_output_tokens: 2600, truncation: 'auto', store: false, temperature: 0.2 };
      const txt = await openAIResp(body, 90000);
      const j = JSON.parse(txt);
      const nums = Array.isArray(j?.numerics)
        ? j.numerics.slice(0, 10).map((x) => {
            const asText = `${x?.measure ?? ''} ${x?.value ?? ''} ${x?.ci ? `(${x.ci})` : ''} ${x?.p ? `p=${x.p}` : ''}`.trim();
            return { measure: String(x?.measure || '').slice(0, 80), value: String(x?.value || '').slice(0, 120), raw: asText.slice(0, 200) };
          })
        : [];
      return {
        type: String(j?.type || 'other'),
        design: String(j?.design || '').slice(0, 220),
        population: String(j?.population || '').slice(0, 240),
        intervention: String(j?.intervention || '').slice(0, 240),
        comparator: String(j?.comparator || '').slice(0, 240),
        outcomes: Array.isArray(j?.outcomes) ? j.outcomes.slice(0, 6).map((s) => String(s).slice(0, 160)) : [],
        delivery: {
          route: String(j?.delivery?.route || '').slice(0, 80),
          dose: String(j?.delivery?.dose || '').slice(0, 100),
          schedule: String(j?.delivery?.schedule || '').slice(0, 100),
          duration: String(j?.delivery?.duration || '').slice(0, 100)
        },
        follow_up: String(j?.follow_up || '').slice(0, 100),
        n: String(j?.n || '').slice(0, 64),
        species: String(j?.species || '').slice(0, 100),
        model: String(j?.model || '').slice(0, 140),
        methods: String(j?.methods || '').slice(0, 500),
        comparators: String(j?.comparators || '').slice(0, 240),
        endpoint_types: Array.isArray(j?.endpoint_types) ? j.endpoint_types.slice(0, 6).map((s) => String(s).slice(0, 80)) : [],
        risk_of_bias: {
          randomization: String(j?.risk_of_bias?.randomization || '').slice(0, 160),
          blinding: String(j?.risk_of_bias?.blinding || '').slice(0, 160),
          confounding: String(j?.risk_of_bias?.confounding || '').slice(0, 160),
          notes: String(j?.risk_of_bias?.notes || '').slice(0, 240)
        },
        key_results: Array.isArray(j?.key_results) ? j.key_results.slice(0, 6).map((s) => String(s).slice(0, 260)) : [],
        numerics: nums,
        limitations: Array.isArray(j?.limitations) ? j.limitations.slice(0, 6).map((s) => String(s).slice(0, 240)) : []
      };
    } catch {
      const nums = extractNumericsWithUnits(doc.text).slice(0, 10).map((n) => ({ measure: 'value', value: n.raw, raw: n.raw }));
      return {
        type: 'other',
        design: '',
        population: '',
        intervention: '',
        comparator: '',
        outcomes: [],
        delivery: { route: '', dose: '', schedule: '', duration: '' },
        follow_up: '',
        n: '',
        species: '',
        model: '',
        methods: '',
        comparators: '',
        endpoint_types: [],
        risk_of_bias: { randomization: '', blinding: '', confounding: '', notes: '' },
        key_results: [],
        numerics: nums,
        limitations: []
      };
    }
  }

  function buildDocFacts(doc) {
    const facts = [];
    const t = String(doc.text || '');
    const head = `${doc.title || ''} ${doc.snippet || ''}`.trim();
    if (head) facts.push(`Title/Context: ${head}`);
    const sents = t.split(/(?<=[\.!?])\s+/).filter((s) => s.length > 60);
    for (const s of sents) {
      if (
        /\b(n\s*=\s*\d+|95%\s*ci|95%\s*confidence|p\s*[=<>]|OR|HR|RR|dose|µg|mg|mL|dataset|accuracy|F1|AUC|benchmark|trial|randomi[sz]ed|cohort|follow-?up)\b/i.test(
          s
        )
      ) {
        facts.push(s.trim());
      }
      if (facts.length >= 10) break;
    }
    if (!facts.length && sents[0]) facts.push(sents[0].trim());
    return facts.slice(0, 10);
  }

  function selectRichExcerpt(doc, cap = 6000) {
    const t = String(doc.text || '');
    if (!t) return '';
    const addBlock = (label, block) => (block ? `\n\n### ${label}\n${block}` : '');
    const findSection = (labelRegex, window = 1600) => {
      const m = t.match(labelRegex);
      if (!m) return '';
      const idx = m.index || 0;
      const start = Math.max(0, idx);
      return t.slice(start, Math.min(t.length, start + window));
    };
    const abstract = findSection(/\b(Abstract|Summary)\b[:\s]/i, 1200);
    const methods = findSection(/\b(Materials and Methods|Methods|Methodology)\b[:\s]/i, 1800);
    const results = findSection(/\b(Results|Findings)\b[:\s]/i, 2000);
    const discuss = findSection(/\b(Discussion|Limitations|Conclusion)\b[:\s]/i, 1600);
    const combined =
      (abstract || '') + addBlock('Methods', methods) + addBlock('Results', results) + addBlock('Discussion', discuss);
    if (combined.trim()) return combined.slice(0, cap);
    return t.slice(0, cap);
  }
  function docToSnippet(doc, cap = 6000) {
    return selectRichExcerpt(doc, cap);
  }

  /* ============================== Claim extraction ============================== */
  async function callSummarizerStrict(subQ, docSnippets, timeoutMs = 24000) {
    const instructions =
      'Extract detailed factual claims from the snippets in strict JSON. ' +
      'Each claim MUST include: "text" (2–3 sentences covering methods→quantitative results→limitations if available), "quote" (≤300 chars), and "source_idx" (integer). ' +
      'Optionally include "locator" and "numbers" (list of concrete values like n, dose/route/duration, effect sizes with CI and p, dataset sizes, metrics). ' +
      'Return EXACT JSON: {"claims":[{ "text": string, "quote": string, "source_idx": number, "locator": {"idx": number,"start": number,"end": number,"page": number|null,"para": number|null} | null, "numbers":[{"raw":string,"value":number,"unit":string}] | [] }]} ' +
      'Target ≥10–16 claims if possible; preserve numeric detail.';
    const input = [
      { role: 'system', content: 'Extract anchored, quantitative claims with strict JSON only. Avoid being concise—include methods + numbers + caveats.' },
      {
        role: 'user',
        content: `Sub-question:
${subQ}

Allowed indices (do NOT invent): ${docSnippets.map((s) => `[#${s.idx}]`).join(' ')}

Snippets:
${docSnippets.map((s) => `[#${s.idx}] ${safeTruncate(s.text, 120000)}`).join('\n\n')}`
      }
    ];
    const body = {
      model: CFG.MODELS.extractor,
      input,
      instructions,
      max_output_tokens: 18000,
      truncation: 'auto',
      store: false,
      temperature: 0.1
    };
    const txt = await openAIResp(body, timeoutMs);
    try {
      return JSON.parse(txt);
    } catch {
      const m = txt.match(/\{[\s\S]*\}$/);
      if (m) {
        try {
          const j2 = JSON.parse(m[0]);
          return j2;
        } catch {
          // 
        }
      }
      return { claims: [] };
    }
  }

  async function callSummarizerFallback(subQ, docSnippets, timeoutMs = 36000) {
    const instructions =
      'Extract 14–22 detailed claims. Each claim should contain 2–3 sentences (methods → quantitative results → limitations where available). ' +
      'Every claim MUST end with a numeric citation [idx] matching allowed indices. Include n/effect sizes and 95% CI, p-values, dose/route/duration OR dataset sizes and metrics when relevant.';
    const input = [
      { role: 'system', content: 'Return JSON when possible; otherwise bullet lines each ending with [idx]. Include numbers and caveats.' },
      {
        role: 'user',
        content: `Sub-question:
${subQ}

Allowed indices: ${docSnippets.map((s) => `[#${s.idx}]`).join(' ')}

Snippets:
${docSnippets.map((s) => `[#${s.idx}] ${safeTruncate(s.text, 24000)}`).join('\n\n')}`
      }
    ];
    const body = {
      model: CFG.MODELS.synthesizer,
      input,
      instructions,
      max_output_tokens: 26000,
      truncation: 'auto',
      store: false,
      temperature: 0.2
    };
    const txt = await openAIResp(body, timeoutMs);
    try {
      const j = JSON.parse(txt);
      if (Array.isArray(j?.claims))
        return j.claims.map((c) => ({
          ...c,
          numbers: Array.isArray(c.numbers) ? c.numbers : extractNumericsWithUnits(String(c.text || ''))
        }));
    } catch {
      // 
    }
    const claims = [];
    for (const line of String(txt).split(/\r?\n/)) {
      const s = line.trim();
      if (!s.startsWith('-')) continue;
      const m = s.match(/ \[(\d+)\]\s*$/);
      const idx = m ? Number(m[1]) : null;
      const text = s.replace(/^-+\s*/, '').replace(/\s*\[\d+\]\s*$/, '').trim();
      if (text && Number.isFinite(idx) && idx > 0) {
        claims.push({
          text,
          quote: '',
          source_idx: idx,
          locator: null,
          numbers: extractNumericsWithUnits(text)
        });
      }
    }
    return claims;
  }

  function heuristicClaims(subQ, docSnippets) {
    const out = [];
    const pushClaim = (txt, idx) => {
      if (txt && idx) out.push({ text: txt.trim(), quote: '', source_idx: idx, locator: null, numbers: extractNumericsWithUnits(txt) });
    };
    for (const sn of docSnippets) {
      const txt = String(sn.text || '');
      const idx = sn.idx;
      const sent = txt
        .split(/[.!?]\s+/)
        .find((s) => s.length > 60 && /(\bn=\d+|\b95%|p\s*[=<>]|OR|HR|RR|dose|route|duration|follow|CI|dataset|accuracy|AUC|F1)/i.test(s));
      if (sent) pushClaim(sent + '.', idx);
    }
    return out.slice(0, 14);
  }

  /* ============================== Evidence store ============================== */
  const evidence = { docs: new Map(), sourceOrder: [], bySubQ: new Map() };
  const metrics = {
    abstractOnlyCount: 0,
    oaResolvedCount: 0,
    blockedPublisherCount: 0,
    docCardBuilt: 0,
    docFactsBuilt: 0
  };

  function registerSearchResults(subqId, results, question) {
    if (!Array.isArray(results)) return;
    if (!evidence.bySubQ.has(subqId)) evidence.bySubQ.set(subqId, new Set());
    const bucket = evidence.bySubQ.get(subqId);
    for (const r of results) {
      const url = normalizeUrl(r.url || '');
      if (!url || isDynamicOrJunk(url)) continue;
      if (!evidence.docs.has(url)) {
        const estDate = r.date || null;
        const doc = {
          url,
          canonical_url: null,
          title: String(r.title || '').trim(),
          snippet: String(r.snippet || '').trim(),
          text: null,
          html: null,
          ctype: null,
          date: estDate,
          dateProvenance: estDate ? 'serp' : null,
          authority_score: authorityScore(url),
          freshness_score: freshnessScore(estDate),
          primary_source: ['gov', 'edu', 'journal', 'standard'].includes(domainClass(url)),
          domain_class: domainClass(url),
          simhash: null,
          fetchedAt: null,
          score: 0,
          blocked: false,
          doc_role: null,
          doc_card: null,
          facts: null
        };
        doc.score = scoreRelevance(`${doc.title} ${doc.snippet}`, question || '');
        evidence.docs.set(url, doc);
      } else {
        const d = evidence.docs.get(url);
        d.score = Math.max(d.score, scoreRelevance(`${d.title} ${d.snippet}`, question || ''));
      }
      bucket.add(url);
    }
  }

  function planSourceOrder() {
    const allUrls = Array.from(evidence.docs.keys());
    evidence.sourceOrder = allUrls.sort((a, b) => {
      const A = evidence.docs.get(a),
        B = evidence.docs.get(b);
      const oaBoostA = oaPreferred(a) ? 1.5 : 0;
      const oaBoostB = oaPreferred(b) ? 1.5 : 0;
      const sa = (A?.score || 0) + (A?.authority_score || 0.0) * 2 + (A?.freshness_score || 0.0) + oaBoostA;
      const sb = (B?.score || 0) + (B?.authority_score || 0.0) * 2 + (B?.freshness_score || 0.0) + oaBoostB;
      return sb - sa;
    });
    return evidence.sourceOrder;
  }

  function sourceIndex(url) {
    const i = evidence.sourceOrder.indexOf(url);
    return i >= 0 ? i + 1 : null;
  }

  function buildNumberedSources() {
    const ordered = evidence.sourceOrder.length ? evidence.sourceOrder : planSourceOrder();
    const alive = ordered.filter((u) => {
      const d = evidence.docs.get(u);
      return !!(d?.text || d?.doc_card || d?.facts);
    });
    const top = alive.slice(0, Math.min(60, alive.length));
    return top.map((u, i) => {
      const d = evidence.docs.get(u);
      return { index: i + 1, url: d?.canonical_url || u, title: d?.title || u };
    });
  }

  /* ============================== Planner & Sub-question Processing ============================== */
  async function callPlanner(prompt) {
    const instructions =
      'Decompose the user question into a compact plan. Return strict JSON: ' +
      '{"plan_title": string, "subquestions":[{"id":"S1","question":string},...], "key_terms":[string], "success_criteria": string}.';
    const body = {
      model: CFG.MODELS.planner,
      input: [{ role: 'user', content: prompt }],
      instructions,
      max_output_tokens: 900,
      truncation: 'auto',
      store: false,
      temperature: 0
    };
    const txt = await openAIResp(body, 120000);
    try {
      return JSON.parse(txt);
    } catch {
      return null;
    }
  }

  async function callQueryGenerator(subQ, knownEntities, timeoutMs = 9000) {
    const instructions =
      'Given a sub-question and known entities, propose 14–22 high-yield web queries using site:, filetype:pdf, review/meta-analysis, and general forms. ' +
      'Prefer site:pmc.ncbi.nlm.nih.gov, site:pubmed.ncbi.nlm.nih.gov, site:arxiv.org, and *.edu/*.gov when relevant. ' +
      'Return STRICT JSON: {"queries":[string,...]}';
    const input = [
      { role: 'system', content: 'Generate diverse search queries with operators.' },
      { role: 'user', content: `Sub-question:\n${subQ}\n\nKnown entities:\n${(knownEntities || []).join(', ')}` }
    ];
    const body = {
      model: CFG.MODELS.fast,
      input,
      instructions,
      max_output_tokens: 700,
      truncation: 'auto',
      store: false,
      temperature: 0.2
    };
    const txt = await openAIResp(body, timeoutMs);
    try {
      const j = JSON.parse(txt);
      return Array.isArray(j?.queries) ? j.queries.slice(0, 22) : [];
    } catch {
      return [];
    }
  }

  async function processSubQuestion(subqId, subqText, knownEntities = [], engines = []) {
    log('subq_start', { subqId, subqText });

    // Seed queries (dynamic) 
    let queries = academicSeedQueries(userPrompt, subqText, engines);
    try {
      const more = await callQueryGenerator(subqText, knownEntities, 14000);
      if (more?.length) queries = Array.from(new Set([...queries, ...more]));
    } catch {
      // 
    }
    log('queries_ready', { subqId, queries: queries.slice(0, 12) });

    // Run searches 
    await pMap(queries.slice(0, Math.min(cfg.maxSearches, 28)), 6, async (q) => {
      const results = await callWebSearch(q, 15000).catch(() => []);
      if (results?.length) {
        log('search_results', {
          engine: 'web+seeds',
          subqId,
          query: q,
          count: results.length,
          sample: results.slice(0, 4).map((r) => r.url)
        });
        log('search_results_urls', { subqId, urls: results.map((r) => r.url) });
        const prioritized = results.sort((a, b) => oaPreferred(b.url) - oaPreferred(a.url));
        registerSearchResults(subqId, prioritized, subqText);
      }
    });

    /* Select candidates (MMR + cap) */
    const bucket = Array.from(evidence.bySubQ.get(subqId) || []);
    const candidates = bucket.map((u) => {
      const d = evidence.docs.get(u);
      return {
        url: u,
        title: d?.title || '',
        text: `${d?.title || ''} ${d?.snippet || ''}`.trim() || d?.title || u,
        metaScore:
          (d?.authority_score || 0) * 2 +
          (d?.freshness_score || 0) +
          (d?.score || 0) * 0.5 +
          (oaPreferred(u) ? 1.5 : 0)
      };
    });

    const perDomain = new Map();
    const domainCapped = [];
    for (const c of candidates.sort((a, b) => b.metaScore - a.metaScore)) {
      const dom = domainName(c.url);
      const used = perDomain.get(dom) || 0;
      if (used >= CFG.SELECT_LIMITS.perDomainCapPerSubQ) continue;
      perDomain.set(dom, used + 1);
      domainCapped.push(c);
    }

    const toEmbed = domainCapped.map((c) => c.text);
    const embeds = await embedTexts(toEmbed).catch(() => domainCapped.map(() => []));
    const K = Math.min(
      CFG.SELECT_LIMITS.fetchHardCapPerSubQ,
      Math.max(CFG.SELECT_LIMITS.mmrMinPerSubQ, Math.floor(domainCapped.length * CFG.SELECT_LIMITS.mmrFrac))
    );
    const pickIdxs = mmrSelect(domainCapped, embeds, K);
    const urlsToFetch = pickIdxs.map((p) => domainCapped[p].url);

    /* Fetch pages + OA resolve + doc cards/facts */
    await pMap(urlsToFetch, 8, async (u) => {
      const got = await fetchPage(u, oaPreferred(u) ? 16000 : 9000, false);
      if (!got.ok) {
        if (isLikelyBlocked(u)) metrics.blockedPublisherCount++;
        log('fetched', { subqId, url: u, status: got.status, ctype: got.ctype, chars: 0, phase: 'breadth' });
        return;
      }
      log('fetched', { subqId, url: u, status: got.status, ctype: got.ctype, chars: (got.text || '').length, phase: 'breadth' });

      const d = evidence.docs.get(u);
      d.text = got.text || d.text;
      d.html = got.html || d.html;
      d.ctype = got.ctype || d.ctype;
      d.fetchedAt = nowIso();

      try {
        const canonical = d.html ? parseCanonicalFromHtml(u, d.html) : null;
        if (canonical) d.canonical_url = canonical;
        const likelyDate = d.html ? parseLikelyDate(d.html) : parseLikelyDate(d.text);
        if (likelyDate && !d.date) {
          d.date = likelyDate;
          d.dateProvenance = 'page';
          d.freshness_score = freshnessScore(likelyDate);
        }
      } catch {
        // 
      }

      if (isAbstractOnly(d)) {
        metrics.abstractOnlyCount++;
        const resolved = await resolveFullTextForDoc(d);
        if (resolved) metrics.oaResolvedCount++;
      }

      if (!d.text && d.canonical_url && d.canonical_url !== u) {
        const deep = await fetchPage(d.canonical_url, 18000, true);
        log('fetched', { subqId, url: d.canonical_url, status: deep.status, ctype: deep.ctype, chars: (deep.text || '').length, phase: 'depth' });
        if (deep.ok) {
          d.text = deep.text || d.text;
          d.html = deep.html || d.html;
          d.ctype = deep.ctype || d.ctype;
          d.fetchedAt = nowIso();
        }
      }

      if (d.text && !d.doc_card) {
        try {
          const card = await buildDocCard(d, subqText);
          if (card) {
            d.doc_card = card;
            metrics.docCardBuilt++;
          }
          const facts = buildDocFacts(d);
          if (facts?.length) {
            d.facts = facts;
            metrics.docFactsBuilt++;
          }
          log('doc_card_built', { url: u, type: card?.type, n: card?.n, methods: card?.methods?.slice?.(0, 80) });
        } catch {
          // 
        }
      }
    });

    /* Pivot to OA if few texts */
    const haveTxt = urlsToFetch.map((u) => evidence.docs.get(u)).filter((d) => d?.text).length;
    if (haveTxt < cfg.minPerSubQSources) {
      const pivotQuery = `${subqText} site:pmc.ncbi.nlm.nih.gov OR site:arxiv.org review OR trial OR benchmark`;
      const pmcRes = await callWebSearch(pivotQuery, 12000).catch(() => []);
      if (pmcRes?.length) {
        registerSearchResults(subqId, pmcRes, subqText);
        const pmcUrls = pmcRes.map((r) => r.url).slice(0, cfg.minPerSubQSources);
        await pMap(pmcUrls, 6, async (u) => {
          const got = await fetchPage(u, 14000, true);
          log('fetched', { subqId, url: u, status: got.status, ctype: got.ctype, chars: (got.text || '').length, phase: 'pivot' });
          if (!got.ok) return;
          const d = evidence.docs.get(u);
          d.text = got.text || d.text;
          d.html = got.html || d.html;
          d.ctype = got.ctype || d.ctype;
          d.fetchedAt = nowIso();
          if (!d.doc_card && d.text) {
            const card = await buildDocCard(d, subqText);
            if (card) {
              d.doc_card = card;
              metrics.docCardBuilt++;
            }
            const facts = buildDocFacts(d);
            if (facts?.length) {
              d.facts = facts;
              metrics.docFactsBuilt++;
            }
          }
        });
      }
    }

    /* Prepare snippets for claim extraction */
    planSourceOrder();
    const subqUrls = Array.from(evidence.bySubQ.get(subqId) || []);
    const docSnippets = [];
    for (const u of subqUrls) {
      const d = evidence.docs.get(u);
      const idx = sourceIndex(u);
      if (!idx || !d?.text) continue;
      docSnippets.push({ idx, text: docToSnippet(d, 6500) });
    }

    /* Claim extraction */
    let claims = [];
    if (docSnippets.length) {
      const strict = await callSummarizerStrict(subqText, docSnippets).catch(() => null);
      if (strict?.claims?.length) {
        claims = strict.claims
          .map((c) => ({
            text: String(c?.text || '').trim(),
            quote: String(c?.quote || '').trim().slice(0, 300),
            source_idx: Number(c?.source_idx) || Number(c?.sourceIdx) || null,
            locator: c?.locator || null,
            numbers: Array.isArray(c?.numbers) ? c.numbers : extractNumericsWithUnits(String(c?.text || ''))
          }))
          .filter((c) => c.text && Number.isFinite(c.source_idx));
      }
      if (!claims.length) {
        const fb = await callSummarizerFallback(subqText, docSnippets).catch(() => []);
        if (Array.isArray(fb)) claims = fb;
      }
      if (!claims.length) claims = heuristicClaims(subqText, docSnippets);
    }

    const pruned = [];
    for (const c of claims) {
      if (!c?.text || !Number.isFinite(c?.source_idx)) continue;
      pruned.push({
        text: c.text.replace(/\s*\[\d+\]\s*$/, ''),
        quote: c.quote || '',
        source_idx: c.source_idx,
        locator: c.locator || null,
        numbers: Array.isArray(c.numbers) ? c.numbers.slice(0, 12) : []
      });
    }

    const added = pruned.slice(0, 36);
    if (!evidence._state) evidence._state = { claims: [] };
    evidence._state.claims = evidence._state.claims || [];
    evidence._state.claims.push(...added);

    log('claims_added', { subqId, added: added.length });
    return added;
  }

  /* ============================== Theming & evidence matrix ============================== */
  function groupClaimsIntoThemes(allClaims) {
    const themes = [];
    const bins = new Map();
    const titleFor = (txt) => {
      const t = String(txt || '').toLowerCase();
      if (/background|definition|terminolog|history|overview/.test(t)) return 'Background & Definitions';
      if (/method|protocol|algorithm|theor|mechanism|pathway|architecture/.test(t)) return 'Mechanisms / Methods / Theory';
      if (/trial|cohort|experiment|dataset|benchmark|results|performance|accuracy|auc|evidence/.test(t)) return 'Evidence & Results';
      if (/compare|versus|alternative|trade[- ]?off|baseline/.test(t)) return 'Comparisons & Alternatives';
      if (/deploy|implementation|practic|cost|scalab|latency|ops|tooling|data/.test(t)) return 'Implementation / Practical Considerations';
      if (/risk|adverse|toxicity|safety|failure|bias|limitation|confound/.test(t)) return 'Risks, Limitations & Failure Modes';
      if (/ethic|privacy|compliance|govern|policy|law|regulation/.test(t)) return 'Ethics, Safety & Compliance';
      return 'General';
    };
    for (const c of allClaims) {
      const key = titleFor(c.text);
      if (!bins.has(key)) bins.set(key, { id: `T${bins.size + 1}`, title: key, claims: [] });
      bins.get(key).claims.push(c);
    }
    for (const v of bins.values()) themes.push(v);
    return themes;
  }

  function buildEvidenceMatrixMd(numberedSources) {
    const rows = [
      '| # | Type | n/Size | Methods | Key results | Limitations |',
      '|---|------|--------|---------|-------------|-------------|'
    ];
    for (const s of numberedSources) {
      const d = evidence.docs.get(s.url) || evidence.docs.get(evidence.sourceOrder[s.index - 1]);
      const card = d?.doc_card || {};
      const n = (card?.n || card?.population || '').toString().slice(0, 24);
      const methods = (card?.methods || '').toString().slice(0, 120);
      const kr = Array.isArray(card?.key_results) ? card.key_results.join('; ').slice(0, 200) : '';
      const lim = Array.isArray(card?.limitations) ? card.limitations.join('; ').slice(0, 140) : '';
      rows.push(`| ${s.index} | ${card?.type || ''} | ${n} | ${methods} | ${kr} | ${lim} |`);
    }
    return rows.join('\n');
  }

  /* ============================== Synthesis, polishing, expansions ============================== */
  async function callSynthesizer(globalPrompt, planObj, claims, numberedSources, themeGroups, evidenceMatrixMd, outlineArr) {
    const sourcesMap = numberedSources.map((s) => `[${s.index}] ${s.url}`).join('\n');

    const cardsText = numberedSources
      .map((s) => {
        const d = evidence.docs.get(s.url);
        if (!d?.doc_card) return null;
        const c = d.doc_card;
        const numerics = (c.numerics || []).map((n) => `${n.measure}: ${n.value}`).join(' | ');
        return `[${s.index}] type=${c.type}; methods=${c.methods}; n/size=${c.n || c.population || ''}; comparators=${c.comparators}; key_results=${(c.key_results || []).join(' || ')}; numerics=${numerics}; limitations=${(c.limitations || []).join(' || ')}`;
      })
      .filter(Boolean)
      .join('\n');

    const themeText = themeGroups
      .map((t, ti) => {
        const bullets = (t.claims || []).map((c) => `- ${c.text} [${c.source_idx}]`).join('\n');
        return `## Theme T${ti + 1}: ${t.title}\n${bullets}`;
      })
      .join('\n\n');

    const outlineText = (Array.isArray(outlineArr) && outlineArr.length
      ? outlineArr
      : [
          'Executive Summary',
          'Background & Key Definitions',
          'Methods / Theory / Mechanisms',
          'Evidence & Results',
          'Comparisons & Alternatives',
          'Implementation / Practical Considerations',
          'Risks, Limitations & Failure Modes',
          'Open Questions & Future Directions'
        ]).map((h, i) => `${i + 1}. ${h}`).join('\n');

    const instructions =
      'Write an evidence-rich mini-review that integrates many sources using the provided outline. ' +
      `Target ~${CFG.APPENDIX_OPTS.targetWordCount} words. ` +
      `Each paragraph should integrate ≥${CFG.COVERAGE.minCitesPerParagraph} distinct citations and never exceed ${CFG.COVERAGE.maxCitesPerSentence} citations per sentence. ` +
      `${CFG.CITATION_POLICY} ` +
      'For each major point, provide detailed exposition per citation: include methods (design/dataset), quantitative results (n/metrics/effect sizes, 95% CIs, p-values), and key limitations/bias. ' +
      'Include comparison/triangulation paragraphs that contrast findings across sources. ' +
      'Close with knowledge gaps and future directions. After the narrative, include an **Evidence Matrix** section rendered as the given Markdown table. ' +
      'Use the exact section headings listed in the OUTLINE.';

    const input = [
      { role: 'system', content: 'You are a senior review author synthesizing evidence into a rigorous mini-review with impeccable citations and quantitative detail.' },
      {
        role: 'user',
        content: `USER PROMPT:
${globalPrompt}

OUTLINE:
${outlineText}

RESEARCH PLAN:
${[
  `Plan title: ${planObj?.plan_title || '(none)'}\n`,
  'Sub-questions:',
  ...(Array.isArray(planObj?.subquestions) ? planObj.subquestions.map((sq) => `- ${sq.id || ''}: ${sq.question}`) : []),
  ''
].join('\n')}

SOURCES MAP (index → URL):
${sourcesMap}

DOC CARDS (index → structured info):
${cardsText || '(no cards available)'}

CLAIMS GROUPED BY THEMES:
${themeText}

EVIDENCE MATRIX (render as-is below the narrative):
${evidenceMatrixMd || '(none)'}`
      }
    ];

    const srcCount = Array.isArray(numberedSources) ? numberedSources.length : 0;
    const subCount = Array.isArray(planObj?.subquestions) ? planObj.subquestions.length : 0;
    const tokenBudget = Math.min(
      CFG.DYNAMIC_LIMITS.hardMaxSynthTokens,
      CFG.DYNAMIC_LIMITS.baseSynthTokens + srcCount * CFG.DYNAMIC_LIMITS.perSourceTokens + subCount * CFG.DYNAMIC_LIMITS.perSubQTokens
    );
    const timeoutMs =
      CFG.DYNAMIC_LIMITS.baseSynthTimeoutMs +
      srcCount * CFG.DYNAMIC_LIMITS.perSourceSynthMs +
      subCount * CFG.DYNAMIC_LIMITS.perSubQSynthMs;

    const body = {
      model: CFG.MODELS.synthesizer,
      input,
      instructions,
      max_output_tokens: tokenBudget,
      truncation: 'auto',
      store: false,
      temperature: 0.2
    };

    const { data } = await openAIRequest(body, timeoutMs);
    return extractOutputText(data);
  }

  async function buildSourceBriefs(numberedSources, limit = 24) {
    const out = {};
    const subset = numberedSources.slice(0, limit);
    await pMap(subset, 6, async (s) => {
      const d = evidence.docs.get(s.url) || {};
      const body = {
        model: CFG.MODELS.critic,
        input: [
          {
            role: 'user',
            content: `Summarize this source in 4–6 bullet points with concrete numbers (methods → main results → harms/risks → limitations).
Title: ${d.title || s.url}
Snippet: ${d.snippet || ''}
Card: ${JSON.stringify(d.doc_card || {})}
Facts:
- ${(d.facts || []).join('\n- ')}
Text (excerpt): ${safeTruncate(d.text || '', 2200)}`
          }
        ],
        instructions: 'Return 4–6 concise bullet points. No extra intro text.',
        max_output_tokens: 700,
        truncation: 'auto',
        store: false,
        temperature: 0.2
      };
      const txt = await openAIResp(body, 30000).catch(() => '');
      out[s.index] = txt || '';
    });
    return out;
  }

  async function generateSourceCapsule(s, targetSection = '') {
    const d = evidence.docs.get(s.url) || {};
    const card = d.doc_card || {};
    const facts = d.facts || [];
    const body = {
      model: CFG.MODELS.critic,
      input: [
        {
          role: 'user',
          content: `Write a 5–7 sentence paragraph on source [${s.index}] with deep coverage (methods → quantitative results → risks/limitations). 
Cite ONLY [${s.index}] at least twice within the paragraph. 
Include n/dataset size, endpoints/metrics, effect sizes with 95% CI and p if present, and dose/route/duration when applicable. 
Best-fit section: "${targetSection || 'General'}".

Title: ${d.title || s.url}
Card: ${JSON.stringify(card)}
Facts:
- ${facts.join('\n- ')}
Text (excerpt): ${safeTruncate(d.text || '', 2400)}`
        }
      ],
      instructions: 'Return a single paragraph, 5–7 sentences, with bracketed numeric citations [idx] (only [idx] for this source).',
      max_output_tokens: 650,
      truncation: 'auto',
      store: false,
      temperature: 0.2
    };
    const txt = await openAIResp(body, 45000).catch(() => '');
    return (txt || '').trim();
  }

  async function buildTriangulationBlocks(sources, count = 4) {
    const subset = sources.slice(0, Math.min(sources.length, CFG.TIERS.coreCount));
    const mapLines = subset.map((s) => `[${s.index}] ${s.url}`).join('\n');
    const packs = subset
      .map((s) => {
        const d = evidence.docs.get(s.url) || {};
        return `[#${s.index}] ${d.title || s.url}
Card:${JSON.stringify(d.doc_card || {})}
Facts:
- ${(d.facts || []).join('\n- ')}`;
      })
      .join('\n\n');

    const body = {
      model: CFG.MODELS.synthesizer,
      input: [
        {
          role: 'user',
          content: `Create ${count} triangulation paragraphs. Each paragraph should compare 2–3 sources (choose from below) on the same question, 
explicitly state agreements/disagreements and plausible reasons (population; dataset; dose/route; follow-up; endpoints/metrics; bias).
Each sentence must include citations and each paragraph must cite at least two distinct sources.

SOURCES MAP:
${mapLines}

SOURCE PACKS:
${packs}`
        }
      ],
      instructions: 'Return exactly the paragraphs, no headings. Maintain high numeric detail and bracketed citations like [3][7].',
      max_output_tokens: 1800,
      truncation: 'auto',
      store: false,
      temperature: 0.2
    };
    const txt = await openAIResp(body, 70000).catch(() => '');
    return (txt || '').trim();
  }

  function computePerSourceStats(txt, numberedSources) {
    const stats = new Map();
    for (const s of numberedSources) stats.set(s.index, { words: 0, mentions: 0, quant: 0, sentences: 0 });
    const sentences = String(txt || '').split(/(?<=[\.!?])\s+/);
    for (const sent of sentences) {
      const citeSet = new Set();
      const pat = /\[(\d+)\]/g;
      let m;
      while ((m = pat.exec(sent))) {
        const n = Number(m[1]);
        if (stats.has(n)) citeSet.add(n);
      }
      if (citeSet.size) {
        const words = sent.trim().split(/\s+/).filter(Boolean).length;
        const per = Math.max(1, citeSet.size);
        const share = Math.ceil(words / per);
        const nums = extractNumericsWithUnits(sent).length;
        for (const idx of citeSet) {
          const s = stats.get(idx);
          s.words += share;
          s.mentions += 1;
          s.quant += nums > 0 ? 1 : 0;
          s.sentences += 1;
        }
      }
    }
    return stats;
  }

  function buildCoverageGoals(numberedSources, allClaims, manuscript = '') {
    const counts = new Map();
    for (const c of allClaims || []) counts.set(c.source_idx, (counts.get(c.source_idx) || 0) + 1);
    const perStats = computePerSourceStats(manuscript, numberedSources);
    const goals = {};
    for (const s of numberedSources) {
      const haveMentions = counts.get(s.index) || 0;
      const st = perStats.get(s.index) || { words: 0, mentions: 0, quant: 0 };
      goals[s.index] = {
        minMentions: CFG.COVERAGE.perSourceMinimumMentions,
        currentMentions: haveMentions,
        mentionDeficit: Math.max(0, CFG.COVERAGE.perSourceMinimumMentions - haveMentions),
        minWords: CFG.COVERAGE.minWordsPerSource,
        currentWords: st.words,
        wordDeficit: Math.max(0, CFG.COVERAGE.minWordsPerSource - st.words),
        minQuant: CFG.COVERAGE.minQuantClaimsPerSource,
        currentQuant: st.quant,
        quantDeficit: Math.max(0, CFG.COVERAGE.minQuantClaimsPerSource - st.quant)
      };
    }
    return goals;
  }

  async function polishForDepth(text, numberedSources, briefs, goals) {
    const sourcesMap = numberedSources.map((s) => `[${s.index}] ${s.url}`).join('\n');
    const perSourceNotes = Object.entries(goals || [])
      .map(
        ([k, v]) =>
          `Source [${k}]: mentions ${v.currentMentions}/${v.minMentions}; words ${v.currentWords}/${v.minWords}; quant ${v.currentQuant}/${v.minQuant}`
      )
      .join('\n');
    const briefText = Object.entries(briefs || {})
      .map(([k, v]) => `- [${k}] ${v}`)
      .join('\n');

    const instructions =
      'Revise and EXPAND the manuscript to meet per-source depth floors. ' +
      'Do NOT compress or remove existing content; you may add sentences and new paragraphs, but keep the outline and section headings unchanged. ' +
      `Targets: ≥${CFG.COVERAGE.minWordsPerSource} words and ≥${CFG.COVERAGE.minQuantClaimsPerSource} quantified claims per used source; ` +
      `≥${CFG.COVERAGE.minCitesPerParagraph} distinct citations per paragraph on average; ≤${CFG.COVERAGE.maxCitesPerSentence} citations per sentence. ` +
      'Integrate quantitative details from briefs. Maintain coherent flow and avoid citation spam.';

    const input = [
      { role: 'system', content: 'You are a meticulous scientific/technical editor expanding depth per citation without compressing text.' },
      {
        role: 'user',
        content: `CURRENT MANUSCRIPT:
${text.replace(/\n+Sources:\s*\n[\s\S]*$/i, '').trim()}

SOURCES MAP:
${sourcesMap}

PER-SOURCE GOALS:
${perSourceNotes}

SOURCE BRIEFS:
${briefText}`
      }
    ];

    const body = {
      model: CFG.MODELS.polish,
      input,
      instructions,
      max_output_tokens: Math.min(CFG.DYNAMIC_LIMITS.hardMaxSynthTokens, 22000),
      truncation: 'auto',
      store: false,
      temperature: 0.2
    };
    const { data } = await openAIRequest(body, 260000);
    return extractOutputText(data);
  }

  async function integrateExpansions(manuscript, capsulesMap, triangulationBlocks, outlineArr) {
    const outlineText = outlineArr.map((h, i) => `${i + 1}. ${h}`).join('\n');
    const capsText = Object.entries(capsulesMap)
      .map(([k, v]) => `[[CAPSULE ${k}]] ${v}`)
      .join('\n');
    const input = [
      { role: 'system', content: 'Integrate expansions into the manuscript under the best-fit sections; keep all original text.' },
      {
        role: 'user',
        content: `OUTLINE:
${outlineText}

CURRENT MANUSCRIPT:
${manuscript.replace(/\n+Sources:\s*\n[\s\S]*$/i, '').trim()}

EXPANSION UNITS:
-- Source Capsules --
${capsText || '(none)'}

-- Triangulation Blocks --
${triangulationBlocks || '(none)'}
`
      }
    ];
    const instructions =
      'Insert each CAPSULE and triangulation block into the most relevant section (do not drop any); keep original paragraphs intact; ' +
      'you may add new paragraphs but must preserve all section headings exactly. Ensure each new sentence has proper numeric citations.';
    const body = {
      model: CFG.MODELS.synthesizer,
      input,
      instructions,
      max_output_tokens: Math.min(CFG.DYNAMIC_LIMITS.hardMaxSynthTokens, 24000),
      truncation: 'auto',
      store: false,
      temperature: 0.2
    };
    const { data } = await openAIRequest(body, 220000);
    return extractOutputText(data);
  }

  /* ============================== Main flow ============================== */
  try {
    const routing = detectDomainRouting(userPrompt);
    log('start', { depth, promptPreview: userPrompt.slice(0, 64), correlationId, routing });

    /* Plan */
    let plan = await callPlanner(userPrompt).catch(() => null);
    if (!plan || !Array.isArray(plan.subquestions) || !plan.subquestions.length) {
      const terms = extractKeyTerms(userPrompt, 8);
      const baseTopic = terms.slice(0, 3).join(' ');
      plan = {
        plan_title: `Plan for: ${safeTruncate(userPrompt, 80)}`,
        subquestions: [
          { id: 'S1', question: `What are the key definitions and background for ${baseTopic || 'this topic'}?` },
          { id: 'S2', question: `What are the main mechanisms/methods/theories relevant to ${baseTopic || 'this topic'}?` },
          { id: 'S3', question: `What is the empirical evidence or benchmark performance for ${baseTopic || 'this topic'}?` },
          { id: 'S4', question: `How does ${baseTopic || 'this topic'} compare with alternatives, and what trade-offs exist?` },
          { id: 'S5', question: `What are the practical considerations, risks/limitations, and open questions for ${baseTopic || 'this topic'}?` }
        ],
        key_terms: terms,
        success_criteria: 'Comprehensive, quantitative, densely cited synthesis with triangulation'
      };
    }
    log('plan_ready', plan);

    /* Outline */
    const outlineArr = await getDynamicOutline(correlationId, userPrompt);
    log('outline_used', { sections: (outlineArr || []).slice(0, 10) });

    /* Sub-questions */
    const knownEntities = plan.key_terms || [];
    const engines = Array.isArray(routing?.engines) ? routing.engines : [];
    const allClaims = [];
    for (const sq of plan.subquestions) {
      const added = await processSubQuestion(sq.id, sq.question, knownEntities, engines).catch(() => []);
      if (added.length) log('subq_metrics', { subqId: sq.id, added: added.length });
      for (const c of added) allClaims.push(c);
    }

    /* OA Top-up */
    const oaCandidates = Array.from(evidence.docs.values())
      .filter((d) => /pubmed\.ncbi\.nlm\.nih\.gov/i.test(d.url) && !d.text)
      .slice(0, CFG.SELECT_LIMITS.oaTopUpMax);

    await pMap(oaCandidates, 6, async (d) => {
      const got = await fetchPage(d.url, 12000, false);
      if (!got.ok) return;
      d.text = got.text || d.text;
      d.html = got.html || d.html;
      d.ctype = got.ctype || d.ctype;
      d.fetchedAt = nowIso();
      const resolved = await resolveFullTextForDoc(d);
      if (resolved) metrics.oaResolvedCount++;
      if (d.text && !d.doc_card) {
        const card = await buildDocCard(d, 'OA top-up');
        if (card) {
          d.doc_card = card;
          metrics.docCardBuilt++;
        }
        const facts = buildDocFacts(d);
        if (facts?.length) {
          d.facts = facts;
          metrics.docFactsBuilt++;
        }
      }
    });

    /* Sources mapping, themes, evidence matrix */
    planSourceOrder();
    const numberedSources = buildNumberedSources();
    const themes = groupClaimsIntoThemes(allClaims);
    const evidenceMatrixMd = buildEvidenceMatrixMd(numberedSources);

    /* Initial synthesis */
    const rawManuscript = await callSynthesizer(
      userPrompt,
      plan,
      allClaims,
      numberedSources,
      themes,
      evidenceMatrixMd,
      outlineArr
    ).catch(() => '');
    log('synth_ready', { chars: (rawManuscript || '').length });

    /* Depth pass */
    const sourceBriefs = await buildSourceBriefs(numberedSources, Math.min(30, numberedSources.length)).catch(() => ({}));
    let coverageGoals = buildCoverageGoals(numberedSources, allClaims, rawManuscript);

    let polishedManuscript = rawManuscript
      ? await polishForDepth(rawManuscript, numberedSources, sourceBriefs, coverageGoals).catch(() => rawManuscript)
      : '';
    if (!polishedManuscript) polishedManuscript = rawManuscript || 'No evidence-backed synthesis was produced.';
    log('polish_ready', { chars: polishedManuscript.length, coverage: 1 });

    /* Extra expansions for deficit sources */
    function listDeficitSources(goals) {
      const need = [];
      for (const [k, v] of Object.entries(goals)) {
        if (v.wordDeficit > 0 || v.quantDeficit > 0 || v.mentionDeficit > 0) need.push(Number(k));
      }
      return need.sort((a, b) => {
        const A = goals[a],
          B = goals[b];
        return B.wordDeficit + B.quantDeficit * 10 + B.mentionDeficit * 2 - (A.wordDeficit + A.quantDeficit * 10 + A.mentionDeficit * 2);
      });
    }

    coverageGoals = buildCoverageGoals(numberedSources, allClaims, polishedManuscript);
    const deficitList = listDeficitSources(coverageGoals).slice(0, CFG.TIERS.coreCount);

    const capsules = {};
    await pMap(
      deficitList.map((idx) => numberedSources.find((s) => s.index === idx)).filter(Boolean),
      5,
      async (s) => {
        const card = evidence.docs.get(s.url)?.doc_card || {};
        const bestSection =
          /trial|cohort|dataset|benchmark/i.test(card?.methods || '')
            ? 'Evidence & Results (studies, benchmarks, case studies)'
            : /implementation|dose|route|deployment|latency|cost/i.test(
                `${card?.methods} ${card?.delivery?.route} ${card?.delivery?.dose}`
              )
            ? 'Implementation / Deployment / Practical Considerations'
            : 'Mechanisms / Methods / Theory';
        const cap = await generateSourceCapsule(s, bestSection);
        if (cap) capsules[s.index] = cap;
      }
    );

    const triBlocks = await buildTriangulationBlocks(numberedSources, 4).catch(() => '');

    /* Integrate expansions */
    let expandedManuscript = await integrateExpansions(polishedManuscript, capsules, triBlocks, outlineArr).catch(
      () => polishedManuscript
    );
    if (!expandedManuscript) expandedManuscript = polishedManuscript;

    /* Final depth polish */
    const finalBriefs = await buildSourceBriefs(numberedSources, Math.min(22, numberedSources.length)).catch(() => ({}));
    const finalGoals = buildCoverageGoals(numberedSources, allClaims, expandedManuscript);
    const finalPolished = await polishForDepth(expandedManuscript, numberedSources, finalBriefs, finalGoals).catch(
      () => expandedManuscript
    );

    /* Ensure Sources block exists */
    const sourcesBlock = numberedSources.map((s) => `[${s.index}] → ${s.url}`).join('\n');
    const ensureSourcesBlock = (txt) => {
      const hasBlock = /\nSources:\s*\n/i.test(txt || '');
      const base = (txt || '').trim();
      return hasBlock ? base : `${base}\n\nSources:\n${sourcesBlock}`;
    };

    /* Coverage metrics */
    function computeCitationCoverage(txt, mapped) {
      try {
        const used = new Set();
        const pat = /\[(\d+)\]/g;
        let m;
        while ((m = pat.exec(txt || ''))) {
          const n = Number(m[1]);
          if (Number.isFinite(n)) used.add(n);
        }
        const total = mapped.length || 1;
        const inMap = new Set(mapped.map((s) => s.index));
        let inUse = 0;
        for (const n of used) if (inMap.has(n)) inUse++;
        return Math.max(0, Math.min(1, inUse / total));
      } catch {
        return 0;
      }
    }
    function estimateTriangulationRatio(txt) {
      const paras = String(txt || '').split(/\n{2,}/).filter((p) => /\S/.test(p));
      let tri = 0;
      for (const p of paras) {
        const uniq = new Set();
        let m;
        const pat = /\[(\d+)\]/g;
        while ((m = pat.exec(p))) uniq.add(m[1]);
        if (uniq.size >= 2) tri++;
      }
      return paras.length ? tri / paras.length : 0;
    }

    const finalText = ensureSourcesBlock(finalPolished);
    const citationCoverage = computeCitationCoverage(finalText, numberedSources);
    const triangulationRatio = estimateTriangulationRatio(finalText);

    const meta = {
      elapsedMs: Date.now() - startedAt,
      sourcesCount: numberedSources.length,
      citationCoverage,
      triangulationRatio,
      oaResolved: metrics.oaResolvedCount,
      abstractOnly: metrics.abstractOnlyCount,
      blockedPublishers: metrics.blockedPublisherCount,
      docCardBuilt: metrics.docCardBuilt,
      docFactsBuilt: metrics.docFactsBuilt
    };

    log('final_stats', meta);

    /* Return final payload (SSE already emits 'done') */
    return { chatGPTResponse: finalText, sources: numberedSources, meta };
  } catch (err) {
    const message = err?.message || String(err);
    emit('error', { message });
    throw err;
  }
}

/* ####################### Titles fetcher ##########################################################
 * =============================================================================================== */

app.post('/fetch-titles', validateJWT, async (req, res) => {
   
  res.type('application/json');
  initializeUserSession(req);
 console.log('Received /fetch-titles request');
  /* Simple per-session quota */
  req.session.requestCount = req.session.requestCount || 0;
  if (req.session.requestCount >= 30) {
    return res.status(429).json({ error: 'Request limit exceeded. You can only make 30 requests per day.' });
  }

  const past_conversations = Array.isArray(req.body?.past_conversations) ? req.body.past_conversations : [];
  const lastUserMessage = past_conversations.slice().reverse().find((message) => message.role === 'user');

  if (lastUserMessage && lastUserMessage.content.length > 10000) {
    return res.json({ chatGPTResponse: 'Try to shorten your input' });
  }

 
  let apiKey = '';
  try {
    apiKey = resolveApiKey(req);
  } catch (e) {
    return res.status(500).json({ error: e.message || 'API Key not set.' });
  }

 
  const timestamp = new Date().toISOString();
  if (lastUserMessage) {
    const formattedUserContent = lastUserMessage.content.replace(/\n+/g, ' ').trim();
    console.log(`[${timestamp}] Session ID: ${req.session.userId} | User to Title Setter: ${formattedUserContent}`);
  }

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: 'gpt-4.1-nano',
        messages: past_conversations,
        temperature: 0.9,
        max_tokens: 100
      })
    });

    if (response.ok) {
      const data = await response.json();
      const assistantMessage = data?.choices?.[0]?.message;

      const formattedAssistantMessage = assistantMessage
        ? String(assistantMessage.content || '').replace(/\n+/g, ' ').trim()
        : '';
      console.log(`[${timestamp}] Session ID: ${req.session.userId} | Title Setter Response: ${formattedAssistantMessage}`);

      req.session.requestCount++;
      req.session.save?.(() => {
        res.json({ chatGPTResponse: assistantMessage ? (assistantMessage.content || '').trim() : '' });
      });
    } else {
      const errTxt = await response.text().catch(() => '');
      throw new Error(`API request failed with status ${response.status}${errTxt ? `: ${errTxt}` : ''}`);
    }
  } catch (error) {
    console.error(`Error during API call or session save: ${error.message}`);
    res.status(500).json({ error: `Internal Server Error: ${error.message}` });
  }
});



app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
});
