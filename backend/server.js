// server.js
// Run: node server.js
// Requires: Node.js v18+ (for global fetch). Install express: npm i express
//
// This server performs real network checks (DNS, TLS, headers, robots, sitemap, HTML analysis)
// No external web APIs are called. The frontend calls /api/audit to request a live audit.

const express = require("express");
const dnsPromises = require("dns").promises;
const tls = require("tls");
const https = require("https");
const http = require("http");
const { URL } = require("url");
const { performance } = require("perf_hooks");
const fs = require("fs");
const axios = require("axios");
const dotenv = require("dotenv");
const path = require("path");

// __dirname is available in CommonJS
dotenv.config({ path: path.join(__dirname, ".env") });

const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(express.static("public")); // serve frontend from ./public

const PORT = process.env.PORT || 3333;

/* ---------- Utilities ---------- */

function safeHost(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.hostname;
  } catch (e) {
    return null;
  }
}

async function dnsLookup(hostname) {
  try {
    const addresses = await dnsPromises.lookup(hostname, { all: true });
    return { ok: true, addresses };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

function tlsInspect(hostname, timeout = 5000) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      servername: hostname,
      port: 443,
      rejectUnauthorized: false,
      timeout
    }, () => {
      try {
        const cert = socket.getPeerCertificate(true) || {};
        const protocol = socket.getProtocol ? socket.getProtocol() : null;
        const cipher = socket.getCipher ? socket.getCipher() : null;
        socket.end();
        resolve({
          ok: true,
          protocol,
          cipher,
          cert: {
            subject: cert.subject || null,
            issuer: cert.issuer || null,
            valid_from: cert.valid_from || null,
            valid_to: cert.valid_to || null
          }
        });
      } catch (e) {
        socket.end();
        resolve({ ok: false, error: String(e) });
      }
    });

    socket.on("error", (err) => resolve({ ok: false, error: String(err) }));
    socket.setTimeout(timeout, () => {
      socket.destroy();
      resolve({ ok: false, error: "TLS timeout" });
    });
  });
}

async function fetchWithTimings(url, opts = {}) {
  // Use Node fetch (v18+). Fallback to https.get if needed.
  const timings = {};
  const t0 = performance.now();
  try {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    return await new Promise((resolve) => {
      const start = performance.now();
      const req = lib.request(u, { method: "GET", headers: { "User-Agent": "LocalSiteAuditor/1.0" } }, (res) => {
        timings.status = res.statusCode;
        timings.headers = res.headers;
        timings.ttfb = performance.now() - start;
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          timings.download = performance.now() - start;
          const body = Buffer.concat(chunks).toString("utf8");
          resolve({ ok: true, body, timings });
        });
      });
      req.on("error", (e) => resolve({ ok: false, error: String(e) }));
      req.setTimeout(15000, () => {
        req.destroy();
        resolve({ ok: false, error: "fetch timeout" });
      });
      req.end();
    });
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function extractMeta(html) {
  const out = {};
  // title
  const mTitle = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (mTitle) out.title = mTitle[1].trim();

  // meta description
  const mDesc = html.match(/<meta[^>]+name=["']description["'][^>]*content=["']([^"']+)["'][^>]*>/i)
    || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]*name=["']description["'][^>]*>/i);
  if (mDesc) out.description = mDesc[1].trim();

  // canonical
  const mCanon = html.match(/<link[^>]+rel=["']canonical["'][^>]*href=["']([^"']+)["'][^>]*>/i);
  if (mCanon) out.canonical = mCanon[1];

  // find link rel=sitemap or robots reference
  const mSitemapLink = html.match(/<link[^>]+rel=["']sitemap["'][^>]*href=["']([^"']+)["'][^>]*>/i);
  if (mSitemapLink) out.sitemapLink = mSitemapLink[1];

  // check for structured data (JSON-LD)
  out.hasJSONLD = /<script[^>]*type=["']application\/ld\+json["'][^>]*>/i.test(html);

  // gather resource references approximation
  const imgs = [...html.matchAll(/<img[^>]+src=["']([^"']+)["']/ig)].map(m=>m[1]);
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/ig)].map(m=>m[1]);
  const links = [...html.matchAll(/<link[^>]+href=["']([^"']+)["']/ig)].map(m=>m[1]);

  out.resources = { images: imgs.length, scripts: scripts.length, links: links.length, resourcesListSample: { imgs: imgs.slice(0,5), scripts: scripts.slice(0,5), links: links.slice(0,5) } };

  return out;
}

function headerSecurityChecks(headers) {
  const issues = [];
  // normalize header keys to lower-case
  const h = {};
  for (const k of Object.keys(headers || {})) h[k.toLowerCase()] = headers[k];

  if (!h['content-security-policy']) issues.push("Missing Content-Security-Policy header");
  if (!h['x-frame-options'] && !(h['content-security-policy'] && /frame-ancestors/i.test(h['content-security-policy']))) issues.push("Missing X-Frame-Options or frame-ancestors directive");
  if (!h['strict-transport-security']) issues.push("Missing HSTS header");
  if (!h['referrer-policy']) issues.push("Missing Referrer-Policy");
  if (!h['permissions-policy'] && !h['feature-policy']) issues.push("Missing Permissions-Policy / Feature-Policy");
  if (!h['x-content-type-options']) issues.push("Missing X-Content-Type-Options (nosniff)");

  return { headers: h, issues };
}

/* ---------- Audit orchestration ---------- */

app.post("/api/audit", async (req, res) => {
  const { url } = req.body ?? {};
  if (!url) return res.status(400).json({ error: "Missing url in body" });

  const hostname = safeHost(url);
  if (!hostname) return res.status(400).json({ error: "Invalid URL" });

  const result = { target: url, generatedAt: new Date().toISOString(), steps: {} };

  // 1) DNS lookup
  result.steps.dns = await dnsLookup(hostname);

  // 2) TLS inspection (if port 443 open)
  result.steps.tls = await tlsInspect(hostname);

  // 3) Fetch root document and measure timings, headers, body
  const page = await fetchWithTimings(url);
  result.steps.fetch = page;

  // 4) Header security checks
  if (page.ok) {
    result.steps.headerSecurity = headerSecurityChecks(page.timings.headers || page.timings);
    // parse HTML for SEO/resource info
    const meta = extractMeta(page.body);
    result.steps.meta = meta;
  } else {
    result.steps.headerSecurity = { headers: {}, issues: ["Could not fetch page"] };
  }

  // 5) robots.txt
  try {
    const robotsUrl = new URL("/robots.txt", url).href;
    const r = await fetchWithTimings(robotsUrl);
    result.steps.robots = r.ok ? { present: true, body: r.body } : { present: false, error: r.error || "not found" };
  } catch (e) {
    result.steps.robots = { present: false, error: String(e) };
  }

  // 6) sitemap guess (robots or standard locations)
  let sitemapInfo = { found: false, locations: [] };
  if (result.steps.robots && result.steps.robots.present && result.steps.robots.body) {
    const sm = result.steps.robots.body.match(/Sitemap:\s*(.+)/i);
    if (sm) sitemapInfo.locations.push(sm[1].trim());
  }
  // try /sitemap.xml
  try {
    const sUrl = new URL("/sitemap.xml", url).href;
    const s = await fetchWithTimings(sUrl);
    if (s.ok && s.body && s.body.length > 20) {
      sitemapInfo.locations.push(sUrl);
      sitemapInfo.found = true;
    }
  } catch(e) {}
  if (result.steps.meta && result.steps.meta.sitemapLink) {
    sitemapInfo.locations.push(result.steps.meta.sitemapLink);
    sitemapInfo.found = true;
  }
  result.steps.sitemap = sitemapInfo;

  // 7) Build summaries & recommendations (local synthesis)
  const findings = [];

  // Security findings from header checks + TLS cert
  const headerIssues = result.steps.headerSecurity?.issues || [];
  if (headerIssues.length) {
    findings.push({
      category: "Security",
      severity: "High",
      summary: `${headerIssues.length} security header issues detected`,
      issues: headerIssues,
      remediation: [
        "Add a strict Content-Security-Policy tailored to the site's inline scripts and resources.",
        "Set X-Frame-Options or use CSP frame-ancestors to prevent clickjacking.",
        "Enable HSTS: set Strict-Transport-Security with long max-age and includeSubDomains.",
        "Set X-Content-Type-Options: nosniff and a strong Referrer-Policy."
      ]
    });
  } else {
    findings.push({
      category: "Security",
      severity: "Low",
      summary: "Security headers present",
      issues: [],
      remediation: ["Maintain headers, consider CSP report-uri if desired"]
    });
  }

  // Performance approximated from fetch timings & resources count
  const meta = result.steps.meta || { resources: { images:0, scripts:0, links:0 } };
  const perfScoreEstimate = Math.max(0, 100 - (meta.resources.scripts * 2 + meta.resources.images + (page.ok ? Math.round((page.timings.download||0)/50) : 30)));
  const perfSeverity = perfScoreEstimate < 50 ? "High" : perfScoreEstimate < 75 ? "Medium" : "Low";
  findings.push({
    category: "Performance & Core Web Vitals (approx)",
    severity: perfSeverity,
    summary: `Estimated performance score ≈ ${perfScoreEstimate}. Resources: scripts=${meta.resources.scripts}, images=${meta.resources.images}`,
    issues: [
      `TTFB ≈ ${page.ok ? Math.round(page.timings.ttfb) + 'ms' : 'unknown'}`,
      `Download time ≈ ${page.ok ? Math.round(page.timings.download) + 'ms' : 'unknown'}`,
      ...(meta.hasJSONLD ? [] : ["No structured data (JSON-LD) detected on page"])
    ],
    remediation: [
      "Compress images and serve modern formats (WebP/AVIF).",
      "Enable Brotli/gzip and set long cache headers for static assets.",
      "Defer non-critical JS and split bundles; use lazy-loading for offscreen images."
    ]
  });

  // SEO
  const seoIssues = [];
  if (!result.steps.robots || !result.steps.robots.present) seoIssues.push("robots.txt missing");
  if (!sitemapInfo.found) seoIssues.push("sitemap.xml not found or not referenced in robots.txt");
  if (!meta.title) seoIssues.push("Missing <title> tag");
  if (!meta.description) seoIssues.push("Missing meta description");
  findings.push({
    category: "SEO",
    severity: seoIssues.length ? "Medium" : "Low",
    summary: seoIssues.length ? `${seoIssues.length} SEO issues` : "Basic SEO present",
    issues: seoIssues,
    remediation: [
      "Add sitemap.xml and reference it from robots.txt and Search Console.",
      "Ensure each page has a unique title and meta description.",
      "Add structured data (JSON-LD) for core entities (Organization, Website, BreadcrumbList)."
    ]
  });

  // Accessibility (basic)
  const a11y = [];
  if (!page.ok) a11y.push("Could not fetch page to run automated accessibility hints");
  else {
    // very basic checks: presence of alt attributes in images sample
    // we only have HTML string; check number of <img> without alt (simple)
    const imgsWithoutAlt = [...page.body.matchAll(/<img\b(?![^>]*\balt=)[^>]*>/ig)].length;
    if (imgsWithoutAlt > 0) a11y.push(`${imgsWithoutAlt} <img> elements missing alt attributes (sample)`);
  }
  findings.push({
    category: "Accessibility",
    severity: a11y.length ? "Medium" : "Low",
    summary: a11y.length ? a11y.join("; ") : "No major automated accessibility issues detected (manual audit recommended)",
    issues: a11y,
    remediation: [
      "Ensure all meaningful images have alt text, use semantic HTML landmarks and ARIA where required.",
      "Check color contrast and keyboard navigation."
    ]
  });

  // DNS & Infra
  const infraIssues = [];
  if (!result.steps.dns.ok) infraIssues.push("DNS lookup failure or issues");
  if (!result.steps.tls.ok) infraIssues.push("TLS inspection failed or site not available on HTTPS");
  findings.push({
    category: "DNS & Infrastructure",
    severity: infraIssues.length ? "High" : "Low",
    summary: infraIssues.length ? infraIssues.join("; ") : "DNS and TLS appear functional",
    issues: infraIssues,
    remediation: [
      "Ensure authoritative nameservers are responsive and that DNS TTLs are appropriate.",
      "Use a CDN for global performance improvements and DDoS protection if needed.",
      "Verify TLS uses modern protocols and ciphers (TLS1.2+/1.3) and enable OCSP stapling."
    ]
  });

  result.findings = findings;
  result.raw = result.steps; // include raw steps

  res.json(result);
});

app.post("/api/explain", async (req, res) => {
  const { auditData, history } = req.body;

  // For follow-up questions, the full auditData might not be sent again.
  // We only need it for the very first message in the conversation.
  if (!auditData && (!history || history.length === 0)) {
    return res.status(400).json({ error: "Missing auditData for initial analysis." });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === "your_gemini_api_key_here") {
    return res.status(500).json({ error: "Gemini API key not configured on the server. Please add it to the .env file." });
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

  let contents = [];

  // If it's the start of a conversation, create the initial system prompt with the full data.
  if (auditData) {
    contents.push({
      role: "user",
      parts: [{
        text: `You are a highly experienced web auditor with 20 years of experience. A site audit was performed and the following raw JSON data was generated. Your role is to act as an expert consultant. Analyze this data and explain the key findings with the authority and depth of a seasoned professional. Focus on the "findings" array to identify the main issues and provide actionable, expert-level recommendations. Start with a high-level executive summary of the most critical issues. Then, for each category (Security, Performance, SEO, Accessibility), provide a detailed analysis of the findings. Your language should be professional and technical, but clear. **Format your response using Markdown for clear structure, including headings, bold text for emphasis, and bullet points for lists.** After your initial analysis, the user might ask follow-up questions. Here is the audit data: ${JSON.stringify(auditData, null, 2)}`
      }]
    });
    // Add the initial "model" response to guide the conversation.
    contents.push({
      role: "model",
      parts: [{ text: "Greetings. I have completed my analysis of the provided website audit. Please let me know which area you would like to discuss first." }]
    });
  }

  // Add the rest of the conversation history for context.
  if (Array.isArray(history)) {
    // If we are not starting a new conversation, append the history.
    if (!auditData) {
       contents = history.map(message => ({
        role: message.role,
        parts: [{ text: message.text }]
      }));
    } else {
      // If we are starting a new conversation, append only the user's follow-up question.
      const lastMessage = history[history.length - 1];
      if (lastMessage) {
        contents.push({
          role: lastMessage.role,
          parts: [{ text: lastMessage.text }]
        });
      }
    }
  }

  try {
    const geminiRequest = { contents };
    const response = await axios.post(url, geminiRequest, {
      headers: { "Content-Type": "application/json" }
    });

    if (response.data.candidates && response.data.candidates.length > 0 && response.data.candidates[0].content) {
      const explanation = response.data.candidates[0].content.parts[0].text;
      res.json({ explanation });
    } else {
      // Check for safety ratings and blocked prompts
      if (response.data.promptFeedback) {
        console.error("Gemini API prompt feedback:", response.data.promptFeedback);
        return res.status(500).json({ error: "The request was blocked by the AI's safety filters.", details: response.data.promptFeedback });
      }
      res.status(500).json({ error: "Failed to get an explanation from the AI.", details: response.data });
    }
  } catch (error) {
    console.error("Error calling Gemini API:", error.response ? JSON.stringify(error.response.data, null, 2) : error.message);
    res.status(500).json({ error: "An error occurred while communicating with the AI assistant." });
  }
});

/* serve a minimal index when root requested */
app.get("/", (req, res) => {
  res.send(`Local Site Auditor server running. Visit / in browser where frontend is served if you copied UI into ./public`);
});

app.listen(PORT, () => {
  console.log(`Local Site Auditor running at http://localhost:${PORT}`);
});
