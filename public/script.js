// script.js (frontend) — calls local backend /api/audit
const form = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const progressWrap = document.getElementById('progressWrap');
const loaderText = document.getElementById('loaderText');
const resultsSection = document.getElementById('results');

window.addEventListener('DOMContentLoaded', () => {
  progressWrap.classList.add('hidden');
  loaderText.textContent = '';
});

function setLoading(on, text) {
  if (on) {
    progressWrap.classList.remove('hidden');
    loaderText.textContent = text || 'Running audit...';
  } else {
    progressWrap.classList.add('hidden');
  }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;
  setLoading(true, 'Starting live audit — DNS lookup...');
  resultsSection.classList.add('hidden');
  try {
    const resp = await fetch('/api/audit', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ url })
    });
    if (!resp.ok) {
      const t = await resp.text();
      setLoading(false);
      alert('Server error: ' + t);
      return;
    }
    setLoading(true, 'Fetching results — synthesizing report...');
    const data = await resp.json();
    setLoading(false);
    renderResults(data);
  } catch (err) {
    setLoading(false);
    alert('Network or server error: ' + err);
  }
});

document.getElementById('clearBtn').addEventListener('click', () => {
  urlInput.value = '';
  resultsSection.classList.add('hidden');
  setLoading(false); // Also hide loader/progress bar
  loaderText.textContent = '';
});

// render helpers
function severityBadge(level) {
  const map = { High: 'high', Medium: 'medium', Low: 'low' };
  return `<span class="badge ${map[level]||'low'}">${level}</span>`;
}

function renderResults(data) {
  document.getElementById('targetDomain').textContent = data.target;
  document.getElementById('timeStamp').textContent = new Date(data.generatedAt).toLocaleString();

  // summary
  const sCard = document.getElementById('synthesisCard');
  sCard.innerHTML = `
    <h3 style="margin:0">${data.target} — Live Audit</h3>
    <div style="color:var(--muted);margin-top:6px">Generated: ${new Date(data.generatedAt).toLocaleString()}</div>
    <div style="margin-top:12px">
      <h4>Top findings</h4>
      <ol>
        ${data.findings.map(f => `<li><strong>${f.category}</strong> ${severityBadge(f.severity)} <div style="color:var(--muted)">${f.summary}</div></li>`).join('')}
      </ol>
    </div>
    <div style="margin-top:10px">
      <button class="btn" id="showRawBtn">Show raw diagnostic JSON</button>
    </div>
  `;

  document.getElementById('showRawBtn').onclick = () => {
    document.querySelector('.tab-btn[data-tab="raw"]').click();
  };

  // details per category
  const securityCard = document.getElementById('securityCard');
  const sec = data.findings.find(f=>f.category==='Security') || {};
  securityCard.innerHTML = `<h3>Security</h3>
    <div style="color:var(--muted);margin-bottom:8px">${sec.summary || '—'}</div>
    ${sec.issues && sec.issues.length ? `<ul>${sec.issues.map(i=>`<li>${i}</li>`).join('')}</ul>` : `<div style="color:var(--muted)">No automatic header issues detected</div>`}
    ${sec.remediation ? `<h4 style="margin-top:8px">Remediation</h4><ul>${sec.remediation.map(r=>`<li>${r}</li>`).join('')}</ul>` : ''}
  `;

  const perfCard = document.getElementById('performanceCard');
  const perf = data.findings.find(f=>f.category && f.category.includes('Performance')) || {};
  perfCard.innerHTML = `<h3>Performance & Core Web Vitals (approx)</h3>
    <div style="color:var(--muted)">${perf.summary || ''}</div>
    ${perf.issues && perf.issues.length ? `<ul>${perf.issues.map(i=>`<li>${i}</li>`).join('')}</ul>` : ''}
    ${perf.remediation ? `<h4>Remediation</h4><ul>${perf.remediation.map(r=>`<li>${r}</li>`).join('')}</ul>` : ''}
  `;

  const seoCard = document.getElementById('seoCard');
  const seo = data.findings.find(f=>f.category==='SEO') || {};
  seoCard.innerHTML = `<h3>SEO</h3><div style="color:var(--muted)">${seo.summary||''}</div>${seo.issues && seo.issues.length ? `<ul>${seo.issues.map(i=>`<li>${i}</li>`).join('')}</ul>` : ''}<h4>Fixes</h4><ul>${seo.remediation.map(r=>`<li>${r}</li>`).join('')}</ul>`;

  const a11yCard = document.getElementById('accessibilityCard');
  const a11y = data.findings.find(f=>f.category==='Accessibility') || {};
  a11yCard.innerHTML = `<h3>Accessibility</h3><div style="color:var(--muted)">${a11y.summary||''}</div>${a11y.remediation ? `<h4>Remediation</h4><ul>${a11y.remediation.map(r=>`<li>${r}</li>`).join('')}</ul>` : ''}`;

  const dnsCard = document.getElementById('dnsCard');
  dnsCard.innerHTML = `<h3>DNS & TLS</h3>
    <div style="color:var(--muted)">
      DNS: ${data.raw.dns.ok ? 'Resolved' : 'Failed'}<br/>
      TLS: ${data.raw.tls.ok ? 'OK' : 'Failed'}
    </div>
    <details style="margin-top:8px"><summary>Raw DNS / TLS details</summary>
      <pre style="background:#020814;padding:10px;border-radius:8px;color:#cfe9ff">${JSON.stringify({dns:data.raw.dns, tls:data.raw.tls},null,2)}</pre>
    </details>
  `;

  // raw JSON
  const raw = document.getElementById('rawJson');
  raw.textContent = JSON.stringify(data, null, 2);
  document.getElementById('downloadBtn').onclick = () => {
    const blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'});
    const u = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = u; a.download = `audit-${data.target.replace(/[:\/]/g,'_')}.json`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(u);
  };

  // enable simple tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.dataset.tab;
      document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
      document.getElementById(tab).classList.add('active');
    };
  });

  resultsSection.classList.remove('hidden');
  document.getElementById('ai').classList.remove('hidden'); // Show AI tab
  initAIChat(data);
}

function initAIChat(auditData) {
  const chatContainer = document.getElementById('chat-container');
  const chatForm = document.getElementById('chat-form');
  const chatInput = document.getElementById('chat-input');
  const chatSendBtn = document.getElementById('chat-send-btn');
  let conversationHistory = [];

  // Clear previous chat
  chatContainer.innerHTML = '';
  chatInput.value = '';
  chatInput.disabled = true;
  chatSendBtn.disabled = true;

  function addMessage(role, text) {
    const messageElem = document.createElement('div');
    messageElem.classList.add('chat-message', role);
    
    // Use a markdown parser to render the response
    if (role === 'assistant') {
        const md = window.markdownit();
        messageElem.innerHTML = md.render(text);
    } else {
        messageElem.textContent = text;
    }
    
    chatContainer.appendChild(messageElem);
    chatContainer.scrollTop = chatContainer.scrollHeight;
    conversationHistory.push({ role, text });
  }

  async function getAIExplanation(initial = false) {
    try {
      const res = await fetch('/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          auditData: initial ? auditData : undefined,
          history: conversationHistory
        })
      });
      if (!res.ok) {
        const err = await res.json();
        addMessage('assistant', `Error: ${err.error}`);
        return;
      }
      const { explanation } = await res.json();
      addMessage('assistant', explanation);
    } catch (err) {
      addMessage('assistant', `Sorry, I couldn't connect to the AI assistant. ${err.message}`);
    } finally {
      chatInput.disabled = false;
      chatSendBtn.disabled = false;
    }
  }

  chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const userMessage = chatInput.value.trim();
    if (!userMessage) return;

    addMessage('user', userMessage);
    chatInput.value = '';
    chatInput.disabled = true;
    chatSendBtn.disabled = true;
    getAIExplanation();
  });

  // Initial welcome message from AI
  addMessage('assistant', 'Analyzing the report with AI...');
  getAIExplanation(true);
}

