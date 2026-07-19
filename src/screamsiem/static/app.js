const $ = id => document.getElementById(id);
let sound = false;
let seen = new Set();
let eventTimes = [];
const pendingActions = new Set();

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[character]));
}

function notify(message, error = false) {
  let toast = $('ui-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'ui-toast';
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.className = error ? 'toast error' : 'toast';
  clearTimeout(toast.hideTimer);
  toast.hideTimer = setTimeout(() => toast.classList.add('hidden'), 2400);
}

async function jsonFetch(url, options) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || body.error || `Request failed (${response.status})`);
  return body;
}

async function loadHostsAndStatus() {
  const [hosts, status] = await Promise.all([
    jsonFetch('/api/hosts'),
    jsonFetch('/api/status')
  ]);
  renderHosts(hosts);
  $('online').textContent = `${hosts.filter(host => host.status === 'online').length} / ${hosts.length}`;
  const ai = status.ai || {};
  $('ai-status').textContent = ai.enabled
    ? `${ai.model} · ${ai.last_result === 'fallback' ? 'fallback' : ai.last_result === 'live' ? 'live' : 'ready'}`
    : 'fallback';
}

async function loadFindings() {
  const findings = await jsonFetch('/api/findings');
  renderFindings(findings);
  $('finding-count').textContent = findings.length;
  $('fleet').textContent = findings.some(finding => finding.severity === 'critical') ? 'CRITICAL' : 'HEALTHY';
}

async function load() {
  await Promise.all([loadHostsAndStatus(), loadFindings()]);
}

function renderHosts(hosts) {
  $('hosts').innerHTML = hosts.length ? `<div class="host-grid">${hosts.map(host => {
    const metrics = host.metrics || {};
    return `<article class="card ${host.status === 'offline' ? 'offline' : ''} ${host.status === 'critical' ? 'critical' : ''}"><h3>${esc(host.name)} <span class="meta">${esc(host.address)}</span></h3><div class="meta">${esc(host.status)} · visibility ${esc(host.visibility)} · MCP ${esc(host.bridge_port || '—')}</div><div class="gauge"><span>Load</span><b>${esc(metrics.load_1 ?? '—')}</b></div><div class="gauge"><span>Memory</span><b>${metrics.memory_total ? Math.round(metrics.memory_used / metrics.memory_total * 100) + '%' : '—'}</b></div><div class="gauge"><span>Processes / listeners</span><b>${esc(metrics.process_count ?? '—')} / ${esc(metrics.listening_sockets ?? '—')}</b></div><div class="gauge"><span>Last seen</span><b>${esc(host.last_seen_at || 'never')}</b></div>${host.last_error ? `<div class="meta">${esc(host.last_error)}</div>` : ''}</article>`;
  }).join('')}</div>` : '<div class="empty">No hosts registered. Use <code>screamsiem host add</code>.</div>';
}

function renderFindings(findings) {
  $('findings').innerHTML = findings.length ? findings.map(finding => {
    const ai = finding.ai_summary || {};
    const advisor = ai.analysis_source === 'gpt-5.6' ? 'GPT-5.6 analysis' : 'Deterministic fallback';
    const actions = (finding.actions || []).map(action => {
      if (action.kind === 'manual_command') {
        return `<div class="action"><b>Model-generated manual action</b><div class="meta">${esc(action.impact)} · risk ${esc(action.risk)}</div><code>${esc(action.manual_command)}</code><button type="button" class="copy-command" data-copy-command="${esc(action.manual_command || '')}">Copy command</button>${action.verification_command ? `<div class="meta">Verify: <code>${esc(action.verification_command)}</code></div>` : ''}</div>`;
      }
      const pending = pendingActions.has(action.id);
      return `<div class="action"><b>Available after approval: ${esc(action.label)}</b><div class="meta">${esc(action.impact)} · risk ${esc(action.risk)}</div><button type="button" class="danger approve-action" data-action-id="${esc(action.id)}" ${pending ? 'disabled' : ''}>${pending ? 'Approving…' : 'Approve exact action'}</button></div>`;
    }).join('');

  const evidence = (ai.observations || []).map(observation => `<li>${esc(observation.text)} <span class="meta">${esc((observation.evidence_ids || []).join(', '))}</span></li>`).join('');
  return `<article class="card ${esc(finding.severity)}"><h3>${esc(finding.severity.toUpperCase())} — ${esc(finding.title)}</h3><div>${esc(finding.machine_summary)}</div><div class="meta">${esc(advisor)} · ${esc(ai.plain_english_summary || 'Investigation pending…')} · confidence ${Math.round((ai.confidence ?? finding.confidence) * 100)}%</div>${evidence ? `<div class="evidence"><b>Evidence</b><ul>${evidence}</ul></div>` : ''}${actions}<div class="evidence">Detector: ${esc(finding.detector_id)} · occurrences ${esc(finding.count)} · updated ${esc(finding.updated_at)}</div></article>`;
  }).join('') : '<div class="empty">No findings. The fleet is quiet.</div>';

  const critical = findings.find(finding => finding.severity === 'critical');
  if (critical) {
    $('critical-banner').classList.remove('hidden');
    $('critical-text').textContent = critical.title;
    document.title = '⚠ CRITICAL · ScreamSIEM';
    if (!seen.has(critical.id) && sound) {
      try {
        const audio = new AudioContext();
        const oscillator = audio.createOscillator();
        oscillator.connect(audio.destination);
        oscillator.start();
        oscillator.stop(audio.currentTime + .12);
      } catch (error) { /* Audio is optional. */ }
    }
    seen.add(critical.id);
  } else {
    $('critical-banner').classList.add('hidden');
    document.title = 'ScreamSIEM';
  }
}

async function copyCommand(button) {
  const command = button.dataset.copyCommand || '';
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(command);
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = command;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      if (!document.execCommand('copy')) throw new Error('clipboard permission denied');
      textarea.remove();
    }
    button.textContent = 'Copied';
    notify('Command copied to clipboard');
    setTimeout(() => { if (button.isConnected) button.textContent = 'Copy command'; }, 1800);
  } catch (error) {
    notify(`Could not copy command: ${error.message}`, true);
  }
}

async function approveAction(button) {
  const id = button.dataset.actionId;
  if (!id || pendingActions.has(id)) return;
  pendingActions.add(id);
  button.disabled = true;
  button.textContent = 'Approving…';
  try {
    const result = await jsonFetch(`/api/actions/${encodeURIComponent(id)}/approve`, {
      method: 'POST',
      headers: { 'X-CSRF-Token': window.SCREAMSIEM.csrf }
    });
    notify(result.state === 'executed' ? 'Action approved and executed' : `Action ${result.state}`);
    await Promise.all([loadFindings(), loadHostsAndStatus()]);
  } catch (error) {
    button.disabled = false;
    button.textContent = 'Approve exact action';
    notify(`Approval failed: ${error.message}`, true);
  } finally {
    pendingActions.delete(id);
  }
}

document.addEventListener('click', event => {
  const copy = event.target.closest('.copy-command');
  if (copy) {
    event.preventDefault();
    copyCommand(copy);
    return;
  }
  const approve = event.target.closest('.approve-action');
  if (approve) {
    event.preventDefault();
    approveAction(approve);
  }
});

function connect() {
  const events = new EventSource('/api/stream');
  events.onopen = () => { $('live').textContent = 'LIVE · SSE'; };
  events.onmessage = message => {
    const value = JSON.parse(message.data);
    if (value.kind === 'event') {
      eventTimes.push(Date.now());
      eventTimes = eventTimes.filter(time => Date.now() - time < 60000);
      $('event-rate').textContent = eventTimes.length;
    }
    // Do not replace the findings DOM for every telemetry event. This keeps
    // command buttons stable while an operator is reading or copying them.
    if (value.kind === 'finding') {
      loadFindings().catch(error => notify(`Refresh failed: ${error.message}`, true));
      loadHostsAndStatus().catch(error => notify(`Refresh failed: ${error.message}`, true));
    } else if (value.kind === 'metric') {
      loadHostsAndStatus().catch(error => notify(`Refresh failed: ${error.message}`, true));
    }
  };
  events.onerror = () => {
    $('live').textContent = 'RECONNECTING';
    events.close();
    setTimeout(connect, 3000);
  };
}

$('refresh').onclick = () => load().catch(error => notify(`Refresh failed: ${error.message}`, true));
$('sound').onclick = () => { sound = true; $('sound').textContent = 'Sound enabled'; };
load().catch(error => notify(`Initial load failed: ${error.message}`, true));
connect();
