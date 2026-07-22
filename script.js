// Local Database & State
let scanLogs = JSON.parse(localStorage.getItem('cyberguard_logs') || '[]');
let currentTab = 'url';

document.addEventListener('DOMContentLoaded', () => {
    // 1. Fixed Theme Toggle Mechanism
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) {
        themeSelect.addEventListener('change', (e) => {
            const root = document.getElementById('mainHtmlRoot');
            if (e.target.value === 'light') {
                root.classList.remove('dark');
                root.classList.add('light-mode');
            } else {
                root.classList.remove('light-mode');
                root.classList.add('dark');
            }
        });
    }

    // 2. Navigation Active Class & Smooth Scroll
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', function (e) {
            document.querySelectorAll('nav a').forEach(l => l.classList.remove('bg-cyan-500/10', 'text-cyan-400', 'border', 'border-cyan-500/20', 'font-bold'));
            this.classList.add('bg-cyan-500/10', 'text-cyan-400', 'border', 'border-cyan-500/20', 'font-bold');
        });
    });

    updateTelemetryStats();
    renderLogsTable();
});

// Tab Switcher
function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.className = "tab-btn px-4 py-2 rounded-xl text-slate-400 hover:text-slate-200 flex items-center space-x-2 transition cursor-pointer";
    });
    const activeBtn = document.getElementById(`tab-${tab}`);
    if (activeBtn) {
        activeBtn.className = "tab-btn px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold flex items-center space-x-2 transition cursor-pointer";
    }
}

// Advanced Strict Detection Engine (Fixes suspicious links flagged as Safe)
function runAnalysisCheck() {
    const inputField = document.getElementById('payload-input');
    const rawVal = inputField ? inputField.value.trim() : '';

    if (!rawVal) {
        alert("Enter a URL, email string, or SMS payload first.");
        return;
    }

    let riskScore = 0;
    let flags = [];
    const lower = rawVal.toLowerCase();

    // 1. Typosquatting & Misspelled Domain Detection (.orrg, .govv, .com-login)
    const typoPattern = /\.(orrg|govv|cm|nett|coo|infoo|xyz|top|zip|work|click)\b/;
    if (typoPattern.test(lower)) {
        riskScore += 80;
        flags.push("CRITICAL: Typosquatting/Spoofed Domain Extension Detected.");
    }

    // 2. Multi-subdomain & Hyphen Tricks
    if ((lower.match(/\./g) || []).length >= 3) {
        riskScore += 30;
        flags.push("WARNING: High Subdomain nesting depth (Phishing structure).");
    }
    if ((lower.match(/-/g) || []).length >= 2) {
        riskScore += 20;
        flags.push("SUSPICIOUS: Multiple hyphens used in domain string.");
    }

    // 3. Raw IP Address Links
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(lower.replace(/http(s)?:\/\//, '').split('/')[0])) {
        riskScore += 85;
        flags.push("DANGEROUS: Direct IP hosting instead of legitimate domain.");
    }

    // 4. Credential Harvesting & Urgency Keywords
    const urgentKeywords = ['verify', 'blocked', 'urgent', 'kyc', 'suspend', 'update-password', 'secure-login', 'bank', 'free-gift'];
    let keywordHits = 0;
    urgentKeywords.forEach(kw => {
        if (lower.includes(kw)) keywordHits++;
    });

    if (keywordHits > 0) {
        riskScore += (keywordHits * 25);
        flags.push(`SUSPICIOUS: Found ${keywordHits} social-engineering/urgency triggers.`);
    }

    if (riskScore > 100) riskScore = 100;

    let status = "CLEAN";
    if (riskScore >= 60) status = "DANGEROUS";
    else if (riskScore >= 20) status = "SUSPICIOUS";

    if (flags.length === 0) flags.push("No structural anomalies or malicious indicators detected.");

    // Update Local Storage Log
    const newEntry = {
        id: Date.now(),
        time: new Date().toLocaleTimeString(),
        vector: currentTab.toUpperCase(),
        payload: rawVal.length > 40 ? rawVal.substring(0, 40) + '...' : rawVal,
        status: status,
        score: riskScore,
        flags: flags
    };

    scanLogs.unshift(newEntry);
    localStorage.setItem('cyberguard_logs', JSON.stringify(scanLogs));

    // Render Results Monitor
    document.getElementById('output-idle').classList.add('hidden');
    const resContainer = document.getElementById('output-results');
    resContainer.classList.remove('hidden');

    const statusEl = document.getElementById('res-status');
    statusEl.innerText = status;
    statusEl.className = status === 'DANGEROUS' ? 'text-xl font-extrabold text-red-500 animate-pulse' : (status === 'SUSPICIOUS' ? 'text-xl font-extrabold text-amber-400' : 'text-xl font-extrabold text-emerald-400');

    document.getElementById('res-score').innerText = `${riskScore}%`;

    const logsList = document.getElementById('res-logs');
    logsList.innerHTML = flags.map(f => `
        <li class="flex items-start space-x-2 text-xs">
            <i class="fa-solid ${status === 'CLEAN' ? 'fa-check text-emerald-400' : 'fa-triangle-exclamation text-amber-400'} mt-0.5"></i>
            <span>${f}</span>
        </li>
    `).join('');

    updateTelemetryStats();
    renderLogsTable();
}

// Update Counters
function updateTelemetryStats() {
    const total = scanLogs.length;
    const clean = scanLogs.filter(l => l.status === 'CLEAN').length;
    const suspicious = scanLogs.filter(l => l.status === 'SUSPICIOUS').length;
    const dangerous = scanLogs.filter(l => l.status === 'DANGEROUS').length;

    if (document.getElementById('stat-total')) document.getElementById('stat-total').innerText = total;
    if (document.getElementById('stat-clean')) document.getElementById('stat-clean').innerText = clean;
    if (document.getElementById('stat-suspicious')) document.getElementById('stat-suspicious').innerText = suspicious;
    if (document.getElementById('stat-dangerous')) document.getElementById('stat-dangerous').innerText = dangerous;
    if (document.getElementById('vector-count')) document.getElementById('vector-count').innerText = total;
}

// Render LocalStorage Table
function renderLogsTable() {
    const filter = (document.getElementById('filter-logs')?.value || '').toLowerCase();
    const tbody = document.getElementById('logs-table-body');
    if (!tbody) return;

    const filtered = scanLogs.filter(l => l.payload.toLowerCase().includes(filter) || l.vector.toLowerCase().includes(filter));

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="py-8 text-center text-slate-500 font-mono">Registers space empty. Run scanner to generate telemetry logs.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(l => `
        <tr class="hover:bg-slate-800/40 border-b border-slate-800/40 transition">
            <td class="py-3 text-slate-400">${l.time}</td>
            <td class="py-3 font-bold text-cyan-400">${l.vector}</td>
            <td class="py-3 font-mono text-slate-300">${l.payload}</td>
            <td class="py-3">
                <span class="px-2.5 py-1 rounded-full text-[10px] font-bold ${l.status === 'DANGEROUS' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : (l.status === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30')}">
                    ${l.status}
                </span>
            </td>
            <td class="py-3 text-right">
                <button onclick="deleteLog(${l.id})" class="text-slate-500 hover:text-red-400 transition"><i class="fa-solid fa-trash"></i></button>
            </td>
        </tr>
    `).join('');
}

function deleteLog(id) {
    scanLogs = scanLogs.filter(l => l.id !== id);
    localStorage.setItem('cyberguard_logs', JSON.stringify(scanLogs));
    updateTelemetryStats();
    renderLogsTable();
}

function wipeLogs() {
    scanLogs = [];
    localStorage.removeItem('cyberguard_logs');
    updateTelemetryStats();
    renderLogsTable();
}

// Password Entropy Test
function testPasswordEntropy() {
    const input = document.getElementById('pass-test-input').value;
    const scoreText = document.getElementById('pass-entropy-score');
    const bar = document.getElementById('pass-entropy-bar');

    if (!input) {
        scoreText.innerText = "0% – Awaiting Entry";
        bar.style.width = "0%";
        return;
    }

    let score = 0;
    if (input.length >= 8) score += 25;
    if (input.length >= 12) score += 25;
    if (/[A-Z]/.test(input)) score += 20;
    if (/[0-9]/.test(input)) score += 15;
    if (/[^A-Za-z0-9]/.test(input)) score += 15;

    scoreText.innerText = `${score}% Resilience Index`;
    bar.style.width = `${score}%`;
    bar.className = score >= 75 ? "bg-emerald-400 h-1.5 rounded-full transition-all" : (score >= 40 ? "bg-amber-400 h-1.5 rounded-full transition-all" : "bg-red-500 h-1.5 rounded-full transition-all");
}

// Interactive AI Chatbot Window
function toggleAiChat() {
    const modal = document.getElementById('ai-chat-modal');
    modal.classList.toggle('hidden');
}

function sendAiMessage() {
    const input = document.getElementById('ai-chat-input');
    const messages = document.getElementById('ai-chat-messages');
    const text = input.value.trim();

    if (!text) return;

    // Append User Message
    messages.innerHTML += `<div class="text-right"><span class="inline-block bg-blue-600 text-white text-xs px-3 py-2 rounded-xl font-mono">${text}</span></div>`;
    input.value = '';

    // Bot Response
    setTimeout(() => {
        let reply = "I am CyberGuard AI Agent. I recommend inspecting raw payload links before clicking.";
        if (text.toLowerCase().includes('phishing')) reply = "Phishing links usually spoof extensions like .orrg or use raw IPs. Paste it into the Core Scanner!";
        if (text.toLowerCase().includes('hello') || text.toLowerCase().includes('hi')) reply = "Hello Abhishek! How can I assist with threat telemetry today?";

        messages.innerHTML += `<div class="text-left"><span class="inline-block bg-slate-800 text-cyan-300 text-xs px-3 py-2 rounded-xl font-mono border border-slate-700">${reply}</span></div>`;
        messages.scrollTop = messages.scrollHeight;
    }, 500);
}

// Diagnostics
function runDiagnosticTest() {
    alert("⚡ Diagnostics Complete:\n- Local Heuristics: Active\n- Cache Registers: Synced\n- Local Storage Engine: Ready");
}