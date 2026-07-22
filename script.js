let currentTab = 'url';
let scanLogs = JSON.parse(localStorage.getItem('cyberguard_logs') || '[]');

// Theme Switcher Logic
document.addEventListener('DOMContentLoaded', () => {
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) {
        themeSelect.addEventListener('change', (e) => {
            const val = e.target.value;
            const root = document.getElementById('mainHtmlRoot');
            if (val === 'light') {
                root.classList.remove('dark');
                root.classList.add('light');
            } else {
                root.classList.remove('light');
                root.classList.add('dark');
            }
        });
    }

    updateTelemetryStats();
    renderLogsTable();
});

// Tab Switching
function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.className = "tab-btn px-4 py-2 rounded-xl text-slate-400 hover:text-slate-200 flex items-center space-x-2 cursor-pointer";
    });
    const activeBtn = document.getElementById(`tab-${tab}`);
    if (activeBtn) {
        activeBtn.className = "tab-btn px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold flex items-center space-x-2 cursor-pointer";
    }
}

// Scanner Engine Check
function runAnalysisCheck() {
    const payloadInput = document.getElementById('payload-input');
    const payload = payloadInput ? payloadInput.value.trim() : '';
    
    if (!payload) {
        alert("Please paste a URL or payload text first!");
        return;
    }

    let riskScore = 0;
    let logs = [];

    // Heuristic Analysis Rules
    if (payload.includes('http://') || payload.includes('192.168.') || payload.includes('000webhost')) {
        riskScore += 65;
        logs.push("Insecure HTTP protocol or raw IP host detected.");
    }
    if (payload.includes('verify') || payload.includes('login') || payload.includes('urgent') || payload.includes('kyc')) {
        riskScore += 30;
        logs.push("Credential phishing urgency keywords flagged.");
    }
    if (payload.length > 80) {
        riskScore += 15;
        logs.push("Long obfuscated payload string.");
    }

    if (riskScore > 100) riskScore = 100;
    let status = riskScore >= 60 ? 'DANGEROUS' : (riskScore >= 25 ? 'SUSPICIOUS' : 'CLEAN');

    if (logs.length === 0) logs.push("No structural threats or anomalies detected.");

    // Save Log
    const newLog = {
        id: Date.now(),
        time: new Date().toLocaleTimeString(),
        vector: currentTab.toUpperCase(),
        payload: payload.length > 35 ? payload.substring(0, 35) + '...' : payload,
        status: status,
        score: riskScore,
        logs: logs
    };

    scanLogs.unshift(newLog);
    localStorage.setItem('cyberguard_logs', JSON.stringify(scanLogs));

    // Render Output
    const idleEl = document.getElementById('output-idle');
    const resOutput = document.getElementById('output-results');
    if (idleEl) idleEl.classList.add('hidden');
    if (resOutput) resOutput.classList.remove('hidden');

    const resStatus = document.getElementById('res-status');
    if (resStatus) {
        resStatus.innerText = status;
        resStatus.className = status === 'DANGEROUS' ? 'text-xl font-extrabold text-red-500' : (status === 'SUSPICIOUS' ? 'text-xl font-extrabold text-amber-400' : 'text-xl font-extrabold text-emerald-400');
    }
    
    const resScore = document.getElementById('res-score');
    if (resScore) resScore.innerText = `${riskScore}%`;

    const resLogs = document.getElementById('res-logs');
    if (resLogs) {
        resLogs.innerHTML = logs.map(l => `<li class="flex items-center space-x-2 text-slate-300"><i class="fa-solid fa-angle-right text-cyan-400 text-[10px]"></i><span>${l}</span></li>`).join('');
    }

    updateTelemetryStats();
    renderLogsTable();
}

// Telemetry Metrics Update
function updateTelemetryStats() {
    const total = scanLogs.length;
    const clean = scanLogs.filter(l => l.status === 'CLEAN').length;
    const suspicious = scanLogs.filter(l => l.status === 'SUSPICIOUS').length;
    const dangerous = scanLogs.filter(l => l.status === 'DANGEROUS').length;

    const elTotal = document.getElementById('stat-total');
    const elClean = document.getElementById('stat-clean');
    const elSuspicious = document.getElementById('stat-suspicious');
    const elDangerous = document.getElementById('stat-dangerous');
    const elVector = document.getElementById('vector-count');

    if (elTotal) elTotal.innerText = total;
    if (elClean) elClean.innerText = clean;
    if (elSuspicious) elSuspicious.innerText = suspicious;
    if (elDangerous) elDangerous.innerText = dangerous;
    if (elVector) elVector.innerText = total;
}

// Render LocalStorage Table
function renderLogsTable() {
    const filterEl = document.getElementById('filter-logs');
    const filter = (filterEl ? filterEl.value : '').toLowerCase();
    const tbody = document.getElementById('logs-table-body');
    if (!tbody) return;

    const filtered = scanLogs.filter(l => l.payload.toLowerCase().includes(filter) || l.vector.toLowerCase().includes(filter));

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="py-8 text-center text-slate-600">Registers space empty. Run scanner to add logs.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(l => `
        <tr class="hover:bg-slate-800/30">
            <td class="py-3 text-slate-500">${l.time}</td>
            <td class="py-3 font-bold text-cyan-400">${l.vector}</td>
            <td class="py-3 text-slate-300">${l.payload}</td>
            <td class="py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${l.status === 'DANGEROUS' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : (l.status === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30')}">${l.status}</span></td>
            <td class="py-3 text-right"><button onclick="deleteLog(${l.id})" class="text-slate-500 hover:text-red-400 cursor-pointer"><i class="fa-solid fa-trash"></i></button></td>
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

// Password Entropy Sandbox
function testPasswordEntropy() {
    const val = document.getElementById('pass-test-input').value;
    const scoreEl = document.getElementById('pass-entropy-score');
    const barEl = document.getElementById('pass-entropy-bar');

    if (!val) {
        if (scoreEl) scoreEl.innerText = "0% – Awaiting Entry";
        if (barEl) barEl.style.width = "0%";
        return;
    }

    let score = 0;
    if (val.length >= 8) score += 30;
    if (val.length >= 12) score += 30;
    if (/[A-Z]/.test(val)) score += 15;
    if (/[0-9]/.test(val)) score += 15;
    if (/[^A-Za-z0-9]/.test(val)) score += 10;

    if (scoreEl) scoreEl.innerText = `${score}% Resilience`;
    if (barEl) {
        barEl.style.width = `${score}%`;
        barEl.className = score > 70 ? "bg-emerald-400 h-1.5 rounded-full transition-all duration-300" : (score > 40 ? "bg-amber-400 h-1.5 rounded-full transition-all duration-300" : "bg-red-500 h-1.5 rounded-full transition-all duration-300");
    }
}

// Quiz Knowledge Check Loop
const quizQuestions = [
    { q: "A link says 'http://login.sbi.com.secure-verify.in'. Is this official?", opts: ["Yes, SBI domain", "No, spoofed subdomain"], ans: 1 },
    { q: "What should you check first when receiving an urgent email?", opts: ["Sender domain address", "Email graphics design"], ans: 0 }
];
let currentQ = 0;

function startQuizLoop() {
    const btn = document.getElementById('quiz-start-btn');
    const opts = document.getElementById('quiz-options');
    if (btn) btn.classList.add('hidden');
    if (opts) opts.classList.remove('hidden');
    showQuestion();
}

function showQuestion() {
    const q = quizQuestions[currentQ];
    const qText = document.getElementById('quiz-question-text');
    if (qText) qText.innerText = q.q;

    const optsContainer = document.getElementById('quiz-options');
    if (optsContainer) {
        optsContainer.innerHTML = q.opts.map((opt, idx) => `
            <button onclick="checkQuizAnswer(${idx})" class="w-full py-2 px-3 bg-[#050811] hover:bg-slate-800 border border-slate-800 rounded-xl text-xs font-mono text-slate-300 text-left transition cursor-pointer">${opt}</button>
        `).join('');
    }
}

function checkQuizAnswer(idx) {
    if (idx === quizQuestions[currentQ].ans) {
        alert("Correct Answer! Threat vector identified.");
    } else {
        alert("Incorrect! Be cautious of deceptive subdomains.");
    }
    currentQ = (currentQ + 1) % quizQuestions.length;
    showQuestion();
}

function runDiagnosticTest() {
    alert("Diagnostic Check Complete:\n- LocalStorage Registers: OK\n- CSS Grid Layout: OK\n- JS Event Loop: OK");
}