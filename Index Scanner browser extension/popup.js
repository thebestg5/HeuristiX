// HeuristiX Chrome Extension - Popup Script
// Standalone version - runs scanner locally in JavaScript

// DOM Elements
const currentUrlEl = document.getElementById('currentUrl');
const statusEl = document.getElementById('status');
const resultEl = document.getElementById('result');
const scanBtn = document.getElementById('scanBtn');
const scoreEl = document.getElementById('score');
const verdictEl = document.getElementById('verdict');
const confidenceEl = document.getElementById('confidence');
const threatsListEl = document.getElementById('threatsList');
const autoScanToggle = document.getElementById('autoScanToggle');
const blockDangerousToggle = document.getElementById('blockDangerousToggle');
const exportBtn = document.getElementById('exportBtn');
const blockSiteBtn = document.getElementById('blockSiteBtn');
const scanHistoryEl = document.getElementById('scanHistory');
const fileInput = document.getElementById('fileInput');
const scanFileBtn = document.getElementById('scanFileBtn');
const fileResult = document.getElementById('fileResult');
const startQuizBtn = document.getElementById('startQuizBtn');
const quizArea = document.getElementById('quizArea');

let currentResult = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  await getCurrentUrl();
  await loadSettings();
  await loadScanHistory();
});

// Load settings
async function loadSettings() {
  try {
    const data = await chrome.storage.local.get(['autoScan', 'blockDangerous']);
    autoScanToggle.checked = data.autoScan || false;
    blockDangerousToggle.checked = data.blockDangerous || false;
  } catch (error) {
    console.error('Failed to load settings:', error);
  }
}

// Save settings
async function saveSettings() {
  try {
    await chrome.storage.local.set({ 
      autoScan: autoScanToggle.checked,
      blockDangerous: blockDangerousToggle.checked
    });
  } catch (error) {
    console.error('Failed to save settings:', error);
  }
}

// Auto-scan toggle
autoScanToggle.addEventListener('change', saveSettings);

// Block dangerous toggle
blockDangerousToggle.addEventListener('change', saveSettings);

// Load scan history
async function loadScanHistory() {
  try {
    const data = await chrome.storage.local.get('scanHistory');
    const history = data.scanHistory || [];
    renderScanHistory(history);
  } catch (error) {
    console.error('Failed to load scan history:', error);
  }
}

// Save scan to history
async function saveToHistory(url, result) {
  try {
    const data = await chrome.storage.local.get('scanHistory');
    const history = data.scanHistory || [];
    
    // Add new scan to beginning
    history.unshift({
      url: url,
      timestamp: new Date().toISOString(),
      score: result.risk_score.score,
      verdict: result.risk_score.verdict,
      threatsCount: result.threats_found
    });
    
    // Keep only last 20 scans
    if (history.length > 20) {
      history.pop();
    }
    
    await chrome.storage.local.set({ scanHistory: history });
    renderScanHistory(history);
  } catch (error) {
    console.error('Failed to save to history:', error);
  }
}

// Render scan history
function renderScanHistory(history) {
  if (!history || history.length === 0) {
    scanHistoryEl.innerHTML = '<div class="no-threats" style="padding: 1rem; font-size: 0.8rem;">No scan history</div>';
    return;
  }
  
  scanHistoryEl.innerHTML = history.map(item => {
    const scoreColor = item.score > 70 ? 'var(--low)' : item.score > 50 ? 'var(--medium)' : 'var(--critical)';
    const time = new Date(item.timestamp).toLocaleTimeString();
    const shortUrl = item.url.length > 40 ? item.url.substring(0, 40) + '...' : item.url;
    
    return `
      <div style="padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); font-size: 0.75rem;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span style="color: var(--muted); word-break: break-all;">${shortUrl}</span>
          <span style="color: ${scoreColor}; font-weight: 700; margin-left: 0.5rem;">${item.score}</span>
        </div>
        <div style="color: var(--muted); margin-top: 0.2rem;">${time} • ${item.verdict}</div>
      </div>
    `;
  }).join('');
}

// Export results
exportBtn.addEventListener('click', () => {
  if (!currentResult) {
    alert('No scan results to export');
    return;
  }
  
  const dataStr = JSON.stringify(currentResult, null, 2);
  const dataBlob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(dataBlob);
  
  const link = document.createElement('a');
  link.href = url;
  link.download = `heuristix-scan-${Date.now()}.json`;
  link.click();
  
  URL.revokeObjectURL(url);
});

// Block site button
blockSiteBtn.addEventListener('click', async () => {
  const url = currentUrlEl.textContent;
  if (!url) return;
  
  const score = currentResult.risk_score.score;
  chrome.runtime.sendMessage({
    action: 'blockSite',
    url: url,
    score: score
  });
  
  alert('Site has been blocked');
  blockSiteBtn.style.display = 'none';
});

// Scan file
scanFileBtn.addEventListener('click', async () => {
  const file = fileInput.files[0];
  if (!file) {
    alert('Please select a file to scan');
    return;
  }
  
  fileResult.style.display = 'block';
  fileResult.innerHTML = '<div style="text-align: center; padding: 1rem; color: var(--accent);">Scanning file...</div>';
  
  try {
    const content = await readFileContent(file);
    const threats = MalwareDetector.analyzeContent(content, file.name, '');
    const riskScore = RiskScorer.score(threats);
    
    // Count severity
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    threats.forEach(t => {
      severityCounts[t.severity] = (severityCounts[t.severity] || 0) + 1;
    });
    
    const score = riskScore.score || 0;
    const verdict = riskScore.verdict || '';
    const scolor = score > 70 ? 'var(--low)' : score > 50 ? 'var(--medium)' : 'var(--critical)';
    
    const threatHtml = threats.length ? threats.map(t => {
      const b = t.severity === 'critical' ? 'critical' : t.severity === 'high' ? 'high' : t.severity === 'medium' ? 'medium' : 'low';
      return `
        <div style="padding: 0.5rem; background: var(--bg); border-radius: 0.5rem; margin-bottom: 0.5rem; border: 1px solid var(--border);">
          <span class="threat-severity ${b}">${t.severity.toUpperCase()}</span> <span style="font-weight: 600;">${t.type}</span>
          <div style="font-size: 0.8rem; color: var(--muted); margin-top: 0.2rem;">${t.description}</div>
        </div>
      `;
    }).join('') : '<div class="no-threats">✓ No threats detected</div>';
    
    fileResult.innerHTML = `
      <div style="background: ${scolor}20; border: 1px solid ${scolor}; border-radius: 0.75rem; padding: 1rem; margin-bottom: 1rem; display: flex; align-items: center; gap: 1rem;">
        <div style="font-size: 2rem; font-weight: 800; color: ${scolor};">${score}/100</div>
        <div>
          <div style="font-weight: 700; color: ${scolor};">${verdict}</div>
          <div style="font-size: 0.8rem; color: var(--muted);">File: ${file.name} (${(file.size / 1024).toFixed(1)} KB)</div>
        </div>
      </div>
      <div style="font-size: 0.9rem; font-weight: 600; margin-bottom: 0.5rem; color: var(--muted);">Threats Found (${threats.length})</div>
      ${threatHtml}
    `;
    
  } catch (error) {
    fileResult.innerHTML = `<div style="color: var(--critical); padding: 1rem;">Scan failed: ${error.message}</div>`;
  }
});

function readFileContent(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = (e) => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

// Phishing Quiz
const quizQuestions = [
  {
    question: 'Which of these is a common phishing indicator?',
    options: ['HTTPS in the URL', 'Misspelled domain name', 'Contact page', 'Privacy policy'],
    correct: 1,
    explanation: 'Attackers often use misspelled domain names to impersonate legitimate sites.'
  },
  {
    question: 'What should you do if you receive an email asking for your password?',
    options: ['Reply with the password', 'Click the link to verify', 'Report as phishing', 'Forward to friends'],
    correct: 2,
    explanation: 'Never share your password via email. Always report suspicious emails as phishing.'
  },
  {
    question: 'Which URL looks suspicious?',
    options: ['https://bank.com/login', 'https://bank-secure.com/login', 'https://secure-bank.com/login', 'https://bank.com/secure-login'],
    correct: 1,
    explanation: 'Hyphens in domain names are often used by phishers to impersonate legitimate brands.'
  },
  {
    question: 'What is a common phishing technique using urgency?',
    options: ['Sending a birthday card', 'Claiming account will be deleted', 'Offering a discount', 'Sharing news'],
    correct: 1,
    explanation: 'Attackers create urgency to make you act without thinking, like threatening account deletion.'
  }
];

let currentQuestionIndex = 0;
let quizScore = 0;

startQuizBtn.addEventListener('click', () => {
  currentQuestionIndex = 0;
  quizScore = 0;
  startQuizBtn.style.display = 'none';
  quizArea.style.display = 'block';
  showQuestion();
});

function showQuestion() {
  if (currentQuestionIndex >= quizQuestions.length) {
    showQuizResults();
    return;
  }
  
  const q = quizQuestions[currentQuestionIndex];
  quizArea.innerHTML = `
    <div style="font-weight: 600; margin-bottom: 0.5rem; color: var(--text);">Question ${currentQuestionIndex + 1}/${quizQuestions.length}</div>
    <div style="margin-bottom: 0.75rem; font-size: 0.85rem; color: var(--muted);">${q.question}</div>
    ${q.options.map((opt, i) => `
      <button class="quiz-option" data-index="${i}" style="width: 100%; padding: 0.5rem; margin-bottom: 0.5rem; background: var(--bg); border: 1px solid var(--border); border-radius: 0.5rem; color: var(--text); cursor: pointer; font-size: 0.8rem; text-align: left;">${opt}</button>
    `).join('')}
  `;
  
  quizArea.querySelectorAll('.quiz-option').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const selectedIndex = parseInt(e.target.dataset.index);
      handleAnswer(selectedIndex);
    });
  });
}

function handleAnswer(selectedIndex) {
  const q = quizQuestions[currentQuestionIndex];
  const isCorrect = selectedIndex === q.correct;
  
  if (isCorrect) {
    quizScore++;
  }
  
  quizArea.innerHTML = `
    <div style="padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 0.75rem; background: ${isCorrect ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)'}; border: 1px solid ${isCorrect ? 'var(--low)' : 'var(--critical)'};">
      <div style="font-weight: 700; color: ${isCorrect ? 'var(--low)' : 'var(--critical)'}; margin-bottom: 0.25rem;">${isCorrect ? '✓ Correct!' : '✗ Incorrect'}</div>
      <div style="font-size: 0.8rem; color: var(--muted);">${q.explanation}</div>
    </div>
    <button onclick="nextQuestion()" style="width: 100%; padding: 0.5rem; background: var(--accent); color: #fff; border: none; border-radius: 0.5rem; font-weight: 600; cursor: pointer; font-size: 0.85rem;">Next Question</button>
  `;
}

window.nextQuestion = function() {
  currentQuestionIndex++;
  showQuestion();
};

function showQuizResults() {
  const percentage = Math.round((quizScore / quizQuestions.length) * 100);
  let message = '';
  let color = '';
  
  if (percentage >= 75) {
    message = 'Excellent! You have great phishing awareness.';
    color = 'var(--low)';
  } else if (percentage >= 50) {
    message = 'Good, but there\'s room for improvement.';
    color = 'var(--medium)';
  } else {
    message = 'Keep learning! Phishing awareness is important.';
    color = 'var(--critical)';
  }
  
  quizArea.innerHTML = `
    <div style="text-align: center; padding: 1rem;">
      <div style="font-size: 2rem; font-weight: 800; color: ${color}; margin-bottom: 0.5rem;">${quizScore}/${quizQuestions.length}</div>
      <div style="font-weight: 600; color: var(--text); margin-bottom: 0.75rem;">Quiz Complete!</div>
      <div style="font-size: 0.85rem; color: var(--muted); margin-bottom: 1rem;">${message}</div>
      <button onclick="restartQuiz()" style="padding: 0.5rem 1rem; background: var(--accent); color: #fff; border: none; border-radius: 0.5rem; font-weight: 600; cursor: pointer; font-size: 0.85rem;">Try Again</button>
    </div>
  `;
}

window.restartQuiz = function() {
  startQuizBtn.style.display = 'block';
  quizArea.style.display = 'none';
};

// Get current tab URL
async function getCurrentUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentUrlEl.textContent = tab.url;
    }
  } catch (error) {
    currentUrlEl.textContent = 'Unable to get URL';
  }
}

// Start scan
scanBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    showStatus('error', '❌', 'Unable to get current tab URL');
    return;
  }
  
  await startScan(tab.id, tab.url);
});

// Start scan locally
async function startScan(tabId, url) {
  try {
    showStatus('loading', '⏳', 'Scanning...');
    scanBtn.disabled = true;
    
    // Inject content script if not already loaded
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        files: ['content.js']
      });
    } catch (e) {
      // Script might already be injected, continue
    }
    
    // Wait a moment for script to initialize
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Get page content from content script
    const content = await chrome.tabs.sendMessage(tabId, { action: 'getPageContent' });
    
    if (!content) {
      throw new Error('Failed to get page content');
    }
    
    // Run local scanner
    const result = runLocalScan(content, url);
    
    displayResults(result);
    scanBtn.disabled = false;
    
  } catch (error) {
    showStatus('error', '❌', 'Scan failed: ' + error.message);
    scanBtn.disabled = false;
  }
}

// Run local scanner using ported detection logic
function runLocalScan(content, url) {
  const allThreats = [];
  
  // Analyze page HTML for phishing
  const phishingThreats = PhishingDetector.analyzePage(content.html, url, url);
  allThreats.push(...phishingThreats);
  
  // Analyze inline scripts for malware
  content.scripts.forEach(script => {
    if (script.type === 'inline' && script.content) {
      const malwareThreats = MalwareDetector.analyzeContent(script.content, url, url);
      allThreats.push(...malwareThreats);
    }
  });
  
  // Analyze links
  const linkThreats = SuspiciousLinkDetector.analyzeLinks(content.links, content.html, url, url);
  allThreats.push(...linkThreats);
  
  // Calculate risk score
  const riskScore = RiskScorer.score(allThreats);
  
  // Count severity
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  allThreats.forEach(t => {
    severityCounts[t.severity] = (severityCounts[t.severity] || 0) + 1;
  });
  
  return {
    base_url: url,
    pages_scanned: 1,
    files_scanned: content.scripts.length,
    scripts_scanned: content.scripts.filter(s => s.type === 'inline').length,
    links_checked: content.links.length,
    threats_found: allThreats.length,
    severity_counts: severityCounts,
    threats: allThreats.map(t => t.toDict()),
    risk_score: riskScore
  };
}

// Display scan results
async function displayResults(result) {
  statusEl.style.display = 'none';
  resultEl.classList.add('show');
  currentResult = result;
  
  const riskScore = result.risk_score || {};
  const score = riskScore.score || 0;
  const verdict = riskScore.verdict || 'Unknown';
  const confidence = riskScore.confidence || {};
  
  // Update badge
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      chrome.runtime.sendMessage({
        action: 'updateBadge',
        score: score,
        tabId: tab.id
      });
    }
  } catch (error) {
    console.error('Failed to update badge:', error);
  }
  
  // Set score color
  scoreEl.className = 'score';
  if (score > 70) {
    scoreEl.classList.add('safe');
  } else if (score > 50) {
    scoreEl.classList.add('moderate');
  } else {
    scoreEl.classList.add('dangerous');
  }
  
  // Set verdict color
  verdictEl.className = 'verdict';
  if (score > 70) {
    verdictEl.classList.add('safe');
  } else if (score > 50) {
    verdictEl.classList.add('moderate');
  } else {
    verdictEl.classList.add('dangerous');
  }
  
  scoreEl.textContent = score;
  verdictEl.textContent = verdict;
  confidenceEl.textContent = confidence.label || '';
  
  // Show block button if score is <= 50 (dangerous)
  if (score <= 50) {
    blockSiteBtn.style.display = 'block';
  } else {
    blockSiteBtn.style.display = 'none';
  }
  
  // Display threats
  const threats = result.threats || [];
  if (threats.length === 0) {
    threatsListEl.innerHTML = '<div class="no-threats">✓ No threats detected</div>';
  } else {
    threatsListEl.innerHTML = threats.map(threat => `
      <div class="threat-item">
        <span class="threat-severity ${threat.severity}">${threat.severity.toUpperCase()}</span>
        <span class="threat-type">${threat.type}</span>
        <div class="threat-desc">${threat.description}</div>
      </div>
    `).join('');
  }
  
  // Save to history
  await saveToHistory(currentUrlEl.textContent, result);
}

// Show status message
function showStatus(type, icon, text) {
  statusEl.style.display = 'block';
  resultEl.classList.remove('show');
  statusEl.className = 'status ' + type;
  statusEl.innerHTML = `
    <div class="status-icon">${icon}</div>
    <div class="status-text">${text}</div>
  `;
}
