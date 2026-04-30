// HeuristiX Scanner - Ported to JavaScript
// Implements the same detection logic as the Python version

class Threat {
  constructor(type, severity, file, line, description, evidence = '') {
    this.type = type;
    this.severity = severity;
    this.file = file;
    this.line = line;
    this.description = description;
    this.evidence = evidence;
  }
  
  toDict() {
    return {
      type: this.type,
      severity: this.severity,
      file: this.file,
      line: this.line,
      description: this.description,
      evidence: this.evidence
    };
  }
}

class RiskScorer {
  static SEVERITY_PENALTY = {
    critical: 15,
    high: 10,
    medium: 5,
    low: 2
  };
  
  static CATEGORY_MULTIPLIER = {
    known_malware: 1.5,
    credential_harvesting: 1.5,
    malicious_domain: 1.4,
    brand_impersonation: 1.3,
    phishing: 1.3,
    obfuscated_js: 1.2,
    forced_redirect: 1.2,
    suspicious_tld: 1.1,
    suspicious_link: 1.0,
    url_obfuscation: 1.0,
    other: 1.0
  };
  
  static CATEGORY_MAP = {
    'Known Malware': 'known_malware',
    'Malicious Script': 'known_malware',
    'Malicious Domain Reference': 'malicious_domain',
    'Malicious Domain': 'malicious_domain',
    'Brand Impersonation': 'brand_impersonation',
    'Credential Harvesting Form': 'credential_harvesting',
    'Cross-Domain Form Action': 'phishing',
    'Phishing Indicator': 'phishing',
    'Link Mismatch / Phishing': 'phishing',
    'Suspicious TLD': 'suspicious_tld',
    'Suspicious Link Keyword': 'suspicious_link',
    'URL Shortener': 'suspicious_link',
    'URL Obfuscation': 'url_obfuscation'
  };
  
  static DESCRIPTION_MAP = {
    'Forced redirect': 'forced_redirect',
    'Obfuscated Payload': 'obfuscated_js',
    'Base64 decoding (possible obfuscation)': 'obfuscated_js',
    'Hex escaped characters': 'obfuscated_js',
    'Unicode escaped characters': 'obfuscated_js',
    'Obfuscated eval via Function constructor': 'obfuscated_js',
    'String reversal obfuscation': 'obfuscated_js',
    'ActiveX exploitation': 'known_malware'
  };
  
  static score(threats) {
    let score = 100;
    const categoryData = {};
    let unmapped = 0;
    
    threats.forEach(t => {
      let cat = this.CATEGORY_MAP[t.type];
      if (!cat) {
        cat = this.DESCRIPTION_MAP[t.description];
      }
      if (!cat) {
        cat = 'other';
        unmapped++;
      }
      
      if (!categoryData[cat]) {
        categoryData[cat] = {};
      }
      const sev = t.severity in this.SEVERITY_PENALTY ? t.severity : 'low';
      categoryData[cat][sev] = (categoryData[cat][sev] || 0) + 1;
    });
    
    const breakdown = {};
    for (const [cat, sevCounts] of Object.entries(categoryData)) {
      const multiplier = this.CATEGORY_MULTIPLIER[cat] || 1.0;
      let catPenalty = 0;
      for (const [sev, count] of Object.entries(sevCounts)) {
        const base = this.SEVERITY_PENALTY[sev] || 2;
        catPenalty += Math.round(base * count * multiplier);
      }
      if (catPenalty > 0) {
        breakdown[cat] = { counts: sevCounts, multiplier: multiplier, points: -catPenalty };
        score -= catPenalty;
      }
    }
    
    score = Math.max(score, 0);
    
    let verdict = '';
    if (score > 70) verdict = 'Safe';
    else if (score > 50) verdict = 'Moderate Risk';
    else if (score > 25) verdict = 'High Risk';
    else if (score > 0) verdict = 'Very Dangerous';
    else verdict = 'Dangerous Phishing Site';
    
    // Confidence calculation
    const behavioralCategories = new Set([
      'forced_redirect', 'obfuscated_js', 'credential_harvesting',
      'brand_impersonation', 'phishing', 'malicious_domain', 'known_malware'
    ]);
    const triggeredBehavioral = Object.keys(categoryData).filter(cat => behavioralCategories.has(cat)).length;
    
    let confidence = 0;
    let confidenceLabel = 'No behavioral flags detected';
    if (triggeredBehavioral === 1) {
      confidence = 40;
      confidenceLabel = 'Low Probability of Malice';
    } else if (triggeredBehavioral === 2) {
      confidence = 70;
      confidenceLabel = 'Moderate Probability of Malice';
    } else if (triggeredBehavioral >= 3) {
      confidence = 95 + Math.min(triggeredBehavioral - 3, 4);
      confidenceLabel = 'High Probability of Malice';
    }
    
    return {
      score: score,
      verdict: verdict,
      breakdown: breakdown,
      max_score: 100,
      confidence: {
        score: confidence,
        label: confidenceLabel,
        behavioral_flags_triggered: triggeredBehavioral
      }
    };
  }
}

class MalwareDetector {
  static JS_MALWARE_PATTERNS = [
    [/new\s+ActiveXObject/i, 'ActiveX exploitation', 'critical'],
    [/WScript\.Shell/i, 'Windows script host exploitation', 'critical'],
    [/Shell\.Application/i, 'Shell application exploitation', 'critical'],
    [/crypto\.[a-zA-Z]+\.(mine|hash)/i, 'Cryptocurrency mining', 'critical'],
    [/CoinHive|coinhive|CryptoLoot|webminer/i, 'Known crypto miner library', 'critical'],
    [/miner\.(start|stop|init)/i, 'Crypto miner control', 'critical'],
    [/document\.write\s*\(\s*<iframe/i, 'Hidden iframe injection', 'high'],
    [/<iframe[^>]*width\s*=\s*["\']?0/i, 'Zero-width iframe (hidden content)', 'high'],
    [/<iframe[^>]*height\s*=\s*["\']?0/i, 'Zero-height iframe (hidden content)', 'high'],
    [/<iframe[^>]*style\s*=\s*["\'][^"\']*display\s*:\s*none/i, 'Hidden iframe via CSS', 'high'],
    [/document\.cookie\s*=/i, 'Cookie manipulation', 'high'],
    [/\.addEventListener\s*\(\s*["\']keydown/i, 'Keylogger detected', 'critical'],
    [/\.addEventListener\s*\(\s*["\']keypress/i, 'Keylogger detected', 'critical'],
    [/\.addEventListener\s*\(\s*["\']keyup/i, 'Keylogger detected', 'critical'],
    [/onkeydown\s*=/i, 'Inline keylogger event', 'critical'],
    [/onkeypress\s*=/i, 'Inline keylogger event', 'critical'],
    [/onkeyup\s*=/i, 'Inline keylogger event', 'critical'],
    [/XMLHttpRequest/i, 'AJAX request (potential data exfiltration)', 'medium'],
    [/fetch\s*\(/i, 'Fetch API (potential data exfiltration)', 'medium'],
    [/navigator\.sendBeacon/i, 'Beacon API (potential data exfiltration)', 'medium'],
    [/window\.location\s*=\s*["\']javascript:/i, 'JavaScript protocol injection', 'high'],
    [/location\.href\s*=\s*["\']javascript:/i, 'JavaScript protocol injection', 'high'],
    [/data:text\/html/i, 'Data URL injection', 'high'],
    [/data:application\/javascript/i, 'Data URL JavaScript injection', 'high'],
    [/fromCharCode/i, 'Character code obfuscation', 'medium'],
    [/charCodeAt/i, 'Character code extraction', 'medium'],
    [/String\.fromCharCode/i, 'String from character codes', 'medium'],
    [/innerHTML\s*=/i, 'innerHTML assignment (XSS risk)', 'medium'],
    [/outerHTML\s*=/i, 'outerHTML assignment (XSS risk)', 'high'],
    [/document\.write\s*\(/i, 'document.write (XSS risk)', 'medium'],
    [/document\.writeln\s*\(/i, 'document.writeln (XSS risk)', 'medium'],
    [/\.exec\s*\(/i, 'Command execution attempt', 'critical'],
    [/\.spawn\s*\(/i, 'Process spawn attempt', 'critical'],
    [/child_process/i, 'Node.js child process (server-side)', 'critical'],
    [/require\s*\(\s*["\']child_process/i, 'Node.js child process import', 'critical'],
    [/require\s*\(\s*["\']fs/i, 'Node.js filesystem access', 'critical'],
    [/require\s*\(\s*["\']net/i, 'Node.js network access', 'critical'],
    [/require\s*\(\s*["\']http/i, 'Node.js HTTP module', 'critical'],
    [/require\s*\(\s*["\']https/i, 'Node.js HTTPS module', 'critical'],
    [/system\s*\(/i, 'System command execution', 'critical'],
    [/exec\s*\(/i, 'Command execution', 'critical'],
    [/passthru\s*\(/i, 'Command execution', 'critical'],
    [/shell_exec\s*\(/i, 'Command execution', 'critical'],
    [/backticks|`[^`]+`/, 'Shell command execution', 'critical']
  ];

  static SECRET_PATTERNS = [
    // AWS Keys
    [/AKIA[0-9A-Z]{16}/i, 'AWS Access Key ID', 'critical'],
    [/aws_access_key_id\s*=\s*["\']?[A-Z0-9]{20}/i, 'AWS Access Key', 'critical'],
    [/aws_secret_access_key\s*=\s*["\']?[A-Za-z0-9\/+=]{40}/i, 'AWS Secret Key', 'critical'],
    // Google API Keys
    [/AIza[0-9A-Za-z\-_]{35}/, 'Google API Key', 'critical'],
    [/ya29\.[0-9A-Za-z\-_]{100,}/, 'Google OAuth Token', 'critical'],
    // Stripe Keys
    [/sk_live_[0-9a-zA-Z]{24}/, 'Stripe Live Secret Key', 'critical'],
    [/sk_test_[0-9a-zA-Z]{24}/, 'Stripe Test Secret Key', 'high'],
    [/pk_live_[0-9a-zA-Z]{24}/, 'Stripe Live Publishable Key', 'high'],
    // GitHub Tokens
    [/ghp_[a-zA-Z0-9]{36}/, 'GitHub Personal Access Token', 'critical'],
    [/gho_[a-zA-Z0-9]{36}/, 'GitHub OAuth Token', 'critical'],
    [/ghu_[a-zA-Z0-9]{36}/, 'GitHub User Token', 'critical'],
    [/ghs_[a-zA-Z0-9]{36}/, 'GitHub Server Token', 'critical'],
    [/ghr_[a-zA-Z0-9]{36}/, 'GitHub Refresh Token', 'critical'],
    // Slack Tokens
    [/xoxb-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/, 'Slack Bot Token', 'critical'],
    [/xoxp-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/, 'Slack User Token', 'critical'],
    // Database Connection Strings
    [/mongodb:\/\/[^\s"']+/i, 'MongoDB Connection String', 'critical'],
    [/mysql:\/\/[^\s"']+/i, 'MySQL Connection String', 'critical'],
    [/postgresql:\/\/[^\s"']+/i, 'PostgreSQL Connection String', 'critical'],
    [/redis:\/\/[^\s"']+/i, 'Redis Connection String', 'critical'],
    // JWT Tokens
    [/eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/, 'JWT Token', 'high'],
    // SSH Keys
    [/-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, 'SSH Private Key', 'critical'],
    [/-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/, 'OpenSSH Private Key', 'critical'],
    [/-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/, 'EC Private Key', 'critical'],
    // API Keys (generic patterns)
    [/api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{32,}/i, 'Generic API Key', 'high'],
    [/secret[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{32,}/i, 'Secret Key', 'critical'],
    [/private[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{32,}/i, 'Private Key', 'critical'],
    [/access[_-]?token\s*[:=]\s*["\']?[a-zA-Z0-9]{32,}/i, 'Access Token', 'high'],
    [/refresh[_-]?token\s*[:=]\s*["\']?[a-zA-Z0-9]{32,}/i, 'Refresh Token', 'high'],
    // Passwords in code
    [/password\s*[:=]\s*["\'][^"\']{8,}/i, 'Hardcoded password', 'critical'],
    [/passwd\s*[:=]\s*["\'][^"\']{8,}/i, 'Hardcoded password', 'critical'],
    [/pwd\s*[:=]\s*["\'][^"\']{8,}/i, 'Hardcoded password', 'critical'],
    // Base64 encoded secrets (likely)
    [/[A-Za-z0-9+/]{40,}={0,2}/, 'Possible Base64 encoded secret', 'medium']
  ];

  static WASM_PATTERNS = [
    [/WebAssembly\.instantiate/i, 'WebAssembly instantiation', 'medium'],
    [/WebAssembly\.instantiateStreaming/i, 'WebAssembly streaming instantiation', 'medium'],
    [/new\s+WebAssembly/i, 'WebAssembly object creation', 'medium'],
    [/\.wasm/i, 'WebAssembly binary file reference', 'medium'],
    [/WebAssembly\.Memory/i, 'WebAssembly memory allocation', 'low'],
    [/WebAssembly\.Table/i, 'WebAssembly table usage', 'low'],
    [/WebAssembly\.Instance/i, 'WebAssembly instance', 'low'],
    [/WebAssembly\.Module/i, 'WebAssembly module', 'low'],
    [/WebAssembly\.compile/i, 'WebAssembly compilation', 'medium'],
    [/atob\([^)]*wasm/i, 'Base64-encoded WASM (obfuscated)', 'high'],
    [/Uint8Array.*wasm/i, 'WASM byte array loading', 'medium'],
    [/fetch.*\.wasm/i, 'WASM file fetch', 'medium'],
    [/\.wasm\?/i, 'WASM file with query parameters (suspicious)', 'high']
  ];

  static FINGERPRINTING_PATTERNS = [
    // Canvas fingerprinting
    [/canvas\.getContext\s*\(\s*['"]2d/i, 'Canvas API access (potential fingerprinting)', 'medium'],
    [/toDataURL\s*\(/i, 'Canvas toDataURL (fingerprinting technique)', 'medium'],
    [/getImageData\s*\(/i, 'Canvas getImageData (fingerprinting technique)', 'medium'],
    // WebGL fingerprinting
    [/webgl|WebGL/i, 'WebGL API access (potential fingerprinting)', 'medium'],
    [/getExtension\s*\(/i, 'WebGL extension query (fingerprinting)', 'medium'],
    [/getParameter\s*\(/i, 'WebGL parameter query (fingerprinting)', 'medium'],
    // Audio fingerprinting
    [/AudioContext|webkitAudioContext/i, 'Audio Context API (potential fingerprinting)', 'medium'],
    [/createOscillator|createAnalyser/i, 'Audio API for fingerprinting', 'medium'],
    // Font fingerprinting
    [/document\.fonts/i, 'Font API access (potential fingerprinting)', 'medium'],
    [/measureText|getComputedStyle/i, 'Font measurement (fingerprinting technique)', 'medium'],
    // Screen/Device fingerprinting
    [/screen\.width|screen\.height/i, 'Screen dimensions (fingerprinting data)', 'low'],
    [/navigator\.hardwareConcurrency/i, 'CPU core count (fingerprinting data)', 'low'],
    [/navigator\.deviceMemory/i, 'Device memory (fingerprinting data)', 'low'],
    [/navigator\.maxTouchPoints/i, 'Touch points (fingerprinting data)', 'low'],
    // Timezone fingerprinting
    [/getTimezoneOffset|Intl\.DateTimeFormat/i, 'Timezone detection (fingerprinting)', 'low'],
    // Language fingerprinting
    [/navigator\.language|navigator\.languages/i, 'Language detection (fingerprinting)', 'low'],
    // Plugin fingerprinting
    [/navigator\.plugins/i, 'Plugin enumeration (fingerprinting)', 'medium'],
    // Media fingerprinting
    [/canPlayType/i, 'Media capability detection (fingerprinting)', 'low'],
    // Battery API
    [/navigator\.getBattery/i, 'Battery API (privacy concern)', 'medium'],
    // Connection API
    [/navigator\.connection/i, 'Network information (fingerprinting)', 'low'],
    // WebRTC fingerprinting
    [/RTCPeerConnection|webkitRTCPeerConnection/i, 'WebRTC (IP leak risk)', 'high'],
    [/getUserMedia/i, 'Media access (privacy concern)', 'medium'],
    // Storage fingerprinting
    [/localStorage|sessionStorage/i, 'Storage access (fingerprinting)', 'low'],
    [/IndexedDB/i, 'IndexedDB access (fingerprinting)', 'low'],
    // Feature detection
    [/Modernizr|feature\.detect/i, 'Feature detection library (fingerprinting)', 'medium'],
    // Fingerprinting libraries
    [/fingerprintjs|fingerprint2|clientjs/i, 'Known fingerprinting library', 'high'],
    [/fingerprint|fingerprint2/i, 'Fingerprinting reference', 'medium']
  ];

  static WEBRTC_LEAK_PATTERNS = [
    // WebRTC connection setup
    [/new\s+RTCPeerConnection/i, 'WebRTC peer connection created (IP leak risk)', 'high'],
    [/webkitRTCPeerConnection/i, 'WebRTC peer connection created (IP leak risk)', 'high'],
    // ICE candidate handling
    [/onicecandidate|addIceCandidate/i, 'ICE candidate handling (potential IP leak)', 'high'],
    [/createOffer|createAnswer/i, 'WebRTC SDP offer/answer (IP leak risk)', 'high'],
    // STUN/TURN servers
    [/stun:|turn:/i, 'STUN/TURN server configuration (IP leak risk)', 'high'],
    [/iceServers/i, 'ICE servers configuration (IP leak risk)', 'high'],
    // Local IP detection
    [/localDescription|remoteDescription/i, 'WebRTC description (IP leak risk)', 'high'],
    [/getLocalStreams|getRemoteStreams/i, 'WebRTC stream access (privacy concern)', 'medium'],
    // Data channels
    [/createDataChannel/i, 'WebRTC data channel (potential data leak)', 'medium'],
    // getUserMedia with WebRTC
    [/getUserMedia.*video|getUserMedia.*audio/i, 'Media access with WebRTC (privacy concern)', 'medium']
  ];

  static STORAGE_PATTERNS = [
    // localStorage access
    [/localStorage\.getItem/i, 'localStorage.getItem (data access)', 'low'],
    [/localStorage\.setItem/i, 'localStorage.setItem (data storage)', 'low'],
    [/localStorage\.removeItem/i, 'localStorage.removeItem (data deletion)', 'low'],
    [/localStorage\.clear/i, 'localStorage.clear (data wipe)', 'medium'],
    [/localStorage\.length/i, 'localStorage.length (data inspection)', 'low'],
    // sessionStorage access
    [/sessionStorage\.getItem/i, 'sessionStorage.getItem (data access)', 'low'],
    [/sessionStorage\.setItem/i, 'sessionStorage.setItem (data storage)', 'low'],
    [/sessionStorage\.removeItem/i, 'sessionStorage.removeItem (data deletion)', 'low'],
    [/sessionStorage\.clear/i, 'sessionStorage.clear (data wipe)', 'medium'],
    [/sessionStorage\.length/i, 'sessionStorage.length (data inspection)', 'low'],
    // IndexedDB access
    [/indexedDB\.open/i, 'IndexedDB.open (database access)', 'medium'],
    [/indexedDB\.deleteDatabase/i, 'IndexedDB.deleteDatabase (database deletion)', 'high'],
    // Cookie storage
    [/document\.cookie\s*=/i, 'Cookie assignment (data storage)', 'medium'],
    [/document\.cookie\s*\+/i, 'Cookie manipulation', 'medium'],
    // Storage event listeners
    [/window\.addEventListener\s*\(\s*['"]storage/i, 'Storage event listener (data monitoring)', 'medium'],
    // Storage inspection
    [/Object\.keys\(localStorage\)/i, 'localStorage keys enumeration', 'low'],
    [/Object\.keys\(sessionStorage\)/i, 'sessionStorage keys enumeration', 'low'],
    // Sensitive data in storage
    [/localStorage\.(password|token|secret|key|credit)/i, 'Sensitive data in localStorage', 'high'],
    [/sessionStorage\.(password|token|secret|key|credit)/i, 'Sensitive data in sessionStorage', 'high']
  ];

  static EXPOSED_FILE_PATTERNS = [
    // Configuration files
    [/\.env/i, 'Exposed .env file (environment variables)', 'critical'],
    [/config\.php/i, 'Exposed config.php file', 'critical'],
    [/config\.json/i, 'Exposed config.json file', 'high'],
    [/config\.yml/i, 'Exposed config.yml file', 'high'],
    [/config\.yaml/i, 'Exposed config.yaml file', 'high'],
    [/application\.yml/i, 'Exposed application.yml file', 'critical'],
    [/application\.properties/i, 'Exposed application.properties file', 'critical'],
    [/web\.xml/i, 'Exposed web.xml file', 'high'],
    [/web\.config/i, 'Exposed web.config file', 'high'],
    // Backup files
    [/\.bak/i, 'Backup file (.bak)', 'medium'],
    [/\.old/i, 'Old file (.old)', 'medium'],
    [/\.backup/i, 'Backup file (.backup)', 'medium'],
    [/\.orig/i, 'Original file (.orig)', 'medium'],
    [/\.save/i, 'Saved file (.save)', 'medium'],
    [/\.swp/i, 'Vim swap file (.swp)', 'medium'],
    [/\.tmp/i, 'Temporary file (.tmp)', 'low'],
    [/~$/i, 'Backup file (~)', 'medium'],
    // Version control
    [/\.git/i, 'Exposed .git directory', 'critical'],
    [/\.svn/i, 'Exposed .svn directory', 'critical'],
    [/\.hg/i, 'Exposed .hg directory', 'critical'],
    // Database files
    [/\.sql/i, 'SQL file (may contain data)', 'high'],
    [/\.db/i, 'Database file (.db)', 'high'],
    [/\.sqlite/i, 'SQLite database file', 'high'],
    [/\.mdb/i, 'Access database file', 'medium'],
    // Log files
    [/\.log/i, 'Log file (.log)', 'medium'],
    [/error_log/i, 'Error log file', 'medium'],
    [/access_log/i, 'Access log file', 'low'],
    // Debug files
    [/debug\.log/i, 'Debug log file', 'medium'],
    [/debug\.txt/i, 'Debug text file', 'medium'],
    // Other sensitive files
    [/passwords\.txt/i, 'Passwords file', 'critical'],
    [/secrets\.txt/i, 'Secrets file', 'critical'],
    [/keys\.txt/i, 'Keys file', 'critical'],
    [/dump/i, 'Dump file (may contain data)', 'high'],
    [/\.pem/i, 'PEM certificate file', 'high'],
    [/\.key/i, 'Private key file', 'critical'],
    [/\.crt/i, 'Certificate file', 'medium'],
    [/\.p12/i, 'PKCS12 certificate file', 'high'],
    [/\.pfx/i, 'PKCS12 certificate file', 'high']
  ];

  static WEBSOCKET_PATTERNS = [
    // WebSocket connections
    [/ws:\/\//i, 'Unencrypted WebSocket (ws://)', 'high'],
    [/wss:\/\//i, 'Encrypted WebSocket (wss://)', 'low'],
    [/new\s+WebSocket/i, 'WebSocket connection created', 'medium'],
    [/WebSocket\.open/i, 'WebSocket open event', 'medium'],
    [/WebSocket\.send/i, 'WebSocket send data', 'medium'],
    [/WebSocket\.close/i, 'WebSocket close connection', 'low'],
    [/socket\.io/i, 'Socket.io library', 'medium'],
    [/io\(/i, 'Socket.io client', 'medium'],
    [/on\s*\(\s*['"]message/i, 'WebSocket message handler', 'low'],
    [/on\s*\(\s*['"]close/i, 'WebSocket close handler', 'low'],
    [/on\s*\(\s*['"]error/i, 'WebSocket error handler', 'medium']
  ];

  static SERVICE_WORKER_PATTERNS = [
    // Service Worker registration
    [/navigator\.serviceWorker/i, 'Service Worker API access', 'medium'],
    [/serviceWorker\.register/i, 'Service Worker registration', 'medium'],
    [/serviceWorker\.ready/i, 'Service Worker ready', 'low'],
    [/serviceWorker\.controller/i, 'Service Worker controller', 'low'],
    // PWA manifest
    [/manifest\.json/i, 'PWA manifest file', 'low'],
    [/rel\s*=\s*['"]manifest/i, 'PWA manifest link', 'low'],
    [/theme-color/i, 'PWA theme color', 'low'],
    // Offline capabilities
    [/CacheStorage/i, 'Cache Storage API (offline capability)', 'medium'],
    [/caches\.open/i, 'Cache storage open', 'medium'],
    [/caches\.match/i, 'Cache storage match', 'medium'],
    [/caches\.add/i, 'Cache storage add', 'medium'],
    // Push notifications
    [/PushManager/i, 'Push Manager API', 'medium'],
    [/subscribe\s*\(/i, 'Push subscription', 'medium'],
    [/showNotification/i, 'Notification API', 'low']
  ];

  static COMMENT_PATTERNS = [
    // Sensitive data in comments
    [/\/\/.*password/i, 'Password in comment', 'high'],
    [/\/\/.*secret/i, 'Secret in comment', 'high'],
    [/\/\/.*token/i, 'Token in comment', 'high'],
    [/\/\/.*key/i, 'Key in comment', 'medium'],
    [/\/\/.*api[_-]?key/i, 'API key in comment', 'high'],
    [/\/\/.*todo.*fix/i, 'TODO/FIX comment (may indicate known issues)', 'low'],
    [/\/\/.*hack/i, 'Hack in comment (suspicious)', 'medium'],
    [/\/\/.*backdoor/i, 'Backdoor in comment (critical)', 'critical'],
    [/\/\/.*debug/i, 'Debug comment (debug code may be present)', 'medium'],
    [/\/\*.*\*\/.*/i, 'Multi-line comment (may contain sensitive info)', 'low'],
    [/<!--.*-->/i, 'HTML comment (may contain sensitive info)', 'low']
  ];

  static ANALYTICS_PATTERNS = [
    // Google Analytics
    [/google-analytics\.com/i, 'Google Analytics', 'low'],
    [/gtag\(/i, 'Google Analytics gtag', 'low'],
    [/ga\(/i, 'Google Analytics ga', 'low'],
    [/_gaq/i, 'Google Analytics _gaq', 'low'],
    // Facebook Pixel
    [/facebook\.net\/.*\/fbevents\.js/i, 'Facebook Pixel', 'low'],
    [/fbq\(/i, 'Facebook Pixel fbq', 'low'],
    // Other analytics
    [/analytics\.js/i, 'Analytics library', 'low'],
    [/tracking\.js/i, 'Tracking library', 'medium'],
    [/segment\.com/i, 'Segment analytics', 'low'],
    [/mixpanel\.com/i, 'Mixpanel analytics', 'low'],
    [/amplitude\.com/i, 'Amplitude analytics', 'low'],
    [/hotjar\.com/i, 'Hotjar analytics', 'medium'],
    [/fullstory\.com/i, 'FullStory analytics', 'medium'],
    // Ad trackers
    [/doubleclick\.net/i, 'DoubleClick ad tracker', 'medium'],
    [/googletagmanager\.com/i, 'Google Tag Manager', 'low'],
    [/googlesyndication\.com/i, 'Google ad syndication', 'medium']
  ];

  static decodeBase64Hex(content) {
    /**
     * Decode Base64 and hex encoded strings to detect obfuscated content.
     */
    const decoded = [];
    
    // Base64 patterns
    const base64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/g;
    let match;
    while ((match = base64Pattern.exec(content)) !== null) {
      try {
        const decodedStr = atob(match[0]);
        if (decodedStr.length > 10 && this.isPrintable(decodedStr)) {
          decoded.push({
            type: 'Base64',
            original: match[0].substring(0, 50) + '...',
            decoded: decodedStr.substring(0, 100)
          });
        }
      } catch (e) {
        // Invalid Base64, skip
      }
    }
    
    // Hex patterns
    const hexPattern = /\\x[0-9a-fA-F]{2}/g;
    const hexMatches = content.match(hexPattern);
    if (hexMatches && hexMatches.length > 5) {
      try {
        let hexStr = hexMatches.join('');
        hexStr = hexStr.replace(/\\x/g, '');
        let decodedStr = '';
        for (let i = 0; i < hexStr.length; i += 2) {
          decodedStr += String.fromCharCode(parseInt(hexStr.substr(i, 2), 16));
        }
        if (this.isPrintable(decodedStr)) {
          decoded.push({
            type: 'Hex',
            original: hexMatches.slice(0, 5).join(' ') + '...',
            decoded: decodedStr.substring(0, 100)
          });
        }
      } catch (e) {
        // Invalid hex, skip
      }
    }
    
    return decoded;
  }

  static isPrintable(str) {
    /**
     * Check if string contains mostly printable ASCII characters.
     */
    const printableCount = (str.match(/[a-zA-Z0-9\s.,!?;:'"(){}[\]<>]/g) || []).length;
    return printableCount / str.length > 0.7;
  }
  
  static JS_CONTEXT_PATTERNS = [
    [/eval\s*\(/i, 'Dynamic code execution (eval)', 'high'],
    [/Function\s*\(\s*['"]\s*return\s+eval/i, 'Obfuscated eval via Function constructor', 'high'],
    [/document\.location\s*=/i, 'Forced redirect', 'high'],
    [/window\.location\s*=[^=]/i, 'Forced redirect', 'high'],
    [/location\.href\s*=[^=]/i, 'Forced redirect', 'high'],
    [/atob\s*\(/i, 'Base64 decoding (possible obfuscation)', 'medium'],
    [/\\x[0-9a-fA-F]{2}/g, 'Hex escaped characters', 'medium'],
    [/\\u[0-9a-fA-F]{4}/g, 'Unicode escaped characters', 'medium'],
    [/String\.prototype\.split\s*\(\s*['"].*['"]\).*\.reverse/i, 'String reversal obfuscation', 'high'],
    [/createElement\s*\(\s*['"]script['"]/i, 'Dynamic script injection', 'high'],
    [/appendChild\s*\(\s*.*script/i, 'Script DOM injection', 'high'],
    [/insertBefore\s*\(\s*.*script/i, 'Script DOM injection', 'high']
  ];
  
  static MALICIOUS_ROOT_DOMAINS = [
    'coinhive.com', 'jsecoin.com', 'cryptoloot.com', 'webmine.cz',
    'ppoi.org', 'kdowqlpt.com', 'trackers.online'
  ];
  
  static CDN_WHITELIST = [
    'github.com', 'githubusercontent.com', 'gitlab.com',
    'google.com', 'gstatic.com', 'googlesource.com',
    'microsoft.com', 'microsoftazure.com', 'azureedge.net',
    'amazonaws.com', 'cloudflare.com', 'cloudfront.net',
    'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net',
    'npmjs.com', 'pypi.org', 'rubygems.org'
  ];
  
  static TRUSTED_DOMAINS = [
    'wikipedia.org', 'wikimedia.org', 'wiktionary.org',
    'google.com', 'youtube.com', 'gmail.com', 'googleapis.com',
    'github.com', 'githubusercontent.com',
    'microsoft.com', 'live.com', 'office.com', 'windows.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'aws.amazon.com',
    'facebook.com', 'instagram.com', 'whatsapp.com',
    'twitter.com', 'x.com',
    'netflix.com', 'spotify.com',
    'linkedin.com',
    'paypal.com',
    'mozilla.org', 'developer.mozilla.org', 'stackoverflow.com',
    'python.org', 'pypi.org',
    'nodejs.org', 'npmjs.com',
    'openai.com',
    'example.com', 'example.org', 'iana.org',
    // News sites
    'hola.com', 'holamadrid.com', 'tubodahola.com', 'holaboda.com', 'suscripciones.hola.com', 'suscribete.hola.com', 'grupohola.com',
    'nytimes.com', 'washingtonpost.com', 'cnn.com', 'bbc.com', 'reuters.com', 'apnews.com',
    'theguardian.com', 'ft.com', 'wsj.com', 'bloomberg.com', 'economist.com',
    'elpais.com', 'elmundo.es', 'abc.es', 'lavanguardia.com', 'elmundo.es',
    'lemonde.fr', 'lefigaro.fr', 'leparisien.fr',
    'spiegel.de', 'zeit.de', 'faz.net',
    'corriere.it', 'repubblica.it', 'lastampa.it',
    'telegraph.co.uk', 'independent.co.uk', 'dailymail.co.uk',
    'foxnews.com', 'msnbc.com', 'nbcnews.com', 'cbsnews.com', 'abcnews.go.com',
    'time.com', 'newsweek.com', 'theatlantic.com', 'vox.com',
    'businessinsider.com', 'techcrunch.com', 'wired.com', 'arstechnica.com',
    'cnet.com', 'zdnet.com', 'theverge.com', 'engadget.com',
    'gizmodo.com', 'lifehacker.com', 'kotaku.com', 'polygon.com',
    'espn.com', 'bleacherreport.com', 'si.com',
    'people.com', 'eonline.com', 'tmz.com',
    'rollingstone.com', 'billboard.com', 'variety.com',
    'nationalgeographic.com', 'discovery.com',
    'weather.com', 'accuweather.com'
  ];
  
  static isMinifiedBundle(content, filePath) {
    const fname = filePath.toLowerCase();
    if (['bundle', 'chunk', 'vendor', 'min.js', 'swagger-ui', 'main.', 'polyfill', 'runtime', 'commons'].some(k => fname.includes(k))) {
      return true;
    }
    const lines = content.split('\n');
    if (lines.length === 0) return false;
    const avg = lines.reduce((sum, l) => sum + l.length, 0) / lines.length;
    return avg > 400 && lines.length < 200;
  }
  
  static isTrustedDomain(url) {
    try {
      const hostname = new URL(url).hostname;
      return this.TRUSTED_DOMAINS.some(domain => hostname === domain || hostname.endsWith('.' + domain));
    } catch {
      return false;
    }
  }
  
  static getRootDomain(url) {
    try {
      const hostname = new URL(url).hostname;
      const parts = hostname.split('.');
      if (parts.length >= 2) {
        return parts.slice(-2).join('.');
      }
      return hostname;
    } catch {
      return '';
    }
  }
  
  static isNewsSite(url) {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      // Check if domain contains news-related keywords
      const newsKeywords = ['news', 'press', 'media', 'journal', 'daily', 'times', 'post', 'herald', 'gazette', 'tribune', 'chronicle', 'sentinel', 'observer', 'reporter', 'tv', 'radio', 'broadcast'];
      const hasNewsKeyword = newsKeywords.some(keyword => hostname.includes(keyword));
      
      // Check if it's in trusted domains (which includes news sites)
      const isTrusted = this.TRUSTED_DOMAINS.some(domain => hostname === domain || hostname.endsWith('.' + domain));
      
      return hasNewsKeyword || isTrusted;
    } catch {
      return false;
    }
  }
  
  static analyzeContent(content, filePath, pageUrl = '') {
    const threats = [];
    const lines = content.split('\n');
    const isMinified = this.isMinifiedBundle(content, filePath);
    const isPageTrusted = pageUrl ? this.isTrustedDomain(pageUrl) : false;
    const isNews = pageUrl ? this.isNewsSite(pageUrl) : false;
    const targetDomain = pageUrl ? this.getRootDomain(pageUrl) : '';
    const seen = new Set();
    
    // Core patterns (always check)
    lines.forEach((line, lineNum) => {
      this.JS_MALWARE_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          if (description === 'ActiveX exploitation' && filePath.toLowerCase().includes('polyfill')) {
            return;
          }
          const key = `Malicious Script-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('Malicious Script', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // Secret detection (always check - high priority)
    lines.forEach((line, lineNum) => {
      this.SECRET_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `Secret Leak-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('Secret Leak', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // WASM detection (always check)
    lines.forEach((line, lineNum) => {
      this.WASM_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `WASM-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('WebAssembly', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // Fingerprinting detection (always check)
    lines.forEach((line, lineNum) => {
      this.FINGERPRINTING_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `Fingerprinting-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('Browser Fingerprinting', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // WebRTC IP leak detection (always check)
    lines.forEach((line, lineNum) => {
      this.WEBRTC_LEAK_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `WebRTC-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('WebRTC IP Leak', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // Storage inspection (always check)
    lines.forEach((line, lineNum) => {
      this.STORAGE_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `Storage-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('Storage Access', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // Exposed file detection (always check)
    lines.forEach((line, lineNum) => {
      this.EXPOSED_FILE_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `ExposedFile-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('Exposed File', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // WebSocket detection (always check)
    lines.forEach((line, lineNum) => {
      this.WEBSOCKET_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `WebSocket-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('WebSocket', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // Service Worker/PWA detection (always check)
    lines.forEach((line, lineNum) => {
      this.SERVICE_WORKER_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `ServiceWorker-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('Service Worker/PWA', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // Comment analysis (always check)
    lines.forEach((line, lineNum) => {
      this.COMMENT_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `Comment-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('Comment Analysis', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });

    // Analytics/tracker detection (always check)
    lines.forEach((line, lineNum) => {
      this.ANALYTICS_PATTERNS.forEach(([pattern, description, severity]) => {
        if (pattern.test(line)) {
          const key = `Analytics-${filePath}-${lineNum}-${description}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('Analytics/Tracker', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
          }
        }
      });
    });
    
    // Context patterns (skip for trusted pages, news sites, and minified)
    if (!isMinified && !isPageTrusted && !isNews) {
      lines.forEach((line, lineNum) => {
        this.JS_CONTEXT_PATTERNS.forEach(([pattern, description, severity]) => {
          if (pattern.test(line)) {
            const key = `Malicious Script-${filePath}-${lineNum}-${description}`;
            if (!seen.has(key)) {
              seen.add(key);
              threats.push(new Threat('Malicious Script', severity, filePath, lineNum + 1, description, line.trim().substring(0, 200)));
            }
          }
        });
      });
    }
    
    // Check for malicious domain references
    const urlPattern = /https?:\/\/[^\s<>"')]+/gi;
    let match;
    while ((match = urlPattern.exec(content)) !== null) {
      const url = match[0];
      const rootDomain = this.getRootDomain(url);
      if (this.MALICIOUS_ROOT_DOMAINS.includes(rootDomain)) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        const key = `Malicious Domain Reference-${filePath}-${lineNum}-${rootDomain}`;
        if (!seen.has(key)) {
          seen.add(key);
          threats.push(new Threat('Malicious Domain Reference', 'critical', filePath, lineNum, `Reference to known malicious domain: ${rootDomain}`, line.trim().substring(0, 200)));
        }
      }
    }
    
    // Check for external payloads
    if (targetDomain) {
      const payloadPattern = /https?:\/\/[^\s<>"')]+\.(exe|zip|sh|msi|dmg|pkg|apk|iso|img)/gi;
      while ((match = payloadPattern.exec(content)) !== null) {
        const url = match[0];
        const linkDomain = this.getRootDomain(url);
        if (linkDomain && linkDomain !== targetDomain) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const isCdn = this.CDN_WHITELIST.some(whitelist => linkDomain.includes(whitelist));
          const severity = isCdn ? 'low' : 'critical';
          const cdnNote = isCdn ? ' (whitelisted CDN)' : '';
          const key = `External Payload-${filePath}-${lineNum}-${url.substring(0, 100)}`;
          if (!seen.has(key)) {
            seen.add(key);
            threats.push(new Threat('External Payload', severity, filePath, lineNum, `Link to executable file on external domain${cdnNote}: ${linkDomain}`, url.substring(0, 150)));
          }
        }
      }
    }
    
    // Check for sensitive data leaks (skip for trusted/news sites)
    if (!isPageTrusted && !isNews) {
      const sensitivePatterns = [
        [/(TODO|FIXME|HACK|BUG)[:\s]/gi, 'Developer TODO/FIXME comment', 'low'],
        [/(API_KEY|APIKEY|API-KEY|SECRET_KEY|SECRET)[:\s=]/gi, 'Hardcoded API key or secret', 'high'],
        [/(PASSWORD|PASSWD|PASSWORD)[:\s=]/gi, 'Hardcoded password reference', 'high'],
        [/(PRIVATE_KEY|PRIVATE-KEY|RSA_PRIVATE)[:\s=]/gi, 'Hardcoded private key reference', 'high'],
        [/(TOKEN|AUTH_TOKEN|JWT)[:\s=]/gi, 'Hardcoded authentication token', 'medium'],
        [/(DATABASE_URL|DB_HOST|DB_PASSWORD)[:\s=]/gi, 'Hardcoded database credentials', 'medium']
      ];
    
      const passwordPlaceholders = ['replaceme', 'replace_me', 'placeholder', 'example', 'test', 'demo', 'changeme', 'change_me', 'your_password', 'yourpassword', 'secret', '123456', 'password', 'admin', 'root', 'pass', 'qwerty'];
      
      lines.forEach((line, lineNum) => {
        const lineStripped = line.trim();
        if (!lineStripped || ['}', ']', ')', '};'].includes(lineStripped)) return;
        if (lineStripped.startsWith('.', '#', '*')) return;
        
        sensitivePatterns.forEach(([pattern, description, severity]) => {
          const match = pattern.exec(lineStripped);
          if (match) {
            let actualSeverity = severity;
            if (match[0].toUpperCase().includes('PASSWORD')) {
              const valueMatch = /[:\s=]\s*['"]?([^'"\s,;]+)/.exec(lineStripped.substring(match.index + match[0].length));
              if (valueMatch && passwordPlaceholders.includes(valueMatch[1].toLowerCase())) {
                actualSeverity = 'low';
                description += ' (placeholder detected)';
              }
            }
            const key = `Sensitive Data Leak-${filePath}-${lineNum}-${description}`;
            if (!seen.has(key)) {
              seen.add(key);
              threats.push(new Threat('Sensitive Data Leak', actualSeverity, filePath, lineNum + 1, description, lineStripped.substring(0, 150)));
            }
          }
        });
      });
    }
    
    return threats;
  }
}

class PhishingDetector {
  static TRUSTED_DOMAINS = MalwareDetector.TRUSTED_DOMAINS;
  
  static BRAND_OFFICIAL_DOMAINS = {
    'paypal': ['paypal.com', 'paypalobjects.com'],
    'apple': ['apple.com', 'icloud.com'],
    'microsoft': ['microsoft.com', 'azure.com', 'office.com', 'live.com'],
    'google': ['google.com', 'gmail.com', 'youtube.com', 'android.com'],
    'facebook': ['facebook.com', 'instagram.com', 'whatsapp.com'],
    'amazon': ['amazon.com', 'aws.amazon.com'],
    'netflix': ['netflix.com'],
    'chase': ['chase.com'],
    'wells fargo': ['wellsfargo.com'],
    'citi': ['citi.com', 'citibank.com'],
    'hsbc': ['hsbc.com'],
    'barclays': ['barclays.com'],
    'santander': ['santander.com'],
    'bbva': ['bbva.com'],
    'deutsche bank': ['deutschebank.com'],
    'ing': ['ing.com'],
    'bank of america': ['bankofamerica.com'],
    'jpmorgan': ['jpmorgan.com', 'chase.com'],
    'capital one': ['capitalone.com'],
    'gmail': ['gmail.com', 'google.com'],
    'yahoo': ['yahoo.com'],
    'outlook': ['outlook.com', 'live.com', 'microsoft.com'],
    'icloud': ['icloud.com', 'apple.com'],
    'protonmail': ['protonmail.com', 'proton.me'],
    'zoho mail': ['zoho.com'],
    'instagram': ['instagram.com', 'facebook.com'],
    'x.com': ['x.com', 'twitter.com'],
    'linkedin': ['linkedin.com'],
    'tiktok': ['tiktok.com'],
    'snapchat': ['snapchat.com'],
    'whatsapp': ['whatsapp.com', 'facebook.com'],
    'telegram': ['telegram.org'],
    'signal': ['signal.org'],
    'discord': ['discord.com'],
    'reddit': ['reddit.com'],
    'pinterest': ['pinterest.com'],
    'wechat': ['wechat.com'],
    'vk': ['vk.com'],
    'yandex': ['yandex.com', 'yandex.ru'],
    'baidu': ['baidu.com'],
    'alibaba': ['alibaba.com'],
    'aliexpress': ['aliexpress.com'],
    'taobao': ['taobao.com'],
    'protonmail': ['protonmail.com'],
    'onedrive': ['onedrive.com', 'live.com'],
    'google drive': ['drive.google.com', 'google.com'],
    'mega': ['mega.nz'],
    'nordvpn': ['nordvpn.com'],
    'expressvpn': ['expressvpn.com'],
    'mcafee': ['mcafee.com'],
    'norton': ['norton.com'],
    'kaspersky': ['kaspersky.com'],
    'avast': ['avast.com'],
    'avg': ['avg.com'],
    'bitdefender': ['bitdefender.com'],
    'malwarebytes': ['malwarebytes.com'],
    'lastpass': ['lastpass.com'],
    '1password': ['1password.com'],
    'dashlane': ['dashlane.com'],
    'bitwarden': ['bitwarden.com'],
    'roblox': ['roblox.com'],
    'minecraft': ['minecraft.net'],
    'fortnite': ['fortnite.com', 'epicgames.com'],
    'valorant': ['valorant.com', 'riotgames.com'],
    'league of legends': ['leagueoflegends.com', 'riotgames.com'],
    'call of duty': ['callofduty.com', 'activision.com'],
    'apex legends': ['apexlegends.com', 'ea.com'],
    'overwatch': ['overwatch.com', 'blizzard.com'],
    'battle.net': ['battle.net', 'blizzard.com'],
    'ea.com': ['ea.com'],
    'ubisoft': ['ubisoft.com'],
    'playstation': ['playstation.com', 'sony.com'],
    'xbox': ['xbox.com', 'microsoft.com'],
    'nintendo': ['nintendo.com'],
    'tinder': ['tinder.com'],
    'bumble': ['bumble.com'],
    'hinge': ['hinge.co'],
    'match': ['match.com'],
    'eharmony': ['eharmony.com'],
    'okcupid': ['okcupid.com'],
    'indeed': ['indeed.com'],
    'glassdoor': ['glassdoor.com'],
    'monster': ['monster.com'],
    'coursera': ['coursera.org'],
    'udemy': ['udemy.com'],
    'edx': ['edx.org'],
    'khan academy': ['khanacademy.org'],
    'codecademy': ['codecademy.com'],
    'duolingo': ['duolingo.com'],
    'wix': ['wix.com'],
    'wordpress': ['wordpress.com'],
    'godaddy': ['godaddy.com'],
    'namecheap': ['namecheap.com'],
    'cloudflare': ['cloudflare.com'],
    'aws': ['aws.amazon.com', 'amazonaws.com'],
    'azure': ['azure.com', 'microsoft.com'],
    'gcp': ['cloud.google.com', 'google.com'],
    'digitalocean': ['digitalocean.com'],
    'heroku': ['heroku.com'],
    'vercel': ['vercel.com'],
    'netlify': ['netlify.com'],
    'firebase': ['firebase.com', 'google.com'],
    'mongodb': ['mongodb.com'],
    'salesforce': ['salesforce.com'],
    'hubspot': ['hubspot.com'],
    'zendesk': ['zendesk.com'],
    'zoho': ['zoho.com'],
    'stripe': ['stripe.com'],
    'square': ['squareup.com'],
    'wise': ['wise.com'],
    'revolut': ['revolut.com'],
    'n26': ['n26.com'],
    'monzo': ['monzo.com'],
    'cash app': ['cash.app', 'squareup.com'],
    'venmo': ['venmo.com'],
    'zelle': ['zellepay.com'],
    'shopify': ['shopify.com'],
    'walmart': ['walmart.com'],
    'target': ['target.com'],
    'best buy': ['bestbuy.com'],
    'costco': ['costco.com'],
    'home depot': ['homedepot.com'],
    'lowes': ['lowes.com'],
    'uber': ['uber.com'],
    'lyft': ['lyft.com'],
    'airbnb': ['airbnb.com'],
    'booking': ['booking.com'],
    'expedia': ['expedia.com'],
    'american airlines': ['aa.com', 'americanairlines.com'],
    'delta': ['delta.com'],
    'united airlines': ['united.com'],
    'fedex': ['fedex.com'],
    'ups': ['ups.com'],
    'dhl': ['dhl.com'],
    'usps': ['usps.com'],
    'disney': ['disney.com'],
    'disney plus': ['disneyplus.com'],
    'hulu': ['hulu.com'],
    'hbo': ['hbo.com'],
    'peacock': ['peacocktv.com'],
    'paramount': ['paramountplus.com'],
    'twitch': ['twitch.tv', 'amazon.com'],
    'steam': ['steampowered.com'],
    'epic games': ['epicgames.com'],
    'riot games': ['riotgames.com'],
    'coinbase': ['coinbase.com'],
    'binance': ['binance.com'],
    'kraken': ['kraken.com'],
    'gemini': ['gemini.com'],
    'metamask': ['metamask.io'],
    'ledger': ['ledger.com'],
    'trezor': ['trezor.io'],
    'blockchain': ['blockchain.com'],
    'robinhood': ['robinhood.com'],
    'fidelity': ['fidelity.com'],
    'schwab': ['schwab.com'],
    'vanguard': ['vanguard.com'],
    'etrade': ['etrade.com'],
    'western union': ['westernunion.com'],
    'moneygram': ['moneygram.com'],
    'github': ['github.com'],
    'gitlab': ['gitlab.com'],
    'bitbucket': ['bitbucket.org'],
    'supabase': ['supabase.com'],
    'auth0': ['auth0.com'],
    'okta': ['okta.com'],
    'render': ['render.com'],
    'fly.io': ['fly.io'],
    'railway': ['railway.app']
  };
  
  static SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.work', '.date', '.party', '.click', '.download', '.win', '.bid', '.loan', '.country', '.stream', '.gdn', '.trade', '.science', '.review', '.ninja', '.rocks', '.site', '.space', '.fun', '.life', '.today', '.press', '.host', '.ooo', '.buzz', '.cafe', '.chat', '.cheap', '.club'];
  
  static PHISHING_PATTERNS = [
    [/<form[^>]*action\s*=\s*['"]https?:\/\/[^'"]*\.(tk|ml|ga|cf|top|xyz|work|date|party|link|click|download|racing|win|bid|loan|men|wang|country|stream|gdn|trade|science|review|ninja|rocks|site|online|space|website|tech|club|fun|store|shop|live|life|news|today|press|host|cloud|agency|digital|social|media|video|photography|gallery|graphics|design|zone|center|city|company|directory|domains|enterprises|holdings|industries|international|limited|management|network|partners|photos|productions|properties|recipes|rentals|repair|report|schule|services|shoes|singles|systems|tienda|tips|tools|town|toys|training|university|vacations|ventures|viajes|villas|vin|vip|vision|vodka|vote|voting|voyage|watch|webcam|website|wed|wedding|whoswho|wien|wiki|wine|works|wtf|ooo|bar|buzz|cab|cafe|camp|care|cash|catering|chat|cheap|church|claims|cleaning|clinic|clothing|coach|codes|coffee|community|computer|condos|construction|contractors|cool|coupons|credit|creditcard|cruises|dating|deals|delivery|democrat|dental|dentist|diamonds|direct|discount|doctor|dog|engineer|equipment|estate|events|exchange|expert|exposed|fail|farm|finance|financial|fish|fitness|flights|florist|football|forsale|foundation|fund|furniture|fyi|games|gifts|gives|glass|gmbh|gold|golf|gratis|green|gripe|group|guide|guitars|guru|haus|healthcare|help|hiphop|hockey|holiday|horse|hospital|house|immobilien|immo|ink|institute|insure|investments|jewelry|juegos|kaufen|kitchen|kiwi|land|lease|legal|lgbt|lighting|limo|link|loans|ltd|maison|marketing|mba|memorial|moda|mortgage|moscow|navy|nyc|one|organic|parts|photo|pics|pictures|place|plumbing|plus|poker|porn|promo|pub|qpon|rehab|reisen|rent|rentals|repair|republican|rest|restaurant|reviews|rich|rip|run|sale|salon|sarl|school|scot|sexy|shiksha|show|skin|soccer|software|soy|studio|style|supplies|supply|support|surf|surgery|tattoo|tax|taxi|team|technology|tennis|theater|theatre|tickets|tires|tours|town|toys|trade|trading|tube|vet|viajes|video|villas|vin|vip|vision|vodka|vote|voting|voyage|watch|webcam|website|wed|wedding|whoswho|wien|wiki|wine|works|wtf|ooo|bar|buzz|cab|cafe|camp|care|cash|catering|chat|cheap|church|claims|cleaning|clinic|clothing|coach|codes|coffee|community|computer|condos|construction|contractors|cool|coupons|credit|creditcard|cruises|dating|deals|delivery|democrat|dental|dentist|diamonds|direct|discount|doctor|dog|engineer|equipment|estate|events|exchange|expert|exposed|fail|farm|finance|financial|fish|fitness|flights|florist|football|forsale|foundation|fund|furniture|fyi|games|gifts|gives|glass|gmbh|gold|golf|gratis|green|gripe|group|guide|guitars|guru|haus|healthcare|help|hiphop|hockey|holiday|horse|hospital|house|immobilien|immo|ink|institute|insure|investments|jewelry|juegos|kaufen|kitchen|kiwi|land|lease|legal|lgbt|lighting|limo|link|loans|ltd|maison|marketing|mba|memorial|moda|mortgage|moscow|navy|nyc|one|organic|parts|photo|pics|pictures|place|plumbing|plus|poker|porn|promo|pub|qpon|rehab|reisen|rent|rentals|repair|republican|rest|restaurant|reviews|rich|rip|run|sale|salon|sarl|school|scot|sexy|shiksha|show|skin|soccer|software|soy|studio|style|supplies|supply|support|surf|surgery|tattoo|tax|taxi|team|technology|tennis|theater|theatre|tickets|tires|tours|town|toys|trade|trading|tube|vet|viajes|video|villas|vin|vip|vision|vodka|vote|voting|voyage|watch|webcam|website|wed|wedding|whoswho|wien|wiki|wine|works|wtf|ooo|bar|buzz|cab|cafe|camp|care|cash|catering|chat|cheap|church|claims|cleaning|clinic|clothing|coach|codes|coffee|community|computer|condos|construction|contractors|cool|coupons|credit|creditcard|cruises|dating|deals|delivery|democrat|dental|dentist|diamonds|direct|discount|doctor|dog|engineer|equipment|estate|events|exchange|expert|exposed|fail|farm|finance|financial|fish|fitness|flights|florist|football|forsale|foundation|fund|furniture|fyi|games|gifts|gives|glass|gmbh|gold|golf|gratis|green|gripe|group|guide|guitars|guru|haus|healthcare|help|hiphop|hockey|holiday|horse|hospital|house|immobilien|immo|ink|institute|insure|investments|jewelry|juegos|kaufen|kitchen|kiwi|land|lease|legal|lgbt|lighting|limo|link|loans|ltd|maison|marketing|mba|memorial|moda|mortgage|moscow|navy|nyc|one|organic|parts|photo|pics|pictures|place|plumbing|plus|poker|porn|promo|pub|qpon|rehab|reisen|rent|rentals|repair|republican|rest|restaurant|reviews|rich|rip|run|sale|salon|sarl|school|scot|sexy|shiksha|show|skin|soccer|software|soy|studio|style|supplies|supply|support|surf|surgery|tattoo|tax|taxi|team|technology|tennis|theater|theatre|tickets|tires|tours|town|toys|trade|trading|tube|vet|viajes|video|villas|vin|vip|vision|vodka|vote|voting|voyage|watch|webcam|website|wed|wedding|whoswho|wien|wiki|wine|works)['"]/i, 'Form submits to suspicious TLD', 'high'],
    [/<form[^>]*action\s*=\s*['"]https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}['"]/i, 'Form submits to IP address', 'high']
  ];
  
  static isTrustedDomain(url) {
    try {
      const hostname = new URL(url).hostname;
      return this.TRUSTED_DOMAINS.some(domain => hostname === domain || hostname.endsWith('.' + domain));
    } catch {
      return false;
    }
  }
  
  static getRootDomain(url) {
    try {
      const hostname = new URL(url).hostname;
      const parts = hostname.split('.');
      if (parts.length >= 2) {
        return parts.slice(-2).join('.');
      }
      return hostname;
    } catch {
      return '';
    }
  }
  
  static analyzePage(html, url, pageUrl) {
    const threats = [];
    const seen = new Set();
    
    // Check for suspicious TLD in forms
    this.PHISHING_PATTERNS.forEach(([pattern, description, severity]) => {
      const match = pattern.exec(html);
      if (match) {
        const key = `Phishing Indicator-${url}-0-${description}`;
        if (!seen.has(key)) {
          seen.add(key);
          threats.push(new Threat('Phishing Indicator', severity, url, 0, description, match[0].substring(0, 200)));
        }
      }
    });
    
    // Check for password forms on non-trusted domains
    const passwordFormRegex = /<form[^>]*>[\s\S]*?<input[^>]*type\s*=\s*['"]password['"][\s\S]*?<\/form>/gi;
    const passwordForms = html.match(passwordFormRegex);
    if (passwordForms && passwordForms.length > 0) {
      if (!this.isTrustedDomain(url)) {
        const key = `Credential Harvesting Form-${url}-0-Password form on untrusted domain`;
        if (!seen.has(key)) {
          seen.add(key);
          threats.push(new Threat('Credential Harvesting Form', 'high', url, 0, 'Password form on untrusted domain', 'Contains password input field'));
        }
      }
    }
    
    // Check for brand impersonation in domain
    const hostname = this.getRootDomain(url);
    for (const [brand, officialDomains] of Object.entries(this.BRAND_OFFICIAL_DOMAINS)) {
      if (hostname.includes(brand.replace(/\s+/g, '')) && !officialDomains.includes(hostname)) {
        const key = `Brand Impersonation-${url}-0-${brand}`;
        if (!seen.has(key)) {
          seen.add(key);
          threats.push(new Threat('Brand Impersonation', 'high', url, 0, `Domain mimics ${brand}`, hostname));
        }
      }
    }
    
    // Check for suspicious TLD
    for (const tld of this.SUSPICIOUS_TLDS) {
      if (hostname.endsWith(tld)) {
        const key = `Suspicious TLD-${url}-0-${tld}`;
        if (!seen.has(key)) {
          seen.add(key);
          threats.push(new Threat('Suspicious TLD', 'medium', url, 0, `Domain uses suspicious TLD: ${tld}`, hostname));
        }
        break;
      }
    }
    
    return threats;
  }
}

class SuspiciousLinkDetector {
  static SUSPICIOUS_KEYWORDS = ['free', 'winner', 'prize', 'lottery', 'million', 'click here', 'verify', 'confirm', 'urgent', 'account suspended', 'security alert', 'update payment', 'bank details'];
  static URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly'];
  static CDN_WHITELIST = MalwareDetector.CDN_WHITELIST;
  
  // Brand-like terms that should trigger mismatch detection
  static BRAND_TERMS = ['paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon', 'netflix', 'chase', 'wells fargo', 'bank of america', 'citibank', 'capital one', 'gmail', 'yahoo', 'outlook', 'icloud', 'instagram', 'twitter', 'linkedin', 'tiktok', 'whatsapp', 'telegram', 'discord', 'reddit', 'pinterest', 'wechat', 'vk', 'yandex', 'baidu', 'alibaba', 'coinbase', 'binance', 'kraken', 'gemini', 'metamask', 'ledger', 'trezor', 'blockchain', 'robinhood', 'fidelity', 'schwab', 'vanguard', 'etrade', 'western union', 'moneygram', 'github', 'gitlab', 'bitbucket'];
  
  // Login/account-related terms
  static LOGIN_TERMS = ['login', 'signin', 'sign in', 'sign-in', 'log in', 'log-in', 'account', 'password', 'verify', 'confirm', 'authenticate', 'secure', 'bank', 'credit card', 'payment', 'billing'];
  
  static analyzeLinks(links, content, url, pageUrl) {
    const threats = [];
    const seen = new Set();
    const targetDomain = MalwareDetector.getRootDomain(pageUrl);
    
    links.forEach(link => {
      try {
        const linkUrl = new URL(link);
        const linkDomain = linkUrl.hostname;
        
        // Skip if link is to the same domain (internal links are never phishing)
        if (targetDomain && linkDomain === targetDomain) {
          return;
        }
        
        // Skip if link is to a subdomain of the target
        if (targetDomain && linkDomain.endsWith('.' + targetDomain)) {
          return;
        }
        
        // Check for URL shorteners
        for (const shortener of this.URL_SHORTENERS) {
          if (linkDomain.includes(shortener)) {
            const key = `URL Shortener-${url}-0-${link}`;
            if (!seen.has(key)) {
              seen.add(key);
              threats.push(new Threat('URL Shortener', 'medium', url, 0, `URL uses shortener service: ${shortener}`, link));
            }
            break;
          }
        }
        
        // Check for suspicious keywords in link text
        const linkTextRegex = new RegExp(`<a[^>]*href=['"]${link.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"][^>]*>([^<]+)</a>`, 'gi');
        const linkMatch = linkTextRegex.exec(content);
        if (linkMatch) {
          const text = linkMatch[1].toLowerCase();
          for (const keyword of this.SUSPICIOUS_KEYWORDS) {
            if (text.includes(keyword)) {
              const key = `Suspicious Link Keyword-${url}-0-${keyword}`;
              if (!seen.has(key)) {
                seen.add(key);
                threats.push(new Threat('Suspicious Link Keyword', 'low', url, 0, `Link contains suspicious keyword: ${keyword}`, text));
              }
              break;
            }
          }
        }
        
        // Check for cross-domain links to non-CDN
        if (targetDomain && linkDomain !== targetDomain) {
          const isCdn = this.CDN_WHITELIST.some(whitelist => linkDomain.includes(whitelist));
          if (!isCdn) {
            // Only flag if the link text is misleading AND contains brand/login terms
            if (linkMatch && linkMatch[1]) {
              const displayedText = linkMatch[1].toLowerCase();
              const linkDomainLower = linkDomain.toLowerCase();
              
              // Check if displayed text contains brand or login terms
              const hasBrandTerm = this.BRAND_TERMS.some(term => displayedText.includes(term));
              const hasLoginTerm = this.LOGIN_TERMS.some(term => displayedText.includes(term));
              
              // Only flag if it looks like a brand/login link but goes to different domain
              if ((hasBrandTerm || hasLoginTerm) && !linkDomainLower.includes(displayedText.replace(/\s+/g, ''))) {
                const key = `Link Mismatch / Phishing-${url}-0-${link}`;
                if (!seen.has(key)) {
                  seen.add(key);
                  threats.push(new Threat('Link Mismatch / Phishing', 'medium', url, 0, `Link displays '${linkMatch[1]}' but points to '${linkDomain}'`, link));
                }
              }
            }
          }
        }
      } catch (e) {
        // Invalid URL, skip
      }
    });
    
    return threats;
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { Threat, RiskScorer, MalwareDetector, PhishingDetector, SuspiciousLinkDetector };
}
