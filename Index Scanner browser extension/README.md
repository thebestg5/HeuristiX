# HeuristiX Chrome Extension

A Chrome extension that scans websites for security threats including malware, phishing, and suspicious links. **Works standalone - no external scanner required.**

## How It Works

The extension runs the full HeuristiX detection engine directly in JavaScript within your browser. It:
- Extracts page content (HTML, scripts, links, forms)
- Analyzes inline scripts for malware patterns
- Detects phishing indicators and brand impersonation
- Checks for suspicious links and external payloads
- Calculates a risk score (0-100) with confidence rating

**No Python installation or external scanner needed** - everything runs in the extension.

## Installation

### Step 1: Generate Extension Icons

The extension needs PNG icons. Run the icon generator:

```bash
cd "C:\Users\Usuario\Desktop\Index Scanner browser extension"
pip install pillow svglib
python generate_icons.py
```

This will create `icon16.png`, `icon48.png`, and `icon128.png` in the `icons/` folder.

### Step 2: Load Extension in Chrome

1. Open Chrome
2. Navigate to `chrome://extensions/`
3. Enable **Developer mode** (toggle in top-right corner)
4. Click **Load unpacked**
5. Select the folder: `C:\Users\Usuario\Desktop\Index Scanner browser extension`
6. The extension will appear in your extensions list

### Optional: Package as .CRX File (For distribution)

To create a .crx file for sharing:

1. Open Chrome
2. Navigate to `chrome://extensions/`
3. Enable **Developer mode**
4. Click **Pack extension**
5. Select the folder: `C:\Users\Usuario\Desktop\Index Scanner browser extension`
6. Chrome will create `heuristix.crx` in the same folder

To install the .crx file, drag and drop it into `chrome://extensions/`

## Usage

1. Navigate to any website in Chrome
2. Click the HeuristiX extension icon (🛡️) in the toolbar
3. Click **"Scan Site"** button
4. Wait for the scan to complete (usually 1-3 seconds)
5. View the security score, verdict, and any detected threats

## Features

- **One-click scanning**: Scan any website directly from your browser
- **Real-time results**: Displays security score (0-100) and verdict
- **Threat details**: Shows all detected threats with severity levels
- **No setup required**: Works immediately after installation
- **Context menu**: Right-click on any page to scan
- **Same detection logic**: Uses the exact same patterns as the Python version

## Detection Capabilities

### Malware Detection
- ActiveX exploitation attempts
- Cryptocurrency mining scripts
- Dynamic code execution (eval)
- Obfuscated payloads (Base64, hex, unicode)
- Script injection patterns
- Known malicious domain references
- External executable file links (.exe, .zip, .sh, etc.)
- Sensitive data leaks (API keys, passwords, tokens)

### Phishing Detection
- Suspicious TLD detection (.tk, .ml, .ga, etc.)
- Form submits to IP addresses
- Password forms on untrusted domains
- Brand impersonation detection
- Cross-domain form actions

### Link Analysis
- URL shortener detection
- Suspicious keyword detection
- Link mismatch / phishing indicators
- Cross-domain link analysis

## Risk Scoring

- **71-100 (Green)**: Safe - No major threats found
- **51-70 (Yellow)**: Moderate Risk - Some suspicious patterns
- **26-50 (Orange)**: High Risk - Multiple threats detected
- **1-25 (Red)**: Very Dangerous - Severe threats
- **0 (Dark Red)**: Dangerous Phishing Site

## Architecture

```
Chrome Extension (popup.js)
    ↓
Content Script (content.js) - Extracts page data
    ↓
Scanner Engine (scanner.js) - JavaScript port of Python detector
    ↓
Results Display (popup.html)
```

All detection logic is ported from the Python version to JavaScript, maintaining identical behavior.

## Differences from Python Version

The Chrome extension version:
- **Scans only the current page** (not multi-page crawling)
- **Analyzes inline scripts only** (external scripts are not fetched due to CORS)
- **Runs entirely in the browser** (no external dependencies)
- **Faster for single-page scans** (no network overhead)

For full multi-page crawling and external script analysis, use the Python version with Docker isolation.

## Troubleshooting

### Icons not showing

- Run `python generate_icons.py` to create PNG icons
- Make sure you have `pillow` and `cairosvg` installed

### Scan fails with "Failed to get page content"

- Refresh the page and try again
- Some pages may block content script injection
- Try on a different page

### Extension not loading

- Check Chrome console for errors (chrome://extensions → Errors)
- Make sure all files are in the correct folder
- Try reloading the extension

## Security Notes

- All scanning happens locally in your browser
- No data is sent to external servers
- No internet connection required for scanning
- The extension only has access to the active tab
- Content scripts run in an isolated world

## Development

To modify the extension:

1. Edit the files in this directory
2. Go to `chrome://extensions/`
3. Click the **Refresh** icon on the HeuristiX extension card
4. Changes will take effect immediately

## License

MIT License - Same as HeuristiX scanner
