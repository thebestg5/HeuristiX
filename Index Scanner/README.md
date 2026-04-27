# HeuristiX

HeuristiX is a smart security scanner that checks websites for bad things. It crawls a site and finds malware, phishing pages, dangerous links, and other threats. Think of it like a security guard that checks every door and window of a website to make sure nothing is hiding.

## What It Does

HeuristiX does many things to keep you safe:

- **Crawls Websites**: It visits every page on a site, following links like a person would, but much faster.
- **Finds Malware**: It looks for bad code that could hurt your computer, like crypto miners or sneaky scripts.
- **Detects Phishing**: It spots fake pages that try to steal your passwords or pretend to be real companies.
- **Checks Links**: It examines every link to see if it goes somewhere dangerous or suspicious.
- **Analyzes Files**: It downloads and checks all the files a site uses (HTML, JavaScript, etc.) to find hidden threats.
- **Shows Results**: It gives you a clear score (0-100) and tells you exactly what's wrong, in simple words.

## Key Features

### 🎯 Smart Detection
- **External Payload Check**: Finds links to dangerous files (.exe, .zip, .sh, .msi, .iso, .img) on other websites
- **Base64 Decoder**: Reads secret coded text and checks if it hides bad stuff
- **Sensitive Data Leak**: Finds when developers accidentally left passwords or secrets in the code
- **Brand Impersonation**: Spots when a site pretends to be a famous company
- **Credential Harvesting**: Detects fake login forms that steal your information

### 📊 Easy-to-Understand Results
- **Risk Score (0-100)**: Green means safe, yellow means be careful, red means dangerous
- **Simple Verdicts**: "Safe", "Moderate Risk", "High Risk", "Very Dangerous", "Dangerous Phishing Site"
- **Threat List**: Shows every problem found, with severity levels (Critical, High, Medium, Low)

### 🔍 Deep Inspection
- **Download Files**: You can download every file the scanner found to check it yourself
- **View All Links**: See every link the crawler discovered
- **Dangerous Sites List**: A special section showing all recently scanned dangerous sites

### 🚀 Fast & Smart
- **Parallel Crawling**: Visits many pages at once to save time
- **Googlebot Mode**: Pretends to be Google's crawler so bad sites show their true colors
- **SSL Bypass**: Can check sites with broken security certificates (common with phishing sites)
- **Persistent History**: Your scan results are saved and loaded when you restart the tool

## How to Install

### Option A: Docker (Recommended for Security Isolation)

**Why use Docker?** HeuristiX downloads files from potentially malicious websites and visits phishing/malware sites. Running it in a Docker container ensures that if a scanned site attempts to exploit the scanner, it will only affect the isolated container - not your host system.

#### Prerequisites
- Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) for Windows

#### Quick Start with Docker
1. **Navigate to the project folder**:
   ```bash
   cd "C:\Users\Usuario\Desktop\Index Scanner"
   ```

2. **Build and run with Docker Compose**:
   ```bash
   docker-compose up --build
   ```

3. **Open Your Browser**: Go to `http://127.0.0.1:5000`

4. **Stop the scanner** when done:
   ```bash
   docker-compose down
   ```

#### Docker Security Features
The Docker configuration includes:
- **Non-root user**: Scanner runs as a limited user inside the container
- **Read-only filesystem**: Prevents malware from modifying the container
- **Resource limits**: CPU and memory limits prevent container abuse
- **Dropped capabilities**: Minimal Linux capabilities for reduced attack surface
- **No new privileges**: Container cannot gain additional permissions

#### Manual Docker Build (Alternative)
```bash
# Build the image
docker build -t heuristix .

# Run the container
docker run -d -p 5000:5000 -v "$(pwd)/reports:/app/reports" --name heuristix-scanner heuristix

# Stop the container
docker stop heuristix-scanner
docker rm heuristix-scanner
```

#### Ephemeral Mode (No Report Persistence)
If you want complete isolation without saving reports to your host:
```bash
docker run -d -p 5000:5000 --read-only --tmpfs /app/reports --name heuristix-scanner heuristix
```
This mode stores reports only in the container's temporary memory - they're deleted when the container stops.

---

### Option B: Local Python Installation

### 1. Install Python
Download Python 3.10 or newer from [python.org](https://www.python.org/downloads/).  
**Important**: During installation on Windows, check the box that says "Add Python to PATH".

### 2. Open the Project Folder
Open a terminal (Command Prompt or PowerShell) and go to the HeuristiX folder:
```bash
cd "C:\Users\Usuario\Desktop\Index Scanner"
```

### 3. Create a Virtual Environment (Recommended)
This keeps HeuristiX separate from your other Python projects:
```bash
python -m venv venv
```

### 4. Activate the Virtual Environment
- **Windows PowerShell**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **Windows Command Prompt**:
  ```cmd
  venv\Scripts\activate.bat
  ```
- **Linux / macOS**:
  ```bash
  source venv/bin/activate
  ```

### 5. Install Dependencies
```bash
pip install -r requirements.txt
```

This installs everything HeuristiX needs to work.

### 6. Initialize the Domain Database (One-Time)
```bash
python -c "import tldextract; tldextract.TLDExtract().extract('example.com')"
```
This downloads a list of website endings (like .com, .org) so HeuristiX works faster.

### 7. Check It Works
```bash
python -c "from scanner import FileAnalyzer; print('OK')"
```
If you see "OK", you're ready to go!

## How to Use

### Web Dashboard (Easiest Way)

#### If Using Docker
1. **Start HeuristiX**:
   ```bash
   docker-compose up --build
   ```

2. **Open Your Browser**: Go to `http://127.0.0.1:5000`

3. **Stop when done**:
   ```bash
   docker-compose down
   ```

#### If Using Local Python
1. **Start HeuristiX**:
   ```bash
   python app.py
   ```

2. **Open Your Browser**: Go to `http://127.0.0.1:5000`

3. **Enter a Website**: Type the URL you want to check (like `https://example.com`)

4. **Click "Start Scan"**: Wait for it to finish

5. **See the Results**:
   - The score tells you how safe the site is
   - Green (71-100) = Safe
   - Yellow (51-70) = Be careful
   - Red (0-50) = Dangerous
   - Click on tabs to see discovered files and links
   - Check the "Dangerous Sites Reported Recently" section for bad sites you've scanned

### Command Line (For Advanced Users)

```bash
# Basic scan
python cli.py example.com --pages 30 --depth 2 --format both

# Quick scan, JSON only
python cli.py example.com --pages 10 --depth 1 --format json

# Deep scan, HTML report only
python cli.py example.com --pages 100 --depth 3 --format html
```

## Understanding the Results

### Risk Score
- **71-100 (Green)**: The site is safe. No major problems found.
- **51-70 (Yellow)**: The site has some suspicious things. Be careful.
- **0-50 (Red)**: The site is dangerous. Do not trust it.

### Threat Severity
- **Critical**: Very dangerous, like known malware or active attacks
- **High**: Serious problems, like phishing or credential stealing
- **Medium**: Suspicious patterns that need attention
- **Low**: Minor issues, probably not a big deal

### Special Features
- **Discovered Files**: Download any file the scanner found to check it yourself
- **Discovered Links**: See every link on the site to verify them manually
- **Dangerous Sites**: A list of all bad sites you've scanned recently

## How It Works (Simple Explanation)

HeuristiX works like a very careful security inspector:

1. **Visits the Website**: It goes to the site you tell it to check
2. **Follows Links**: It clicks on links to find other pages on the same site
3. **Downloads Files**: It gets all the files the site uses (HTML, JavaScript, etc.)
4. **Reads the Code**: It looks through all the code for bad patterns
5. **Checks Links**: It examines every link to see if it goes somewhere safe
6. **Scores the Site**: It gives the site a safety score based on what it found
7. **Shows You the Report**: It tells you exactly what problems it found

## What Makes HeuristiX Special

- **Googlebot Mode**: Many bad sites show clean code to normal browsers but show malware to search engines. HeuristiX pretends to be Google's crawler so the bad sites reveal their true nature.
- **SSL Bypass**: Phishing sites often have broken security certificates. HeuristiX can still check them anyway.
- **Base64 Decoding**: Bad guys sometimes hide malicious code in secret coded text. HeuristiX decodes it and checks what's inside.
- **CDN Whitelist**: It knows that links to GitHub, Google, Microsoft, etc. are usually safe, so it doesn't falsely flag them as dangerous.
- **Password Placeholder Detection**: It can tell the difference between a real password and a placeholder like "REPLACEME".

## Project Structure

```
Index Scanner/
├── app.py                    # Web server (the dashboard)
├── cli.py                    # Command-line tool
├── requirements.txt          # All the Python packages needed
├── scanner/
│   ├── __init__.py           # Package file
│   ├── crawler.py            # The part that visits websites
│   ├── analyzer.py           # The part that runs all the checks
│   ├── detectors.py          # The specific threat detectors
│   └── reporter.py           # Creates the reports
├── templates/
│   └── index.html            # The web dashboard you see
└── reports/                  # Where scan results are saved
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'scanner'"
Make sure you're running commands from the main folder (`Index Scanner/`), not from inside the `scanner/` folder.

### "SyntaxError" or weird errors
You need Python 3.10 or newer. Check with `python --version`.

### First scan is very slow
Run the domain database initialization step (Step 6 above). It only needs to be done once.

### Cannot reach a site that works in my browser
HeuristiX uses Googlebot's identity. Some sites block bots. You can change this in `scanner/crawler.py` if needed.

## Legal & Ethical Notice

HeuristiX is for **security research and authorized testing only**.
## License

MIT License – use responsibly and ethically.

