"""
HeuristiX Display Module
Handles ASCII art logo, colored console output, and logging utilities.
"""

import sys
import os
from colorama import init, Fore, Style, Back

# Initialize colorama for cross-platform support
init(autoreset=True)


class Colors:
    """Color constants for HeuristiX output."""
    BRIGHT_GREEN = Fore.LIGHTGREEN_EX
    GREEN = Fore.GREEN
    RED = Fore.RED
    BRIGHT_RED = Fore.LIGHTRED_EX
    YELLOW = Fore.YELLOW
    BRIGHT_YELLOW = Fore.LIGHTYELLOW_EX
    CYAN = Fore.CYAN
    BRIGHT_CYAN = Fore.LIGHTCYAN_EX
    WHITE = Fore.WHITE
    DIM = Fore.LIGHTBLACK_EX
    RESET = Style.RESET_ALL


HEURISTIX_LOGO = f"""
{Colors.BRIGHT_GREEN}
    ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗███╗   ██╗ ██████╗ 
    ██║ ██╔╝██╔══██╗██╔════╝██║ ██╔╝██╔════╝████╗  ██║██╔═══██╗
    █████╔╝ ███████║██║     █████╔╝ █████╗  ██╔██╗ ██║██║   ██║
    ██╔═██╗ ██╔══██║██║     ██╔═██╗ ██╔══╝  ██║╚██╗██║██║   ██║
    ██║  ██╗██║  ██║╚██████╗██║  ██╗███████╗██║ ╚████║╚██████╔╝
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ 
{Colors.GREEN}
                    Advanced Web Security Scanner
{Colors.BRIGHT_GREEN}
                           v1.0 - HeuristiX
{Colors.RESET}
"""

REMEDIATION_GUIDE = {
    'Malicious Script': {
        'critical': [
            'Remove the malicious script immediately',
            'Scan all files for similar patterns',
            'Check for unauthorized code changes',
            'Review access logs for intrusions',
            'Consider rebuilding from clean backup'
        ],
        'high': [
            'Review and remove suspicious code',
            'Verify the source of the script',
            'Check if code is necessary for functionality',
            'Sanitize user inputs if script processes data'
        ],
        'medium': [
            'Review code for potential security issues',
            'Consider if functionality can be replaced with safer alternatives',
            'Add input validation if script processes user data'
        ],
        'low': [
            'Monitor for changes in this code',
            'Document why this pattern exists'
        ]
    },
    'Secret Leak': {
        'critical': [
            'Rotate all exposed secrets immediately',
            'Revoke compromised API keys and tokens',
            'Check for unauthorized access using these credentials',
            'Remove secrets from code and use environment variables',
            'Scan entire codebase for other secrets'
        ],
        'high': [
            'Rotate exposed credentials',
            'Move secrets to secure vault (e.g., AWS Secrets Manager, HashiCorp Vault)',
            'Implement secret scanning in CI/CD pipeline'
        ],
        'medium': [
            'Review if secret is still valid',
            'Consider using environment variables',
            'Add to .gitignore if in repository'
        ],
        'low': [
            'Investigate if this is a false positive',
            'Document the purpose of the secret'
        ]
    },
    'WebAssembly': {
        'critical': [
            'Review WASM binary for malicious code',
            'Check if WASM is from trusted source',
            'Consider blocking WASM execution if not needed'
        ],
        'high': [
            'Verify WASM source and purpose',
            'Check for obfuscated WASM code',
            'Review if WASM functionality is necessary'
        ],
        'medium': [
            'Monitor WASM execution',
            'Document WASM usage and purpose'
        ],
        'low': [
            'Review if WASM can be replaced with JavaScript'
        ]
    },
    'Missing Security Header': {
        'critical': [
            'Add Content-Security-Policy header immediately',
            'Add Strict-Transport-Security header for HTTPS sites',
            'Review and implement all security headers'
        ],
        'high': [
            'Add missing security headers',
            'Configure headers with appropriate values',
            'Test headers with security scanners'
        ],
        'medium': [
            'Add recommended security headers',
            'Review OWASP security header guidelines'
        ],
        'low': [
            'Consider adding optional security headers'
        ]
    },
    'Phishing': {
        'critical': [
            'Block access to this site',
            'Report to phishing reporting services',
            'Warn all users who may have visited',
            'Investigate source of phishing link'
        ],
        'high': [
            'Verify site legitimacy before proceeding',
            'Do not enter any credentials',
            'Report to security team'
        ],
        'medium': [
            'Review site carefully for signs of phishing',
            'Check URL for typosquatting',
            'Verify SSL certificate'
        ],
        'low': [
            'Be cautious with this site',
            'Verify site authenticity'
        ]
    },
    'Brand Impersonation': {
        'critical': [
            'Report to brand owner',
            'Block access to impersonating site',
            'Check for similar domains'
        ],
        'high': [
            'Verify if this is legitimate or impersonation',
            'Contact brand owner if unsure',
            'Do not provide sensitive information'
        ],
        'medium': [
            'Review domain for typosquatting',
            'Check SSL certificate issuer'
        ],
        'low': [
            'Be cautious with brand similarity'
        ]
    },
    'Credential Harvesting': {
        'critical': [
            'Block the site immediately',
            'Do not enter any credentials',
            'Report to security team',
            'Check if you have already submitted credentials'
        ],
        'high': [
            'Verify site legitimacy before entering credentials',
            'Check URL carefully',
            'Look for security indicators'
        ],
        'medium': [
            'Review form for suspicious fields',
            'Check if SSL is present'
        ],
        'low': [
            'Be cautious with login forms'
        ]
    },
    'External Payload': {
        'critical': [
            'Do not download or execute the file',
            'Scan the file with antivirus',
            'Block the domain hosting the file'
        ],
        'high': [
            'Verify file source before downloading',
            'Scan file with multiple antivirus engines',
            'Check file hash against threat intelligence'
        ],
        'medium': [
            'Review file type and purpose',
            'Check if download is necessary'
        ],
        'low': [
            'Be cautious with external file downloads'
        ]
    }
}

def get_remediation_steps(threat_type: str, severity: str) -> list:
    """Get remediation steps for a specific threat type and severity."""
    if threat_type not in REMEDIATION_GUIDE:
        return ['Review the threat and consult security team']
    
    severity_steps = REMEDIATION_GUIDE[threat_type].get(severity, [])
    if not severity_steps:
        # Fall back to lower severity steps
        for sev in ['low', 'medium', 'high', 'critical']:
            if sev in REMEDIATION_GUIDE[threat_type]:
                return REMEDIATION_GUIDE[threat_type][sev]
    
    return severity_steps


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_logo():
    """Print the HeuristiX ASCII logo in vibrant green."""
    clear_screen()
    print(HEURISTIX_LOGO)


def print_status(message: str, color: str = Colors.WHITE):
    """Print a status message with the specified color."""
    print(f"{color}[+] {message}{Colors.RESET}")


def print_startup_sequence():
    """Print the HeuristiX startup sequence with loading messages."""
    print_logo()
    print_status("Initializing HeuristiX Engine...", Colors.WHITE)
    print_status("Loading behavioral modules...", Colors.WHITE)
    print_status("Loading malware detection patterns...", Colors.DIM)
    print_status("Loading phishing detection rules...", Colors.DIM)
    print_status("Configuring stealth mode...", Colors.DIM)
    print_status("Engine ready. Awaiting Target URL...", Colors.BRIGHT_GREEN)
    print()


def log_info(message: str):
    """Log an INFO message in white."""
    print(f"{Colors.CYAN}[INFO]{Colors.WHITE} {message}{Colors.RESET}")


def log_warning(message: str):
    """Log a WARNING message in yellow."""
    print(f"{Colors.YELLOW}[WARN]{Colors.WHITE} {message}{Colors.RESET}")


def log_error(message: str):
    """Log an ERROR message in red."""
    print(f"{Colors.RED}[ERROR]{Colors.WHITE} {message}{Colors.RESET}")


def log_critical(message: str):
    """Log a CRITICAL message in bright red."""
    print(f"{Colors.BRIGHT_RED}[CRITICAL]{Colors.WHITE} {message}{Colors.RESET}")


def log_threat(severity: str, message: str):
    """Log a threat with color based on severity."""
    if severity.lower() == 'critical':
        print(f"{Colors.BRIGHT_RED}[CRITICAL THREAT]{Colors.WHITE} {message}{Colors.RESET}")
    elif severity.lower() == 'high':
        print(f"{Colors.YELLOW}[HIGH THREAT]{Colors.WHITE} {message}{Colors.RESET}")
    elif severity.lower() == 'medium':
        print(f"{Colors.BRIGHT_YELLOW}[MEDIUM THREAT]{Colors.WHITE} {message}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[LOW THREAT]{Colors.WHITE} {message}{Colors.RESET}")


def log_scan_start(url: str, max_pages: int, max_depth: int, stealth_mode: bool = False):
    """Log the start of a scan."""
    print()
    print_status(f"Starting scan: {url}", Colors.BRIGHT_CYAN)
    print_status(f"Max Pages: {max_pages} | Depth: {max_depth} | Stealth: {'ON' if stealth_mode else 'OFF'}", Colors.DIM)
    print()


def log_scan_complete(score: int, verdict: str, confidence: int = 0):
    """Log the completion of a scan."""
    color = Colors.BRIGHT_GREEN if score > 70 else Colors.YELLOW if score > 50 else Colors.BRIGHT_RED
    print_status(f"Scan Complete - Score: {score}/100 - {verdict}", color)
    if confidence > 0:
        conf_color = Colors.BRIGHT_RED if confidence >= 85 else Colors.YELLOW if confidence >= 60 else Colors.GREEN
        print_status(f"Confidence: {confidence}% - {'High Probability of Malice' if confidence >= 85 else 'Moderate Probability of Malice' if confidence >= 60 else 'Low Probability of Malice'}", conf_color)
    print()
