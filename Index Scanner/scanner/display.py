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
