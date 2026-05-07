"""
╔══════════════════════════════════════════════════════════════╗
║           NetSentinel — AI-Powered Network Security Tool     ║
║            Year Project | v2.0                   ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import datetime
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich import box
from langchain_groq import ChatGroq

# Simple conversation memory (no langchain.memory dependency)
class SimpleMemory:
    def __init__(self, k=10):
        self.k = k
        self.messages = []  # list of {"role": "user"/"assistant", "content": str}

    def add_user_message(self, text):
        self.messages.append({"role": "user", "content": text})
        self._trim()

    def add_ai_message(self, text):
        self.messages.append({"role": "assistant", "content": text})
        self._trim()

    def _trim(self):
        # Keep last k*2 messages (k exchanges)
        if len(self.messages) > self.k * 2:
            self.messages = self.messages[-(self.k * 2):]

    def get_messages(self):
        return self.messages

from Scanner import scan_ports, grab_banner
from Network import ping_host, get_network_info, traceroute
from Logs import analyze_logs
from Vuln import detect_vulnerability, check_ssl
from Report import generate_report

# ─────────────────────────────────────────────
#  INIT
# ─────────────────────────────────────────────
load_dotenv()
console = Console()

API_KEY = os.getenv("GROQ_API_KEY")
if not API_KEY:
    console.print("[bold red]❌ ERROR:[/bold red] GROQ_API_KEY not found in .env file")
    sys.exit(1)

llm = ChatGroq(
    groq_api_key=API_KEY,
    model_name="llama-3.1-8b-instant",
    temperature=0.3
)

# Conversation memory (last 10 exchanges)
memory = SimpleMemory(k=10)

# Session log for report generation
session_log = []

SYSTEM_PROMPT = """You are NetSentinel, an expert AI cybersecurity assistant. 
You help with network security, vulnerability analysis, threat intelligence, 
port scanning interpretation, and general cybersecurity questions.
Be concise, technical, and professional. Format important info clearly."""

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
def print_banner():
    banner = """
 ███╗   ██╗███████╗████████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ██╔██╗ ██║█████╗     ██║       ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ██║╚██╗██║██╔══╝     ██║       ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ██║ ╚████║███████╗   ██║       ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print(
        Panel.fit(
            "[bold white]AI-Powered Network Security & Reconnaissance Tool[/bold white]\ by Faisal Mushtaq n"
            "[dim]| Powered by Groq LLaMA 3.1 + LangChain[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

# ─────────────────────────────────────────────
#  HELP TABLE
# ─────────────────────────────────────────────
def print_help():
    table = Table(title="📋 Available Commands", box=box.ROUNDED, border_style="cyan")
    table.add_column("Command", style="bold yellow", width=35)
    table.add_column("Description", style="white")
    table.add_column("Example", style="dim green")

    commands = [
        ("scan ports <ip>",         "TCP port scan (20–1024)",        "scan ports 192.168.8.8"),
        ("deep scan <ip>",          "Port scan + banner grabbing",    "deep scan 192.168.8.1"),
        ("ping <host>",             "ICMP ping test",                 "ping google.com"),
        ("traceroute <host>",       "Hop-by-hop trace",               "traceroute 8.8.8.8"),
        ("network info",            "Local network details",          "network info"),
        ("check ssl <domain>",      "SSL/TLS certificate check",      "check ssl google.com"),
        ("analyze log <text>",      "AI log threat analysis",         "analyze log <paste log>"),
        ("vuln check",              "Basic vulnerability audit",      "vuln check"),
        ("generate report",         "Export session as JSON report",  "generate report"),
        ("history",                 "Show conversation history",      "history"),
        ("clear",                   "Clear screen",                   "clear"),
        ("help",                    "Show this menu",                 "help"),
        ("exit / quit",             "Exit NetSentinel",               "exit"),
    ]
    for cmd, desc, ex in commands:
        table.add_row(cmd, desc, ex)

    console.print(table)
    console.print("[dim]💡 Any other input is sent to the AI assistant.[/dim]\n")

# ─────────────────────────────────────────────
#  AI CHAT (with memory)
# ─────────────────────────────────────────────
def ask_ai(query: str) -> str:
    # Build message list with memory
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(memory.get_messages())
    messages.append({"role": "user", "content": query})

    response = llm.invoke(messages)
    answer = response.content

    # Save to memory
    memory.add_user_message(query)
    memory.add_ai_message(answer)

    return answer

# ─────────────────────────────────────────────
#  COMMAND ROUTER
# ─────────────────────────────────────────────
def route_command(query: str) -> str:
    q = query.strip().lower()
    parts = query.strip().split()

    # CREATOR / IDENTITY
    if any(phrase in q for phrase in [
        "who built you", "who made you", "who created you",
        "who developed you", "who is your creator", "who are you made by",
        "who designed you", "your developer", "your creator", "your maker","who buid you"
    ]):
        return (
            "🛡️ I am [bold cyan]NetSentinel v2.0[/bold cyan] — an AI-powered network security assistant.\n\n"
            "👨‍💻 Built by [bold green]Faisal[/bold green].\n"
            "⚡ Powered by Groq LLaMA 3.1 + LangChain + Python."
        )

    # PORT SCAN
    elif q.startswith("scan port") or (q.startswith("scan") and "port" in q):
        ip = parts[-1]
        with console.status(f"[cyan]Scanning ports on {ip}...[/cyan]", spinner="dots"):
            results = scan_ports(ip)
        return _format_port_results(ip, results)

    # DEEP SCAN (ports + banners)
    elif q.startswith("deep scan"):
        ip = parts[-1]
        with console.status(f"[cyan]Deep scanning {ip}...[/cyan]", spinner="dots"):
            results = scan_ports(ip)
            banners = {p: grab_banner(ip, p) for p in results[:10]}
        return _format_deep_scan(ip, results, banners)

    # PING
    elif q.startswith("ping"):
        host = parts[-1]
        with console.status(f"[cyan]Pinging {host}...[/cyan]", spinner="dots"):
            result = ping_host(host)
        return result

    # TRACEROUTE
    elif q.startswith("traceroute") or q.startswith("trace"):
        host = parts[-1]
        with console.status(f"[cyan]Tracing route to {host}...[/cyan]", spinner="dots"):
            result = traceroute(host)
        return result

    # NETWORK INFO
    elif "network info" in q or "my network" in q:
        with console.status("[cyan]Gathering network info...[/cyan]", spinner="dots"):
            result = get_network_info()
        return result

    # SSL CHECK
    elif q.startswith("check ssl") or q.startswith("ssl"):
        domain = parts[-1]
        with console.status(f"[cyan]Checking SSL for {domain}...[/cyan]", spinner="dots"):
            result = check_ssl(domain)
        return result

    # LOG ANALYSIS
    elif q.startswith("analyze log"):
        log_text = query[len("analyze log"):].strip()
        if not log_text:
            return "❌ Please provide log text after 'analyze log'"
        local = analyze_logs(log_text)
        ai_analysis = ask_ai(f"Analyze this log entry for threats:\n{log_text}")
        return f"{local}\n\n🤖 AI Analysis:\n{ai_analysis}"

    # VULNERABILITY CHECK
    elif "vuln check" in q or "vulnerability" in q:
        with console.status("[cyan]Running vulnerability audit...[/cyan]", spinner="dots"):
            result = detect_vulnerability()
        return result

    # GENERATE REPORT
    elif q.startswith("generate report"):
        path = generate_report(session_log)
        return f"✅ Report saved to: [bold green]{path}[/bold green]"

    # HISTORY
    elif q == "history":
        return _format_history()

    # CLEAR
    elif q == "clear":
        console.clear()
        print_banner()
        return ""

    # HELP
    elif q == "help":
        print_help()
        return ""

    # AI FALLBACK
    else:
        with console.status("[cyan]Thinking...[/cyan]", spinner="dots"):
            return ask_ai(query)

# ─────────────────────────────────────────────
#  FORMATTERS
# ─────────────────────────────────────────────
def _format_port_results(ip: str, ports: list) -> str:
    if not ports:
        return f"[yellow]No open ports found on {ip}[/yellow]"

    table = Table(title=f"🔍 Open Ports — {ip}", box=box.SIMPLE_HEAVY, border_style="green")
    table.add_column("Port", style="bold cyan", justify="center")
    table.add_column("Service", style="white")
    table.add_column("Risk", style="bold")

    service_map = {
        21: ("FTP", "🔴 High"),
        22: ("SSH", "🟡 Medium"),
        23: ("Telnet", "🔴 High"),
        25: ("SMTP", "🟡 Medium"),
        53: ("DNS", "🟢 Low"),
        80: ("HTTP", "🟡 Medium"),
        110: ("POP3", "🟡 Medium"),
        143: ("IMAP", "🟡 Medium"),
        443: ("HTTPS", "🟢 Low"),
        445: ("SMB", "🔴 High"),
        3306: ("MySQL", "🔴 High"),
        3389: ("RDP", "🔴 High"),
        8080: ("HTTP-Alt", "🟡 Medium"),
    }

    for p in ports:
        svc, risk = service_map.get(p, ("Unknown", "⚪ Unknown"))
        table.add_row(str(p), svc, risk)

    # Convert table to string for logging - we'll print it directly
    console.print(table)
    return f"Found [bold green]{len(ports)}[/bold green] open ports."

def _format_deep_scan(ip: str, ports: list, banners: dict) -> str:
    _format_port_results(ip, ports)
    if banners:
        console.print("\n[bold yellow]📌 Service Banners:[/bold yellow]")
        for port, banner in banners.items():
            if banner:
                console.print(f"  Port [cyan]{port}[/cyan]: [dim]{banner[:80]}[/dim]")
    return f"Deep scan complete. Grabbed banners for {len(banners)} ports."

def _format_history():
    msgs = memory.get_messages()
    if not msgs:
        return "No conversation history yet."
    lines = []
    for msg in msgs[-10:]:
        role = "You" if msg["role"] == "user" else "AI"
        color = "cyan" if role == "You" else "green"
        lines.append(f"[bold {color}]{role}:[/bold {color}] {msg['content'][:120]}...")
    return "\n".join(lines)

# ─────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────
def main():
    console.clear()
    print_banner()
    console.print(
        "[dim]Type [bold white]help[/bold white] to see commands, "
        "[bold white]exit[/bold white] to quit.[/dim]\n"
    )

    while True:
        try:
            query = Prompt.ask("[bold cyan]NetSentinel[/bold cyan]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow]👋 Exiting NetSentinel. Stay secure![/bold yellow]")
            break

        if not query:
            continue

        if query.lower() in ("exit", "quit", "q"):
            console.print("[bold yellow]👋 Exiting NetSentinel. Stay secure![/bold yellow]")
            break

        # Log the query
        session_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "query": query,
        })

        try:
            result = route_command(query)
            if result:
                console.print(
                    Panel(
                        result,
                        border_style="dim green",
                        padding=(0, 1),
                    )
                )
                session_log[-1]["result"] = result
        except Exception as e:
            console.print(f"[bold red]❌ Error:[/bold red] {str(e)}")

        console.print()

if __name__ == "__main__":
    main()
