#!/usr/bin/env python3
"""
vlair shell - Interactive REPL for the vlair security toolkit.

Provides a persistent prompt so analysts can run multiple commands in one
session without re-typing 'vlair' each time.

    $ vlair shell
    vlair> analyze suspicious.eml
    vlair> check hash 44d88612fea8a8f36de82e1278abb02f
    vlair> workflow phishing-email report.eml --verbose
    vlair> exit
"""

import cmd
import os
import shlex
import sys
from pathlib import Path


# ── ANSI colours (stripped when not a TTY) ───────────────────────────────────
def _c(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


BANNER = """
  ██╗   ██╗██╗      █████╗ ██╗██████╗
  ██║   ██║██║     ██╔══██╗██║██╔══██╗
  ██║   ██║██║     ███████║██║██████╔╝
  ╚██╗ ██╔╝██║     ██╔══██║██║██╔══██╗
   ╚████╔╝ ███████╗██║  ██║██║██║  ██║
    ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝

  Security Operations Toolkit — interactive shell
  Type  help  for commands,  exit  to quit.
"""

HELP_TEXT = """\
Commands
────────────────────────────────────────────────────────────
  analyze  <input>                Auto-detect and analyze input
  check    <type> <value>         Quick indicator lookup
  workflow <name> <input>         Run a pre-built workflow
  investigate <subcommand>        Automated investigation engine

Individual tools
  eml  ioc  hash  intel  log  pcap  url  yara  cert
  deobfuscate  feeds  carve

Discovery
  list                            List all available tools
  search  <keyword>               Search tools by keyword
  info    <tool>                  Show tool documentation
  status                          API keys, cache, history

Shell
  help  [command]                 Show this help or per-command help
  exit | quit | Ctrl-D            Leave the shell

Examples
────────────────────────────────────────────────────────────
  analyze suspicious.eml
  analyze 44d88612fea8a8f36de82e1278abb02f
  check domain malicious.com
  workflow phishing-email report.eml --verbose
  investigate phishing --file report.eml --mock
  hash 44d88612fea8a8f36de82e1278abb02f
  intel 1.2.3.4

Use Up / Down arrows to navigate history.
"""


class VlairShell(cmd.Cmd):
    """Interactive REPL shell for vlair."""

    intro = ""  # printed after cmdloop() starts; we print the banner ourselves
    prompt = _c("1;36", "vlair") + "> "

    # ── History ──────────────────────────────────────────────────────────────

    def preloop(self):
        print(_c("1;36", BANNER))
        self._load_history()

    def postloop(self):
        self._save_history()

    def _history_path(self) -> Path:
        return Path.home() / ".vlair_history"

    def _load_history(self):
        try:
            import readline

            history = self._history_path()
            if history.exists():
                readline.read_history_file(str(history))
            readline.set_history_length(500)
        except (ImportError, OSError):
            pass

    def _save_history(self):
        try:
            import readline

            readline.write_history_file(str(self._history_path()))
        except (ImportError, OSError):
            pass

    # ── Dispatcher ───────────────────────────────────────────────────────────

    def _dispatch(self, argv: list):
        """
        Set sys.argv to ['vlair'] + argv and call the main CLI entry point,
        catching SystemExit so the shell keeps running.
        """
        from vlair.cli.main import main

        old_argv = sys.argv
        sys.argv = ["vlair"] + argv
        try:
            main()
        except SystemExit:
            pass
        finally:
            sys.argv = old_argv

    def _split(self, args: str) -> list:
        """Parse a shell-style argument string; report errors inline."""
        try:
            return shlex.split(args)
        except ValueError as exc:
            print(f"Parse error: {exc}", file=sys.stderr)
            return []

    # ── Fallback for bare tool names (e.g. 'eml foo.eml') ───────────────────

    def default(self, line: str):
        parts = self._split(line)
        if parts:
            self._dispatch(parts)

    # ── Smart commands ────────────────────────────────────────────────────────

    def do_analyze(self, args: str):
        """Auto-detect input type and run the appropriate analysis.

        Usage:  analyze <input> [--verbose] [--json] [--quiet] [--report html|md]

        Examples:
          analyze suspicious.eml
          analyze 44d88612fea8a8f36de82e1278abb02f
          analyze malicious.com --verbose
          analyze capture.pcap --json"""
        parts = self._split(args)
        if not parts:
            print("Usage: analyze <input>  (see 'help analyze')")
            return
        self._dispatch(["analyze"] + parts)

    def do_check(self, args: str):
        """Quick single-indicator lookup routed to the right tool.

        Usage:  check hash|domain|ip|url <value> [--json] [--verbose]

        Examples:
          check hash 44d88612fea8a8f36de82e1278abb02f
          check domain malicious.com
          check ip 1.2.3.4 --json
          check url http://evil.com/payload"""
        parts = self._split(args)
        if not parts:
            print("Usage: check hash|domain|ip|url <value>  (see 'help check')")
            return
        self._dispatch(["check"] + parts)

    def do_workflow(self, args: str):
        """Run a pre-built multi-step investigation workflow.

        Usage:  workflow <name> <input> [--verbose] [--json] [--report html|md]

        Workflows:
          phishing-email     Comprehensive phishing email investigation
          malware-triage     Quick malware analysis
          ioc-hunt           Bulk IOC threat hunting
          network-forensics  PCAP forensic analysis
          log-investigation  Security log investigation

        Examples:
          workflow phishing-email suspicious.eml
          workflow malware-triage sample.exe --verbose"""
        parts = self._split(args)
        if not parts:
            print("Usage: workflow <name> <input>  (see 'help workflow')")
            return
        self._dispatch(["workflow"] + parts)

    def do_investigate(self, args: str):
        """Automated investigation engine.

        Usage:
          investigate phishing --file <eml> [--mock] [--verbose] [--json]
          investigate status  <investigation-id>
          investigate list    [--last 24h] [--limit N]
          investigate results <investigation-id> [--json]

        Examples:
          investigate phishing --file suspicious.eml --mock
          investigate status INV-2026-01-31-ABCD1234
          investigate list --last 24h"""
        parts = self._split(args)
        self._dispatch(["investigate"] + parts)

    # ── Discovery commands ────────────────────────────────────────────────────

    def do_list(self, args: str):
        """List all available tools grouped by category."""
        self._dispatch(["list"])

    def do_search(self, args: str):
        """Search for tools by keyword.

        Usage:  search <keyword>

        Example:  search phishing"""
        parts = self._split(args)
        if not parts:
            print("Usage: search <keyword>")
            return
        self._dispatch(["search"] + parts)

    def do_info(self, args: str):
        """Show detailed documentation for a tool.

        Usage:  info <tool>

        Example:  info hash"""
        parts = self._split(args)
        if not parts:
            print("Usage: info <tool>")
            return
        self._dispatch(["info"] + parts)

    def do_status(self, args: str):
        """Show API key status, cache statistics, and recent analysis history."""
        self._dispatch(["status"])

    # ── Individual tool shortcuts ─────────────────────────────────────────────

    def do_eml(self, args: str):
        """Parse and analyse an email (.eml) file.

        Usage:  eml <file.eml> [--vt] [--output <path>]"""
        self._dispatch(["eml"] + self._split(args))

    def do_ioc(self, args: str):
        """Extract IOCs (IPs, domains, hashes, URLs, CVEs) from a file or text.

        Usage:  ioc <file> [--format json|csv|txt] [--output <path>]"""
        self._dispatch(["ioc"] + self._split(args))

    def do_hash(self, args: str):
        """Look up a file hash against VirusTotal and MalwareBazaar.

        Usage:  hash <md5|sha1|sha256>"""
        self._dispatch(["hash"] + self._split(args))

    def do_intel(self, args: str):
        """Get threat intelligence for a domain or IP address.

        Usage:  intel <domain|ip>"""
        self._dispatch(["intel"] + self._split(args))

    def do_log(self, args: str):
        """Analyse a log file for security events (Apache, Nginx, syslog).

        Usage:  log <logfile> [--format json|txt]"""
        self._dispatch(["log"] + self._split(args))

    def do_pcap(self, args: str):
        """Analyse a PCAP/PCAPNG network capture.

        Usage:  pcap <file.pcap>"""
        self._dispatch(["pcap"] + self._split(args))

    def do_url(self, args: str):
        """Check a URL's reputation and detect suspicious patterns.

        Usage:  url "<url>" [--json]"""
        self._dispatch(["url"] + self._split(args))

    def do_yara(self, args: str):
        """Run YARA rules against files or directories.

        Usage:  yara scan <path> [--rules <rules_dir>]"""
        self._dispatch(["yara"] + self._split(args))

    def do_cert(self, args: str):
        """Analyse an SSL/TLS certificate from a live host or file.

        Usage:  cert <https://host | hostname | file.pem>"""
        self._dispatch(["cert"] + self._split(args))

    def do_deobfuscate(self, args: str):
        """Deobfuscate JS, PowerShell, VBScript, or Batch scripts.

        Usage:  deobfuscate <file> [--extract-iocs] [--verbose]"""
        self._dispatch(["deobfuscate"] + self._split(args))

    def do_feeds(self, args: str):
        """Aggregate and query threat intelligence feeds.

        Usage:  feeds update|search|stats [args]"""
        self._dispatch(["feeds"] + self._split(args))

    def do_carve(self, args: str):
        """Carve embedded files from disk images or memory dumps.

        Usage:  carve --image <file> --output <dir>"""
        self._dispatch(["carve"] + self._split(args))

    # ── Shell control ─────────────────────────────────────────────────────────

    def do_exit(self, args: str):
        """Exit the vlair shell."""
        print("Goodbye!")
        return True

    def do_quit(self, args: str):
        """Exit the vlair shell."""
        return self.do_exit(args)

    def do_EOF(self, args: str):
        """Exit on Ctrl-D."""
        print()
        return self.do_exit(args)

    def emptyline(self):
        """Do nothing on an empty line (don't repeat the last command)."""

    # ── Custom help ───────────────────────────────────────────────────────────

    def do_help(self, args: str):
        """Show help.  'help <command>' shows per-command detail."""
        if args:
            super().do_help(args)
        else:
            print(HELP_TEXT)


def run_shell():
    """Entry point called by main.py."""
    shell = VlairShell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nGoodbye!")
