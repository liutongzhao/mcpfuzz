"""Single source of truth for the tool's identity.

Change the brand/command name here only; every display site imports from this module.
"""
from __future__ import annotations

# Human-facing brand name, shown in report titles and console banners.
APP_NAME = "Calchas"
# Command-line program name (argparse prog) and the console-script entry point.
CLI_NAME = "calchas"
# Internal marker token embedded in generated benign values / placeholder keys
# (temp-file prefixes, key-position injection fillers). Not user-facing branding;
# kept centralized so a rebrand stays a one-line change.
MARKER = "calchas"
# Prefix for the random canary token minted per probe (embedded in payloads and
# matched in responses/logs). Any unique, URL/shell-safe string works.
TOKEN_PREFIX = "clx"
