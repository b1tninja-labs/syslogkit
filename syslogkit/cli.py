"""Command line entry point for syslogkit.

The CLI is how most people meet a protocol library, so it is part of the public surface and
gets the same typing and testing discipline as the rest of the package.
"""

from __future__ import annotations

import argparse
import sys

USAGE = """\
Examples:
  syslogkit listen --tls 0.0.0.0:6514 --cert ./server.pem --ca ./ca.pem"""


def build_parser():
    return argparse.ArgumentParser(
        prog="syslogkit",
        description="The syslog protocol with structured data, the transport mappings that matter (UDP, TCP framing, TLS, DTLS) and a receiver that does not lose a line",
        epilog=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv=None):
    """Parse arguments, then refuse to pretend the protocol works.

    Exiting non-zero is the correct behaviour for a shell. A CLI that printed a friendly
    banner and exited 0 would be indistinguishable from one that actually did something.
    """
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_usage(sys.stderr)
    print("syslogkit: no protocol behaviour is implemented yet; see ROADMAP.md", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
