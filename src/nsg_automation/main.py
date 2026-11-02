"""Entry point for the ``nsg-tool`` console script."""

from __future__ import annotations

from nsg_automation.cli.app import cli


def main() -> None:
    # Click expands wildcards on Windows, which would turn "*" (any port/address) into file names.
    cli(prog_name="nsg-tool", windows_expand_args=False)


if __name__ == "__main__":
    main()
