"""Allow ``python -m cyberforge`` to run the CLI."""

from cyberforge.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
