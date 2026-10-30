#!/usr/bin/env python3
"""Create demo sender keys in a private directory; never print key contents."""
import os
from pathlib import Path
import secrets


def main():
    directory = Path(__file__).resolve().parents[1] / "secrets"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    for env, name in (("TRUDI_DECOY_CEF_KEY_FILE", "decoy-cef.key"),
                      ("TRUDI_WINDECOY_CEF_KEY_FILE", "windecoy-cef.key")):
        if os.environ.get(env):
            continue
        path = directory / name
        # The private parent protects these files on the host; 0444 allows
        # the unprivileged decoy to read its Docker Compose secret mount.
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w") as file:
            file.write(secrets.token_hex(32) + "\n")


if __name__ == "__main__":
    main()
