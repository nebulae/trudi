"""Python < 3.11 compatibility shim for the hindsight subprocess ONLY.

misc.hindsight_chrome prepends this directory to PYTHONPATH for the child
process. /opt/pyhindsight runs Python 3.10, but pyhindsight/utils.py uses
``datetime.UTC`` (added in 3.11), so every timestamp conversion raised
AttributeError. ``datetime.UTC`` is an alias of ``datetime.timezone.utc``; the
installed package is left untouched.
"""
import datetime

if not hasattr(datetime, "UTC"):
    datetime.UTC = datetime.timezone.utc
