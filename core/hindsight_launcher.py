"""Run installed Hindsight with the equivalent UTC alias on Python 3.10.

Hindsight 2026.01 uses datetime.UTC (introduced in 3.11) but its installed
interpreter may be 3.10. Keep its own dependency environment and script path.
"""
import datetime
import runpy
import sys

if not hasattr(datetime, 'UTC'):
    datetime.UTC = datetime.timezone.utc

if __name__ == '__main__':
    script = sys.argv[1]
    sys.argv = sys.argv[1:]
    runpy.run_path(script, run_name='__main__')
