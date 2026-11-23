"""Environment check before a live run — see dfirconsole/preflight.py.

    python preflight.py              # checks the current workspace
    python preflight.py D:\\CASE42  # checks another workspace
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dfirconsole.preflight import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
