"""Audit a simulated, deliberately weak domain. No network access.

python examples/weak_demo.py                # print Markdown
python examples/weak_demo.py report.html    # write the HTML report
"""

import sys
from pathlib import Path

from mailshield.audit import audit_domain
from mailshield.report import to_html, to_markdown


class Fake:
    def txt(self, name):
        return {"weak.example": ["v=spf1 +all"]}.get(name, [])

    def mx(self, name):
        return []


report = audit_domain("weak.example", Fake())
if len(sys.argv) > 1:
    Path(sys.argv[1]).write_text(to_html(report), encoding="utf-8")
    print(f"wrote {sys.argv[1]}")
else:
    print(to_markdown(report))
