from mailshield.audit import audit_domain
from mailshield.report import to_markdown


class Fake:
    def txt(self, name):
        return {"weak.example": ["v=spf1 +all"]}.get(name, [])


print(to_markdown(audit_domain("weak.example", Fake())))
