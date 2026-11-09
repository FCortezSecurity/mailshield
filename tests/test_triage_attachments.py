import hashlib

from conftest import make_message

from mailshield.triage.attachments import inspect_attachments

EXE = b"MZ" + b"\x90" * 100


def run(*attachments):
    findings, facts = inspect_attachments(make_message(attachments=attachments))
    return {f.id for f in findings}, facts


def test_no_attachments():
    assert run() == (set(), [])


def test_double_extension_and_dangerous_type():
    found, _ = run(("invoice.pdf.exe", EXE, "application/octet-stream"))
    assert {"ATT-DOUBLE-EXTENSION", "ATT-DANGEROUS-TYPE"} <= found


def test_disguised_executable():
    found, _ = run(("photo.jpg", EXE, "image/jpeg"))
    assert found == {"ATT-DISGUISED-EXECUTABLE"}
    found, _ = run(("tool.exe", EXE, "application/octet-stream"))
    assert "ATT-DISGUISED-EXECUTABLE" not in found
    found, _ = run(("note.txt", b"MZ is a short note", "text/plain"))
    assert "ATT-DISGUISED-EXECUTABLE" not in found


def test_macro_html_and_archive():
    found, _ = run(
        ("a.docm", b"PK", "application/octet-stream"),
        ("b.html", b"<html>", "text/html"),
        ("c.zip", b"PK", "application/zip"),
    )
    assert {"ATT-MACRO-DOCUMENT", "ATT-HTML", "ATT-ARCHIVE"} <= found


def test_reversing_characters_in_name():
    found, facts = run(("invoice\u202egpj.exe", EXE, "application/octet-stream"))
    assert "ATT-HIDDEN-CHARACTERS" in found
    assert "\u202e" not in facts[0]["name"] and "\\u202e" in facts[0]["name"]


def test_facts_contain_hash_and_size_but_never_content():
    data = b"hello attachment"
    _, facts = run(("notes.txt", data, "text/plain"))
    assert facts == [
        {
            "name": "notes.txt",
            "content_type": "text/plain",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    ]


def test_clean_documents_are_quiet():
    found, _ = run(("report.pdf", b"%PDF-1.7 body", "application/pdf"))
    assert found == set()
