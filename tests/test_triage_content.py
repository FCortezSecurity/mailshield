from conftest import make_message

from mailshield.triage.body import extract_bodies
from mailshield.triage.content import analyze_content


def ids(text="", subject="", html=None):
    msg = make_message(text=text, html=html, subject=subject)
    return {f.id: f for f in analyze_content(subject, extract_bodies(msg))}


def test_payment_change():
    found = ids("Please note our updated wire instructions are attached.")
    assert found["TXT-PAYMENT-CHANGE"].severity.label == "high"
    assert "updated wire instructions" in found["TXT-PAYMENT-CHANGE"].detail


def test_closing_wire_in_either_order():
    assert "TXT-CLOSING-WIRE" in ids("The title company needs the wire today.")
    assert "TXT-CLOSING-WIRE" in ids("Send the wire for the closing by Friday.")


def test_gift_cards_and_credential_lures():
    assert "TXT-GIFT-CARD" in ids("Can you buy gift cards for the team?")
    assert "TXT-CREDENTIAL-LURE" in ids("Your account has been suspended. Verify your account.")


def test_urgency_needs_two_signals():
    assert "TXT-URGENCY-SECRECY" not in ids("This is urgent.")
    assert "TXT-URGENCY-SECRECY" in ids("This is urgent, please keep this between us.")


def test_curly_apostrophes_and_subject_and_html_are_scanned():
    assert "TXT-URGENCY-SECRECY" in ids("I can\u2019t talk right now. Do it immediately.")
    assert "TXT-PAYMENT-CHANGE" in ids(subject="New bank details for invoice")
    assert "TXT-GIFT-CARD" in ids(text="hi", html="<p>buy a <b>gift</b> <b>card</b></p>")


def test_normal_business_mail_is_quiet():
    assert ids("Hi team, the quarterly report is attached. Lunch is at noon.") == {}


def test_evidence_is_cleaned_and_bounded():
    found = ids("updated wire instructions" + "\x1b[2J")
    assert "\x1b" not in found["TXT-PAYMENT-CHANGE"].detail


def test_huge_input_is_bounded():
    text = "wire " * 200_000
    assert isinstance(ids(text), dict)


def test_natural_payment_change_phrasings():
    for phrase in (
        "Please update our wire instructions today.",
        "We are changing our bank details.",
        "Use the new account number below.",
        "Our account number is 1234 and the routing number is 5678.",
        "The routing number is 5678 and the account number is 1234.",
    ):
        assert "TXT-PAYMENT-CHANGE" in ids(phrase), phrase


def test_wire_as_a_verb_near_closing_is_not_flagged():
    assert "TXT-CLOSING-WIRE" not in ids("The closing dinner is at 7pm. Wire me the photos.")
    assert "TXT-CLOSING-WIRE" in ids("Closing is Friday. Here are the wire instructions.")


def test_long_proximity_matches_are_shortened_in_evidence():
    found = ids("Closing is Friday and " + "filler words " * 3 + "here are the wire instructions.")
    detail = found["TXT-CLOSING-WIRE"].detail
    assert " ... " in detail
    assert all(len(part) <= 90 for part in detail.split("Matched: ")[1].split("; "))
