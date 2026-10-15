"""Form features: forms, credential fields, hidden inputs and form actions (tasks 4-8).

Part 3: DOM structural analysis.

Why: credential theft needs two things - a form that ASKS for secrets and a
place the data is SENT. Part 2 already extracted every form, input (with
type, name, label, hidden flag) and resolved action; this module only
classifies and counts them. Nothing is re-parsed here.

Input classes (rules in configs/dom_features.yaml -> field_rules), checked
in priority order so one field is counted once:
    password > card > otp_pin > email > username
A field is in a class when its type or autocomplete token is listed, or a
regex matches "type name id placeholder autocomplete label" (English,
Sinhala, Tamil, plus a few words from kits in the dataset) and no ``exclude``
regex of that class does (e.g. an identity card is not a payment card).
Fields that cannot hold typed data (hidden, submit, checkbox, ...) are skipped.

Every group function returns (features, details): details feed the evidence
texts (e.g. which domain a password form posts to). Prefilled values are
never looked at, so nothing masked by Part 2 is ever revealed.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from c2_analyzer.dom.dictionary import Dictionary, load_dictionary
from c2_analyzer.schemas.parsed_page import Form, InputField, ParsedPage
from c2_analyzer.utils.url import domain_of_host

NULL_ACTION_PREFIXES = ("javascript:",)
FIELD_CLASSES = ("password", "card", "otp_pin", "email", "username")


def _ratio(part: float, whole: float) -> float:
    return round(part / whole, 4) if whole else 0.0


def field_text(field: InputField) -> str:
    """The attribute text the class regexes search in."""
    parts = (
        field.type,
        field.name,
        field.id,
        field.placeholder,
        field.autocomplete,
        field.label_text,
    )
    return " ".join(part for part in parts if part).lower()


def classify_field(field: InputField, dictionary: Dictionary | None = None) -> str | None:
    """password | card | otp_pin | email | username | None."""
    dictionary = dictionary or load_dictionary()
    kind = (field.type or "").lower()
    if kind in dictionary.skip_types:
        return None
    tokens = set((field.autocomplete or "").lower().split())
    text = field_text(field)
    for rule in dictionary.field_classes:  # priority order from the YAML
        if kind in rule.types or tokens & rule.autocomplete:
            return rule.name
        if any(pattern.search(text) for pattern in rule.patterns) and not any(
            pattern.search(text) for pattern in rule.exclude
        ):
            return rule.name
    return None


def _host(url: str | None) -> str | None:
    try:
        return urlsplit(url).hostname if url else None
    except ValueError:
        return None


def is_ip_url(url: str | None) -> bool:
    """True for http(s)://1.2.3.4/... or http://[::1]/..."""
    host = _host(url) if url and url.lower().startswith(("http://", "https://")) else None
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def known_service(form: Form, services: tuple[str, ...]) -> str | None:
    """The form-collection service a form posts to (by host or registrable domain)."""
    host = (_host(form.action_abs) or "").lower()
    if not host:
        return None
    candidates = {host, domain_of_host(host)}
    for service in services:
        if service in candidates or host.endswith("." + service):
            return service
    return None


def _has_password(form: Form, dictionary: Dictionary) -> bool:
    return any(classify_field(field, dictionary) == "password" for field in form.inputs)


def _is_null_action(form: Form) -> bool:
    raw = (form.action_raw or "").strip().lower()
    return raw in ("", "#") or raw.startswith("#") or raw.startswith(NULL_ACTION_PREFIXES)


def form_features(page: ParsedPage, page_url_known: bool) -> tuple[dict, dict]:
    """Groups forms, credentials, hidden_inputs, form_actions -> (features, details)."""
    dictionary = load_dictionary()
    inputs = page.all_inputs
    classes = [classify_field(field, dictionary) for field in inputs]
    count = {name: classes.count(name) for name in FIELD_CLASSES}
    hidden_inputs = sum(field.hidden for field in inputs)

    external = [form for form in page.forms if form.is_external_action] if page_url_known else []
    password_external = [form for form in external if _has_password(form, dictionary)]
    to_ip = [form for form in page.forms if is_ip_url(form.action_abs)]
    services = [(form, known_service(form, dictionary.known_form_services)) for form in page.forms]
    services = [(form, name) for form, name in services if name]
    get_password = [
        form
        for form in page.forms
        if form.method.upper() == "GET" and _has_password(form, dictionary)
    ]

    features = {
        "form_count": len(page.forms),
        "has_form": int(bool(page.forms)),
        "inputs_total": len(inputs),
        "inputs_outside_forms_count": len(page.inputs_outside_forms),
        "password_field_count": count["password"],
        "has_password_field": int(count["password"] > 0),
        "email_field_count": count["email"],
        "username_field_count": count["username"],
        "otp_pin_field_count": count["otp_pin"],
        "card_field_count": count["card"],
        "sensitive_field_count": count["password"] + count["otp_pin"] + count["card"],
        "hidden_input_count": hidden_inputs,
        "hidden_input_ratio": _ratio(hidden_inputs, len(inputs)),
        "external_form_action_count": len(external),
        "has_external_form_action": int(bool(external)),
        "password_form_external_action": int(bool(password_external)),
        "form_action_to_ip": int(bool(to_ip)),
        "form_action_empty_or_js": sum(_is_null_action(form) for form in page.forms),
        "form_action_to_known_form_service": int(bool(services)),
        "form_method_get_with_password": int(bool(get_password)),
    }

    def names(kind: str) -> list[str]:
        return [
            field.name or field.id or field.label_text or field.type
            for field, found in zip(inputs, classes, strict=True)
            if found == kind
        ][:10]

    details = {
        "password_field_count": {"fields": names("password")},
        "email_field_count": {"fields": names("email")},
        "username_field_count": {"fields": names("username")},
        "otp_pin_field_count": {"fields": names("otp_pin")},
        "card_field_count": {"fields": names("card")},
        "inputs_outside_forms_count": {
            "fields": [f.name or f.id or f.type for f in page.inputs_outside_forms][:10]
        },
        "hidden_input_count": {
            "fields": [f.name or f.id or f.type for f in inputs if f.hidden][:10]
        },
        "has_external_form_action": {
            "domains": ", ".join(sorted({f.action_domain or "?" for f in external})),
            "actions": [f.action_abs for f in external][:5],
        },
        "form_action_to_ip": {"action": to_ip[0].action_abs if to_ip else None},
        "form_action_empty_or_js": {
            "actions": [f.action_raw or "(empty)" for f in page.forms if _is_null_action(f)][:5]
        },
        "form_action_to_known_form_service": {
            "service": services[0][1] if services else None,
            "action": services[0][0].action_abs if services else None,
        },
        "form_method_get_with_password": {
            "action": get_password[0].action_abs if get_password else None
        },
    }
    if password_external:
        form = password_external[0]
        details["password_form_external_action"] = {
            "action": form.action_abs,
            "domain": form.action_domain,
            "form_index": form.index,
        }
    return features, details
