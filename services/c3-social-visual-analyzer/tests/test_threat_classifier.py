from app.services.threat_classifier import CATEGORIES, classify

LEGIT_PROBS = {"legitimate": 0.9, "phishing": 0.04, "financial_scam": 0.03, "data_theft": 0.03}


def run(**overrides):
    args = {"category_probs": LEGIT_PROBS, "misinformation_prob": 0.1, "scam_probability": 0.1, "post_text": "Nice day",
            "ocr_text": "", "embedded_url": None, "capture": None, "consistency": None, "risk": {"level": "LOW", "score": 0.1}}
    args.update(overrides)
    return classify(**args)


def detected(result):
    return [d["category"] for d in result["detected"]]


def test_legitimate_when_nothing_fires():
    result = run()
    assert result["primary"] == "LEGITIMATE"
    assert detected(result) == []
    assert [c["category"] for c in result["categories"]] == list(CATEGORIES)


def test_model_category_with_keyword_support():
    result = run(category_probs={"legitimate": 0.2, "phishing": 0.45, "financial_scam": 0.3, "data_theft": 0.05},
                 post_text="Your account has been suspended. Verify your account now.")
    assert result["primary"] == "PHISHING"
    phishing = next(c for c in result["categories"] if c["category"] == "PHISHING")
    assert phishing["score"] > 0.45 and any("verify your account" in e.lower() for e in phishing["evidence"])


def test_data_theft_from_several_credential_requests():
    result = run(post_text="Send your NIC copy, card number and the OTP code to claim your refund.")
    assert "DATA_THEFT" in detected(result)


def test_gift_card_survey_lure_is_data_theft_and_brand_impersonation():
    """Apple gift-card survey scams: brand mismatch is primary; data theft co-detects."""
    post = (
        "CONGRATULATIONS! YOU COULD WIN A $1,000 APPLE GIFT CARD! "
        "Apple customers have a chance to receive an exclusive $1,000 gift card through our special "
        "customer rewards survey! Answer 4 simple questions. Complete the 60-second survey. "
        "Verify your eligibility. Claim your exclusive reward. Claim Your $1,000 Gift Card Now!"
    )
    consistency = {
        "flags": [{"code": "BRAND_DOMAIN_MISMATCH", "severity": "high",
                   "detail": "Apple is presented but the link goes to a non-Apple domain"}],
        "brand_identity_mismatch": {"detected": True, "strength": "strong"},
    }
    result = run(post_text=post, consistency=consistency, misinformation_prob=None)
    assert result["primary"] == "BRAND_IMPERSONATION"
    assert "DATA_THEFT" in detected(result)
    data = next(c for c in result["categories"] if c["category"] == "DATA_THEFT")
    assert data["score"] >= 0.5
    assert any("survey" in e.lower() or "harvest" in e.lower() for e in data["evidence"])


def test_brand_impersonation_from_lookalike_domain():
    consistency = {"flags": [{"code": "LOOKALIKE_DOMAIN", "severity": "high", "detail": "paypa1.com imitates paypal.com"}],
                   "brand_identity_mismatch": {"detected": True, "strength": "strong"}}
    result = run(consistency=consistency)
    assert result["primary"] == "BRAND_IMPERSONATION"


def test_malware_from_download_and_file_link():
    assert run(capture={"error_code": "DOWNLOAD_BLOCKED"})["primary"] == "MALWARE"
    assert run(embedded_url="https://example.com/files/WhatsApp-Gold.apk")["primary"] == "MALWARE"


def test_browser_abuse_from_permission_prompt_and_fake_alert():
    assert run(capture={"notification_requests": 1})["primary"] == "BROWSER_ABUSE"
    page = {"page_title": "Windows Defender Alert", "page_text": "Your computer is infected. Call Microsoft Support now."}
    assert run(capture=page)["primary"] == "BROWSER_ABUSE"


def test_other_scam_when_risky_but_unspecific():
    result = run(scam_probability=0.8, risk={"level": "MEDIUM", "score": 0.55})
    assert result["primary"] == "OTHER_SCAM"


def test_misinformation_co_occurs():
    result = run(misinformation_prob=0.9)
    assert result["primary"] == "MISINFORMATION"
    scam = run(misinformation_prob=0.9, capture={"error_code": "DOWNLOAD_BLOCKED"})
    assert scam["primary"] == "MALWARE" and "MISINFORMATION" in detected(scam)


def test_promotional_posts_are_outside_the_misinformation_domain():
    from app.services.threat_classifier import looks_brand_marketing, looks_promotional, misinformation_skip_reason

    assert looks_promotional("Shop now at our Amazon store - 20% discount this week!")
    assert looks_promotional("Get a $500 Kroger Gift Card! USA Citizen only")
    assert not looks_promotional("Scientists confirm the moon is slowly turning into cheese, NASA hides the truth")

    ionos = (
        'We\'re excited about this maximalism trend, and we\'ve got a hunch you\'ll be seeing much more of it in 2024. '
        'What are your thoughts on this trend? See all our predicted web design trends here.'
    )
    assert looks_brand_marketing(ionos)
    assert misinformation_skip_reason(ionos)
    assert misinformation_skip_reason(
        "Nice day at the office.",
        {"domain_check": {"status": "official"}, "brand_identity_mismatch": {"detected": False}},
    )
    assert not misinformation_skip_reason(
        "Scientists confirm the moon is slowly turning into cheese, NASA hides the truth",
    )
    assert not misinformation_skip_reason(
        "Your PayPal account is locked",
        {"domain_check": {"status": "lookalike"}, "brand_identity_mismatch": {"detected": True}},
    )


def test_rules_still_work_without_text_models():
    result = run(category_probs=None, misinformation_prob=None, capture={"notification_requests": 2})
    assert result["primary"] == "BROWSER_ABUSE"
    assert not result["category_model_available"]
