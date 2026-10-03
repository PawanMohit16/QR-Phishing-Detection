#!/usr/bin/env python3
"""
Project 12 - Smishing & QR-Based Social Engineering Analyzer
All data is SYNTHETIC. Domains use fictional names and the reserved
.example/.test TLDs, so nothing here points to a real site.

Usage:
  python smishing_analyzer.py dataset            # Module 1: build dataset.csv
  python smishing_analyzer.py train              # ML: train + evaluate model
  python smishing_analyzer.py analyze "text..."  # Modules 2-4 on one message
  python smishing_analyzer.py ocr image.png      # OCR a screenshot, then analyze
  python smishing_analyzer.py demo               # analyze a few sample messages
Install: pip install pandas scikit-learn   (OCR: pip install pytesseract pillow opencv-python
         + Tesseract binary; QR: opencv-python)
"""
import csv, random, re, sys, json
from urllib.parse import urlparse

random.seed(42)

# --------------------------------------------------------------------------
# MODULE 1 - SYNTHETIC DATASET
# --------------------------------------------------------------------------
LEGIT = {
    "sms": ["Your AcmeCorp verification code is {n}. Do not share it with anyone.",
            "Reminder: team meeting at {t} in Room 4. - AcmeCorp Admin",
            "Your payslip for this month is available in the HR portal at https://hr.acmecorp.example"],
    "notification": ["Your AcmeCorp VPN password expires in 14 days. Change it anytime at https://it.acmecorp.example/password",
                     "Calendar: Quarterly review moved to {t}."],
    "account_alert": ["AcmeBank: A login to your account was made from your usual device. If this was you, no action needed.",
                      "AcmeBank: Your statement is ready. Log in via the official app to view it."],
    "delivery": ["AcmeCourier: Your parcel #{n} is out for delivery today. Track in the AcmeCourier app.",
                 "AcmeCourier: Parcel #{n} delivered to reception at {t}."],
    "qr": ["QR on office poster linking to https://wifi.acmecorp.example/guest for guest Wi-Fi sign-in.",
           "QR on cafeteria menu opening https://menu.acmecorp.example/today."],
}
SUSP = {
    "sms": ["Hi, this is HR. Please review the new bonus policy here: {u}",
            "You have 1 unread voicemail. Listen: {u}"],
    "notification": ["Your mailbox storage is almost full. Manage storage: {u}",
                     "A document was shared with you. Open it: {u}"],
    "account_alert": ["AcmeBank: New payee added. Not you? Review at {u}",
                      "Your account will be reviewed soon. Confirm your details: {u}"],
    "delivery": ["AcmeCourier: Your parcel is waiting. Reschedule delivery: {u}",
                 "Delivery attempt failed. Update your address at {u}"],
    "qr": ["QR sticker on a meeting-room door says 'Scan for room booking' and opens {u}",
           "QR on a flyer in the lobby: 'Scan for free coffee', opens {u}"],
}
HIGH = {
    "sms": ["URGENT: CEO needs gift cards immediately. Reply now, do not tell anyone. {u}",
            "FINAL WARNING: Your salary payment is on hold. Verify your bank details within 2 hours: {u}"],
    "notification": ["SECURITY ALERT: Your AcmeCorp password expires TODAY. Login now to avoid lockout: {u}",
                     "Your account has been suspended. Click here immediately to restore access: {u}"],
    "account_alert": ["AcmeBank ALERT: Unauthorized transaction of $4,999 detected! Confirm your PIN and OTP now: {u}",
                      "Your card has been blocked. Verify card number and CVV within 30 minutes or lose access: {u}"],
    "delivery": ["AcmeCourier: Parcel held at customs. Pay a $2.99 fee within 24 hours or it will be returned: {u}",
                 "LAST NOTICE: Package undeliverable. Confirm card details to release it: {u}"],
    "qr": ["QR on a parking-fine notice: 'Pay penalty now or face legal action', opens {u}",
           "QR on a fake IT poster: 'Scan to re-verify your login immediately', opens {u}"],
}
BAD_URLS = ["http://acmebank-secure-login.example/verify", "https://bit.ly/3xAmpLe", "http://acmecorp-hr.support.test/pay",
            "https://tinyurl.com/acme-demo", "http://192.0.2.45/login", "https://acmecourier-track.top.test/r?id=77",
            "https://acme-payroll.verify-now.test/confirm", "https://t.co/aBcDeF"]

def build_dataset(n_per_cell=14, path="dataset.csv"):
    rows = []
    for label, bank in (("legitimate", LEGIT), ("suspicious", SUSP), ("high-risk", HIGH)):
        for cat, templates in bank.items():
            for _ in range(n_per_cell):
                t = random.choice(templates)
                msg = t.format(n=random.randint(100000, 999999), t=f"{random.randint(9,17)}:00",
                               u=random.choice(BAD_URLS))
                rows.append({"text": msg, "category": cat, "label": label})
    random.shuffle(rows)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["text", "category", "label"]); w.writeheader(); w.writerows(rows)
    print(f"Wrote {len(rows)} synthetic messages to {path}")
    return rows

# --------------------------------------------------------------------------
# MODULE 2 - EXTRACTION
# --------------------------------------------------------------------------
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
SUSP_TLDS = {"xyz", "top", "click", "icu", "live", "support", "zip", "test"}   # 'test' = simulation TLD
TRUSTED = {"acmecorp.example", "hr.acmecorp.example", "it.acmecorp.example", "wifi.acmecorp.example", "menu.acmecorp.example"}
BRANDS = ("acme", "bank", "courier", "payroll", "hr")

KEYWORDS = {
    "urgency": ["urgent", "immediately", "now", "today", "final", "last notice", "within", "expires", "asap", "hurry", "warning"],
    "financial": ["payment", "bank", "card", "cvv", "salary", "fee", "refund", "transaction", "$", "pay", "bonus", "invoice", "penalty"],
    "account": ["account", "password", "login", "verify", "otp", "pin", "suspended", "blocked", "locked", "credentials", "security"],
}
CTA = ["click here", "tap here", "scan now", "scan to", "reply now", "log in", "login now", "verify", "confirm", "update your",
       "reschedule", "open it", "pay", "call now", "review at", "listen", "restore access"]

def extract(text):
    low = text.lower()
    urls = [u.rstrip(".,)") for u in URL_RE.findall(text)]
    info = {"urls": urls, "shortened": [], "suspicious_domains": [], "domain_flags": {}}
    for u in urls:
        host = (urlparse(u if "://" in u else "http://" + u).hostname or "").lower()
        flags = []
        if host in SHORTENERS: info["shortened"].append(u); flags.append("URL shortener hides destination")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): flags.append("raw IP address")
        if host.startswith("xn--") or "xn--" in host: flags.append("punycode look-alike")
        if host.count("-") >= 2: flags.append("many hyphens")
        if host.rsplit(".", 1)[-1] in SUSP_TLDS: flags.append("risky TLD")
        if any(b in host for b in BRANDS) and host not in TRUSTED and host not in SHORTENERS:
            flags.append("brand look-alike on untrusted domain")
        if u.lower().startswith("http://"): flags.append("no HTTPS")
        if flags: info["suspicious_domains"].append(host); info["domain_flags"][host] = flags
    for k, words in KEYWORDS.items():
        info[k] = sorted({w for w in words if re.search(r"(?<!\w)" + re.escape(w) + (r"" if w == "$" else r"\b"), low)})
    info["cta"] = sorted({c for c in CTA if c in low})
    return info

# --------------------------------------------------------------------------
# MODULE 3 - PSYCHOLOGICAL ANALYSIS
# --------------------------------------------------------------------------
PSY = {
    "urgency":   ["urgent", "immediately", "within", "expires", "today", "final", "last notice", "now", "hours", "minutes"],
    "fear":      ["suspended", "blocked", "unauthorized", "legal action", "penalty", "lose access", "lockout", "warning", "returned", "hold", "customs"],
    "curiosity": ["voicemail", "shared with you", "unread", "document", "waiting", "parcel", "package", "scan for"],
    "authority": ["ceo", "hr", "it department", "bank", "police", "tax", "manager", "security team", "customs", "admin"],
    "reward":    ["bonus", "free", "refund", "prize", "gift", "won", "cashback", "salary"],
    "trust":     ["do not share", "official", "your usual", "acmecorp", "acmebank", "acmecourier", "reminder", "verification code"],
}
def psychology(text):
    low = text.lower()
    scores = {k: sum(1 for w in ws if w in low) for k, ws in PSY.items()}
    scores = {k: v for k, v in scores.items() if v}
    return dict(sorted(scores.items(), key=lambda x: -x[1]))

# --------------------------------------------------------------------------
# MODULE 4 - RISK SCORE + RECOMMENDATION
# --------------------------------------------------------------------------
WEIGHTS = {  # indicator -> points (capped at 100)
    "shortened_url": 20, "suspicious_domain": 20, "raw_ip": 15, "no_https": 8,
    "urgency_kw": 7, "financial_kw": 6, "account_kw": 6, "cta": 6, "credential_request": 18,
    "fear": 6, "authority": 5, "reward": 5, "secrecy": 12, "qr_context": 6,
}
ACTIONS = {
    "legitimate": "No action needed. Still prefer opening the official app or portal yourself.",
    "suspicious": "Do not click or scan. Verify via a known channel (official app / phone number) and report to IT.",
    "high-risk":  "DO NOT click, scan, reply or pay. Report to the security team, delete the message, and if you entered "
                  "credentials, change passwords and alert IT immediately.",
}
def risk_score(text):
    e, p, low = extract(text), psychology(text), text.lower()
    hits = {}
    def add(k, why): hits[k] = (WEIGHTS[k], why)
    if e["shortened"]: add("shortened_url", f"Shortened link: {e['shortened'][0]}")
    if e["suspicious_domains"]: add("suspicious_domain", "; ".join(f"{h}: {', '.join(f)}" for h, f in e["domain_flags"].items()))
    if any("raw IP" in f for fl in e["domain_flags"].values() for f in fl): add("raw_ip", "Link uses a bare IP address")
    if e["urls"] and any(u.lower().startswith("http://") for u in e["urls"]): add("no_https", "Link is not HTTPS")
    if e["urgency"]: add("urgency_kw", "Urgency words: " + ", ".join(e["urgency"]))
    if e["financial"]: add("financial_kw", "Financial words: " + ", ".join(e["financial"]))
    if e["account"]: add("account_kw", "Account words: " + ", ".join(e["account"]))
    if e["cta"]: add("cta", "Call-to-action: " + ", ".join(e["cta"]))
    if re.search(r"\b(otp|pin|cvv|card number|password|bank details|credentials)\b", low) and e["cta"]:
        add("credential_request", "Asks for sensitive credentials")
    if "fear" in p: add("fear", "Fear/threat language")
    if "authority" in p and e["urls"] and e["suspicious_domains"]: add("authority", "Authority claim + untrusted link")
    if "reward" in p and e["urls"]: add("reward", "Reward/bonus bait")
    if re.search(r"do not tell|don't tell|keep this secret|gift card", low): add("secrecy", "Secrecy / gift-card pattern (BEC)")
    if re.search(r"\bqr\b|scan", low) and e["urls"]: add("qr_context", "QR/scan lure leading to a link")
    # trust cues from a verified domain reduce risk
    score = min(100, sum(w for w, _ in hits.values()))
    if e["urls"] and not e["suspicious_domains"] and not e["shortened"] and not hits.get("credential_request"):
        score = max(0, score - 15)
    level = "high-risk" if score >= 50 else "suspicious" if score >= 22 else "legitimate"
    top = list(p)[:3]
    return {"score": score, "level": level, "indicators": {k: v[1] for k, v in hits.items()},
            "psychological_techniques": top or ["none detected"], "action": ACTIONS[level], "extracted": e}

# --------------------------------------------------------------------------
# ML MODEL (TF-IDF + hand-crafted indicator features -> Logistic Regression)
# --------------------------------------------------------------------------
def enrich(t):
    """Append indicator tokens so the vectoriser sees engineered features."""
    e = extract(t); tok = []
    tok += ["F_SHORT"] * bool(e["shortened"]) + ["F_BADDOM"] * bool(e["suspicious_domains"]) + ["F_URL"] * bool(e["urls"])
    tok += [f"F_{k.upper()}{min(len(e[k]),3)}" for k in ("urgency", "financial", "account", "cta")]
    return t + " " + " ".join(tok)

def export_model(clf, path="model.json"):
    """Save TF-IDF + logistic regression as plain JSON (no sklearn needed at serving time)."""
    vec, lr = clf.steps[0][1], clf.steps[1][1]
    json.dump({"classes": list(lr.classes_), "vocab": {t: int(i) for t, i in vec.vocabulary_.items()},
               "idf": [round(float(x), 6) for x in vec.idf_],
               "coef": [[round(float(w), 6) for w in row] for row in lr.coef_],
               "intercept": [round(float(b), 6) for b in lr.intercept_]}, open(path, "w"))

def ml_predict(text, m):
    """Pure-Python inference identical to the sklearn pipeline."""
    import math
    toks = re.findall(r"(?u)\b\w\w+\b", enrich(text).lower())
    cnt = {}
    for g in toks + [a + " " + b for a, b in zip(toks, toks[1:])]:
        i = m["vocab"].get(g)
        if i is not None: cnt[i] = cnt.get(i, 0) + 1
    x = {i: (1 + math.log(c)) * m["idf"][i] for i, c in cnt.items()}
    n = math.sqrt(sum(v * v for v in x.values())) or 1.0
    z = [b + sum(row[i] * v / n for i, v in x.items()) for row, b in zip(m["coef"], m["intercept"])]
    mx = max(z); ex = [math.exp(v - mx) for v in z]; tot = sum(ex)
    probs = {c: round(e / tot, 3) for c, e in zip(m["classes"], ex)}
    return max(probs, key=probs.get), probs

def full_analysis(text, model=None):
    """Rule engine + ML blended: final = 0.6*rule score + 0.4*ML risk score."""
    r = risk_score(text)
    out = {"rule_score": r["score"], "rule_level": r["level"], "indicators": r["indicators"],
           "psychology": r["psychological_techniques"], "urls": r["extracted"]["urls"], "ml": None}
    final = r["score"]
    if model:
        label, probs = ml_predict(text, model)
        ml_score = 50 * probs.get("suspicious", 0) + 100 * probs.get("high-risk", 0)
        final = round(0.6 * r["score"] + 0.4 * ml_score)
        out["ml"] = {"label": label, "probs": probs, "score": round(ml_score)}
    level = "high-risk" if final >= 50 else "suspicious" if final >= 22 else "legitimate"
    out.update(score=final, level=level, action=ACTIONS[level])
    return out

def train(path="dataset.csv", model_path="model.json"):
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.pipeline import make_pipeline
    try: df = pd.read_csv(path)
    except FileNotFoundError: build_dataset(path=path); df = pd.read_csv(path)
    X = df.text.map(enrich); y = df.label
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=1)
    clf = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True), LogisticRegression(max_iter=1000, class_weight="balanced"))
    clf.fit(Xtr, ytr); pred = clf.predict(Xte)
    print(classification_report(yte, pred)); print("Confusion matrix:\n", confusion_matrix(yte, pred, labels=["legitimate", "suspicious", "high-risk"]))
    print("Rule-based score accuracy on full dataset: %.2f" % (df.text.map(lambda t: risk_score(t)["level"]) == df.label).mean())
    clf.fit(X, y)   # final model uses all data
    export_model(clf, model_path); print("Saved", model_path)

# --------------------------------------------------------------------------
# OCR / QR input (optional)
# --------------------------------------------------------------------------
def ocr_image(path):
    import cv2, pytesseract
    img = cv2.imread(path)
    text = pytesseract.image_to_string(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY))
    qr, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    return (text + ("\n" + qr if qr else "")).strip()

def report(text):
    r = risk_score(text)
    print("=" * 60); print("MESSAGE:", text[:140])
    print(f"RISK SCORE : {r['score']}/100  ->  {r['level'].upper()}")
    print("INDICATORS :"); [print(f"  - {k}: {v}") for k, v in r["indicators"].items()] or None
    print("PSYCHOLOGY :", ", ".join(r["psychological_techniques"]))
    print("ACTION     :", r["action"])

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "demo"
    if cmd == "dataset": build_dataset()
    elif cmd == "train": train()
    elif cmd == "analyze": report(" ".join(sys.argv[2:]))
    elif cmd == "ocr": report(ocr_image(sys.argv[2]))
    else:
        for rows in (LEGIT, SUSP, HIGH):
            report(random.choice(rows["delivery"]).format(n=123456, t="10:00", u=random.choice(BAD_URLS)))
