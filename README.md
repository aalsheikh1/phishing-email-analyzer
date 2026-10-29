# 🎣 Phishing Email Analyzer

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566-red)

A Python tool that inspects a suspicious email (`.eml` file) the way a SOC analyst would, checks it for common phishing indicators, and gives it a suspicion score and verdict.

Phishing is how most attacks start (**MITRE ATT&CK T1566**). This tool answers the first questions an analyst asks during email triage: *Who really sent this? Where do the replies and links go? Is it pressuring me? Is the attachment dangerous?*

---

## ✨ Features

| Check | What it catches | ATT&CK |
|---|---|---|
| 🔍 Reply-To mismatch | The email claims to come from one domain, but replies secretly go to another | T1566 |
| 🔗 Deceptive links | The visible link text shows one address, but the real link goes somewhere else | T1566.002 |
| ⏰ Urgency keywords | Pressure words like "urgent", "verify", "suspended", "action required" | T1566 |
| 📎 Dangerous attachments | Macro Office files, executables, scripts, disk images, HTML files | T1566.001 |
| 📊 Scoring | Each check adds +1 and the total gives a HIGH / MEDIUM / LOW verdict | |
| 🎨 Colored output | Red for findings, green for clean checks (turned off when output is saved to a file) | |
| 📦 No dependencies | Python standard library only | |

---

## 🚀 Usage

```bash
python phishing_analyzer.py samples/sample_phish.eml
python phishing_analyzer.py samples/sample_legit.eml
```

### Analyze your own emails

Most email clients can save a message as an `.eml` file:

- **Gmail:** open the email → ⋮ → **Download message**
- **Outlook:** open the email → **File** → **Save as**

> ⚠️ The tool only reads the email as text. It never opens links or attachments, so it is safe to run on real phishing emails. Still, never click anything inside them yourself.

---

## 📊 Sample Output

<!-- Add a screenshot of the colored terminal output here -->

```text
PHISHING ANALYSIS: samples/sample_phish.eml
From:        IT Support <support@yourcompany.com>
Reply-To:    support@secure-verify.ru
Subject:     URGENT: Verify your account immediately
Attachments: Invoice_March.xlsm

FINDINGS:
  [!] From-domain 'yourcompany.com' != Reply-To-domain 'secure-verify.ru' - reply goes somewhere else (+1)
  [!] Link shows 'https://yourcompany.com/login' but goes to 'http://login-verify.ru/steal' - the visible link lies (+1)
  [!] Urgency keywords: urgent, verify, suspend, immediately, action required, unusual activity - pressure is a phishing tell (+1)
  [!] Dangerous attachment: Invoice_March.xlsm (+1)

Suspicion score: 4
Verdict: HIGH - Likely phishing. Do not click, do not reply.
```

```text
PHISHING ANALYSIS: samples/sample_legit.eml
From:        Morning Byte Newsletter <newsletter@bytebrief.com>
Reply-To:    newsletter@bytebrief.com
Subject:     This week in tech: 5 stories worth your coffee
Attachments: (none)

FINDINGS:
  [ok] From and Reply-To domains agree
  [ok] No deceptive display-text links
  [ok] No urgency keywords
  [ok] No dangerous attachment types

Suspicion score: 0
Verdict: LOW - Looks benign. No action needed.
```

---

## 🔍 How It Works

1. **Parse:** Python's built-in `email` library reads the headers, body, and attachments.
2. **Reply-To check:** compares the domain in `From` with the domain in `Reply-To`.
3. **Link check:** pulls every `<a>` tag out of the HTML body. If the visible text looks like an address, its domain is compared with the real `href` domain (`www.` is ignored).
4. **Urgency check:** searches the subject and body for pressure phrases. Matching the start of a word means "suspend" also catches "suspended".
5. **Attachment check:** flags risky file extensions. Only the end of the name counts, so tricks like `invoice.pdf.exe` are caught.
6. **Score:**

| Score | Verdict |
|---|---|
| 2 or more | 🔴 **HIGH:** likely phishing |
| 1 | 🟡 **MEDIUM:** suspicious, verify the sender another way |
| 0 | 🟢 **LOW:** looks benign |

### 🧪 Test Data

| File | Scenario | Score |
|---|---|---|
| `samples/sample_phish.eml` | Fake "IT Support" email with all four red flags | 4 → HIGH |
| `samples/sample_legit.eml` | Normal newsletter | 0 → LOW |

> The sample attachment is a line of harmless placeholder text, not real malware.

---

## 🚧 Limitations

- **No SPF / DKIM / DMARC checks.** The `From` header can be forged, and the tool doesn't yet read the `Authentication-Results` header.
- **Lookalike domains** like `paypa1.com` or `micros0ft.com` are not detected yet.
- **Keyword matching is simple.** Real emails sometimes say "verify", and phishers can avoid the list.
- **Only link text that looks like an address is compared.** A link that says "Click here" is not checked.
- **Every check is worth +1.** A real tool would weight stronger signals more heavily.

---

## 🗺️ Roadmap

- [ ] SPF / DKIM / DMARC results from the `Authentication-Results` header
- [ ] Lookalike domain detection
- [ ] Test against real phishing emails from public datasets
- [ ] Extract all URLs and domains as IOCs
- [ ] JSON output for a SIEM

---

## 📚 References

- [MITRE ATT&CK T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK T1566.001: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1566.002: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

> ⚠️ Only analyze emails you own or are authorized to investigate.
