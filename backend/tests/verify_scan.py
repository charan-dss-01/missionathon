import urllib.request
import urllib.parse
import json

content = """From: "Microsoft Security Team" <security-alert@company-notice.com>
Reply-To: exfiltrate@drop-box-mail.ru
To: victim@enterprise-corp.com
Subject: ACTION REQUIRED: Your Microsoft 365 Password Expires in 24 Hours!
Date: Mon, 16 Oct 2026 10:14:00 +0000
Authentication-Results: spf=fail dkim=none dmarc=fail

Dear Employee,

Your Microsoft 365 work account password will expire within 24 hours. Failure to comply will result in immediate account suspension and revocation of all corporate credentials.

Please confirm your password and submit your one-time verification code immediately to keep your access active:
<a href="http://login-m365-verify.attacker-portal.net/auth">https://account.microsoft.com/security</a>

Sincerely,
Corporate IT Helpdesk & Security Operations"""

data = urllib.parse.urlencode({
    'raw_content': content,
    'input_type': 'raw_text',
    'force_fallback': 'false',
    'simulate_both_fail': 'false'
}).encode()

req = urllib.request.Request('http://localhost:3001/api/analyze', data=data)
with urllib.request.urlopen(req) as res:
    payload = json.loads(res.read())
    print("SUCCESS ID:", payload['id'])
    print("OVERALL SCORE:", payload['risk']['overall_score'])
    print("RATING:", payload['risk']['overall_rating'])
    print("EVIDENCE COUNT:", len(payload['evidence']))
    for ev in payload['evidence']:
        print(f"  - [{ev['rule_id']}] {ev['title']} ({ev['severity']})")
    print("PROVIDER USED:", payload['llm_interpretation']['provider_used'])
