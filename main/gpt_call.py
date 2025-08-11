# main/mail_checker.py
import json, os, time
import requests
import logging
from config import OPENAI_API_KEY

def analyze_email_with_ai(plain_text: str, html_body: str) -> dict:
    if not OPENAI_API_KEY:
        logging.warning("OPENAI_API_KEY is not set; skipping AI analysis")
        return {}
    # cap sizes
    plain = (plain_text or "")
    html  = (html_body or "")

    logging.info("gpt input: " + plain + " LINKS: " + html)

    prompt = f"""
You are an extraction engine. From the following email content, extract:
- code: the 6-8 digit one-time code if present
- signin_url: the URL a user should click to sign in (unwrap trackers if possible)
- service: best guess service (e.g., openai.com, yahoo.com)
- confidence: 0..1
Return ONLY JSON with keys: code, signin_url, service, confidence.

Plain text:
{plain}

HTML:
{html}
"""

    url = "https://api.openai.com/v1/responses"
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    body = {
        "model": "gpt-5-mini",
        "input": prompt,
        "text": { "format": { "type": "json_object" } },  # fix: use supported type
        "max_output_tokens": 300
    }
    for attempt in range(2):
        try:
            r = requests.post(url, headers=headers, json=body, timeout=20)
            logging.info("OpenAI status=%s attempt=%s", r.status_code, attempt + 1)
            logging.info("OpenAI raw response (truncated): %s", r.text[:2000])

            if r.status_code == 200:
                data = r.json()
                # primary field for Responses API
                text = data.get("output_text")
                # fallbacks for older/newer variants
                if not text and "output" in data and isinstance(data["output"], list):
                    # concatenate any string segments
                    text = "".join(
                        seg.get("content", "") if isinstance(seg, dict) else str(seg)
                        for seg in data["output"]
                    ) or None
                if text:
                    try:
                        parsed = json.loads(text)
                        logging.info("OpenAI parsed JSON: %s", parsed)
                        return parsed
                    except Exception as e:
                        logging.warning("OpenAI JSON parse failed: %s; raw: %s", e, text[:1000])
                        return {}
                else:
                    logging.info("OpenAI returned empty content")
                    return {}
            else:
                logging.warning("OpenAI non-200: %s body: %s", r.status_code, r.text[:1000])
        except Exception as e:
            logging.exception("OpenAI call failed on attempt %s: %s", attempt + 1, e)
            time.sleep(0.5)
    return {}