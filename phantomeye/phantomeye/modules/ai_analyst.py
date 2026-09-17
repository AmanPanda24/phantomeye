"""
PhantomEye — AI Analyst Module (Multi-Provider)
Supports: Ollama (local/free), Groq (free tier), Gemini (free tier), Anthropic (paid)

Configure via:
  phantomeye config --show      → see current provider
  Set ai_provider + ai_api_key in ~/.phantomeye/config.json
"""

import json
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

OLLAMA_URL  = "http://localhost:11434/api/generate"
GROQ_URL    = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_URL  = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

DEFAULT_MODELS = {
    "ollama":     "mistral",
    "groq":       "llama-3.1-70b-versatile",
    "gemini":     "gemini-1.5-flash",
    "anthropic":  "claude-sonnet-4-20250514",
}

SYSTEM_PROMPT = """You are PhantomEye's AI Analyst — an expert OSINT intelligence officer.
Your task is to synthesize raw reconnaissance data into a structured, actionable intelligence report.

Guidelines:
- Be concise but comprehensive
- Highlight anomalies, risks, and notable findings
- Identify patterns across the collected data
- Suggest follow-up investigation vectors where appropriate
- Flag any indicators of compromise (IoC) or suspicious patterns
- Keep the report professional and objective
- Format your response in clear sections using markdown
- Never fabricate data; only analyze what was provided
- Include an "Intelligence Summary" section at the top with key findings
- End with "Recommended Next Steps" listing specific follow-up actions

Ethical reminder: This tool is for authorized security research, penetration testing,
and legitimate OSINT investigations only. Always operate within legal boundaries."""

PROMPT_TEMPLATES = {
    "username": """Analyse the following username OSINT data for target: {target}

Raw data:
{data}

Provide:
1. **Intelligence Summary** — Key findings in 3-5 bullet points
2. **Platform Footprint** — Analysis of where the user is active
3. **Digital Behaviour Pattern** — What the presence pattern reveals
4. **Risk Indicators** — Any concerning findings
5. **Recommended Next Steps** — Specific follow-up actions""",

    "email": """Analyse the following email address OSINT data for target: {target}

Raw data:
{data}

Provide:
1. **Intelligence Summary** — Key findings in 3-5 bullet points
2. **Breach Analysis** — Assessment of data breach exposure
3. **Account Legitimacy** — Is this a real, active account or throwaway?
4. **Social Footprint** — What the email's online presence reveals
5. **Risk Assessment** — Severity of any discovered issues
6. **Recommended Next Steps** — Specific follow-up actions""",

    "ip": """Analyse the following IP address OSINT data for target: {target}

Raw data:
{data}

Provide:
1. **Intelligence Summary** — Key findings in 3-5 bullet points
2. **Infrastructure Assessment** — What this IP represents
3. **Geopolitical Context** — Location and jurisdiction analysis
4. **Threat Indicators** — Abuse scores, proxy/VPN usage, malicious patterns
5. **Attack Surface** — Open ports, services, vulnerabilities if Shodan data present
6. **Recommended Next Steps** — Specific follow-up actions""",

    "domain": """Analyse the following domain OSINT data for target: {target}

Raw data:
{data}

Provide:
1. **Intelligence Summary** — Key findings in 3-5 bullet points
2. **Domain Maturity** — Age, history, and legitimacy assessment
3. **Infrastructure Overview** — Hosting, CDN, technology stack
4. **Security Posture** — SSL, DNS security, headers analysis
5. **Technology Fingerprint** — What the tech stack reveals
6. **Subdomains of Interest** — Notable subdomains discovered
7. **Recommended Next Steps** — Specific follow-up actions""",

    "phone": """Analyse the following phone number OSINT data for target: {target}

Raw data:
{data}

Provide:
1. **Intelligence Summary** — Key findings in 3-5 bullet points
2. **Number Attribution** — Region, carrier, line type analysis
3. **Legitimacy Assessment** — Is this a VoIP, burner, or real number?
4. **OSINT Vectors** — Best approaches for further investigation
5. **Recommended Next Steps** — Specific follow-up actions""",
}

class AIAnalyst:
    def __init__(self, api_key: str = "", provider: str = "", model: str = ""):
        """
        Auto-detects the best available provider if none specified.
        Priority: Anthropic → Groq → Gemini → Ollama (local)
        """
        self.api_key = api_key

        # Resolve provider
        if provider:
            self.provider = provider.lower()
        else:
            self.provider = self._auto_detect_provider(api_key)

        # Resolve model
        self.model = model or DEFAULT_MODELS.get(self.provider, "mistral")

        console.print(
            f"[dim]AI provider: [bold]{self.provider}[/bold] · model: [bold]{self.model}[/bold][/dim]"
        )

    def _auto_detect_provider(self, api_key: str) -> str:
        """Pick the best provider based on what's configured."""
        if api_key:
            # Identify key format
            if api_key.startswith("sk-ant-"):
                return "anthropic"
            if api_key.startswith("gsk_"):
                return "groq"
            if len(api_key) > 30:
                return "gemini"

        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=3)
            if r.status_code == 200:
                return "ollama"
        except Exception:
            pass

        return "ollama"   
    
    def analyse(self, target_type: str, target: str, data: dict) -> str:
        template = PROMPT_TEMPLATES.get(target_type, PROMPT_TEMPLATES["username"])
        prompt = template.format(
            target=target,
            data=json.dumps(data, indent=2, default=str)
        )

        dispatch = {
            "ollama":    self._call_ollama,
            "groq":      self._call_groq,
            "gemini":    self._call_gemini,
            "anthropic": self._call_anthropic,
        }

        fn = dispatch.get(self.provider)
        if not fn:
            return (
                f"❌ Unknown AI provider '{self.provider}'. "
                "Valid options: ollama, groq, gemini, anthropic"
            )

        with Progress(
            SpinnerColumn(),
            TextColumn(f"[magenta]AI analyst working ({self.provider}/{self.model})…"),
            console=console,
            transient=True,
        ) as prog:
            prog.add_task("", total=None)
            return fn(prompt)

    def _call_ollama(self, prompt: str) -> str:
        full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
        try:
            resp = requests.post(
                OLLAMA_URL,
                json={"model": self.model, "prompt": full_prompt, "stream": False},
                timeout=180,   # local models can be slow
            )
            if resp.status_code == 200:
                return resp.json().get("response", "No response from Ollama")
            elif resp.status_code == 404:
                return (
                    f"❌ Model '{self.model}' not found in Ollama.\n"
                    f"Pull it first: ollama pull {self.model}"
                )
            return f"❌ Ollama error: HTTP {resp.status_code} — {resp.text[:200]}"

        except requests.exceptions.ConnectionError:
            return (
                "❌ Cannot connect to Ollama.\n"
                "Start it with:  ollama serve\n"
                "Install guide:  https://ollama.com/install"
            )
        except requests.exceptions.Timeout:
            return (
                f"❌ Ollama timed out (180s). Model '{self.model}' may be too large "
                "for your hardware. Try: ollama pull phi3"
            )
        except Exception as e:
            return f"❌ Ollama error: {e}"

    def _call_groq(self, prompt: str) -> str:
        if not self.api_key:
            return (
                "❌ No Groq API key set.\n"
                "Get a free key at: https://console.groq.com\n"
                "Then run: phantomeye config --anthropic-key YOUR_GROQ_KEY"
            )
        try:
            resp = requests.post(
                GROQ_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type":  "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                    "max_tokens": 2048,
                    "temperature": 0.3,
                },
                timeout=60,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            elif resp.status_code == 401:
                return "❌ Invalid Groq API key. Get a free key at: https://console.groq.com"
            elif resp.status_code == 429:
                return "❌ Groq rate limit hit. Free tier: 30 req/min. Wait a moment and retry."
            return f"❌ Groq error: HTTP {resp.status_code} — {resp.text[:300]}"

        except requests.exceptions.Timeout:
            return "❌ Groq request timed out (60s)."
        except Exception as e:
            return f"❌ Groq error: {e}"

    def _call_gemini(self, prompt: str) -> str:
        if not self.api_key:
            return (
                "❌ No Gemini API key set.\n"
                "Get a free key at: https://aistudio.google.com\n"
                "Then run: phantomeye config --anthropic-key YOUR_GEMINI_KEY"
            )
        full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
        url = GEMINI_URL.format(model=self.model)
        try:
            resp = requests.post(
                f"{url}?key={self.api_key}",
                json={
                    "contents": [{"parts": [{"text": full_prompt}]}],
                    "generationConfig": {
                        "maxOutputTokens": 2048,
                        "temperature": 0.3,
                    },
                },
                timeout=60,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            elif resp.status_code == 400:
                return f"❌ Gemini bad request: {resp.json().get('error', {}).get('message', resp.text[:200])}"
            elif resp.status_code == 403:
                return "❌ Invalid Gemini API key. Get a free key at: https://aistudio.google.com"
            elif resp.status_code == 429:
                return "❌ Gemini rate limit hit. Free tier: 15 req/min, 1500 req/day."
            return f"❌ Gemini error: HTTP {resp.status_code} — {resp.text[:300]}"

        except requests.exceptions.Timeout:
            return "❌ Gemini request timed out (60s)."
        except Exception as e:
            return f"❌ Gemini error: {e}"

    def _call_anthropic(self, prompt: str) -> str:
        if not self.api_key:
            return (
                "❌ No Anthropic API key set.\n"
                "Get one at: https://console.anthropic.com\n"
                "Then run: phantomeye config --anthropic-key YOUR_KEY"
            )
        try:
            resp = requests.post(
                ANTHROPIC_URL,
                headers={
                    "x-api-key":         self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type":      "application/json",
                },
                json={
                    "model":      self.model,
                    "max_tokens": 2048,
                    "system":     SYSTEM_PROMPT,
                    "messages":   [{"role": "user", "content": prompt}],
                },
                timeout=60,
            )
            if resp.status_code == 200:
                return resp.json()["content"][0]["text"]
            elif resp.status_code == 401:
                return "❌ Invalid Anthropic API key."
            elif resp.status_code == 429:
                return "❌ Anthropic rate limit exceeded. Wait and retry."
            return f"❌ Anthropic error: HTTP {resp.status_code} — {resp.text[:300]}"

        except requests.exceptions.Timeout:
            return "❌ Anthropic request timed out (60s)."
        except Exception as e:
            return f"❌ Anthropic error: {e}"
