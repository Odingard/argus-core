import os
import warnings
import threading

import anthropic
import openai

with warnings.catch_warnings():
    warnings.simplefilter("ignore", FutureWarning)
    import google.generativeai as genai

from dotenv import load_dotenv

load_dotenv(override=True)

# Default timeout for all LLM judge calls — prevents infinite hangs on
# slow/dropped provider connections. Override with ARGUS_JUDGE_TIMEOUT_S.
_JUDGE_TIMEOUT_S = float(os.environ.get("ARGUS_JUDGE_TIMEOUT_S", "45"))


class MockMessageContent:
    def __init__(self, text):
        self.text = text

class MockMessageResponse:
    def __init__(self, text, stop_reason="end_turn"):
        self.content = [MockMessageContent(text)]
        self.stop_reason = stop_reason

class ArgusMessagesAPI:
    def __init__(self):
        self.anthropic_client = None
        self.openai_client = None
        
        if os.environ.get("ANTHROPIC_API_KEY"):
            self.anthropic_client = anthropic.Anthropic(
                timeout=_JUDGE_TIMEOUT_S,
            )
        if os.environ.get("OPENAI_API_KEY"):
            self.openai_client = openai.OpenAI(
                timeout=_JUDGE_TIMEOUT_S,
            )
        if os.environ.get("GEMINI_API_KEY"):
            genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
            
    def create(self, model: str, messages: list[dict], max_tokens: int = 4000, **kwargs):
        provider = "anthropic"
        model_lower = model.lower()
        if "gpt-" in model_lower or "o1" in model_lower or "o3" in model_lower:
            provider = "openai"
        elif "gemini" in model_lower:
            provider = "gemini"
            
        # 2026 Model Aliasing
        if provider == "openai":
            if "gpt-5.4-pro" in model_lower: model = "gpt-4o"
        elif provider == "anthropic":
            # Map any unknown claude variants to the latest known good model
            if model not in (
                "claude-opus-4-5", "claude-sonnet-4-5",
                "claude-opus-4-20250514", "claude-sonnet-4-20250514",
                "claude-haiku-4-5-20251001",
                "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
                "claude-3-opus-20240229",
            ):
                model = "claude-sonnet-4-20250514"
        elif provider == "gemini":
            if "gemini-3.1-pro" in model_lower: model = "gemini-1.5-pro"
            
        if provider == "openai":
            if not self.openai_client:
                raise ValueError("OPENAI_API_KEY not configured")
            
            kw = {}
            if "o1" in model_lower or "o3" in model_lower:
                kw = {"max_completion_tokens": max_tokens}
            else:
                kw = {"max_tokens": max_tokens}

            # Run synchronous OpenAI call in a thread with a hard timeout
            # so a slow/dropped connection never hangs the entire engagement.
            result = [None]
            exc    = [None]

            def _call():
                try:
                    result[0] = self.openai_client.chat.completions.create(
                        model=model,
                        messages=messages,
                        **kw
                    )
                except Exception as e:
                    exc[0] = e

            t = threading.Thread(target=_call, daemon=True)
            t.start()
            t.join(timeout=_JUDGE_TIMEOUT_S)
            if t.is_alive():
                raise TimeoutError(
                    f"LLM judge call to {model} exceeded "
                    f"{_JUDGE_TIMEOUT_S}s — skipping probe"
                )
            if exc[0] is not None:
                raise exc[0]
            resp = result[0]
            return MockMessageResponse(
                resp.choices[0].message.content,
                resp.choices[0].finish_reason,
            )
            
        elif provider == "gemini":
            if not os.environ.get("GEMINI_API_KEY"):
                raise ValueError("GEMINI_API_KEY not configured")
            prompt = "\n\n".join([m['content'] for m in messages if 'content' in m])
            gemini_model = genai.GenerativeModel(model)
            response = gemini_model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(max_output_tokens=max_tokens)
            )
            return MockMessageResponse(response.text)
            
        else:
            if not self.anthropic_client:
                raise ValueError(f"ANTHROPIC_API_KEY not configured for model {model}")

            result = [None]
            exc    = [None]

            def _call_anthropic():
                try:
                    result[0] = self.anthropic_client.messages.create(
                        model=model,
                        max_tokens=max_tokens,
                        messages=messages,
                        **kwargs
                    )
                except Exception as e:
                    exc[0] = e

            t = threading.Thread(target=_call_anthropic, daemon=True)
            t.start()
            t.join(timeout=_JUDGE_TIMEOUT_S)
            if t.is_alive():
                raise TimeoutError(
                    f"LLM judge call to {model} exceeded "
                    f"{_JUDGE_TIMEOUT_S}s — skipping probe"
                )
            if exc[0] is not None:
                raise exc[0]
            return result[0]

class ArgusClient:
    """Seamless Multi-Provider Interface mimicking Anthropic.Anthropic()"""
    def __init__(self):
        self.messages = ArgusMessagesAPI()
