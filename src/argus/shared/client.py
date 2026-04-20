import os
import anthropic
import openai
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

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
            self.anthropic_client = anthropic.Anthropic()
        if os.environ.get("OPENAI_API_KEY"):
            self.openai_client = openai.OpenAI()
        if os.environ.get("GEMINI_API_KEY"):
            genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
            
    def create(self, model: str, messages: list[dict], max_tokens: int = 4000, **kwargs):
        provider = "anthropic"
        model_lower = model.lower()
        if "gpt-" in model_lower or "o1" in model_lower or "o3" in model_lower:
            provider = "openai"
        elif "gemini" in model_lower:
            provider = "gemini"
            
        if provider == "openai":
            if not self.openai_client:
                raise ValueError("OPENAI_API_KEY not configured")
            
            kw = {}
            if "o1" in model_lower or "o3" in model_lower:
                kw = {"max_completion_tokens": max_tokens}
            else:
                kw = {"max_tokens": max_tokens}
            
            resp = self.openai_client.chat.completions.create(
                model=model,
                messages=messages,
                **kw
            )
            return MockMessageResponse(resp.choices[0].message.content, resp.choices[0].finish_reason)
            
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
            return self.anthropic_client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=messages,
                **kwargs
            )

class ArgusClient:
    """Seamless Multi-Provider Interface mimicking Anthropic.Anthropic()"""
    def __init__(self):
        self.messages = ArgusMessagesAPI()
