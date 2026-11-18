
import json
import urllib.error
import urllib.request


class OllamaClient:
    """Connects AgentShield to a locally running Ollama model."""

    def __init__(
        self,
        model: str = "qwen2.5:3b",
        base_url: str = "http://localhost:11434",
        timeout: int = 120,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Send a prompt to Ollama and return the generated text."""

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string.")

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        if system_prompt:
            payload["system"] = system_prompt

        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            url=f"{self.base_url}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout
            ) as response:
                result = json.load(response)

        except urllib.error.URLError as exc:
            raise ConnectionError(
                "Cannot connect to Ollama. Check that Ollama is running."
            ) from exc

        if not isinstance(result, dict):
            raise ValueError("Ollama returned an invalid response.")

        generated_text = result.get("response")

        if not isinstance(generated_text, str):
            raise ValueError("Ollama response contains no generated text.")

        return generated_text
