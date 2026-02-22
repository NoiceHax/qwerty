"""Gemini AI service — client for Google Generative AI.

Handles API calls, retries, timeouts, and error handling.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)


class GeminiServiceError(Exception):
    pass


class GeminiService:
    """Wrapper around the Google Generative AI SDK."""

    def __init__(self):
        if not settings.gemini_api_key:
            raise GeminiServiceError("GEMINI_API_KEY not configured")

        import google.generativeai as genai
        genai.configure(api_key=settings.gemini_api_key)
        self._model = genai.GenerativeModel(settings.gemini_model)
        logger.info(f"GeminiService initialized with model={settings.gemini_model}")

    async def generate(self, prompt: str, system_instruction: str = "") -> str:
        """Generate a text response from Gemini.

        Uses synchronous SDK wrapped for async compatibility.
        """
        import google.generativeai as genai

        try:
            logger.info(f"Gemini: sending prompt ({len(prompt)} chars)")

            # Build the full prompt with system context
            full_prompt = f"{system_instruction}\n\n{prompt}" if system_instruction else prompt

            response = self._model.generate_content(
                full_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=2048,
                ),
            )

            text = response.text
            logger.info(f"Gemini: received response ({len(text)} chars)")
            return text

        except Exception as exc:
            logger.error(f"Gemini API error: {exc}")
            raise GeminiServiceError(f"Gemini generation failed: {exc}") from exc
