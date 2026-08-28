"""Whisper transcription wrapper — local model, JSON output with timestamps."""

import json
import os
import urllib.request
import wave


def transcribe_via_openai(wav_path: str, model: str = "whisper-1",
                          api_key: str | None = None) -> dict:
    """Transcribe a WAV via any OpenAI-compatible /v1/audio/transcriptions endpoint.

    Uses OPENAI_API_KEY and OPENAI_BASE_URL from the environment (standard
    OpenAI-style config) so no internal endpoint or key is hardcoded. Falls
    back to api.openai.com if OPENAI_BASE_URL is unset.

    Returns the same shape as transcribe_with_model: {text, segments, ...}.
    """
    key = api_key or os.environ.get("OPENAI_API_KEY")
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    if not key:
        raise RuntimeError("No OPENAI_API_KEY in environment for transcription")

    url = f"{base.rstrip('/')}/audio/transcriptions"
    boundary = "----plaude"
    with open(wav_path, "rb") as f:
        wav_bytes = f.read()

    body = bytearray()
    for name, val in [("model", model)]:
        body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{val}\r\n".encode()
    body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.wav\"\r\nContent-Type: audio/wav\r\n\r\n".encode()
    body += wav_bytes
    body += f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(url, data=bytes(body), headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    })
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.load(resp)

    duration = _get_wav_duration(wav_path)
    text = (data.get("text") or "").strip()
    return {
        "duration_seconds": round(duration, 1) if duration else 0.0,
        "model": model,
        "language": "unknown",
        "segments": [{"start": 0.0, "end": round(duration, 2) if duration else 0.0, "text": text}],
        "text": text,
    }


def load_model(model_name: str = "medium"):
    """Load a Whisper model. Call once and reuse across transcriptions.

    Whisper is imported lazily so the module stays importable (and patchable)
    without the heavy torch/whisper stack being present.
    """
    try:
        import whisper
    except ImportError:
        raise ImportError(
            "openai-whisper is not installed in this environment. "
            "This build has the ML/transcription stack removed (see "
            "~/openplaudit-no-whisper.patch). Sync downloads and decodes audio "
            "but skips transcription."
        ) from None
    return whisper.load_model(model_name)


def _get_wav_duration(wav_path: str) -> float | None:
    """Read actual audio duration from a WAV file header. Returns None for non-WAV."""
    try:
        with wave.open(wav_path, "rb") as wf:
            return wf.getnframes() / wf.getframerate()
    except Exception:
        return None


def transcribe_with_model(
    model,
    wav_path: str,
    model_name: str = "medium",
    language: str | None = "en",
) -> dict:
    """Transcribe a WAV file using a pre-loaded Whisper model.

    Returns a dict with file metadata, full text, and timestamped segments.
    Duration is derived from the audio file when possible, falling back to
    Whisper's last segment end time.
    """
    options = {}
    if language:
        options["language"] = language

    result = model.transcribe(wav_path, **options)

    segments = [
        {"start": round(s["start"], 2), "end": round(s["end"], 2), "text": s["text"].strip()}
        for s in result.get("segments", [])
    ]

    # Prefer actual audio duration from file header; fall back to segment end
    duration = _get_wav_duration(wav_path)
    if duration is None:
        duration = segments[-1]["end"] if segments else 0.0

    return {
        "duration_seconds": round(duration, 1),
        "model": model_name,
        "language": result.get("language", language or "unknown"),
        "segments": segments,
        "text": result.get("text", "").strip(),
    }
