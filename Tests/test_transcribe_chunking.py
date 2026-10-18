"""Tests for chunked transcription of long audio.

Hosted Whisper endpoints cap audio duration (vLLM: 600s by default) and upload
size, so a long recording must be split, transcribed piecewise, and stitched
with the segments rebased onto the original timeline.
"""

import wave

import pytest

from plaude.transcription import whisper as W


def _write_wav(path, seconds: int, rate: int = 16000, channels: int = 1,
               width: int = 2, fill: int = 1):
    with wave.open(str(path), "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(width)
        w.setframerate(rate)
        w.writeframes(bytes([fill]) * (rate * seconds * channels * width))


def _fake_post(monkeypatch, calls):
    def fake(url, key, model, wav_bytes, timeout=300):
        # Confirm each chunk is a standalone, readable WAV.
        import io
        with wave.open(io.BytesIO(wav_bytes), "rb") as w:
            frames = w.getnframes()
            rate = w.getframerate()
        calls.append(round(frames / rate, 1))
        return {"text": f"chunk{len(calls)}"}
    monkeypatch.setattr(W, "_post_audio", fake)


def test_short_audio_is_sent_whole(tmp_path, monkeypatch):
    wav = tmp_path / "short.wav"
    _write_wav(wav, 60)
    calls = []
    _fake_post(monkeypatch, calls)
    monkeypatch.setenv("OPENAI_API_KEY", "k")

    r = W.transcribe_via_openai(str(wav), chunk_seconds=540)
    assert calls == [60.0], "short audio must be one request"
    assert r["text"] == "chunk1"
    assert "chunks" not in r  # single-shot path doesn't report chunking


def test_long_audio_is_split_and_stitched(tmp_path, monkeypatch):
    wav = tmp_path / "long.wav"
    _write_wav(wav, 1300)  # 1300s -> three chunks at 540s
    calls = []
    _fake_post(monkeypatch, calls)
    monkeypatch.setenv("OPENAI_API_KEY", "k")

    r = W.transcribe_via_openai(str(wav), chunk_seconds=540)
    assert calls == [540.0, 540.0, 220.0]
    assert r["chunks"] == 3
    assert r["text"] == "chunk1 chunk2 chunk3"
    assert r["duration_seconds"] == 1300.0


def test_segments_are_rebased_onto_full_timeline(tmp_path, monkeypatch):
    """Each piece must get a segment offset by where it started."""
    wav = tmp_path / "long.wav"
    _write_wav(wav, 1300)
    calls = []
    _fake_post(monkeypatch, calls)
    monkeypatch.setenv("OPENAI_API_KEY", "k")

    r = W.transcribe_via_openai(str(wav), chunk_seconds=540)
    starts = [s["start"] for s in r["segments"]]
    ends = [s["end"] for s in r["segments"]]
    assert len(r["segments"]) == 3, "every chunk needs an entry, not just the first"
    assert starts == [0.0, 540.0, 1080.0]
    assert ends == [540.0, 1080.0, 1300.0]


def test_chunk_frames_are_exact_multiple_of_rate(tmp_path):
    """Chunk boundaries must land on whole sample frames or WAVs are invalid."""
    wav = tmp_path / "x.wav"
    _write_wav(wav, 7, rate=44100)
    chunks = list(W._iter_wav_chunks(str(wav), 2))
    durations = [round(d, 4) for _, _, d, _ in chunks]
    assert durations == [2.0, 2.0, 2.0, 1.0]
    # Total must account for every source frame.
    assert sum(d for _, _, d, _ in chunks) == pytest.approx(7.0, abs=1e-6)


def test_multichannel_and_nondefault_rate_roundtrip(tmp_path):
    wav = tmp_path / "s.wav"
    _write_wav(wav, 4, rate=8000, channels=2)
    chunks = list(W._iter_wav_chunks(str(wav), 3))
    assert len(chunks) == 2
    import io
    for _, _, _, b in chunks:
        with wave.open(io.BytesIO(b), "rb") as w:
            assert w.getnchannels() == 2
            assert w.getframerate() == 8000


def test_missing_api_key_raises(tmp_path, monkeypatch):
    wav = tmp_path / "x.wav"
    _write_wav(wav, 5)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="No OPENAI_API_KEY"):
        W.transcribe_via_openai(str(wav))
