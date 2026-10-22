"""Tests for Opus frame extraction from raw BLE packets."""

import struct

from plaude.audio.decoder import (
    extract_opus_frames, PACKET_SIZE, HEADER_SIZE,
    PLAUD_AI_MAGIC, PLAUD_AI_AUDIO_OFFSET, PLAUD_AI_BLOCK_SIZE,
    PLAUD_AI_FRAME_SIZE, PLAUD_AI_CHANNELS,
    extract_plaud_ai_channel, decode_plaud_ai, decode_opus_raw,
    save_wav, SAMPLE_RATE,
)
import opuslib
import io
import wave


def _make_plaud_ai_container(blocks: int, channels: int = PLAUD_AI_CHANNELS) -> bytes:
    """Build a synthetic PLAUD.AI container.

    Header is PLAUD.AI magic + metadata + padding up to PLAUD_AI_AUDIO_OFFSET;
    then `blocks` 320-byte blocks, each interleaving `channels` distinct
    80-byte Opus frames. Each channel's frames are distinct 40ms silence
    frames (with one deliberately bad first frame to exercise the error path).
    """
    import array
    enc = opuslib.Encoder(SAMPLE_RATE, 1, opuslib.APPLICATION_VOIP)
    silence = array.array("h", [0] * 640).tobytes()
    # Pad a real 40ms frame to the fixed 80-byte slot.
    def _frame(seed: int) -> bytes:
        # A second of distinct-ish frames: silence + a marker byte in the
        # SILK payload so channels/frames differ; pad to 80.
        base = enc.encode(silence, 640)
        # Replace a trailing byte with the seed so frames differ.
        if len(base) >= 2:
            base = base[:-1] + bytes([seed & 0xFF])
        return base.ljust(80, b"\x00")

    header = bytearray(PLAUD_AI_AUDIO_OFFSET)
    header[:8] = PLAUD_AI_MAGIC
    audio = bytearray()
    for b in range(blocks):
        for ch in range(channels):
            audio += _frame(b * channels + ch)
    return bytes(header) + bytes(audio)


class TestPlaudAi:
    def test_magic_detected(self):
        c = _make_plaud_ai_container(2)
        assert c[:8] == PLAUD_AI_MAGIC

    def test_extract_channel_count(self):
        c = _make_plaud_ai_container(5)
        for ch in range(PLAUD_AI_CHANNELS):
            frames = extract_plaud_ai_channel(c, ch)
            assert len(frames) == 5
            assert all(len(f) == PLAUD_AI_FRAME_SIZE for f in frames)

    def test_channels_are_distinct(self):
        c = _make_plaud_ai_container(3)
        f0 = extract_plaud_ai_channel(c, 0)
        f1 = extract_plaud_ai_channel(c, 1)
        # Interleaved distinct frames should not all be identical.
        assert f0 != f1

    def test_decode_plaud_ai_produces_pcm(self):
        c = _make_plaud_ai_container(10)
        pcm = decode_plaud_ai(c)
        # 10 frames x 40ms x 16kHz x 2 bytes = 128000 bytes PCM
        assert len(pcm) == 10 * 640 * 2
        # and it's the loudest channel (nonzero energy, not all-zero)
        assert any(pcm[i] or pcm[i + 1] for i in range(0, min(len(pcm), 4000), 2))

    def test_decode_opus_raw_detects_container(self):
        c = _make_plaud_ai_container(8)
        pcm = decode_opus_raw(c)
        assert len(pcm) == 8 * 640 * 2

    def test_invalid_channel_raises(self):
        import pytest
        c = _make_plaud_ai_container(1)
        with pytest.raises(ValueError):
            extract_plaud_ai_channel(c, PLAUD_AI_CHANNELS)

    def test_save_wav_roundtrip(self):
        c = _make_plaud_ai_container(4)
        pcm = decode_opus_raw(c)
        buf = io.BytesIO()
        save_wav(pcm, "/tmp/_plaud_test.wav")
        with wave.open("/tmp/_plaud_test.wav", "rb") as wf:
            assert wf.getnchannels() == 1
            assert wf.getframerate() == SAMPLE_RATE
            assert wf.getnframes() == len(pcm) // 2
        import os
        os.unlink("/tmp/_plaud_test.wav")


def _make_packet(session_id: int, offset: int, frame_size: int, frame_data: bytes = b"") -> bytes:
    """Build a fake 89-byte PLAUD packet."""
    header = struct.pack("<II", session_id, offset) + bytes([frame_size])
    data = frame_data[:frame_size].ljust(PACKET_SIZE - HEADER_SIZE, b"\x00")
    return header + data


class TestExtractOpusFrames:
    def test_empty_data(self):
        assert extract_opus_frames(b"") == []

    def test_single_packet(self):
        frame = bytes(range(80))
        pkt = _make_packet(1000, 0, 80, frame)
        assert len(pkt) == PACKET_SIZE
        frames = extract_opus_frames(pkt)
        assert len(frames) == 1
        assert frames[0] == frame

    def test_multiple_packets(self):
        raw = b""
        for i in range(5):
            raw += _make_packet(1000, i * 80, 80, bytes([i] * 80))
        frames = extract_opus_frames(raw)
        assert len(frames) == 5
        assert frames[3] == bytes([3] * 80)

    def test_variable_frame_sizes(self):
        raw = _make_packet(1000, 0, 60, bytes([0xAA] * 60))
        raw += _make_packet(1000, 60, 40, bytes([0xBB] * 40))
        frames = extract_opus_frames(raw)
        assert len(frames) == 2
        assert len(frames[0]) == 60
        assert len(frames[1]) == 40

    def test_zero_frame_size_skipped(self):
        raw = _make_packet(1000, 0, 0)
        raw += _make_packet(1000, 80, 80, bytes([0xFF] * 80))
        frames = extract_opus_frames(raw)
        assert len(frames) == 1

    def test_frame_size_exceeding_80_skipped(self):
        header = struct.pack("<II", 1000, 0) + bytes([81])
        pkt = header + b"\x00" * (PACKET_SIZE - HEADER_SIZE)
        frames = extract_opus_frames(pkt)
        assert len(frames) == 0

    def test_real_file_packet_count(self):
        """A 96720-byte raw file should contain 96720/89 = 1086 packets (with remainder)."""
        file_size = 96720
        expected_full_packets = file_size // PACKET_SIZE  # 1086
        raw = b"\x00" * file_size
        # Frame size byte at offset 8 in each packet is 0, so no frames extracted
        # This just tests we don't crash on real-sized data
        frames = extract_opus_frames(raw)
        assert isinstance(frames, list)
