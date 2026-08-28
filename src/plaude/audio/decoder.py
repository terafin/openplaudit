"""Opus decoding to WAV.

Two source formats are supported:

1. v20 file-sync (NB100, portVersion>=20): the device streams the actual
   encoded audio container bytes — an OGG/Opus file (magic "OggS"), chunked
   by offset with no per-frame framing added. Detected by probing for "OggS".
2. Legacy 89-byte raw packets (older firmware): each packet is
   [session_id:4][offset:4][frame_size:1][opus_frame:80], a sequence of
   20ms 16kHz mono frames.

Both decode to 16kHz mono 16-bit PCM.
"""

import io
import struct
import wave

import opuslib

SAMPLE_RATE = 16000
CHANNELS = 1
FRAME_DURATION_MS = 20
SAMPLES_PER_FRAME = SAMPLE_RATE * FRAME_DURATION_MS // 1000  # 320
PACKET_SIZE = 89
HEADER_SIZE = 9  # session_id(4) + offset(4) + frame_size(1)
OGG_MAGIC = b"OggS"


def extract_opus_frames(raw_data: bytes) -> list[bytes]:
    """Extract Opus frames from raw PLAUD BLE packets.

    Each packet is 89 bytes: 9-byte header + up to 80-byte Opus frame.
    The frame_size byte at offset 8 gives the actual Opus frame length.
    """
    frames = []
    offset = 0
    while offset + HEADER_SIZE <= len(raw_data):
        if offset + PACKET_SIZE > len(raw_data):
            # Partial trailing packet — extract what we can
            remaining = len(raw_data) - offset
            if remaining > HEADER_SIZE:
                frame_size = raw_data[offset + 8]
                available = remaining - HEADER_SIZE
                if frame_size > 0 and available >= frame_size:
                    frames.append(raw_data[offset + HEADER_SIZE:offset + HEADER_SIZE + frame_size])
            break

        frame_size = raw_data[offset + 8]
        if frame_size > 0 and frame_size <= 80:
            frames.append(raw_data[offset + HEADER_SIZE:offset + HEADER_SIZE + frame_size])
        offset += PACKET_SIZE

    return frames


def decode_opus_frames(frames: list[bytes]) -> bytes:
    """Decode a list of Opus frames to raw PCM (16-bit LE, 16kHz mono)."""
    decoder = opuslib.Decoder(SAMPLE_RATE, CHANNELS)
    pcm_chunks = []
    for frame in frames:
        try:
            pcm = decoder.decode(frame, SAMPLES_PER_FRAME)
            pcm_chunks.append(pcm)
        except opuslib.OpusError:
            # Insert silence for corrupted frames
            pcm_chunks.append(b"\x00" * SAMPLES_PER_FRAME * 2)
    return b"".join(pcm_chunks)


def decode_ogg_opus(raw_data: bytes) -> bytes:
    """Decode an OGG/Opus container (as streamed by v20 devices) to PCM.

    Walks OGG pages, reassembles lacing-segment packets, skips the OpusHead /
    OpusTags header pages, and feeds each packet to an Opus decoder.
    """
    decoder = opuslib.Decoder(SAMPLE_RATE, CHANNELS)
    pcm_chunks = []
    offset = 0
    n = len(raw_data)
    max_frame_samples = 5760  # max Opus frame at any rate

    while offset + 27 <= n:
        if raw_data[offset:offset + 4] != OGG_MAGIC:
            offset += 1
            continue

        # OGG page: "OggS" + 22 bytes + segment_count(1) + lacing table
        seg_count = raw_data[offset + 26]
        table_start = offset + 27
        table_end = table_start + seg_count
        if table_end > n:
            break
        lacing = raw_data[table_start:table_end]

        body_start = table_end
        body_size = sum(lacing)
        if body_start + body_size > n:
            break

        # Reassemble packets from the lacing values: a segment of 255 is
        # continued on the next lacing byte; a value < 255 closes the packet.
        packet = bytearray()
        for seg in lacing:
            packet += raw_data[body_start:body_start + seg]
            body_start += seg
            if seg < 255:
                if len(packet) > 8 and packet[:8] in (b"OpusHead", b"OpusTags"):
                    packet = bytearray()
                    continue
                try:
                    pcm = decoder.decode(bytes(packet), max_frame_samples)
                    pcm_chunks.append(pcm)
                except opuslib.OpusError:
                    pass
                packet = bytearray()

        offset = body_start

    if not pcm_chunks:
        raise ValueError("No decodable Opus packets found in OGG data")
    return b"".join(pcm_chunks)


def decode_opus_raw(raw_data: bytes) -> bytes:
    """Decode raw PLAUD BLE data to PCM audio.

    Auto-detects the container: OGG/Opus (v20 file-sync) vs raw 89-byte frames.
    """
    if raw_data[:4] == OGG_MAGIC:
        return decode_ogg_opus(raw_data)
    frames = extract_opus_frames(raw_data)
    return decode_opus_frames(frames)


def save_wav(pcm_data: bytes, path: str, sample_rate: int = SAMPLE_RATE) -> None:
    """Write raw PCM data to a WAV file."""
    with wave.open(path, "wb") as wf:
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(2)  # 16-bit
        wf.setframerate(sample_rate)
        wf.writeframes(pcm_data)


def get_wav_duration(wav_path: str) -> float | None:
    """Read actual audio duration from a WAV file header. Returns None for non-WAV."""
    try:
        with wave.open(wav_path, "rb") as wf:
            return wf.getnframes() / wf.getframerate()
    except Exception:
        return None


def pcm_to_wav_bytes(pcm_data: bytes, sample_rate: int = SAMPLE_RATE) -> bytes:
    """Convert raw PCM data to in-memory WAV bytes."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(pcm_data)
    return buf.getvalue()
