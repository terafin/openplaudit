import Foundation

/// Minimal Ogg/Opus muxer.
///
/// The PLAUD.AI container yields bare Opus frames with no container, and the
/// transcription endpoint needs a real file. Muxing into Ogg means the phone
/// needs no Opus codec at all — the server decodes it. (Verified: the endpoint
/// accepts Ogg/Opus and transcribes it correctly.)
///
/// Only what a decoder needs is written: an OpusHead page, an empty OpusTags
/// page, then audio pages carrying the frames.
public enum OggOpus {
    /// Opus timestamps are always in 48 kHz samples regardless of the source
    /// rate, so one 20 ms frame advances the granule by 960 — not by the 320
    /// samples the frame represents at 16 kHz. Getting this wrong makes the
    /// file report a duration 3× too short while still decoding.
    private static let granulePerFrame: UInt64 = 960

    /// Frames per audio page. Small pages keep memory low for a multi-hour
    /// recording; the value only affects container overhead.
    private static let framesPerPage = 50

    /// Structural Opus packet check (RFC 6716 §3.1 TOC).
    ///
    /// A device glitch can leave a junk frame in the stream. The Python client
    /// decodes tolerantly and substitutes silence, but hosted decoders reject
    /// the WHOLE file for one bad packet — measured: 1 bad frame in 1728 made
    /// vLLM answer "invalid or corrupted audio". Dropping it is the right call;
    /// the alternative is losing the transcript.
    public static func isValidOpusPacket(_ frame: Data) -> Bool {
        guard let toc = frame.first else { return false }
        let payload = frame.count - 1
        switch toc & 0x03 {
        case 0: return payload >= 1          // one frame
        case 1: return payload >= 2 && payload % 2 == 0   // two equal frames
        case 2: return payload >= 2          // two, second shorter
        default: return payload >= 2         // arbitrary count
        }
    }

    public static func mux(frames: Data, frameSize: Int = 80,
                           sampleRate: Int = 16000, channels: Int = 1,
                           serial: UInt32 = 0x50_4C_41_55) -> Data {
        var out = Data()
        var sequence: UInt32 = 0
        var granule: UInt64 = 0

        // 1. OpusHead (19 bytes), BOS page.
        var head = Data("OpusHead".utf8)
        head.append(1)                                  // version
        head.append(UInt8(channels))
        head.appendLE(UInt16(312))                      // pre-skip
        head.appendLE(UInt32(sampleRate))
        head.appendLE(UInt16(0))                        // output gain
        head.append(0)                                  // channel mapping family
        out.append(page(packets: [head], headerType: 0x02, granule: 0,
                        serial: serial, sequence: &sequence))

        // 2. OpusTags, empty vendor comment.
        var tags = Data("OpusTags".utf8)
        let vendor = Data("plaude".utf8)
        tags.appendLE(UInt32(vendor.count))
        tags.append(vendor)
        tags.appendLE(UInt32(0))                        // no user comments
        out.append(page(packets: [tags], headerType: 0, granule: 0,
                        serial: serial, sequence: &sequence))

        // 3. Audio pages.
        var packet: [Data] = []
        var offset = 0
        while offset < frames.count {
            let end = min(offset + frameSize, frames.count)
            let frame = frames.subdata(in: offset..<end)
            offset = end
            if frame.count < frameSize { break }        // drop a torn tail
            guard isValidOpusPacket(frame) else { continue }   // skip junk
            packet.append(frame)
            if packet.count == framesPerPage {
                granule += UInt64(packet.count) * granulePerFrame
                out.append(page(packets: packet, headerType: 0, granule: granule,
                                serial: serial, sequence: &sequence))
                packet.removeAll(keepingCapacity: true)
            }
        }
        if !packet.isEmpty {
            granule += UInt64(packet.count) * granulePerFrame
            out.append(page(packets: packet, headerType: 0x04, granule: granule,
                            serial: serial, sequence: &sequence))   // EOS
        }
        return out
    }

    // MARK: - Page assembly

    private static func page(packets: [Data], headerType: UInt8, granule: UInt64,
                             serial: UInt32, sequence: inout UInt32) -> Data {
        // A packet longer than 255 bytes spans multiple lacing values.
        var lacing = [UInt8]()
        for p in packets {
            var remaining = p.count
            while remaining >= 255 { lacing.append(255); remaining -= 255 }
            lacing.append(UInt8(remaining))
        }
        // Ogg allows at most 255 lacing values per page; our packets are small,
        // so a single page always fits.

        var header = Data()
        header.append(contentsOf: Array("OggS".utf8))
        header.append(0)                                // stream structure version
        header.append(headerType)
        header.appendLE(granule)
        header.appendLE(serial)
        header.appendLE(sequence)
        header.appendLE(UInt32(0))                      // CRC placeholder
        header.append(UInt8(lacing.count))
        header.append(contentsOf: lacing)

        var body = Data()
        for p in packets { body.append(p) }

        var pageData = header
        pageData.append(body)
        let crc = crc32(pageData)
        // Checksum lives at bytes 22..<26 ("OggS" 4 + version 1 + type 1 +
        // granule 8 + serial 4 + sequence 4), computed over the whole page with
        // this field zeroed — which it is at this point.
        let crcOffset = 22
        pageData.replaceSubrange(crcOffset..<(crcOffset + 4), with: Data([
            UInt8(crc & 0xff), UInt8((crc >> 8) & 0xff),
            UInt8((crc >> 16) & 0xff), UInt8((crc >> 24) & 0xff),
        ]))
        sequence += 1
        return pageData
    }

    /// Ogg's CRC-32: polynomial 0x04C11DB7, init 0, no reflection, no final XOR.
    static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0
        for byte in data {
            crc ^= UInt32(byte) << 24
            for _ in 0..<8 {
                crc = (crc & 0x8000_0000) != 0 ? (crc << 1) ^ 0x04C1_1DB7 : (crc << 1)
            }
        }
        return crc
    }
}

extension Data {
    mutating func appendLE(_ v: UInt16) {
        append(UInt8(v & 0xff)); append(UInt8((v >> 8) & 0xff))
    }
    mutating func appendLE(_ v: UInt32) {
        append(UInt8(v & 0xff)); append(UInt8((v >> 8) & 0xff))
        append(UInt8((v >> 16) & 0xff)); append(UInt8((v >> 24) & 0xff))
    }
    mutating func appendLE(_ v: UInt64) {
        for i in 0..<8 { append(UInt8((v >> (8 * UInt64(i))) & 0xff)) }
    }
}
