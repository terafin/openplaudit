import Foundation
import os

private let log = Logger(subsystem: "com.openplaudit.app", category: "transfer")

/// portVersion-20 file download.
///
/// The legacy `downloadFile` parses 89-byte voice records (9-byte header + one
/// 80-byte Opus frame). A v20 device instead streams 0x02 frames of
/// `[type:1][session:4][offset:4][chunk_len:1][data]`, where `data` is a slice
/// of the file — for E2EE recordings that is raw PLAUD.AI container bytes, not
/// frames. Feeding those to the 89-byte path produced "Data not 89-byte
/// aligned".
///
/// Offsets are authoritative, so the assembler only appends in order and asks
/// the device to resend from the missing offset when a notification is dropped.
public struct V20Assembler: Sendable {
    public private(set) var bytes: [UInt8] = []
    public private(set) var expected: Int = 0
    public private(set) var done = false
    public private(set) var gapAt: Int?
    public private(set) var lastProgress = Date()
    public let sessionID: UInt32
    public let fileSize: Int

    public init(sessionID: UInt32, fileSize: Int) {
        self.sessionID = sessionID
        self.fileSize = fileSize
        bytes.reserveCapacity(fileSize)
    }

    /// Consume one decrypted notification frame.
    public mutating func consume(_ frame: Data) {
        guard frame.count >= 10, frame[0] == 0x02 else { return }
        let sid = UInt32(frame[1]) | (UInt32(frame[2]) << 8)
                 | (UInt32(frame[3]) << 16) | (UInt32(frame[4]) << 24)
        guard sid == sessionID else { return }        // stale frame, earlier file
        let offset = UInt32(frame[5]) | (UInt32(frame[6]) << 8)
                   | (UInt32(frame[7]) << 16) | (UInt32(frame[8]) << 24)
        if offset == 0xFFFF_FFFF { done = true; return }

        let len = Int(frame[9])
        guard frame.count >= 10 + len else { return }
        let slice = frame.subdata(in: 10..<(10 + len))

        if Int(offset) != expected {
            if Int(offset) > expected { gapAt = expected }
            return
        }
        bytes.append(contentsOf: slice)
        expected += len
        lastProgress = Date()
    }

    public mutating func clearGap() { gapAt = nil }

    public var isComplete: Bool { expected >= fileSize || done }
}

extension PlaudClient {
    /// Tell the device a recording is safely on our side.
    ///
    /// Verified: sending this alone drops the session from the device's list
    /// (6 -> 5) without a transfer. It is how a recording is freed, since there
    /// is no BLE delete command.
    public func releaseSession(_ sessionID: UInt32) async {
        var payload = Data()
        var sid = sessionID.littleEndian
        payload.append(Data(bytes: &sid, count: 4))
        try? await send(cmdSyncFileStop, payload: payload)
    }

    /// Battery percentage (cmd 9 BATT_STATUS).
    ///
    /// Response payload is `[status, level]` — verified on hardware: `01 3a`
    /// reads back 58%. Values outside 0-100 are rejected rather than shown.
    public func batteryLevel() async -> Int? {
        do {
            try await send(cmdBattStatus)
            guard let resp = await waitResponse(cmdBattStatus, timeout: 6.0),
                  let level = resp.last, level <= 100 else { return nil }
            return Int(level)
        } catch {
            return nil
        }
    }

    /// Download a v20 recording. Returns the raw file bytes (the PLAUD.AI
    /// container for E2EE recordings) exactly as the device reports them.
    public func downloadFileV20(
        sessionID: UInt32,
        fileSize: UInt32,
        progress: (@Sendable (Int, Int) -> Void)? = nil
    ) async throws -> Data {
        let assembler = V20Assembler(sessionID: sessionID, fileSize: Int(fileSize))
        self.beginAssembly(assembler)

        defer { self.endAssembly() }

        var resends = 0
        let maxResendsAtOffset = 20

        func startFrom(_ offset: UInt32) async throws {
            var payload = Data()
            var sid = sessionID.littleEndian
            var off = offset.littleEndian
            var fs = fileSize.littleEndian
            payload.append(Data(bytes: &sid, count: 4))
            payload.append(Data(bytes: &off, count: 4))
            payload.append(Data(bytes: &fs, count: 4))
            try await send(cmdSyncFileStart, payload: payload)
            guard let head = await waitResponse(cmdSyncFileStart, timeout: 10.0) else {
                throw DownloadError("No response to SYNC_FILE_HEAD")
            }
            // Payload is [session_id:4][status:1] — the status is the FIFTH
            // byte. Reading index 3 reports the session id's high byte instead.
            if head.count >= 5, head[4] != 0 {
                throw DownloadError("Device rejected the transfer (status \(head[4]))")
            }
        }

        try await startFrom(0)

        let deadline = Date().addingTimeInterval(3600)
        var lastSeen = -1
        var stalledSince = Date()

        while Date() < deadline {
            guard let state = self.assemblerState() else { break }

            if state.isComplete { break }
            if let gap = state.gapAt {
                resends += 1
                guard resends <= maxResendsAtOffset else {
                    throw DownloadError("Transfer stuck: device would not resend from \(gap)")
                }
                log.info("gap at \(gap) — resending")
                self.clearGap()
                try await startFrom(UInt32(gap))
                continue
            }
            if state.expected != lastSeen {
                lastSeen = state.expected
                stalledSince = Date()
                progress?(state.expected, Int(fileSize))
            } else if Date().timeIntervalSince(stalledSince) > 120 {
                throw DownloadError(
                    "Transfer stalled at \(state.expected)/\(fileSize) bytes")
            }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }

        guard let final = self.assemblerState() else {
            throw DownloadError("Transfer state lost")
        }
        guard final.expected >= Int(fileSize) else {
            throw DownloadError(
                "Transfer incomplete: \(final.expected)/\(fileSize) bytes")
        }

        // Close the transfer. This is what makes the device mark the recording
        // as transferred and free its space — verified on hardware: sending it
        // dropped the session count from 7 to 6. There is no BLE delete
        // command; STOP is the only mechanism.
        var stop = Data()
        var sid = sessionID.littleEndian
        stop.append(Data(bytes: &sid, count: 4))
        try? await send(cmdSyncFileStop, payload: stop)

        return Data(final.bytes)
    }
}
