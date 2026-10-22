/// Direct device sync — talks to the PLAUD recorder over BLE from the phone.
///
/// No Mac in the loop: the phone authenticates to the device (v20 RSA
/// pre-handshake), downloads the recording, decrypts the PLAUD.AI container,
/// muxes the Opus frames into Ogg, and uploads that to a transcription
/// endpoint. The server decodes Opus, so the phone needs no codec.

import Foundation
import SwiftUI
import BLEKit
import PlaudCore
import SharedKit

@MainActor
final class DeviceSyncModel: ObservableObject {
    enum Stage: Equatable {
        case idle
        case scanning
        case connecting
        case authenticating
        case listing
        case downloading(Double)
        case decrypting
        case transcribing(Int, Int)
        case done(String)
        case failed(String)
    }

    @Published private(set) var stage: Stage = .idle
    @Published private(set) var devices: [DiscoveredDevice] = []
    @Published private(set) var recordings: [RecordingSession] = []
    @Published private(set) var lastTranscriptPath: URL?
    @Published var credentialsMarkdown: String = ""
    @Published var deviceAddress: String = ""
    @Published var endpoint: String = "https://bifrost.siliconspirit.net/v1/audio/transcriptions"
    @Published var apiKey: String = ""
    @Published var model: String = "vllm/whisper-large-v3"

    private let credsKey = "plaud.credentials"
    private let addressKey = "plaud.address"
    private let endpointKey = "plaud.endpoint"
    private let apiKeyKey = "plaud.apikey"

    init() {
        credentialsMarkdown = KeychainHelper.load(key: credsKey) ?? ""
        deviceAddress = KeychainHelper.load(key: addressKey) ?? ""
        endpoint = KeychainHelper.load(key: endpointKey) ?? endpoint
        apiKey = KeychainHelper.load(key: apiKeyKey) ?? ""
    }

    var isConfigured: Bool {
        !credentialsMarkdown.isEmpty && !deviceAddress.isEmpty && !apiKey.isEmpty
    }

    func saveSettings() {
        try? KeychainHelper.save(key: credsKey, value: credentialsMarkdown)
        try? KeychainHelper.save(key: addressKey, value: deviceAddress)
        try? KeychainHelper.save(key: endpointKey, value: endpoint)
        try? KeychainHelper.save(key: apiKeyKey, value: apiKey)
    }

    // MARK: - Scan

    func scan() async {
        stage = .scanning
        devices = await BLEScanner().scan(timeout: 12)
        stage = devices.isEmpty ? .failed("No PLAUD device found — tap Record once to wake it, and make sure the PLAUD app isn't connected.") : .idle
    }

    // MARK: - Sync

    func sync(address: String) async {
        guard let creds = try? DeviceCredentials.parse(markdown: credentialsMarkdown) else {
            stage = .failed("Credentials missing or unreadable — paste plaud-credentials.md")
            return
        }
        guard let url = URL(string: endpoint), !apiKey.isEmpty else {
            stage = .failed("Transcription endpoint or API key missing")
            return
        }

        let client = PlaudClient(address: address, token: "", credentials: creds)
        do {
            stage = .connecting
            try await client.connect()

            stage = .authenticating
            _ = try await client.handshake()
            try await client.timeSync()

            stage = .listing
            let sessions = try await client.getSessions()
            recordings = sessions
            guard !sessions.isEmpty else {
                stage = .failed("No recordings on the device")
                await client.disconnect()
                return
            }

            let transcriber = Transcriber(endpoint: url, apiKey: apiKey, model: model)
            var completed = 0

            for session in sessions {
                stage = .downloading(0)
                let raw = try await downloadFile(
                    client: client, sessionID: session.sessionID,
                    fileSize: session.fileSize
                )

                stage = .decrypting
                let frames = try PLAUDAIContainer.decryptToFrames(
                    raw, privateKeyPEM: creds.rsaPrivateKeyPEM)

                stage = .transcribing(0, 1)
                let result = try await transcriber.transcribe(frames: frames)

                let title = Self.title(for: session.sessionID)
                let md = TranscriptMarkdown.render(result, title: title,
                                                   created: Date(timeIntervalSince1970: TimeInterval(session.sessionID)))
                lastTranscriptPath = try save(markdown: md, name: Self.fileName(for: session.sessionID))
                completed += 1
            }

            await client.disconnect()
            stage = .done("Synced \(completed) recording\(completed == 1 ? "" : "s")")
        } catch {
            await client.disconnect()
            stage = .failed(error.localizedDescription)
        }
    }

    // MARK: - Output

    /// Markdown goes to the app's Documents directory, which is visible in the
    /// Files app (and therefore reachable by Obsidian / iCloud Drive).
    private func save(markdown: String, name: String) throws -> URL {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Plaud", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("\(name).md")
        try markdown.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    static func fileName(for sessionID: UInt32) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd_HHmmss"
        f.timeZone = TimeZone(identifier: "UTC")
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(sessionID))) + "_UTC"
    }

    static func title(for sessionID: UInt32) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm"
        f.timeZone = TimeZone(identifier: "UTC")
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(sessionID))) + " UTC"
    }
}
