/// Direct-from-device sync screen.
///
/// Lets the phone pull recordings straight off the PLAUD recorder and produce
/// Markdown notes, with no Mac involved.

import SwiftUI
import BLEKit

struct DeviceSyncView: View {
    @StateObject private var model = DeviceSyncModel()
    @State private var showSettings = false

    var body: some View {
        NavigationStack {
            List {
                statusSection
                if !model.isConfigured {
                    Section {
                        Button("Set up device access") { showSettings = true }
                    } footer: {
                        Text("Needs your device credentials and a transcription key. Nothing leaves the phone except the audio you choose to transcribe.")
                    }
                } else {
                    deviceSection
                    if !model.recordings.isEmpty { recordingsSection }
                }
            }
            .navigationTitle("From Device")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                }
            }
            .sheet(isPresented: $showSettings) { DeviceSettingsView(model: model) }
            .refreshable { await model.scan() }
        }
    }

    @ViewBuilder private var statusSection: some View {
        switch model.stage {
        case .idle:
            EmptyView()
        case .scanning:
            LabeledContent("Scanning…") { ProgressView() }
        case .connecting:
            LabeledContent("Connecting…") { ProgressView() }
        case .authenticating:
            LabeledContent("Authenticating…") { ProgressView() }
        case .listing:
            LabeledContent("Reading device…") { ProgressView() }
        case .downloading(let p):
            VStack(alignment: .leading) {
                Text("Downloading \(Int(p * 100))%")
                ProgressView(value: p)
            }
        case .decrypting:
            LabeledContent("Decrypting…") { ProgressView() }
        case .transcribing(let d, let t):
            VStack(alignment: .leading) {
                Text("Transcribing \(d)/\(t)")
                ProgressView(value: Double(d), total: Double(max(t, 1)))
            }
        case .done(let msg):
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                Text(msg)
            }
        case .failed(let msg):
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text(msg)
            }
        }
    }

    @ViewBuilder private var deviceSection: some View {
        Section("Device") {
            if model.devices.isEmpty {
                Button("Scan for recorder") { Task { await model.scan() } }
            } else {
                ForEach(model.devices, id: \.identifier) { device in
                    Button {
                        Task { await model.sync(address: device.identifier.uuidString) }
                    } label: {
                        HStack {
                            Text(device.name)
                            Spacer()
                            Text("\(device.rssi) dBm").foregroundStyle(.secondary)
                        }
                    }
                    .disabled(!isIdle)
                }
                Button("Scan again") { Task { await model.scan() } }
            }
        }
    }

    @ViewBuilder private var recordingsSection: some View {
        Section("On device") {
            ForEach(model.recordings, id: \.sessionID) { session in
                HStack {
                    Text(DeviceSyncModel.title(for: session.sessionID))
                    Spacer()
                    Text(ByteCountFormatter.string(fromByteCount: Int64(session.fileSize), countStyle: .file))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var isIdle: Bool {
        switch model.stage {
        case .idle, .done, .failed: return true
        default: return false
        }
    }
}

struct DeviceSettingsView: View {
    @ObservedObject var model: DeviceSyncModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $model.credentialsMarkdown)
                        .frame(minHeight: 140)
                        .font(.caption.monospaced())
                } header: {
                    Text("Device credentials")
                } footer: {
                    Text("Paste the contents of plaud-credentials.md. Stored in the Keychain.")
                }
                Section("Transcription") {
                    TextField("Endpoint", text: $model.endpoint)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                    SecureField("API key", text: $model.apiKey)
                    TextField("Model", text: $model.model)
                        .autocorrectionDisabled()
                }
            }
            .navigationTitle("Device Setup")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { model.saveSettings(); dismiss() }
                }
            }
        }
    }
}
