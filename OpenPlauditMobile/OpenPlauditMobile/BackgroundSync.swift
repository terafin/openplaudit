/// Periodic background sync.
///
/// iOS will not let a bulk BLE transfer run indefinitely in the background, but
/// it does hand out short execution windows — ~30 s for a refresh, minutes for
/// a processing task. That is enough for short recordings, which is the common
/// case; long ones simply wait for the next window or for the app to be opened.

import Foundation
import BackgroundTasks
import os

private let log = Logger(subsystem: "com.terafin.openplaudit", category: "background")

enum BackgroundSync {
    static let refreshID = "com.terafin.openplaudit.refresh"
    static let processingID = "com.terafin.openplaudit.processing"

    /// Register handlers. Must run before the app finishes launching.
    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: refreshID,
                                        using: nil) { task in
            handle(task, budget: 25, maxBytes: 1_500_000)
        }
        BGTaskScheduler.shared.register(forTaskWithIdentifier: processingID,
                                        using: nil) { task in
            handle(task, budget: 240, maxBytes: 40_000_000)
        }
    }

    /// Ask iOS for another run. Called after each sync and on backgrounding.
    static func schedule() {
        let refresh = BGAppRefreshTaskRequest(identifier: refreshID)
        refresh.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        do { try BGTaskScheduler.shared.submit(refresh) }
        catch { log.debug("refresh schedule: \(error.localizedDescription)") }

        let processing = BGProcessingTaskRequest(identifier: processingID)
        processing.requiresNetworkConnectivity = true
        processing.requiresExternalPower = false
        processing.earliestBeginDate = Date(timeIntervalSinceNow: 60 * 60)
        do { try BGTaskScheduler.shared.submit(processing) }
        catch { log.debug("processing schedule: \(error.localizedDescription)") }
    }

    private static func handle(_ task: BGTask, budget: TimeInterval,
                               maxBytes: Int) {
        schedule()
        // BGTask is not Sendable; the same escape hatch the BLE delegate bridge
        // uses. Completion must be reported exactly once.
        nonisolated(unsafe) let bgTask = task
        let work = Task { @MainActor in
            let model = DeviceSyncModel()
            let ok = await model.syncInBackground(timeBudget: budget,
                                                  maxRecordingBytes: maxBytes)
            bgTask.setTaskCompleted(success: ok)
        }
        bgTask.expirationHandler = {
            log.info("background window expired")
            work.cancel()
        }
    }
}
