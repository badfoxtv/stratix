// RemoteLogSink.swift
// Ships GLogger lines to a developer machine on the local network for sideloaded debug builds.
//

import Foundation
import os

/// Batches log lines and POSTs them as plain text to `StratixRemoteLogURL` (Info.plist).
///
/// Inactive unless that key holds a URL, so App Store / upstream builds send nothing.
/// Lines are redacted before they leave the device: JWTs and any long token-like run
/// (refresh tokens, gsTokens, transfer tokens) are replaced with a placeholder.
public final class RemoteLogSink: Sendable {
    public static let shared = RemoteLogSink(
        endpoint: (Bundle.main.object(forInfoDictionaryKey: "StratixRemoteLogURL") as? String)
            .flatMap { raw in
                let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                return trimmed.isEmpty ? nil : URL(string: trimmed)
            },
        verbose: (Bundle.main.object(forInfoDictionaryKey: "StratixRemoteLogVerbose") as? Bool) ?? false
    )

    private struct State: Sendable {
        var buffer: [String] = []
        var flushScheduled = false
    }

    private static let maxBufferedLines = 2000
    private let endpoint: URL?
    private let session: URLSession
    private let state = OSAllocatedUnfairLock(initialState: State())

    /// Debug builds for the owner's own account only: ship full request/response bodies,
    /// including tokens, without redaction (`StratixRemoteLogVerbose` in Info.plist).
    public let verbose: Bool

    init(endpoint: URL?, verbose: Bool = false) {
        self.endpoint = endpoint
        self.verbose = endpoint != nil && verbose
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 5
        configuration.waitsForConnectivity = false
        self.session = URLSession(configuration: configuration)
    }

    public var isActive: Bool { endpoint != nil }

    public func record(level: String, category: String, message: String) {
        guard endpoint != nil else { return }
        let body = verbose ? message : Self.redact(message)
        let line = "\(Date.now.formatted(.iso8601)) [\(level)] [\(category)] \(body)"
        let shouldScheduleFlush = state.withLock { state -> Bool in
            state.buffer.append(line)
            if state.buffer.count > Self.maxBufferedLines {
                state.buffer.removeFirst(state.buffer.count - Self.maxBufferedLines)
            }
            guard !state.flushScheduled else { return false }
            state.flushScheduled = true
            return true
        }
        guard shouldScheduleFlush else { return }
        Task.detached(priority: .utility) { [self] in
            try? await Task.sleep(for: .milliseconds(400))
            await flush()
        }
    }

    private func flush() async {
        guard let endpoint else { return }
        let lines = state.withLock { state -> [String] in
            let pending = state.buffer
            state.buffer.removeAll()
            state.flushScheduled = false
            return pending
        }
        guard !lines.isEmpty else { return }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("text/plain; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(lines.joined(separator: "\n").utf8)
        // Best effort: a missing collector must never affect the app.
        _ = try? await session.data(for: request)
    }

    /// Replaces JWTs and long token-like runs so credentials never reach the collector.
    /// Dots and slashes are excluded from the run class so hostnames and URL paths stay
    /// readable; tokens are still caught because their segments are long on their own.
    static func redact(_ message: String) -> String {
        var result = message
        if let jwt = try? Regex(#"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]*)?"#) {
            result = result.replacing(jwt, with: "<jwt>")
        }
        if let longToken = try? Regex(#"[A-Za-z0-9+=_\-!*$%]{40,}"#) {
            result = result.replacing(longToken, with: "<redacted>")
        }
        return result
    }
}
