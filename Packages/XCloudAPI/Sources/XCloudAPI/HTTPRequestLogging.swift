// HTTPRequestLogging.swift
// One log line per auth / xCloud HTTP exchange so launch failures can be read remotely.
//

import Foundation
import DiagnosticsKit

extension URLSession {
    /// `data(for:)` plus a log line: method, host+path, status, latency, and a short body
    /// excerpt for failures and for the session-lifecycle endpoints. Bodies pass through
    /// `RemoteLogSink` redaction before leaving the device; query strings are never logged.
    func loggedData(for request: URLRequest) async throws -> (Data, URLResponse) {
        let logger = GLogger(category: .api)
        let method = request.httpMethod ?? "GET"
        let target = "\(request.url?.host ?? "?")\(request.url?.path ?? "")"
        let started = ContinuousClock.now
        do {
            let (data, response) = try await data(for: request)
            let elapsed = started.duration(to: .now).components
            let ms = elapsed.seconds * 1000 + elapsed.attoseconds / 1_000_000_000_000_000
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            var line = "HTTP \(method) \(target) -> \(status) (\(ms) ms)"
            if status >= 400 || Self.shouldLogBody(path: request.url?.path ?? "") {
                let excerpt = String(decoding: data.prefix(600), as: UTF8.self)
                    .replacingOccurrences(of: "\n", with: " ")
                if !excerpt.isEmpty { line += " body: \(excerpt)" }
            }
            if status >= 400 { logger.error(line) } else { logger.info(line) }
            return (data, response)
        } catch {
            logger.error("HTTP \(method) \(target) failed: \(error.localizedDescription)")
            throw error
        }
    }

    private static func shouldLogBody(path: String) -> Bool {
        let lowered = path.lowercased()
        return lowered.hasSuffix("/state")
            || lowered.hasSuffix("/play")
            || lowered.hasSuffix("/connect")
            || lowered.hasSuffix("/login/user")
    }
}
