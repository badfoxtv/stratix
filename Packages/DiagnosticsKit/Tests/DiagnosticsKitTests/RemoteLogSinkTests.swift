// RemoteLogSinkTests.swift
// Exercises remote log redaction.
//

import Testing
@testable import DiagnosticsKit

struct RemoteLogSinkTests {
    @Test func redact_removesJWTsAndLongTokens() {
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlLXBhcnQ"
        let refresh = "M.C5_BAY.0.U.-Cg" + String(repeating: "Ab3x", count: 30) + "!*$"
        let redacted = RemoteLogSink.redact("token=\(jwt) rt=\(refresh)")
        #expect(!redacted.contains("eyJhbGci"))
        #expect(!redacted.contains("Ab3xAb3x"))
        #expect(redacted.contains("<jwt>"))
    }

    @Test func redact_keepsHostsPathsAndErrors() {
        let line = "HTTP POST wus2.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/1A2B3C4D-1111-2222-3333-444455556666/connect -> 202"
        #expect(RemoteLogSink.redact(line) == line)
        let error = "InternalCode :-2147186503 at addandsigninuserv2operation.cpp:85"
        #expect(RemoteLogSink.redact(error) == error)
    }

    @Test func inactiveSinkDoesNothing() {
        let sink = RemoteLogSink(endpoint: nil)
        #expect(sink.isActive == false)
        sink.record(level: "INFO", category: "Test", message: "ignored")
    }
}
