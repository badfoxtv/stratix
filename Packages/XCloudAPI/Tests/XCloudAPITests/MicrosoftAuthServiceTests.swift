// MicrosoftAuthServiceTests.swift
// Exercises microsoft auth service behavior.
//

import Testing
import Foundation
@testable import XCloudAPI

@Suite(.serialized)
struct MicrosoftAuthServiceTests {

    @Test func requestDeviceCode_mapsVerificationUriComplete() async throws {
        let service = makeAuthService { request in
            #expect(request.url?.absoluteString.contains("/devicecode") == true)
            return .json(statusCode: 200, body: [
                "device_code": "device-token",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://microsoft.com/devicelogin",
                "verification_uri_complete": "https://microsoft.com/devicelogin?otc=123",
                "expires_in": 900,
                "interval": 5
            ])
        }

        let info = try await service.requestDeviceCode()

        #expect(info.verificationUriComplete == "https://microsoft.com/devicelogin?otc=123")
    }

    @Test func requestDeviceCode_requestsPlayXboxComScopesWithoutProfile() async throws {
        let capture = RequestCaptureBox()
        let service = makeAuthService { request in
            capture.body = requestFormBodyString(request)
            return .json(statusCode: 200, body: [
                "device_code": "d", "user_code": "U", "verification_uri": "https://microsoft.com/link",
                "expires_in": 900, "interval": 5
            ])
        }

        _ = try await service.requestDeviceCode()

        #expect(capture.body.contains("scope=xboxlive.signin%20offline_access%20openid"))
        #expect(!capture.body.contains("profile"))
    }

    @Test func fetchLPT_usesConsumersV2EndpointLikePlayXboxCom() async throws {
        let capture = RequestCaptureBox()

        let service = makeAuthService { request in
            capture.url = request.url
            capture.body = requestFormBodyString(request)
            return .json(statusCode: 200, body: [
                "access_token": "lpt-token",
                "refresh_token": "refresh-rotated",
                "expires_in": 3600,
                "token_type": "bearer"
            ])
        }

        do {
            let token = try await service.fetchLPT(refreshToken: "refresh-original")
            #expect(token == "lpt-token")
        } catch let error as AuthError {
            // Package tests run in a restricted environment where Keychain writes can fail.
            // We still validate the request construction below.
            if case .networkError(let message) = error {
                #expect(message.contains("Keychain save failed"))
            } else {
                Issue.record("Unexpected auth error: \(error)")
            }
        }

        #expect(capture.url?.host == "login.microsoftonline.com")
        #expect(capture.url?.path == "/consumers/oauth2/v2.0/token")
        #expect(capture.body.contains("grant_type=refresh_token"))
        #expect(capture.body.contains("refresh_token=refresh-original"))
        #expect(capture.body.contains("client_id=1f907974-e22b-4810-a9de-d9647380c97e"))
        #expect(capture.body.contains("PURPOSE_XBOX_CLOUD_CONSOLE_TRANSFER_TOKEN"))
    }

    @Test func fetchLPT_fallsBackToLoginLiveWhenV2Fails() async throws {
        let hosts = HostLog()
        let service = makeAuthService { request in
            hosts.append(request.url?.host ?? "")
            if request.url?.host == "login.microsoftonline.com" {
                return .json(statusCode: 400, body: ["error": "invalid_scope", "error_description": "nope"])
            }
            return .json(statusCode: 200, body: ["access_token": "live-lpt", "expires_in": 3600])
        }

        do {
            let token = try await service.fetchLPT(refreshToken: "refresh-original")
            #expect(token == "live-lpt")
        } catch let error as AuthError {
            if case .networkError(let message) = error {
                #expect(message.contains("Keychain save failed"))
            } else {
                Issue.record("Unexpected auth error: \(error)")
            }
        }

        #expect(hosts.values == ["login.microsoftonline.com", "login.live.com"])
    }

    @Test func fetchLPT_surfacesHttpErrors() async {
        let service = makeAuthService { _ in
            .json(statusCode: 400, body: [
                "error": "invalid_grant",
                "error_description": "The refresh token is invalid."
            ])
        }

        do {
            _ = try await service.fetchLPT(refreshToken: "bad-refresh")
            Issue.record("Expected fetchLPT to throw on HTTP 400")
        } catch let error as AuthError {
            if case .tokenExchangeFailed(let message) = error {
                #expect(message.contains("LPT HTTP 400"))
                #expect(message.contains("invalid_grant"))
            } else {
                Issue.record("Expected tokenExchangeFailed, got \(error)")
            }
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test func formBody_percentEncodesPlusAndReservedCharacters() throws {
        let data = try #require(formURLEncodedBody([
            URLQueryItem(name: "refresh_token", value: "M.C5_BAY.0.U.-Ab+cd/ef=gh!ij*kl$$mn&op~"),
            URLQueryItem(name: "scope", value: "xboxlive.signin openid")
        ]))
        let body = try #require(String(data: data, encoding: .utf8))
        #expect(body == "refresh_token=M.C5_BAY.0.U.-Ab%2Bcd%2Fef%3Dgh%21ij%2Akl%24%24mn%26op~&scope=xboxlive.signin%20openid")
    }

    @Test func gssvLogin_sendsForwardedForWhenRegionBypassEnabled() async {
        let headers = await gssvLoginForwardedForHeaders(bypassIP: RegionBypassCountry.poland.forwardedForIP)

        #expect(headers.count == 3) // xhome, xgpuweb, xgpuwebf2p
        #expect(headers.allSatisfy { $0 == "45.134.212.66" })
    }

    @Test func gssvLogin_omitsForwardedForWhenRegionBypassOff() async {
        let headers = await gssvLoginForwardedForHeaders(bypassIP: RegionBypassCountry.off.forwardedForIP)

        #expect(headers.count == 3)
        #expect(headers.allSatisfy { $0 == nil })
    }

    @Test func regionBypassCountry_missingOrUnknownValueFallsBackToPoland() throws {
        let defaults = try #require(UserDefaults(suiteName: "RegionBypassCountryTests"))
        defer { defaults.removePersistentDomain(forName: "RegionBypassCountryTests") }

        #expect(RegionBypassCountry.current(defaults: defaults) == .poland)

        defaults.set("Atlantis", forKey: RegionBypassCountry.defaultsKey)
        #expect(RegionBypassCountry.current(defaults: defaults) == .poland)

        defaults.set("Off", forKey: RegionBypassCountry.defaultsKey)
        #expect(RegionBypassCountry.current(defaults: defaults) == .off)
    }
}

/// Runs the full token exchange against stubs and returns the X-Forwarded-For value
/// seen on each GSSV `/v2/login/user` request.
private func gssvLoginForwardedForHeaders(bypassIP: String?) async -> [String?] {
    let capture = HeaderCaptureBox()
    AuthURLProtocolStub.setHandler { request in
        if request.url?.path == "/v2/login/user" {
            capture.append(request.value(forHTTPHeaderField: "X-Forwarded-For"))
            return .json(statusCode: 200, body: ["gsToken": "gs-token"])
        }
        return .json(statusCode: 200, body: ["Token": "xbox-token"])
    }
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [AuthURLProtocolStub.self]
    let service = MicrosoftAuthService(
        tokenStore: TokenStore(),
        session: URLSession(configuration: config),
        regionBypassIP: { bypassIP }
    )

    // Keychain writes can fail in the package test sandbox; only the requests matter here.
    _ = try? await service.exchangeForStreamTokens(msaAccessToken: "msa-token")
    return capture.values
}

/// Collects headers from concurrent URLProtocol callbacks; the lock guards `storage`.
private final class HeaderCaptureBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String?] = []

    func append(_ value: String?) {
        lock.lock(); defer { lock.unlock() }
        storage.append(value)
    }

    var values: [String?] {
        lock.lock(); defer { lock.unlock() }
        return storage
    }
}

// MARK: - Test helpers

private struct StubAuthHTTPResponse {
    let statusCode: Int
    let body: Data

    static func json(statusCode: Int, body: Any) -> Self {
        .init(statusCode: statusCode, body: try! JSONSerialization.data(withJSONObject: body))
    }
}

private final class AuthURLProtocolStub: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var handler: (@Sendable (URLRequest) throws -> StubAuthHTTPResponse)?

    static func setHandler(_ handler: @escaping @Sendable (URLRequest) throws -> StubAuthHTTPResponse) {
        lock.lock()
        defer { lock.unlock() }
        self.handler = handler
    }

    static func clearHandler() {
        lock.lock()
        defer { lock.unlock() }
        handler = nil
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let handler: (@Sendable (URLRequest) throws -> StubAuthHTTPResponse)?
        Self.lock.lock()
        handler = Self.handler
        Self.lock.unlock()

        guard let handler else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "AuthURLProtocolStub", code: 0))
            return
        }

        do {
            let stub = try handler(request)
            let response = HTTPURLResponse(
                url: request.url ?? URL(string: "https://example.com")!,
                statusCode: stub.statusCode,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if !stub.body.isEmpty {
                client?.urlProtocol(self, didLoad: stub.body)
            }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

private func makeAuthService(
    tokenStore: TokenStore = TokenStore(),
    handler: @escaping @Sendable (URLRequest) throws -> StubAuthHTTPResponse
) -> MicrosoftAuthService {
    AuthURLProtocolStub.setHandler(handler)
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [AuthURLProtocolStub.self]
    let session = URLSession(configuration: config)
    return MicrosoftAuthService(tokenStore: tokenStore, session: session)
}

private final class RequestCaptureBox: @unchecked Sendable {
    var url: URL?
    var body: String = ""
}

private func requestFormBodyString(_ request: URLRequest) -> String {
    if let body = request.httpBody {
        return String(data: body, encoding: .utf8) ?? ""
    }
    guard let stream = request.httpBodyStream else { return "" }
    stream.open()
    defer { stream.close() }
    var data = Data()
    let bufferSize = 1024
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
    defer { buffer.deallocate() }
    while stream.hasBytesAvailable {
        let read = stream.read(buffer, maxLength: bufferSize)
        if read <= 0 { break }
        data.append(buffer, count: read)
    }
    return String(data: data, encoding: .utf8) ?? ""
}

private final class HostLog: @unchecked Sendable {
    // Test-only; the stub handler runs serially, the lock guards the cross-thread read.
    private let lock = NSLock()
    private var storage: [String] = []
    func append(_ host: String) { lock.lock(); storage.append(host); lock.unlock() }
    var values: [String] { lock.lock(); defer { lock.unlock() }; return storage }
}
