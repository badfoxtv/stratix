// RegionBypass.swift
// Spoofs the client country on the GSSV login request so xCloud can be used from
// unsupported regions without a VPN. Mirrors Better xCloud's "Bypass region restriction".
//

import Foundation

/// Country whose IP is sent as `X-Forwarded-For` on `/v2/login/user`.
///
/// Only the login request carries the header; the stream itself connects directly,
/// so there is no added latency compared to a VPN. Raw values double as picker labels.
public enum RegionBypassCountry: String, CaseIterable, Sendable {
    case off = "Off"
    case poland = "Poland"
    case brazil = "Brazil"
    case japan = "Japan"
    case korea = "Korea"
    case unitedStates = "United States"

    /// UserDefaults key shared with `SettingsStore.StreamSettings.regionBypass`.
    public static let defaultsKey = "stratix.stream.regionBypass"

    /// IPs taken from Better xCloud (`src/enums/bypass-servers.ts`).
    public var forwardedForIP: String? {
        switch self {
        case .off: nil
        case .poland: "45.134.212.66"
        case .brazil: "169.150.198.66"
        case .japan: "138.199.21.239"
        case .korea: "121.125.60.151"
        case .unitedStates: "143.244.47.65"
        }
    }

    /// Reads the current selection; unknown or missing values resolve to `.off`.
    public static func current(defaults: UserDefaults = .standard) -> RegionBypassCountry {
        defaults.string(forKey: defaultsKey).flatMap(RegionBypassCountry.init(rawValue:)) ?? .off
    }
}
