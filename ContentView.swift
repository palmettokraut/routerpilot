import SwiftUI
import WebKit
import Foundation
import CryptoKit
import Security
import UIKit

// MARK: - Secure Keychain Manager
class KeychainManager {
    static let shared = KeychainManager()
    private init() {}
    
    private let serviceIdentifier = "com.ftc.routerpilot"
    
    func storePassword(_ password: String, for username: String, server: String = "192.168.1.1") -> Bool {
        let account = "\(username)@\(server)"
        let passwordData = Data(password.utf8)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: account,
            kSecAttrServer as String: server,
            kSecAttrService as String: serviceIdentifier,
            kSecValueData as String: passwordData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    func retrievePassword(for username: String, server: String = "192.168.1.1") -> String? {
        let account = "\(username)@\(server)"
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: account,
            kSecAttrServer as String: server,
            kSecAttrService as String: serviceIdentifier,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let passwordData = result as? Data,
              let password = String(data: passwordData, encoding: .utf8) else {
            return nil
        }
        
        return password
    }
    
    func clearAllData() {
        let queries = [
            [kSecClass as String: kSecClassInternetPassword, kSecAttrService as String: serviceIdentifier]
        ]
        
        for query in queries {
            SecItemDelete(query as CFDictionary)
        }
    }
}

class UnifiedSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
                return
            }
        }
        
        completionHandler(.performDefaultHandling, nil)
    }
}

// MARK: - Configuration Manager
class SecureConfigurationManager: ObservableObject {
    static let shared = SecureConfigurationManager()
    
    @Published var routerIP: String = "192.168.1.1"
    
    private init() {}
}

// MARK: - Enhanced Router Data Models
struct RouterInfo: Codable {
    let modelName: String
    let firmwareVersion: String
    let uptime: String
    let serialNumber: String
    let fsan: String
    let hostName: String
    let currentTime: String
    let timeZone: String
    let operationalMode: String
    let operationalRole: String
    let cpuUsage: Double
    let memoryUsage: Double
    let lastUpdated: Date
}

struct NetworkConfig: Codable {
    let wanStatus: String
    let wanIP: String
    let lanIP: String
    let ipv6Status: String
    let ipv6IP: String
    let tr069Status: String
    let connectedDevices: Int
    let dhcpEnabled: Bool
    let satellites: [SatelliteInfo]
    let dhcpClients: [DHCPClient]
    let ethPorts: Int
    let gethPorts: Int
    let usbPorts: Int
    let wirelessPorts: Int
    let lastUpdated: Date
}

struct SatelliteInfo: Codable, Identifiable {
    let id = UUID()
    let name: String
    let macAddress: String
    let ipAddress: String
    let connectionType: String
    let modelNumber: String
    let exosVersion: String
}

struct DHCPClient: Codable, Identifiable {
    let id = UUID()
    let deviceName: String
    let ipAddress: String
    let macAddress: String
    let leaseTime: String
    let deviceType: String
}

struct WirelessConfig: Codable {
    let primarySSID: String
    let primaryEnabled: Bool
    let guestSSID: String?
    let connectedDevices: Int
    let signalStrength: Double
    let wirelessPorts: Int
    let band24Ports: Int
    let band5Ports: Int
    let band6Ports: Int
    let band5Type: String
    let radioInfo: [RadioInfo]
    let wirelessNetworks: [WirelessNetwork]
    let lastUpdated: Date
}

struct RadioInfo: Codable, Identifiable {
    let id = UUID()
    let radioId: Int
    let band: String
}

struct WirelessNetwork: Codable, Identifiable {
    let id = UUID()
    let ssid: String
    let enabled: Bool
    let band: String
    let security: String
    let connectedClients: Int
}

// MARK: - Data Models for Web Scanner
struct DiscoveredPage: Identifiable, Codable {
    let id = UUID()
    let url: String
    let title: String
    let pageType: PageType
    let lastScanned: Date
    let dataFound: [String]
    let hasDeviceData: Bool
    let hasWirelessData: Bool
    let hasSystemData: Bool
}

enum PageType: String, CaseIterable, Codable {
    case dashboard = "Dashboard"
    case status = "Status"
    case support = "Support"
    case utilities = "Utilities"
    case configuration = "Configuration"
    case unknown = "Unknown"
}

struct ScrapedData: Codable {
    let devices: [ScrapedDevice]
    let wirelessNetworks: [ScrapedWirelessNetwork]
    let systemInfo: [ScrapedSystemInfo]
    let connectionInfo: [ScrapedConnectionInfo]
    let extractedAt: Date
}

struct ScrapedDevice: Identifiable, Codable {
    let id = UUID()
    let name: String
    let ipAddress: String
    let macAddress: String
    let deviceType: String
    let connectionType: String
    let isOnline: Bool
    let source: String
}

struct ScrapedWirelessNetwork: Identifiable, Codable {
    let id = UUID()
    let ssid: String
    let band: String
    let channel: String
    let security: String
    let isEnabled: Bool
    let connectedDevices: Int
    let signalStrength: Double
    let source: String
}

struct ScrapedSystemInfo: Identifiable, Codable {
    let id = UUID()
    let parameter: String
    let value: String
    let category: String
    let source: String
}

struct ScrapedConnectionInfo: Identifiable, Codable {
    let id = UUID()
    let parameter: String
    let value: String
    let status: String
    let source: String
}

// MARK: - Enhanced GigaSpire Web Scanner with Full Page List and Better SPA Handling
class GigaSpireWebScanner: ObservableObject {
    static let shared = GigaSpireWebScanner()
    
    @Published var isScanning = false
    @Published var scanProgress = 0.0
    @Published var currentScanStatus = ""
    @Published var discoveredPages: [DiscoveredPage] = []
    @Published var scrapedData: ScrapedData?
    @Published var debugLogs: [String] = []
    
    private let urlSession: URLSession
    
    private var baseURL: String = "https://192.168.1.1"
    private var authCookies: [HTTPCookie] = []
    private var authHeaders: [String: String] = [:]
    
    private init() {
        let config = URLSessionConfiguration.default
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        
        self.urlSession = URLSession(
            configuration: config,
            delegate: UnifiedSessionDelegate(),
            delegateQueue: nil
        )
    }
    
    // FULL LIST OF ALL 58 GIGASPIRE PAGES
    private let knownPages = [
        "https://192.168.1.1/#/dashboard",
        "https://192.168.1.1/#/html/status/status_system.html",
        "https://192.168.1.1/#/html/status/status_connection.html",
        "https://192.168.1.1/#/html/status/status_devicetable.html",
        "https://192.168.1.1/#/html/status/status_internetstatus_ipv6.html",
        "https://192.168.1.1/#/html/status/status_lanstatus_ipv6.html",
        "https://192.168.1.1/#/html/status/status_wirelessstatus.html",
        "https://192.168.1.1/#/html/utilities/utilities/backup&restore",
        "https://192.168.1.1/#/html/utilities/utilities/reboot",
        "https://192.168.1.1/#/html/utilities/utilities/ping_test",
        "https://192.168.1.1/#/html/utilities/utilities/traceroute",
        "https://192.168.1.1/#/html/advanced/ip/dhcp_setting",
        "https://192.168.1.1/#/html/advanced/ip/dhcp_reservation",
        "https://192.168.1.1/#/html/advanced/ip/dns_host_mapping",
        "https://192.168.1.1/#/html/advanced/ip/dynamic_dns",
        "https://192.168.1.1/#/html/advanced/ip/ipv6_lan_setting",
        "https://192.168.1.1/#/html/advanced/ip/x_lan_setting",
        "https://192.168.1.1/#/html/advanced/advanced/security/administrator_credentials",
        "https://192.168.1.1/#/html/advanced/advanced/security/upnp",
        "https://192.168.1.1/#/html/advanced/advanced/security/firewall",
        "https://192.168.1.1/#/html/advanced/advanced/security/DMZ_Hosting",
        "https://192.168.1.1/#/html/advanced/advanced/security/port_forwarding",
        "https://192.168.1.1/#/html/advanced/advanced/security/arp_spoofing",
        "https://192.168.1.1/#/html/advanced/advanced/security/web_logging",
        "https://192.168.1.1/#/html/advanced/blocking/scheduling_access/scheduling_access",
        "https://192.168.1.1/#/html/advanced/blocking/service_blocking",
        "https://192.168.1.1/#/html/advanced/blocking/website_blocking",
        "https://192.168.1.1/#/html/advanced/advanced/controls",
        "https://192.168.1.1/#/html/wireless/radio",
        "https://192.168.1.1/#/html/wireless/primary",
        "https://192.168.1.1/#/html/wireless/wifi_secondary",
        "https://192.168.1.1/#/html/wireless/wps",
        "https://192.168.1.1/#/html/support/support/tr_069",
        "https://192.168.1.1/#/html/support/support/service_wan_vlan",
        "https://192.168.1.1/#/html/support/support/lan_status",
        "https://192.168.1.1/#/html/support/support/dns_server",
        "https://192.168.1.1/#/html/support/support/service_static_routes",
        "https://192.168.1.1/#/html/support/support/voip_gateway_settings",
        "https://192.168.1.1/#/html/support/support/line_features",
        "https://192.168.1.1/#/html/support/support/voip_diagnostics",
        "https://192.168.1.1/#/html/support/support/igmp/igmp_setup",
        "https://192.168.1.1/#/html/support/support/smart_activate",
        "https://192.168.1.1/#/html/support/support/remote_management",
        "https://192.168.1.1/#/html/support/support/qos",
        "https://192.168.1.1/#/html/support/support/shaping",
        "https://192.168.1.1/#/html/support/support/acl",
        "https://192.168.1.1/#/html/support/support/device_logs",
        "https://192.168.1.1/#/html/support/support/configuration_save",
        "https://192.168.1.1/#/html/support/support/diagnosis/pcap",
        "https://192.168.1.1/#/html/support/support/diagnosis/over_air",
        "https://192.168.1.1/#/html/support/support/diagnosis/vca",
        "https://192.168.1.1/#/html/support/support/diagnosis/port_mirror",
        "https://192.168.1.1/#/html/support/support/diagnosis/log_analysis",
        "https://192.168.1.1/#/html/support/support/diagnosis/net_statistics",
        "https://192.168.1.1/#/html/support/support/support_wireless",
        "https://192.168.1.1/#/html/support/support/support_upgrade/upgrade_image",
        "https://192.168.1.1/#/html/support/support/support_container_apps",
        "https://192.168.1.1/#/html/beta/beta/wifi_analytics"
    ]
    
    // ADDITIONAL API ENDPOINTS TO TRY
    private let apiEndpoints = [
        "dhcp_clients.cmd",
        "client_list.cmd",
        "device_list.cmd",
        "connected_devices.cmd",
        "device_table.cmd",
        "device_info.cmd",
        "lan_clients.cmd",
        "network_clients.cmd",
        "wireless_clients.cmd",
        "wl_clients.cmd",
        "station_list.cmd",
        "associated_devices.cmd",
        "dhcp_leases.cmd",
        "arp_table.cmd",
        "hosts.cmd",
        "lan_status.cmd",
        "network_status.cmd",
        "wifi_status.cmd",
        "wireless_status.cmd",
        "system_status.cmd",
        "device_status.cmd",
        "interface_status.cmd"
    ]
    
    // WebView for SPA handling
    private var webView: WKWebView?
    
    func setAuthenticationData(cookies: [HTTPCookie], headers: [String: String]) {
        self.authCookies = cookies
        self.authHeaders = headers
        addLog("🔐 Authentication data set: \(cookies.count) cookies, \(headers.count) headers")
    }
    
    private func extractFirstMatch(from text: String, pattern: String) -> String? {
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
            if let match = regex.firstMatch(in: text, range: NSRange(location: 0, length: text.count)) {
                if match.numberOfRanges > 1 {
                    let range = Range(match.range(at: 1), in: text)!
                    return String(text[range]).trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
        } catch {
            return nil
        }
        return nil
    }

    private func hasDeviceData(in content: String) -> Bool {
        let deviceIndicators = [
            "device", "client", "MAC", "dhcp", "hostname", "ip address",
            "connected", "ethernet", "wireless client", "lan client",
            "device table", "client list", "connected devices"
        ]
        
        let lowercaseContent = content.lowercased()
        for indicator in deviceIndicators {
            if lowercaseContent.contains(indicator.lowercased()) {
                addLog("📱 Device data indicator found: \(indicator)")
                return true
            }
        }
        return false
    }

    private func hasWirelessData(in content: String) -> Bool {
        let wirelessIndicators = [
            "SSID", "wireless", "WiFi", "wifi", "radio", "antenna",
            "signal", "channel", "frequency", "802.11", "access point",
            "wireless network", "wifi config", "wireless status"
        ]
        
        let lowercaseContent = content.lowercased()
        for indicator in wirelessIndicators {
            if lowercaseContent.contains(indicator.lowercased()) {
                addLog("📶 Wireless data indicator found: \(indicator)")
                return true
            }
        }
        return false
    }

    private func hasSystemData(in content: String) -> Bool {
        let systemIndicators = [
            "system", "model", "version", "firmware", "uptime", "memory",
            "cpu", "temperature", "status", "configuration", "serial",
            "system info", "device info", "router status"
        ]
        
        let lowercaseContent = content.lowercased()
        for indicator in systemIndicators {
            if lowercaseContent.contains(indicator.lowercased()) {
                addLog("🔧 System data indicator found: \(indicator)")
                return true
            }
        }
        return false
    }

    // MARK: - Fixed extractTitle method (for GigaSpireWebScanner)
    private func extractTitle(from content: String, url: String = "") -> String {
        // Try multiple title extraction methods
        if let title = extractFirst(from: content, pattern: "<title[^>]*>([^<]+)</title>") {
            let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
            if !cleanTitle.isEmpty {
                return cleanTitle
            }
        }
        
        // Try meta title
        if let title = extractFirst(from: content, pattern: "<meta[^>]*property=[\"']og:title[\"'][^>]*content=[\"']([^\"']+)[\"']") {
            let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
            if !cleanTitle.isEmpty {
                return cleanTitle
            }
        }
        
        // Try h1 tag
        if let title = extractFirst(from: content, pattern: "<h1[^>]*>([^<]+)</h1>") {
            let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
            if !cleanTitle.isEmpty {
                return cleanTitle
            }
        }
        
        // Try to extract from Angular or page-specific patterns
        if let title = extractFirst(from: content, pattern: "ng-bind=[\"']([^\"']+)[\"']") {
            let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
            if !cleanTitle.isEmpty {
                return cleanTitle
            }
        }
        
        // Try to extract from URL path if provided
        if !url.isEmpty, let urlPath = url.split(separator: "/").last {
            let pathTitle = String(urlPath).replacingOccurrences(of: "_", with: " ")
                .replacingOccurrences(of: ".html", with: "")
                .capitalized
            if !pathTitle.isEmpty {
                return pathTitle
            }
        }
        
        return "Router Page"
    }
    
    private func findDataElements(in content: String) -> [String] {
        var elements: [String] = []
        
        let dataIndicators = [
            ("device", "Device Information"),
            ("client", "Client Data"),
            ("MAC", "MAC Addresses"),
            ("IP", "IP Addresses"),
            ("SSID", "Wireless Networks"),
            ("wireless", "Wireless Configuration"),
            ("status", "Status Information"),
            ("connection", "Connection Data"),
            ("system", "System Information"),
            ("model", "Device Model"),
            ("version", "Version Information"),
            ("dhcp", "DHCP Configuration"),
            ("reservation", "DHCP Reservations"),
            ("lease", "DHCP Leases"),
            ("hostname", "Hostnames"),
            ("gateway", "Gateway Information"),
            ("satellite", "Satellite Information"),
            ("radio", "Radio Configuration"),
            ("channel", "Channel Information"),
            ("frequency", "Frequency Data"),
            ("signal", "Signal Strength"),
            ("security", "Security Settings"),
            ("firewall", "Firewall Configuration"),
            ("port", "Port Information"),
            ("vlan", "VLAN Configuration"),
            ("tr069", "TR-069 Management"),
            ("upnp", "UPnP Settings"),
            ("qos", "QoS Configuration"),
            ("bandwidth", "Bandwidth Information"),
            ("traffic", "Traffic Statistics"),
            ("log", "Log Information"),
            ("diagnostic", "Diagnostic Data"),
            ("upgrade", "Upgrade Information"),
            ("backup", "Backup/Restore"),
            ("reboot", "Reboot Options"),
            ("ping", "Ping Test"),
            ("traceroute", "Traceroute"),
            ("dns", "DNS Configuration"),
            ("ntp", "Time Configuration"),
            ("snmp", "SNMP Settings")
        ]
        
        let lowercaseContent = content.lowercased()
        for (keyword, description) in dataIndicators {
            if lowercaseContent.contains(keyword.lowercased()) {
                elements.append(description)
            }
        }
        
        // Look for table structures
        let tableCount = countMatches(in: content, pattern: "<table[^>]*>")
        if tableCount > 0 {
            elements.append("Data Tables (\(tableCount))")
        }
        
        // Look for form structures
        let formCount = countMatches(in: content, pattern: "<form[^>]*>")
        if formCount > 0 {
            elements.append("Configuration Forms (\(formCount))")
        }
        
        // Look for Angular directives
        let ngRepeatCount = countMatches(in: content, pattern: "ng-repeat")
        if ngRepeatCount > 0 {
            elements.append("Dynamic Lists (\(ngRepeatCount))")
        }
        
        // Look for specific router data patterns
        if content.contains("192.168.") {
            elements.append("IP Addresses")
        }
        
        if content.contains(":") && content.contains("-") {
            // Likely MAC addresses
            elements.append("Hardware Addresses")
        }
        
        return Array(Set(elements)) // Remove duplicates
    }

    private func countMatches(in text: String, pattern: String) -> Int {
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
            let matches = regex.matches(in: text, range: NSRange(location: 0, length: text.count))
            return matches.count
        } catch {
            return 0
        }
    }
    
    
    // MARK: - Enhanced Scanning with Multiple Approaches
    @MainActor
    func scanAllPages() async {
        isScanning = true
        scanProgress = 0.0
        currentScanStatus = "Starting comprehensive scan..."
        discoveredPages.removeAll()
        
        addLog("🚀 === STARTING COMPREHENSIVE SCAN ===")
        addLog("📋 Will scan ALL \(knownPages.count) pages + \(apiEndpoints.count) API endpoints")
        
        // Phase 1: Quick API endpoint scan (20%)
        currentScanStatus = "Phase 1: Scanning API endpoints..."
        await scanAPIEndpoints()
        scanProgress = 0.2
        
        // Phase 2: Static HTML fetch (40%)
        currentScanStatus = "Phase 2: Scanning static HTML pages..."
        await scanStaticHTMLPages()
        scanProgress = 0.6
        
        // Phase 3: SPA WebView scan for dynamic content (30%)
        currentScanStatus = "Phase 3: Using WebView for dynamic content..."
        await scanWithWebView()
        scanProgress = 0.9
        
        // Phase 4: Data analysis and extraction (10%)
        currentScanStatus = "Phase 4: Analyzing extracted data..."
        await analyzeAndConsolidateData()
        scanProgress = 1.0
        
        currentScanStatus = "Comprehensive scan complete!"
        addLog("✅ === COMPREHENSIVE SCAN COMPLETE ===")
        addLog("📊 Found \(discoveredPages.count) pages")
        
        isScanning = false
    }
    
    // MARK: - Phase 1: API Endpoint Scanning
    private func scanAPIEndpoints() async {
        addLog("🔍 === PHASE 1: API ENDPOINT SCANNING ===")
        
        for (index, endpoint) in apiEndpoints.enumerated() {
            let progress = 0.0 + (Double(index) / Double(apiEndpoints.count)) * 0.2
            await MainActor.run {
                self.scanProgress = progress
                self.currentScanStatus = "Scanning API endpoint \(index + 1)/\(apiEndpoints.count): \(endpoint)"
            }
            
            // Try different HTTP methods and parameters
            let methods = ["POST", "GET"]
            let paramSets = [
                "action=get",
                "action=list",
                "cmd=get_data",
                "{\"action\":\"get\"}",
                "format=json",
                ""
            ]
            
            for method in methods {
                for params in paramSets {
                    if let data = await callRouterAPI(endpoint: endpoint, postData: params.isEmpty ? nil : params, method: method) {
                        let response = String(data: data, encoding: .utf8) ?? ""
                        
                        if response.count > 50 && !response.contains("#ERROR") && !response.contains("login") {
                            addLog("✅ API SUCCESS: \(endpoint) (\(method)) -> \(response.count) bytes")
                            await processAPIResponse(endpoint: endpoint, response: response, method: method, params: params)
                            break // Found working combination, move to next endpoint
                        }
                    }
                }
            }
            
            // Small delay between endpoints
            try? await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
        }
    }
    
    // MARK: - Phase 2: Static HTML Page Scanning
    private func scanStaticHTMLPages() async {
        addLog("🔍 === PHASE 2: STATIC HTML SCANNING ===")
        
        for (index, pageUrl) in knownPages.enumerated() {
            let progress = 0.2 + (Double(index) / Double(knownPages.count)) * 0.4
            await MainActor.run {
                self.scanProgress = progress
                self.currentScanStatus = "Scanning page \(index + 1)/\(knownPages.count): \(extractPageName(pageUrl))"
            }
            
            addLog("📄 Scanning: \(pageUrl)")
            
            if let content = await fetchPageWithSSLBypass(pageUrl) {
                let page = analyzePage(url: pageUrl, content: content)
                
                await MainActor.run {
                    self.discoveredPages.append(page)
                }
                
                // Extract any visible data from static content
                await extractDataFromStaticContent(content: content, source: pageUrl)
            }
            
            // Small delay between pages
            try? await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        }
    }
    
    // MARK: - Phase 3: WebView SPA Scanning
    private func scanWithWebView() async {
        addLog("🔍 === PHASE 3: WEBVIEW SPA SCANNING ===")
        
        // Only scan key pages with WebView due to performance
        let keyPages = [
            "https://192.168.1.1/#/dashboard",
            "https://192.168.1.1/#/html/status/status_devicetable.html",
            "https://192.168.1.1/#/html/advanced/ip/dhcp_setting",
            "https://192.168.1.1/#/html/wireless/primary",
            "https://192.168.1.1/#/html/support/support/lan_status"
        ]
        
        for (index, pageUrl) in keyPages.enumerated() {
            let progress = 0.6 + (Double(index) / Double(keyPages.count)) * 0.3
            await MainActor.run {
                self.scanProgress = progress
                self.currentScanStatus = "WebView scanning: \(extractPageName(pageUrl))"
            }
            
            await scanPageWithWebView(pageUrl)
            
            // Longer delay for WebView operations
            try? await Task.sleep(nanoseconds: 3_000_000_000) // 3 seconds
        }
    }
    
    // MARK: - WebView Implementation for SPA Content
    private func scanPageWithWebView(_ url: String) async {
        return await withCheckedContinuation { continuation in
            DispatchQueue.main.async {
                self.setupWebViewForScanning(url: url) { extractedData in
                    self.addLog("🌐 WebView extracted: \(extractedData.count) bytes from \(url)")
                    
                    if extractedData.count > 100 { // Substantial content
                        Task {
                            await self.processEnhancedWebViewContent(extractedData, source: url)
                        }
                    }
                    
                    continuation.resume()
                }
            }
        }
    }
    
    // MARK: - Enhanced WebView SSL Configuration
    // Replace the existing setupWebViewForScanning method in GigaSpireWebScanner with this enhanced version

    private func setupWebViewForScanning(url: String, completion: @escaping (String) -> Void) {
        let config = WKWebViewConfiguration()
        
        // CRITICAL: Enhanced SSL and security settings
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        config.preferences.javaScriptCanOpenWindowsAutomatically = true
        config.preferences.javaScriptEnabled = true
        
        // Enhanced preferences for router compatibility
        config.preferences.setValue(true, forKey: "allowUniversalAccessFromFileURLs")
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        config.preferences.setValue(false, forKey: "webSecurityEnabled")
        config.preferences.setValue(true, forKey: "allowRunningInsecureContent")
        
        // Set cookies BEFORE creating WebView
        for cookie in authCookies {
            config.websiteDataStore.httpCookieStore.setCookie(cookie) { }
        }
        
        let webView = WKWebView(frame: CGRect(x: 0, y: 0, width: 1200, height: 800), configuration: config)
        webView.isHidden = true
        webView.allowsBackForwardNavigationGestures = false
        
        // Add to window hierarchy
        DispatchQueue.main.async {
            if let windowScene = UIApplication.shared.connectedScenes.first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene,
               let window = windowScene.windows.first(where: { $0.isKeyWindow }) {
                window.addSubview(webView)
            }
        }
        
        // Create enhanced delegate with better SSL handling
        let delegate = EnhancedWebViewDelegate(url: url) { [weak webView] content in
            DispatchQueue.main.async {
                webView?.removeFromSuperview()
            }
            completion(content)
        }
        
        webView.navigationDelegate = delegate
        
        // Enhanced request with all authentication data
        if let pageURL = URL(string: url) {
            var request = URLRequest(url: pageURL)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.timeoutInterval = 45 // Increased timeout
            
            // Add ALL authentication headers
            for (key, value) in authHeaders {
                request.setValue(value, forHTTPHeaderField: key)
            }
            
            // Enhanced headers for better router compatibility
            request.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", forHTTPHeaderField: "User-Agent")
            request.setValue("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", forHTTPHeaderField: "Accept")
            request.setValue("en-US,en;q=0.9", forHTTPHeaderField: "Accept-Language")
            request.setValue("gzip, deflate", forHTTPHeaderField: "Accept-Encoding")
            request.setValue("keep-alive", forHTTPHeaderField: "Connection")
            request.setValue("https://192.168.1.1", forHTTPHeaderField: "Origin")
            request.setValue("https://192.168.1.1", forHTTPHeaderField: "Referer")
            request.setValue("1", forHTTPHeaderField: "Upgrade-Insecure-Requests")
            request.setValue("max-age=0", forHTTPHeaderField: "Cache-Control")
            
            addLog("🌐 Loading WebView: \(url)")
            webView.load(request)
        }
        
        // Extended timeout for complex pages
        DispatchQueue.main.asyncAfter(deadline: .now() + 60) { // Increased to 60 seconds
            webView.removeFromSuperview()
            completion("")
        }
    }

    // MARK: - Enhanced WebView Delegate with Better Error Handling
    class EnhancedWebViewDelegate: NSObject, WKNavigationDelegate {
        private let url: String
        private let completion: (String) -> Void
        private var hasCompleted = false
        private var startTime = Date()
        private var retryCount = 0
        private let maxRetries = 3
        
        init(url: String, completion: @escaping (String) -> Void) {
            self.url = url
            self.completion = completion
            super.init()
        }
        
        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            startTime = Date()
            print("🌐 WebView started loading: \(url)")
        }
        
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            guard !hasCompleted else { return }
            print("🌐 WebView finished loading: \(url)")
            
            // Increased wait time for Angular/SPA rendering
            DispatchQueue.main.asyncAfter(deadline: .now() + 15) { // Increased from 3 to 15 seconds
                self.extractDynamicContent(from: webView)
            }
        }
        
        func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            print("🔒 WebView SSL challenge for: \(challenge.protectionSpace.host)")
            
            // ENHANCED: Handle all SSL certificate challenges
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
                if let serverTrust = challenge.protectionSpace.serverTrust {
                    print("✅ WebView: Accepting SSL certificate for router")
                    let credential = URLCredential(trust: serverTrust)
                    completionHandler(.useCredential, credential)
                    return
                }
            }
            
            // Handle client certificate challenges
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
                print("🔑 WebView: Client certificate challenge")
                completionHandler(.performDefaultHandling, nil)
                return
            }
            
            // Handle HTTP basic authentication
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPBasic ||
               challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPDigest {
                print("🔐 WebView: HTTP authentication challenge")
                completionHandler(.performDefaultHandling, nil)
                return
            }
            
            // Default: Accept any certificate for router
            if let serverTrust = challenge.protectionSpace.serverTrust {
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        }
        
        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            print("❌ WebView navigation failed for \(url): \(error.localizedDescription)")
            
            let nsError = error as NSError
            print("❌ Error details: Domain=\(nsError.domain), Code=\(nsError.code)")
            
            // Retry logic for SSL and network errors
            if (nsError.code == -1202 || nsError.code == -1200 || nsError.code == -1001) && retryCount < maxRetries {
                retryCount += 1
                print("🔄 WebView retry \(retryCount)/\(maxRetries) for \(url)")
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                    if let pageURL = URL(string: self.url) {
                        let request = URLRequest(url: pageURL)
                        webView.load(request)
                    }
                }
                return
            }
            
            // If retries exhausted, complete with empty content
            completeWithContent("")
        }
        
        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            print("❌ WebView provisional navigation failed for \(url): \(error.localizedDescription)")
            
            let nsError = error as NSError
            
            // Specific handling for SSL errors (-1202)
            if nsError.code == -1202 && retryCount < maxRetries {
                retryCount += 1
                print("🔄 WebView SSL retry \(retryCount)/\(maxRetries) for \(url)")
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    if let pageURL = URL(string: self.url) {
                        var request = URLRequest(url: pageURL)
                        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
                        webView.load(request)
                    }
                }
                return
            }
            
            completeWithContent("")
        }
        
        private func extractDynamicContent(from webView: WKWebView) {
            guard !hasCompleted else { return }
            
            let loadingTime = Date().timeIntervalSince(startTime)
            print("🌐 Extracting dynamic content from: \(url) (loaded in \(loadingTime)s)")
            
            // ENHANCED: Comprehensive content extraction script
            let extractionScript = """
            (function() {
                console.log('Starting comprehensive content extraction for: \(url)');
                
                // Wait for any final rendering
                return new Promise((resolve) => {
                    setTimeout(() => {
                        try {
                            var result = {
                                html: document.documentElement.outerHTML,
                                text: document.body ? (document.body.innerText || document.body.textContent || '') : '',
                                title: document.title || 'No Title',
                                url: window.location.href,
                                readyState: document.readyState,
                                bodyLength: document.body ? document.body.innerHTML.length : 0,
                                
                                // Extract tables
                                tables: [],
                                
                                // Extract device data
                                devices: [],
                                ips: [],
                                macs: [],
                                
                                // Extract forms
                                forms: [],
                                
                                // Debug info
                                debug: {
                                    scriptsCount: document.scripts.length,
                                    hasAngular: typeof angular !== 'undefined',
                                    hasJQuery: typeof $ !== 'undefined',
                                    elementCount: document.querySelectorAll('*').length
                                }
                            };
                            
                            console.log('Document ready state:', result.readyState);
                            console.log('Body length:', result.bodyLength);
                            console.log('Element count:', result.debug.elementCount);
                            
                            // Extract all meaningful tables
                            var tables = document.querySelectorAll('table');
                            console.log('Found tables:', tables.length);
                            
                            for (var i = 0; i < tables.length; i++) {
                                var tableText = tables[i].innerText || tables[i].textContent || '';
                                if (tableText.length > 50) {
                                    result.tables.push({
                                        html: tables[i].outerHTML,
                                        text: tableText,
                                        rowCount: tables[i].rows ? tables[i].rows.length : 0,
                                        index: i
                                    });
                                }
                            }
                            
                            // Extract all forms
                            var forms = document.querySelectorAll('form');
                            for (var i = 0; i < forms.length; i++) {
                                result.forms.push({
                                    html: forms[i].outerHTML,
                                    action: forms[i].action || '',
                                    method: forms[i].method || 'GET',
                                    inputCount: forms[i].querySelectorAll('input').length
                                });
                            }
                            
                            // Enhanced IP address detection
                            var bodyText = result.text + ' ' + result.html;
                            var ipPattern = /\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/g;
                            var ips = bodyText.match(ipPattern) || [];
                            result.ips = [...new Set(ips)].filter(ip => {
                                return ip !== '0.0.0.0' && ip !== '255.255.255.255' && ip !== '127.0.0.1';
                            });
                            
                            // Enhanced MAC address detection
                            var macPattern = /\\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\\b/g;
                            var macs = bodyText.match(macPattern) || [];
                            result.macs = [...new Set(macs)];
                            
                            // Look for device names and hostnames
                            var deviceNamePattern = /\\b(?:hostname|device[\\s_-]?name|client[\\s_-]?name)\\s*[:=]?\\s*([\\w\\-\\.]{2,32})/gi;
                            var deviceNames = [];
                            var match;
                            while ((match = deviceNamePattern.exec(bodyText)) !== null) {
                                deviceNames.push(match[1]);
                            }
                            result.devices = [...new Set(deviceNames)];
                            
                            // Try to access Angular scope data if available
                            try {
                                if (window.angular) {
                                    result.angular = {
                                        hasAngular: true,
                                        version: angular.version ? angular.version.full : 'unknown'
                                    };
                                    
                                    // Try to get scope from body
                                    var bodyElement = angular.element(document.body);
                                    if (bodyElement && bodyElement.scope) {
                                        var bodyScope = bodyElement.scope();
                                        if (bodyScope) {
                                            result.angular.scopeKeys = Object.keys(bodyScope).slice(0, 20);
                                            
                                            // Look for common router data properties
                                            var dataKeys = ['devices', 'clients', 'dhcpClients', 'connectedDevices', 'deviceList', 'hosts'];
                                            for (var key of dataKeys) {
                                                if (bodyScope[key]) {
                                                    result.angular[key] = bodyScope[key];
                                                    console.log('Found Angular data:', key, bodyScope[key]);
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch(e) {
                                result.angular = { error: e.toString() };
                            }
                            
                            // Try to access global router data variables
                            var globalKeys = ['routerData', 'deviceList', 'dhcpClients', 'connectedDevices', 'networkConfig', 'systemInfo', 'wifiConfig'];
                            result.globals = {};
                            for (var key of globalKeys) {
                                if (window[key]) {
                                    result.globals[key] = window[key];
                                    console.log('Found global data:', key, window[key]);
                                }
                            }
                            
                            console.log('Extraction complete:', {
                                htmlLength: result.html.length,
                                textLength: result.text.length,
                                tablesFound: result.tables.length,
                                formsFound: result.forms.length,
                                ipsFound: result.ips.length,
                                macsFound: result.macs.length,
                                devicesFound: result.devices.length
                            });
                            
                            resolve(JSON.stringify(result));
                            
                        } catch(e) {
                            console.error('Content extraction error:', e);
                            resolve(JSON.stringify({
                                error: e.toString(),
                                html: document.documentElement.outerHTML || '',
                                text: document.body ? (document.body.innerText || '') : '',
                                title: document.title || '',
                                url: window.location.href || ''
                            }));
                        }
                    }, 5000); // Wait 5 seconds for final rendering
                });
            })();
            """
            
            // Execute the enhanced content extraction
            webView.evaluateJavaScript(extractionScript) { result, error in
                if let error = error {
                    print("❌ JavaScript execution error: \(error)")
                    self.fallbackContentExtraction(webView: webView)
                } else if let jsonString = result as? String {
                    print("✅ Enhanced content extraction successful: \(jsonString.count) chars")
                    self.completeWithContent(jsonString)
                } else {
                    print("⚠️ No result from enhanced extraction, trying fallback")
                    self.fallbackContentExtraction(webView: webView)
                }
            }
        }
        
        private func fallbackContentExtraction(webView: WKWebView) {
            print("🔄 Fallback content extraction for: \(url)")
            
            // Get basic HTML content
            webView.evaluateJavaScript("document.documentElement.outerHTML") { htmlResult, error in
                let finalHTML = htmlResult as? String ?? ""
                
                // Get text content
                webView.evaluateJavaScript("document.body ? (document.body.innerText || document.body.textContent || '') : ''") { textResult, error in
                    let finalText = textResult as? String ?? ""
                    
                    let fallbackContent = """
                    {
                        "html": \(self.escapeForJSON(finalHTML)),
                        "text": \(self.escapeForJSON(finalText)),
                        "title": "Fallback Content",
                        "url": \(self.escapeForJSON(self.url)),
                        "fallback": true
                    }
                    """
                    
                    print("✅ Fallback extraction complete: \(fallbackContent.count) chars")
                    self.completeWithContent(fallbackContent)
                }
            }
        }
        
        private func escapeForJSON(_ string: String) -> String {
            // Simple JSON escaping
            let escaped = string
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\n", with: "\\n")
                .replacingOccurrences(of: "\r", with: "\\r")
                .replacingOccurrences(of: "\t", with: "\\t")
            
            return "\"\(escaped)\""
        }
        
        private func completeWithContent(_ content: String) {
            guard !hasCompleted else { return }
            hasCompleted = true
            completion(content)
        }
    }

    // MARK: - Add this method to process the enhanced WebView content
    // Add this to GigaSpireWebScanner class

    private func processEnhancedWebViewContent(_ jsonString: String, source: String) async {
        addLog("🔄 Processing enhanced WebView content from: \(source)")
        
        guard let data = jsonString.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            addLog("❌ Failed to parse WebView JSON from \(source)")
            return
        }
        
        addLog("✅ Parsed WebView JSON from \(source)")
        
        // Extract IPs
        if let ips = json["ips"] as? [String] {
            addLog("📍 Found \(ips.count) IP addresses: \(ips.joined(separator: ", "))")
        }
        
        // Extract MACs
        if let macs = json["macs"] as? [String] {
            addLog("🔗 Found \(macs.count) MAC addresses: \(macs.joined(separator: ", "))")
        }
        
        // Extract device names
        if let devices = json["devices"] as? [String] {
            addLog("📱 Found \(devices.count) device names: \(devices.joined(separator: ", "))")
        }
        
        // Extract tables
        if let tables = json["tables"] as? [[String: Any]] {
            addLog("📊 Found \(tables.count) data tables")
            for (index, table) in tables.enumerated() {
                if let rowCount = table["rowCount"] as? Int,
                   let text = table["text"] as? String {
                    addLog("   📋 Table \(index): \(rowCount) rows, \(text.count) chars")
                    
                    // Process table content for device data
                    await extractDataFromTableContent(text, source: "\(source).table\(index)")
                }
            }
        }
        
        // Extract Angular data
        if let angular = json["angular"] as? [String: Any] {
            addLog("🅰️ Angular data found:")
            if let scopeKeys = angular["scopeKeys"] as? [String] {
                addLog("   🔑 Scope keys: \(scopeKeys.joined(separator: ", "))")
            }
            
            // Check for device data in Angular scope
            let deviceKeys = ["devices", "clients", "dhcpClients", "connectedDevices", "deviceList"]
            for key in deviceKeys {
                if let deviceData = angular[key] {
                    addLog("   📱 Found Angular \(key): \(deviceData)")
                }
            }
        }
        
        // Extract global data
        if let globals = json["globals"] as? [String: Any] {
            addLog("🌍 Global data found:")
            for (key, value) in globals {
                addLog("   🔧 Global \(key): \(value)")
            }
        }
    }

    private func extractDataFromTableContent(_ tableText: String, source: String) async {
        addLog("🔍 Extracting data from table: \(source)")
        
        // Look for device data patterns in table text
        let lines = tableText.components(separatedBy: .newlines)
        var foundDevices: [DHCPClient] = []
        
        for line in lines {
            let trimmedLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmedLine.count > 20 { // Skip empty or very short lines
                
                // Look for IP and MAC patterns in the line
                let ipPattern = #"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"#
                let macPattern = #"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"#
                
                if let ip = extractFirstMatch(from: trimmedLine, pattern: ipPattern),
                   let mac = extractFirstMatch(from: trimmedLine, pattern: macPattern) {
                    
                    // Extract potential device name (usually the text that's not IP or MAC)
                    var deviceName = trimmedLine
                        .replacingOccurrences(of: ip, with: "")
                        .replacingOccurrences(of: mac, with: "")
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    
                    if deviceName.isEmpty {
                        deviceName = "Device-\(ip.split(separator: ".").last ?? "Unknown")"
                    }
                    
                    let device = DHCPClient(
                        deviceName: deviceName,
                        ipAddress: ip,
                        macAddress: mac,
                        leaseTime: "Unknown",
                        deviceType: "Unknown"
                    )
                    
                    foundDevices.append(device)
                    addLog("📱 Table device: \(device.deviceName) - \(device.ipAddress) - \(device.macAddress)")
                }
            }
        }
        
        if !foundDevices.isEmpty {
            addLog("✅ Table \(source) found \(foundDevices.count) devices")
            // You can store these devices or merge with your main collection
        }
    }
    
    // MARK: - Data Processing Methods
    private func processAPIResponse(endpoint: String, response: String, method: String, params: String) async {
        addLog("📊 Processing API response: \(endpoint)")
        
        // Try to parse as JSON first
        if let data = response.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) {
            
            if let dict = json as? [String: Any] {
                await extractDataFromJSON(dict, source: "\(endpoint) (\(method))")
            } else if let array = json as? [[String: Any]] {
                for item in array {
                    await extractDataFromJSON(item, source: "\(endpoint) (\(method))")
                }
            }
        } else {
            // Try to extract data from non-JSON responses
            await extractDataFromText(response, source: "\(endpoint) (\(method))")
        }
    }
    
    private func extractDataFromJSON(_ json: [String: Any], source: String) async {
        // Look for device/client data
        let deviceKeys = ["devices", "clients", "dhcp_clients", "connected_devices", "lan_clients", "hosts"]
        
        for key in deviceKeys {
            if let deviceArray = json[key] as? [[String: Any]] {
                for deviceData in deviceArray {
                    if let device = createDeviceFromJSON(deviceData, source: source) {
                        // Store device data
                        addLog("📱 Found device: \(device.name) - \(device.ipAddress)")
                    }
                }
            }
        }
        
        // Look for wireless data
        let wirelessKeys = ["wireless", "wifi", "ssids", "networks", "access_points"]
        
        for key in wirelessKeys {
            if let wirelessArray = json[key] as? [[String: Any]] {
                for networkData in wirelessArray {
                    if let network = createWirelessFromJSON(networkData, source: source) {
                        addLog("📶 Found wireless: \(network.ssid)")
                    }
                }
            }
        }
        
        // Look for system info
        if let systemInfo = json["system_info"] as? [[String: Any]] {
            for info in systemInfo {
                if let param = info["param"] as? String,
                   let value = info["value"] as? String {
                    addLog("🔧 System: \(param) = \(value)")
                }
            }
        }
    }
    
    private func extractDataFromText(_ text: String, source: String) async {
        // Extract IP addresses
        let ipPattern = #"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"#
        let ipMatches = findMatches(in: text, pattern: ipPattern)
        
        for ip in ipMatches {
            if isValidIPAddress(ip) {
                addLog("🌐 Found IP: \(ip) in \(source)")
            }
        }
        
        // Extract MAC addresses
        let macPattern = #"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"#
        let macMatches = findMatches(in: text, pattern: macPattern)
        
        for mac in macMatches {
            addLog("🔗 Found MAC: \(mac) in \(source)")
        }
    }
    
    private func extractDataFromStaticContent(content: String, source: String) async {
        // This is your existing static extraction logic
        await extractDataFromText(content, source: source)
    }
    
    private func extractDataFromDynamicContent(content: String, source: String) async {
        addLog("🔄 Extracting from dynamic content: \(source)")
        
        // Look for JavaScript-loaded data
        let dataPatterns = [
            #"device.*?:\s*['""]([^'""]*)['"""]"#,
            #"client.*?:\s*['""]([^'""]*)['"""]"#,
            #"ssid.*?:\s*['""]([^'""]*)['"""]"#,
            #"ip.*?:\s*['""]([^'""]*)['"""]"#
        ]
        
        for pattern in dataPatterns {
            let matches = findMatches(in: content, pattern: pattern)
            for match in matches {
                addLog("🎯 Dynamic data found: \(match)")
            }
        }
    }
    
    // MARK: - Phase 4: Data Analysis
    private func analyzeAndConsolidateData() async {
        addLog("🔍 === PHASE 4: DATA ANALYSIS ===")
        
        // This would consolidate all the extracted data
        // and create the final ScrapedData object
        
        await MainActor.run {
            self.currentScanStatus = "Analysis complete!"
        }
    }
    
    // MARK: - Helper Methods
    private func extractPageName(_ url: String) -> String {
        if let lastComponent = url.split(separator: "/").last {
            return String(lastComponent)
        }
        return "Unknown"
    }
    
    private func callRouterAPI(endpoint: String, postData: String?, method: String = "POST") async -> Data? {
        let fullURL = endpoint.isEmpty ? baseURL : "\(baseURL)/\(endpoint)"
        
        guard let url = URL(string: fullURL) else {
            return nil
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 10
        
        // Add authentication headers
        for (key, value) in authHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        // Add standard headers
        request.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15", forHTTPHeaderField: "User-Agent")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue("gzip, deflate", forHTTPHeaderField: "Accept-Encoding")
        request.setValue(baseURL, forHTTPHeaderField: "Origin")
        request.setValue(baseURL, forHTTPHeaderField: "Referer")
        
        if method == "POST" {
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            if let postData = postData {
                request.httpBody = postData.data(using: .utf8)
            }
        }
        
        // Add cookies
        if !authCookies.isEmpty {
            let cookieHeaders = HTTPCookie.requestHeaderFields(with: authCookies)
            for (key, value) in cookieHeaders {
                request.setValue(value, forHTTPHeaderField: key)
            }
        }
        
        do {
            let (data, response) = try await urlSession.data(for: request)
            
            if let httpResponse = response as? HTTPURLResponse {
                if httpResponse.statusCode == 200 {
                    return data
                }
            }
        } catch {
            // Ignore errors, we're trying many endpoints
        }
        
        return nil
    }
    
    
    
    // MARK: - Keep existing helper methods
    private func findMatches(in text: String, pattern: String) -> [String] {
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive, .dotMatchesLineSeparators])
            let matches = regex.matches(in: text, range: NSRange(location: 0, length: text.count))
            
            return matches.compactMap { match in
                if let range = Range(match.range, in: text) {
                    return String(text[range])
                }
                return nil
            }
        } catch {
            return []
        }
    }
    
    private func determinePageType(from url: String) -> PageType {
        if url.contains("/status/") { return .status }
        if url.contains("/support/") { return .support }
        if url.contains("/utilities/") { return .utilities }
        if url.contains("/dashboard") { return .dashboard }
        if url.contains("/advanced/") { return .configuration }
        if url.contains("/wireless/") { return .configuration }
        return .unknown
    }
    
    
    private func extractFirst(from text: String, pattern: String) -> String? {
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
            if let match = regex.firstMatch(in: text, range: NSRange(location: 0, length: text.count)) {
                if match.numberOfRanges > 1 {
                    let range = Range(match.range(at: 1), in: text)!
                    return String(text[range]).trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
        } catch {
            return nil
        }
        return nil
    }
    
    private func createDeviceFromJSON(_ json: [String: Any], source: String) -> ScrapedDevice? {
        let nameFields = ["hostname", "name", "device_name", "deviceName", "host", "client_name"]
        let ipFields = ["ip", "ip_address", "ipAddress", "address", "lan_ip"]
        let macFields = ["mac", "mac_address", "macAddress", "hwaddr", "hw_addr"]
        
        var name: String?
        var ip: String?
        var mac: String?
        
        for field in nameFields {
            if let value = json[field] as? String, !value.isEmpty {
                name = value
                break
            }
        }
        
        for field in ipFields {
            if let value = json[field] as? String, !value.isEmpty, isValidIPAddress(value) {
                ip = value
                break
            }
        }
        
        for field in macFields {
            if let value = json[field] as? String, !value.isEmpty, isValidMACAddress(value) {
                mac = value
                break
            }
        }
        
        if let ip = ip, let mac = mac {
            return ScrapedDevice(
                name: name ?? "Device-\(ip.split(separator: ".").last ?? "Unknown")",
                ipAddress: ip,
                macAddress: mac,
                deviceType: (json["device_type"] as? String) ?? "Unknown",
                connectionType: (json["connection_type"] as? String) ?? "Unknown",
                isOnline: (json["online"] as? Bool) ?? true,
                source: source
            )
        }
        
        return nil
    }
    
    private func createWirelessFromJSON(_ json: [String: Any], source: String) -> ScrapedWirelessNetwork? {
        guard let ssid = json["ssid"] as? String ?? json["network_name"] as? String,
              !ssid.isEmpty else {
            return nil
        }
        
        return ScrapedWirelessNetwork(
            ssid: ssid,
            band: (json["band"] as? String) ?? "Unknown",
            channel: (json["channel"] as? String) ?? "Unknown",
            security: (json["security"] as? String) ?? "Unknown",
            isEnabled: (json["enabled"] as? Bool) ?? true,
            connectedDevices: (json["connected_devices"] as? Int) ?? 0,
            signalStrength: (json["signal_strength"] as? Double) ?? 0.0,
            source: source
        )
    }
    
    private func isValidMACAddress(_ mac: String) -> Bool {
        let pattern = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        do {
            let regex = try NSRegularExpression(pattern: pattern)
            return regex.firstMatch(in: mac, range: NSRange(location: 0, length: mac.count)) != nil
        } catch {
            return false
        }
    }
    
    private func isValidIPAddress(_ ip: String) -> Bool {
        let parts = ip.components(separatedBy: ".")
        guard parts.count == 4 else { return false }
        
        for part in parts {
            guard let num = Int(part), num >= 0 && num <= 255 else { return false }
        }
        
        return true
    }
    
    private func addLog(_ message: String) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let logEntry = "[\(timestamp)] \(message)"
        
        DispatchQueue.main.async {
            self.debugLogs.append(logEntry)
            if self.debugLogs.count > 500 { // Increased for comprehensive scan
                self.debugLogs.removeFirst()
            }
        }
        
        print(logEntry)
    }
    // MARK: - Add these missing methods to the GigaSpireWebScanner class
    // Insert these methods inside the GigaSpireWebScanner class, before the closing brace

    private func fetchPageWithSSLBypass(_ fullURL: String) async -> String? {
        guard let url = URL(string: fullURL) else {
            addLog("⚠️ Invalid URL: \(fullURL)")
            return nil
        }
        
        addLog("📡 Fetching static content: \(fullURL)")
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 20
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        
        // Add ALL authentication headers
        for (key, value) in authHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        // Enhanced headers for better router compatibility
        request.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", forHTTPHeaderField: "User-Agent")
        request.setValue("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", forHTTPHeaderField: "Accept")
        request.setValue("en-US,en;q=0.9", forHTTPHeaderField: "Accept-Language")
        request.setValue("gzip, deflate", forHTTPHeaderField: "Accept-Encoding")
        request.setValue("keep-alive", forHTTPHeaderField: "Connection")
        request.setValue("https://192.168.1.1", forHTTPHeaderField: "Origin")
        request.setValue("https://192.168.1.1", forHTTPHeaderField: "Referer")
        request.setValue("1", forHTTPHeaderField: "Upgrade-Insecure-Requests")
        request.setValue("max-age=0", forHTTPHeaderField: "Cache-Control")
        
        // Add cookies to request using proper format
        if !authCookies.isEmpty {
            let cookieHeaders = HTTPCookie.requestHeaderFields(with: authCookies)
            for (key, value) in cookieHeaders {
                request.setValue(value, forHTTPHeaderField: key)
                addLog("🍪 Adding cookie header: \(key)")
            }
        }
        
        do {
            let (data, response) = try await urlSession.data(for: request)
            
            if let httpResponse = response as? HTTPURLResponse {
                addLog("📄 Static fetch response: \(httpResponse.statusCode) for \(fullURL)")
                
                if httpResponse.statusCode == 200 {
                    if let content = String(data: data, encoding: .utf8) {
                        addLog("✅ Static content retrieved: \(content.count) chars from \(fullURL)")
                        
                        // Check if we got actual content or just a login redirect
                        if content.contains("<html") && !content.contains("login") {
                            return content
                        } else {
                            addLog("⚠️ Got login page or invalid content from \(fullURL)")
                            return nil
                        }
                    } else {
                        addLog("⚠️ Could not decode content from \(fullURL)")
                    }
                } else if httpResponse.statusCode == 302 || httpResponse.statusCode == 301 {
                    addLog("🔄 Redirect response for \(fullURL)")
                    if let location = httpResponse.value(forHTTPHeaderField: "Location") {
                        addLog("🔄 Following redirect to: \(location)")
                        return await fetchPageWithSSLBypass(location)
                    }
                } else {
                    addLog("❌ HTTP error \(httpResponse.statusCode) for \(fullURL)")
                }
            }
        } catch {
            addLog("❌ Static fetch error for \(fullURL): \(error.localizedDescription)")
            
            if (error as NSError).code == -1202 {
                addLog("🔒 SSL error detected, this is expected for router certificates")
            }
        }
        
        return nil
    }

    private func analyzePage(url: String, content: String) -> DiscoveredPage {
        let title = extractTitle(from: content, url: url)
        let pageType = determinePageType(from: url)
        let dataFound = findDataElements(in: content)
        
        addLog("🔍 Analyzing page: \(title) (\(content.count) chars)")
        
        return DiscoveredPage(
            url: url,
            title: title,
            pageType: pageType,
            lastScanned: Date(),
            dataFound: dataFound,
            hasDeviceData: hasDeviceData(in: content),
            hasWirelessData: hasWirelessData(in: content),
            hasSystemData: hasSystemData(in: content)
        )
    }
}

// MARK: - Enhanced SPA Scanner with Complete Page Recording
class CompleteSPAScanner: ObservableObject {
    static let shared = CompleteSPAScanner()
    
    @Published var isScanning = false
    @Published var scanProgress = 0.0
    @Published var currentScanStatus = ""
    @Published var recordedPages: [RecordedPage] = []
    @Published var extractedData: ExtractedRouterData?
    @Published var debugLogs: [String] = []
    
    private let urlSession: URLSession
    
    private var baseURL: String = "https://192.168.1.1"
    private var authCookies: [HTTPCookie] = []
    private var authHeaders: [String: String] = [:]
    
    private init() {
        let config = URLSessionConfiguration.default
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        
        self.urlSession = URLSession(
            configuration: config,
            delegate: SSLBypassSessionDelegate(),
            delegateQueue: nil
        )
    }
    
        private func analyzePage(url: String, content: String) -> RecordedPage {
            let title = extractPageTitle(from: content, url: url)
            let pageName = extractPageName(url)
            
            addLog("🔍 Analyzing page: \(title) (\(content.count) chars)")
            
            return RecordedPage(
                url: url,
                pageName: pageName,
                initialHTMLContent: content,
                finalHTMLContent: content,
                finalTextContent: extractTextContent(from: content),
                javascriptData: "{}",
                loadingTime: 0.0,
                finalContentSize: content.count,
                hasDeviceData: hasDeviceData(in: content),
                hasWirelessData: hasWirelessData(in: content),
                hasSystemData: hasSystemData(in: content),
                recordedAt: Date()
            )
        }
        
        private func extractPageTitle(from content: String, url: String = "") -> String {
            // Try multiple title extraction methods
            if let title = extractFirstMatch(from: content, pattern: "<title[^>]*>([^<]+)</title>") {
                let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
                if !cleanTitle.isEmpty {
                    return cleanTitle
                }
            }
            
            // Try meta title
            if let title = extractFirstMatch(from: content, pattern: "<meta[^>]*property=[\"']og:title[\"'][^>]*content=[\"']([^\"']+)[\"']") {
                let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
                if !cleanTitle.isEmpty {
                    return cleanTitle
                }
            }
            
            // Try h1 tag
            if let title = extractFirstMatch(from: content, pattern: "<h1[^>]*>([^<]+)</h1>") {
                let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
                if !cleanTitle.isEmpty {
                    return cleanTitle
                }
            }
            
            // Try to extract from URL path if provided
            if !url.isEmpty, let urlPath = url.split(separator: "/").last {
                let pathTitle = String(urlPath).replacingOccurrences(of: "_", with: " ")
                    .replacingOccurrences(of: ".html", with: "")
                    .capitalized
                if !pathTitle.isEmpty {
                    return pathTitle
                }
            }
            
            return "Router Page"
        }
        
        private func extractTextContent(from content: String) -> String {
            // Simple text extraction - remove HTML tags
            let pattern = "<[^>]+>"
            do {
                let regex = try NSRegularExpression(pattern: pattern, options: [])
                let textContent = regex.stringByReplacingMatches(
                    in: content,
                    range: NSRange(location: 0, length: content.count),
                    withTemplate: ""
                )
                return textContent.trimmingCharacters(in: .whitespacesAndNewlines)
            } catch {
                return content
            }
        }
        
        private func hasDeviceData(in content: String) -> Bool {
            let deviceIndicators = [
                "device", "client", "MAC", "dhcp", "hostname", "ip address",
                "connected", "ethernet", "wireless client", "lan client",
                "device table", "client list", "connected devices"
            ]
            
            let lowercaseContent = content.lowercased()
            for indicator in deviceIndicators {
                if lowercaseContent.contains(indicator.lowercased()) {
                    addLog("📱 Device data indicator found: \(indicator)")
                    return true
                }
            }
            return false
        }
        
        private func hasWirelessData(in content: String) -> Bool {
            let wirelessIndicators = [
                "SSID", "wireless", "WiFi", "wifi", "radio", "antenna",
                "signal", "channel", "frequency", "802.11", "access point",
                "wireless network", "wifi config", "wireless status"
            ]
            
            let lowercaseContent = content.lowercased()
            for indicator in wirelessIndicators {
                if lowercaseContent.contains(indicator.lowercased()) {
                    addLog("📶 Wireless data indicator found: \(indicator)")
                    return true
                }
            }
            return false
        }
        
        private func hasSystemData(in content: String) -> Bool {
            let systemIndicators = [
                "system", "model", "version", "firmware", "uptime", "memory",
                "cpu", "temperature", "status", "configuration", "serial",
                "system info", "device info", "router status"
            ]
            
            let lowercaseContent = content.lowercased()
            for indicator in systemIndicators {
                if lowercaseContent.contains(indicator.lowercased()) {
                    addLog("🔧 System data indicator found: \(indicator)")
                    return true
                }
            }
            return false
        }
    
    // Complete list of all GigaSpire pages
    private let allPages = [
        "https://192.168.1.1/#/dashboard",
        "https://192.168.1.1/#/html/status/status_system.html",
        "https://192.168.1.1/#/html/status/status_connection.html",
        "https://192.168.1.1/#/html/status/status_devicetable.html",
        "https://192.168.1.1/#/html/status/status_internetstatus_ipv6.html",
        "https://192.168.1.1/#/html/status/status_lanstatus_ipv6.html",
        "https://192.168.1.1/#/html/status/status_wirelessstatus.html",
        "https://192.168.1.1/#/html/utilities/utilities/backup&restore",
        "https://192.168.1.1/#/html/utilities/utilities/reboot",
        "https://192.168.1.1/#/html/utilities/utilities/ping_test",
        "https://192.168.1.1/#/html/utilities/utilities/traceroute",
        "https://192.168.1.1/#/html/advanced/ip/dhcp_setting",
        "https://192.168.1.1/#/html/advanced/ip/dhcp_reservation",
        "https://192.168.1.1/#/html/advanced/ip/dns_host_mapping",
        "https://192.168.1.1/#/html/advanced/ip/dynamic_dns",
        "https://192.168.1.1/#/html/advanced/ip/ipv6_lan_setting",
        "https://192.168.1.1/#/html/advanced/ip/x_lan_setting",
        "https://192.168.1.1/#/html/advanced/advanced/security/administrator_credentials",
        "https://192.168.1.1/#/html/advanced/advanced/security/upnp",
        "https://192.168.1.1/#/html/advanced/advanced/security/firewall",
        "https://192.168.1.1/#/html/advanced/advanced/security/DMZ_Hosting",
        "https://192.168.1.1/#/html/advanced/advanced/security/port_forwarding",
        "https://192.168.1.1/#/html/advanced/advanced/security/arp_spoofing",
        "https://192.168.1.1/#/html/advanced/advanced/security/web_logging",
        "https://192.168.1.1/#/html/advanced/blocking/scheduling_access/scheduling_access",
        "https://192.168.1.1/#/html/advanced/blocking/service_blocking",
        "https://192.168.1.1/#/html/advanced/blocking/website_blocking",
        "https://192.168.1.1/#/html/advanced/advanced/controls",
        "https://192.168.1.1/#/html/wireless/radio",
        "https://192.168.1.1/#/html/wireless/primary",
        "https://192.168.1.1/#/html/wireless/wifi_secondary",
        "https://192.168.1.1/#/html/wireless/wps",
        "https://192.168.1.1/#/html/support/support/tr_069",
        "https://192.168.1.1/#/html/support/support/service_wan_vlan",
        "https://192.168.1.1/#/html/support/support/lan_status",
        "https://192.168.1.1/#/html/support/support/dns_server",
        "https://192.168.1.1/#/html/support/support/service_static_routes",
        "https://192.168.1.1/#/html/support/support/voip_gateway_settings",
        "https://192.168.1.1/#/html/support/support/line_features",
        "https://192.168.1.1/#/html/support/support/voip_diagnostics",
        "https://192.168.1.1/#/html/support/support/igmp/igmp_setup",
        "https://192.168.1.1/#/html/support/support/smart_activate",
        "https://192.168.1.1/#/html/support/support/remote_management",
        "https://192.168.1.1/#/html/support/support/qos",
        "https://192.168.1.1/#/html/support/support/shaping",
        "https://192.168.1.1/#/html/support/support/acl",
        "https://192.168.1.1/#/html/support/support/device_logs",
        "https://192.168.1.1/#/html/support/support/configuration_save",
        "https://192.168.1.1/#/html/support/support/diagnosis/pcap",
        "https://192.168.1.1/#/html/support/support/diagnosis/over_air",
        "https://192.168.1.1/#/html/support/support/diagnosis/vca",
        "https://192.168.1.1/#/html/support/support/diagnosis/port_mirror",
        "https://192.168.1.1/#/html/support/support/diagnosis/log_analysis",
        "https://192.168.1.1/#/html/support/support/diagnosis/net_statistics",
        "https://192.168.1.1/#/html/support/support/support_wireless",
        "https://192.168.1.1/#/html/support/support/support_upgrade/upgrade_image",
        "https://192.168.1.1/#/html/support/support/support_container_apps",
        "https://192.168.1.1/#/html/beta/beta/wifi_analytics"
    ]
    
    // Working API endpoints from console output
    private let workingAPIEndpoints = [
        "device_table.cmd",      // 389 bytes - PROMISING!
        "network_status.cmd",    // 227 bytes - Working
        "board_capabilities.cmd", // 353 bytes - Working
        "status_system.cmd"      // 1134 bytes - Working
    ]
    
    func setAuthenticationData(cookies: [HTTPCookie], headers: [String: String]) {
        self.authCookies = cookies
        self.authHeaders = headers
        addLog("🔐 Authentication data set: \(cookies.count) cookies, \(headers.count) headers")
    }
    
    // MARK: - Main Scanning Function
    @MainActor
    func scanAllPagesCompletely() async {
        isScanning = true
        scanProgress = 0.0
        currentScanStatus = "Starting complete page recording..."
        recordedPages.removeAll()
        
        addLog("🚀 === STARTING COMPLETE PAGE RECORDING ===")
        addLog("📋 Will record ALL \(allPages.count) pages with full content")
        
        // Phase 1: Leverage working API endpoints (20%)
        await scanWorkingAPIEndpoints()
        scanProgress = 0.2
        
        // Phase 2: Record each page completely (80%)
        await recordAllPagesCompletely()
        scanProgress = 1.0
        
        // Analyze all recorded content
        await analyzeRecordedContent()
        
        currentScanStatus = "Complete page recording finished!"
        addLog("✅ === COMPLETE SCAN FINISHED ===")
        addLog("📊 Recorded \(recordedPages.count) pages with full content")
        
        isScanning = false
    }
    
    // MARK: - Phase 1: Working API Endpoints
    private func scanWorkingAPIEndpoints() async {
        addLog("🔍 === PHASE 1: WORKING API ENDPOINTS ===")
        currentScanStatus = "Extracting data from working API endpoints..."
        
        for endpoint in workingAPIEndpoints {
            addLog("📡 Calling working API: \(endpoint)")
            
            // Try multiple parameter combinations
            let paramSets = [
                "action=get",
                "action=list",
                "cmd=get_data",
                "{\"action\":\"get\"}",
                ""
            ]
            
            for params in paramSets {
                if let data = await callRouterAPI(endpoint: endpoint, postData: params.isEmpty ? nil : params) {
                    let response = String(data: data, encoding: .utf8) ?? ""
                    
                    if response.count > 50 {
                        addLog("✅ API \(endpoint): \(response.count) bytes")
                        await processAPIResponse(endpoint: endpoint, response: response)
                        break // Found working combination
                    }
                }
            }
        }
    }
    
    // MARK: - Phase 2: Complete Page Recording
    private func recordAllPagesCompletely() async {
        addLog("🔍 === PHASE 2: COMPLETE PAGE RECORDING ===")
        
        for (index, pageUrl) in allPages.enumerated() {
            let progress = 0.2 + (Double(index) / Double(allPages.count)) * 0.8
            await MainActor.run {
                self.scanProgress = progress
                self.currentScanStatus = "Recording page \(index + 1)/\(allPages.count): \(extractPageName(pageUrl))"
            }
            
            addLog("📄 === RECORDING PAGE: \(pageUrl) ===")
            
            // Record page with complete loading
            if let recordedPage = await recordPageCompletely(pageUrl) {
                await MainActor.run {
                    self.recordedPages.append(recordedPage)
                }
                
                addLog("✅ Page recorded: \(recordedPage.finalContentSize) bytes")
                
                // Extract data from this page
                await extractDataFromRecordedPage(recordedPage)
            } else {
                addLog("❌ Failed to record: \(pageUrl)")
            }
            
            // Delay between pages to avoid overwhelming
            try? await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        }
    }
    
    // MARK: - Complete Page Recording with Proper SPA Loading
    private func recordPageCompletely(_ url: String) async -> RecordedPage? {
        return await withCheckedContinuation { continuation in
            DispatchQueue.main.async {
                self.setupCompletePageRecorder(url: url) { recordedPage in
                    continuation.resume(returning: recordedPage)
                }
            }
        }
    }
    
    // MARK: - FIXED: Enhanced WebView Configuration with Proper SSL Bypass
    private func setupCompletePageRecorder(url: String, completion: @escaping (RecordedPage?) -> Void) {
        let config = WKWebViewConfiguration()
        
        // Use default persistent store for better cookie handling
        config.websiteDataStore = WKWebsiteDataStore.default()
        
        // CRITICAL: Set cookies BEFORE creating WebView
        for cookie in authCookies {
            config.websiteDataStore.httpCookieStore.setCookie(cookie) { }
        }
        
        // Enhanced preferences for better compatibility
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        config.preferences.javaScriptCanOpenWindowsAutomatically = true
        
        // Disable web security for local router access
        config.preferences.setValue(true, forKey: "allowUniversalAccessFromFileURLs")
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        
        let webView = WKWebView(frame: CGRect(x: 0, y: 0, width: 1200, height: 800), configuration: config)
        webView.isHidden = true
        webView.allowsBackForwardNavigationGestures = false
        
        // Add to window
        if let windowScene = UIApplication.shared.connectedScenes.first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene,
           let window = windowScene.windows.first(where: { $0.isKeyWindow }) {
            window.addSubview(webView)
        }
        
        // Create ENHANCED delegate for complete recording
        let delegate = EnhancedPageRecordingDelegate(url: url) { [weak webView] recordedPage in
            webView?.removeFromSuperview()
            completion(recordedPage)
        }
        
        webView.navigationDelegate = delegate
        
        // Load the page with PROPER authentication headers
        if let pageURL = URL(string: url) {
            var request = URLRequest(url: pageURL)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.timeoutInterval = 30
            
            // Add ALL authentication headers
            for (key, value) in authHeaders {
                request.setValue(value, forHTTPHeaderField: key)
            }
            
            // Add additional headers for better router compatibility
            request.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", forHTTPHeaderField: "User-Agent")
            request.setValue("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", forHTTPHeaderField: "Accept")
            request.setValue("en-US,en;q=0.9", forHTTPHeaderField: "Accept-Language")
            request.setValue("gzip, deflate", forHTTPHeaderField: "Accept-Encoding")
            request.setValue("keep-alive", forHTTPHeaderField: "Connection")
            request.setValue("https://192.168.1.1", forHTTPHeaderField: "Origin")
            request.setValue("https://192.168.1.1", forHTTPHeaderField: "Referer")
            request.setValue("1", forHTTPHeaderField: "Upgrade-Insecure-Requests")
            
            webView.load(request)
        }
        
        // Extended timeout for complex SPA pages
        DispatchQueue.main.asyncAfter(deadline: .now() + 45) {
            webView.removeFromSuperview()
            completion(nil)
        }
    }
    // MARK: - FIXED: Enhanced Page Recording Delegate with Better SSL and Content Handling
    class EnhancedPageRecordingDelegate: NSObject, WKNavigationDelegate {
        private let url: String
        private let completion: (RecordedPage?) -> Void
        private var hasCompleted = false
        private var startTime = Date()
        private var initialHTML = ""
        private var loadAttempts = 0
        private let maxLoadAttempts = 3
        
        init(url: String, completion: @escaping (RecordedPage?) -> Void) {
            self.url = url
            self.completion = completion
            super.init()
        }
        
        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            startTime = Date()
            print("🌐 Started loading: \(url)")
        }
        
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            guard !hasCompleted else { return }
            print("🌐 Initial load finished: \(url)")
            
            // Capture initial HTML immediately
            webView.evaluateJavaScript("document.documentElement.outerHTML") { result, error in
                if let html = result as? String {
                    self.initialHTML = html
                    print("📄 Initial HTML captured: \(html.count) chars")
                }
            }
            
            // Wait for Angular/SPA to fully load and render - INCREASED WAIT TIME
            DispatchQueue.main.asyncAfter(deadline: .now() + 12) { // Increased from 8 to 12 seconds
                self.attemptContentCapture(webView: webView)
            }
        }
        
        func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            // CRITICAL: Enhanced SSL bypass for router certificates
            print("🔒 Handling SSL challenge for: \(challenge.protectionSpace.host)")
            
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
                if let serverTrust = challenge.protectionSpace.serverTrust {
                    let credential = URLCredential(trust: serverTrust)
                    print("✅ SSL bypass applied for router")
                    completionHandler(.useCredential, credential)
                    return
                }
            }
            
            // Also handle client certificate challenges
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
                print("⚠️ Client certificate challenge - using default handling")
                completionHandler(.performDefaultHandling, nil)
                return
            }
            
            completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
        }
        
        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            print("❌ WebView navigation failed for \(url): \(error.localizedDescription)")
            
            // Retry logic for SSL failures
            if (error as NSError).code == -1202 && loadAttempts < maxLoadAttempts {
                loadAttempts += 1
                print("🔄 Retrying load attempt \(loadAttempts) for \(url)")
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    if let pageURL = URL(string: self.url) {
                        let request = URLRequest(url: pageURL)
                        webView.load(request)
                    }
                }
                return
            }
            
            completeWithFailure()
        }
        
        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            print("❌ WebView provisional navigation failed for \(url): \(error.localizedDescription)")
            print("❌ Error details: \((error as NSError).userInfo)")
            
            // Retry logic for SSL failures
            if (error as NSError).code == -1202 && loadAttempts < maxLoadAttempts {
                loadAttempts += 1
                print("🔄 Retrying provisional load attempt \(loadAttempts) for \(url)")
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    if let pageURL = URL(string: self.url) {
                        let request = URLRequest(url: pageURL)
                        webView.load(request)
                    }
                }
                return
            }
            
            completeWithFailure()
        }
        
        private func attemptContentCapture(webView: WKWebView) {
            guard !hasCompleted else { return }
            
            let loadingTime = Date().timeIntervalSince(startTime)
            print("🌐 Attempting content capture for: \(url) (loaded in \(loadingTime)s)")
            
            // ENHANCED: Comprehensive content extraction with multiple attempts
            let enhancedScript = """
            (function() {
                console.log('Starting enhanced content extraction for: \(url)');
                
                // Wait additional time for any final Angular rendering
                setTimeout(function() {
                    try {
                        var result = {
                            html: document.documentElement.outerHTML,
                            text: document.body ? (document.body.innerText || document.body.textContent || '') : '',
                            title: document.title || 'No Title',
                            url: window.location.href,
                            tables: [],
                            forms: [],
                            deviceData: [],
                            networkData: [],
                            systemData: [],
                            angularData: {},
                            debugInfo: {
                                hasAngular: typeof angular !== 'undefined',
                                hasJQuery: typeof $ !== 'undefined',
                                scriptsCount: document.scripts.length,
                                bodyLength: document.body ? document.body.innerHTML.length : 0,
                                readyState: document.readyState
                            }
                        };
                        
                        console.log('Document ready state:', document.readyState);
                        console.log('Body length:', result.debugInfo.bodyLength);
                        
                        // Capture all tables with meaningful content
                        var tables = document.querySelectorAll('table');
                        console.log('Found tables:', tables.length);
                        for (var i = 0; i < tables.length; i++) {
                            var tableText = tables[i].innerText || tables[i].textContent || '';
                            if (tableText.length > 20) { // Only capture tables with substantial content
                                result.tables.push({
                                    html: tables[i].outerHTML,
                                    text: tableText,
                                    rowCount: tables[i].rows ? tables[i].rows.length : 0
                                });
                            }
                        }
                        
                        // Capture all forms
                        var forms = document.querySelectorAll('form');
                        for (var i = 0; i < forms.length; i++) {
                            result.forms.push({
                                html: forms[i].outerHTML,
                                action: forms[i].action || '',
                                method: forms[i].method || 'GET'
                            });
                        }
                        
                        // Look for device/network data patterns in the rendered content
                        var bodyText = result.text;
                        
                        // Enhanced IP address detection
                        var ipPattern = /\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/g;
                        var ips = bodyText.match(ipPattern) || [];
                        result.deviceData = ips.filter(function(ip) {
                            return ip !== '0.0.0.0' && ip !== '255.255.255.255';
                        });
                        
                        // Enhanced MAC address detection
                        var macPattern = /\\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\\b/g;
                        var macs = bodyText.match(macPattern) || [];
                        result.networkData = macs;
                        
                        // Look for device names and hostnames
                        var deviceNamePattern = /\\b(?:hostname|device[\\s_-]?name|client[\\s_-]?name)\\s*[:=]?\\s*([\\w\\-\\.]{2,32})/gi;
                        var deviceNames = [];
                        var match;
                        while ((match = deviceNamePattern.exec(bodyText)) !== null) {
                            deviceNames.push(match[1]);
                        }
                        result.systemData = deviceNames;
                        
                        // Try to access Angular scope data if available
                        try {
                            if (window.angular) {
                                result.angularData.hasAngular = true;
                                
                                // Try to get scope from body
                                var bodyScope = angular.element(document.body).scope();
                                if (bodyScope) {
                                    result.angularData.scopeKeys = Object.keys(bodyScope).slice(0, 20); // Limit keys
                                    
                                    // Look for common router data properties
                                    if (bodyScope.devices) result.angularData.devices = bodyScope.devices;
                                    if (bodyScope.clients) result.angularData.clients = bodyScope.clients;
                                    if (bodyScope.dhcpClients) result.angularData.dhcpClients = bodyScope.dhcpClients;
                                    if (bodyScope.wirelessNetworks) result.angularData.wirelessNetworks = bodyScope.wirelessNetworks;
                                    if (bodyScope.systemInfo) result.angularData.systemInfo = bodyScope.systemInfo;
                                }
                                
                                // Try to get scope from ng-controller elements
                                var controllers = document.querySelectorAll('[ng-controller]');
                                for (var i = 0; i < controllers.length; i++) {
                                    try {
                                        var controllerScope = angular.element(controllers[i]).scope();
                                        if (controllerScope && controllerScope !== bodyScope) {
                                            result.angularData['controller_' + i] = {
                                                name: controllers[i].getAttribute('ng-controller'),
                                                keys: Object.keys(controllerScope).slice(0, 10)
                                            };
                                        }
                                    } catch(e) {
                                        // Ignore controller scope errors
                                    }
                                }
                            }
                        } catch(e) {
                            result.angularData.error = e.toString();
                        }
                        
                        // Try to access any global router data variables
                        var globalDataKeys = ['routerData', 'deviceList', 'dhcpClients', 'connectedDevices', 'networkConfig', 'systemInfo'];
                        for (var i = 0; i < globalDataKeys.length; i++) {
                            var key = globalDataKeys[i];
                            if (window[key]) {
                                result.angularData[key] = window[key];
                            }
                        }
                        
                        console.log('Content extraction complete:', {
                            htmlLength: result.html.length,
                            textLength: result.text.length,
                            tablesFound: result.tables.length,
                            formsFound: result.forms.length,
                            ipsFound: result.deviceData.length,
                            macsFound: result.networkData.length
                        });
                        
                        return JSON.stringify(result);
                        
                    } catch(e) {
                        console.error('Content extraction error:', e);
                        return JSON.stringify({
                            error: e.toString(),
                            html: document.documentElement.outerHTML,
                            text: document.body ? document.body.innerText : '',
                            title: document.title,
                            url: window.location.href
                        });
                    }
                }, 3000); // Additional 3 second wait for final rendering
            })();
            """
            
            // Execute the enhanced content extraction
            webView.evaluateJavaScript(enhancedScript) { result, error in
                if let error = error {
                    print("❌ JavaScript execution error: \(error)")
                    // Fallback to basic HTML extraction
                    self.fallbackContentExtraction(webView: webView)
                } else if let jsonString = result as? String {
                    print("✅ Enhanced content extraction successful: \(jsonString.count) chars")
                    self.processExtractedContent(jsonString, webView: webView)
                } else {
                    print("⚠️ No result from enhanced extraction, trying fallback")
                    self.fallbackContentExtraction(webView: webView)
                }
            }
        }
        
        private func fallbackContentExtraction(webView: WKWebView) {
            print("🔄 Fallback content extraction for: \(url)")
            
            // Get basic HTML content
            webView.evaluateJavaScript("document.documentElement.outerHTML") { htmlResult, error in
                let finalHTML = htmlResult as? String ?? self.initialHTML
                
                // Get text content
                webView.evaluateJavaScript("document.body ? (document.body.innerText || document.body.textContent || '') : ''") { textResult, error in
                    let finalText = textResult as? String ?? ""
                    
                    let recordedPage = RecordedPage(
                        url: self.url,
                        pageName: self.extractPageName(self.url),
                        initialHTMLContent: self.initialHTML,
                        finalHTMLContent: finalHTML,
                        finalTextContent: finalText,
                        javascriptData: "{}",
                        loadingTime: Date().timeIntervalSince(self.startTime),
                        finalContentSize: finalHTML.count + finalText.count,
                        hasDeviceData: finalHTML.contains("device") || finalHTML.contains("client") || finalHTML.contains("MAC") || finalText.contains("IP"),
                        hasWirelessData: finalHTML.contains("SSID") || finalHTML.contains("wireless") || finalHTML.contains("WiFi"),
                        hasSystemData: finalHTML.contains("system") || finalHTML.contains("model") || finalHTML.contains("version"),
                        recordedAt: Date()
                    )
                    
                    print("✅ Fallback extraction complete: \(recordedPage.finalContentSize) bytes")
                    self.completeWithSuccess(recordedPage)
                }
            }
        }
        
        private func processExtractedContent(_ jsonString: String, webView: WKWebView) {
            // Parse the extracted JSON data
            if let data = jsonString.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                
                let finalHTML = json["html"] as? String ?? initialHTML
                let finalText = json["text"] as? String ?? ""
                let jsData = jsonString
                
                let recordedPage = RecordedPage(
                    url: url,
                    pageName: extractPageName(url),
                    initialHTMLContent: initialHTML,
                    finalHTMLContent: finalHTML,
                    finalTextContent: finalText,
                    javascriptData: jsData,
                    loadingTime: Date().timeIntervalSince(startTime),
                    finalContentSize: finalHTML.count + finalText.count,
                    hasDeviceData: finalHTML.contains("device") || finalHTML.contains("client") || finalHTML.contains("MAC") || finalText.contains("IP"),
                    hasWirelessData: finalHTML.contains("SSID") || finalHTML.contains("wireless") || finalHTML.contains("WiFi"),
                    hasSystemData: finalHTML.contains("system") || finalHTML.contains("model") || finalHTML.contains("version"),
                    recordedAt: Date()
                )
                
                completeWithSuccess(recordedPage)
            } else {
                fallbackContentExtraction(webView: webView)
            }
        }
        
        private func completeWithSuccess(_ recordedPage: RecordedPage) {
            guard !hasCompleted else { return }
            hasCompleted = true
            completion(recordedPage)
        }
        
        private func completeWithFailure() {
            guard !hasCompleted else { return }
            hasCompleted = true
            completion(nil)
        }
        
        private func extractPageName(_ url: String) -> String {
            if let lastComponent = url.split(separator: "/").last {
                return String(lastComponent)
            }
            return "Unknown"
        }
    }

    // MARK: - Data Processing
    private func processAPIResponse(endpoint: String, response: String) async {
        // Process JSON data from working APIs
        if let data = response.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) {
            
            if let dict = json as? [String: Any] {
                await extractDataFromJSON(dict, source: endpoint)
            }
        }
    }
    
    private func extractDataFromJSON(_ json: [String: Any], source: String) async {
        // Look for device/client data in various formats
        let deviceKeys = ["devices", "clients", "dhcp_clients", "connected_devices", "device_list", "lan_clients"]
        
        for key in deviceKeys {
            if let deviceArray = json[key] as? [[String: Any]] {
                for deviceData in deviceArray {
                    if let device = createDeviceFromJSON(deviceData, source: source) {
                        addLog("📱 Found device from \(source): \(device.name) - \(device.ipAddress)")
                    }
                }
            }
        }
        
        // Look for system information
        if let systemInfo = json["system_info"] as? [[String: Any]] {
            for info in systemInfo {
                if let param = info["param"] as? String,
                   let value = info["value"] as? String {
                    addLog("🔧 System info from \(source): \(param) = \(value)")
                }
            }
        }
    }
    
    private func extractDataFromRecordedPage(_ page: RecordedPage) async {
        addLog("🔍 Analyzing recorded page: \(page.pageName)")
        
        // Extract devices from final content
        let devices = extractDevicesFromHTML(page.finalHTMLContent)
        for device in devices {
            addLog("📱 Found device in \(page.pageName): \(device.name) - \(device.ipAddress)")
        }
        
        // Extract wireless info
        let wirelessNetworks = extractWirelessFromHTML(page.finalHTMLContent)
        for network in wirelessNetworks {
            addLog("📶 Found wireless in \(page.pageName): \(network.ssid)")
        }
        
        // Extract system info
        let systemInfo = extractSystemInfoFromHTML(page.finalHTMLContent)
        for info in systemInfo {
            addLog("🔧 Found system info in \(page.pageName): \(info.parameter) = \(info.value)")
        }
    }
    
    private func analyzeRecordedContent() async {
        addLog("🔍 === ANALYZING ALL RECORDED CONTENT ===")
        
        var allDevices: [ExtractedDevice] = []
        var allWirelessNetworks: [ExtractedWirelessNetwork] = []
        var allSystemInfo: [ExtractedSystemInfo] = []
        
        for page in recordedPages {
            allDevices.append(contentsOf: extractDevicesFromHTML(page.finalHTMLContent))
            allWirelessNetworks.append(contentsOf: extractWirelessFromHTML(page.finalHTMLContent))
            allSystemInfo.append(contentsOf: extractSystemInfoFromHTML(page.finalHTMLContent))
        }
        
        // Remove duplicates and consolidate
        let uniqueDevices = removeDuplicateDevices(allDevices)
        let uniqueWireless = removeDuplicateWireless(allWirelessNetworks)
        let consolidatedSystemInfo = consolidateSystemInfo(allSystemInfo)
        
        await MainActor.run {
            self.extractedData = ExtractedRouterData(
                devices: uniqueDevices,
                wirelessNetworks: uniqueWireless,
                systemInfo: consolidatedSystemInfo,
                extractedAt: Date(),
                totalPagesScanned: self.recordedPages.count
            )
        }
        
        addLog("📊 FINAL RESULTS:")
        addLog("   📱 Devices: \(uniqueDevices.count)")
        addLog("   📶 Wireless Networks: \(uniqueWireless.count)")
        addLog("   🔧 System Info: \(consolidatedSystemInfo.count)")
    }
    
    // MARK: - Data Extraction Methods
    private func extractDevicesFromHTML(_ html: String) -> [ExtractedDevice] {
        var devices: [ExtractedDevice] = []
        
        // Look for device tables and patterns
        let devicePatterns = [
            // Table row with name, IP, MAC
            #"<tr[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>.*?<td[^>]*>([0-9A-Fa-f:]{17})</td>.*?</tr>"#,
            // JSON-like device data
            #""name"\s*:\s*"([^"]+)".*?"ip"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})".*?"mac"\s*:\s*"([0-9A-Fa-f:]{17})""#,
            // Angular ng-repeat patterns
            #"ng-repeat[^>]*device[^>]*>.*?([^<]+).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?([0-9A-Fa-f:]{17})"#
        ]
        
        for pattern in devicePatterns {
            let matches = findMatches(in: html, pattern: pattern, groups: 3)
            for match in matches {
                if match.count >= 3 {
                    let name = match[0].trimmingCharacters(in: .whitespacesAndNewlines)
                    let ip = match[1]
                    let mac = match[2]
                    
                    if isValidIPAddress(ip) && isValidMACAddress(mac) {
                        devices.append(ExtractedDevice(
                            name: name.isEmpty ? "Device-\(ip)" : name,
                            ipAddress: ip,
                            macAddress: mac,
                            deviceType: "Unknown",
                            isOnline: true,
                            source: "HTML"
                        ))
                    }
                }
            }
        }
        
        return devices
    }
    
    private func extractWirelessFromHTML(_ html: String) -> [ExtractedWirelessNetwork] {
        var networks: [ExtractedWirelessNetwork] = []
        
        let wirelessPatterns = [
            #"ssid[^>]*>([^<]+)<"#,
            #""ssid"\s*:\s*"([^"]+)""#,
            #"network.*?name[^>]*>([^<]+)<"#
        ]
        
        for pattern in wirelessPatterns {
            let matches = findMatches(in: html, pattern: pattern, groups: 1)
            for match in matches {
                if !match.isEmpty {
                    let ssid = match[0].trimmingCharacters(in: .whitespacesAndNewlines)
                    if ssid.count >= 2 && ssid.count <= 32 {
                        networks.append(ExtractedWirelessNetwork(
                            ssid: ssid,
                            band: "Unknown",
                            security: "Unknown",
                            isEnabled: true,
                            source: "HTML"
                        ))
                    }
                }
            }
        }
        
        return networks
    }
    
    private func extractSystemInfoFromHTML(_ html: String) -> [ExtractedSystemInfo] {
        var systemInfo: [ExtractedSystemInfo] = []
        
        let systemPatterns = [
            #"<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>"#,
            #""([^"]+)"\s*:\s*"([^"]+)""#
        ]
        
        for pattern in systemPatterns {
            let matches = findMatches(in: html, pattern: pattern, groups: 2)
            for match in matches {
                if match.count >= 2 {
                    let param = match[0].trimmingCharacters(in: .whitespacesAndNewlines)
                    let value = match[1].trimmingCharacters(in: .whitespacesAndNewlines)
                    
                    if param.count > 2 && value.count > 0 {
                        systemInfo.append(ExtractedSystemInfo(
                            parameter: param,
                            value: value,
                            source: "HTML"
                        ))
                    }
                }
            }
        }
        
        return systemInfo
    }
    
    // MARK: - Helper Methods
    private func callRouterAPI(endpoint: String, postData: String?, method: String = "POST") async -> Data? {
        let fullURL = endpoint.isEmpty ? baseURL : "\(baseURL)/\(endpoint)"
        
        guard let url = URL(string: fullURL) else {
            return nil
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 15
        
        // Add authentication headers
        for (key, value) in authHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        // Add standard headers
        request.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15", forHTTPHeaderField: "User-Agent")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue(baseURL, forHTTPHeaderField: "Origin")
        request.setValue(baseURL, forHTTPHeaderField: "Referer")
        
        if method == "POST" {
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            if let postData = postData {
                request.httpBody = postData.data(using: .utf8)
            }
        }
        
        // Add cookies
        if !authCookies.isEmpty {
            let cookieHeaders = HTTPCookie.requestHeaderFields(with: authCookies)
            for (key, value) in cookieHeaders {
                request.setValue(value, forHTTPHeaderField: key)
            }
        }
        
        do {
            let (data, response) = try await urlSession.data(for: request)
            
            if let httpResponse = response as? HTTPURLResponse,
               httpResponse.statusCode == 200 {
                return data
            }
        } catch {
            // Continue with other requests
        }
        
        return nil
    }
    
    private func findMatches(in text: String, pattern: String, groups: Int) -> [[String]] {
        var results: [[String]] = []
        
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive, .dotMatchesLineSeparators])
            let matches = regex.matches(in: text, range: NSRange(location: 0, length: text.count))
            
            for match in matches {
                var matchGroup: [String] = []
                for i in 1...groups {
                    if i < match.numberOfRanges,
                       let range = Range(match.range(at: i), in: text) {
                        matchGroup.append(String(text[range]))
                    }
                }
                if !matchGroup.isEmpty {
                    results.append(matchGroup)
                }
            }
        } catch {
            return []
        }
        
        return results
    }
    
    private func extractPageName(_ url: String) -> String {
        if let lastComponent = url.split(separator: "/").last {
            return String(lastComponent)
        }
        return "Unknown"
    }
    
    private func createDeviceFromJSON(_ json: [String: Any], source: String) -> ExtractedDevice? {
        // Implementation similar to previous versions
        return nil
    }
    
    private func isValidIPAddress(_ ip: String) -> Bool {
        let parts = ip.components(separatedBy: ".")
        guard parts.count == 4 else { return false }
        
        for part in parts {
            guard let num = Int(part), num >= 0 && num <= 255 else { return false }
        }
        
        return true
    }
    
    private func isValidMACAddress(_ mac: String) -> Bool {
        let pattern = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        do {
            let regex = try NSRegularExpression(pattern: pattern)
            return regex.firstMatch(in: mac, range: NSRange(location: 0, length: mac.count)) != nil
        } catch {
            return false
        }
    }
    
    private func removeDuplicateDevices(_ devices: [ExtractedDevice]) -> [ExtractedDevice] {
        var uniqueDevices: [ExtractedDevice] = []
        var seenMACs: Set<String> = []
        
        for device in devices {
            if !seenMACs.contains(device.macAddress) {
                seenMACs.insert(device.macAddress)
                uniqueDevices.append(device)
            }
        }
        
        return uniqueDevices
    }
    
    private func removeDuplicateWireless(_ networks: [ExtractedWirelessNetwork]) -> [ExtractedWirelessNetwork] {
        var uniqueNetworks: [ExtractedWirelessNetwork] = []
        var seenSSIDs: Set<String> = []
        
        for network in networks {
            if !seenSSIDs.contains(network.ssid) {
                seenSSIDs.insert(network.ssid)
                uniqueNetworks.append(network)
            }
        }
        
        return uniqueNetworks
    }
    
    private func consolidateSystemInfo(_ info: [ExtractedSystemInfo]) -> [ExtractedSystemInfo] {
        var consolidatedInfo: [ExtractedSystemInfo] = []
        var seenParameters: Set<String> = []
        
        for item in info {
            if !seenParameters.contains(item.parameter) {
                seenParameters.insert(item.parameter)
                consolidatedInfo.append(item)
            }
        }
        
        return consolidatedInfo
    }
    
    private func addLog(_ message: String) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let logEntry = "[\(timestamp)] \(message)"
        
        DispatchQueue.main.async {
            self.debugLogs.append(logEntry)
            if self.debugLogs.count > 500 {
                self.debugLogs.removeFirst()
            }
        }
        
        print(logEntry)
    }
    
}

// MARK: - Data Models
struct RecordedPage: Identifiable {
    let id = UUID()
    let url: String
    let pageName: String
    let initialHTMLContent: String
    let finalHTMLContent: String
    let finalTextContent: String
    let javascriptData: String
    let loadingTime: TimeInterval
    let finalContentSize: Int
    let hasDeviceData: Bool
    let hasWirelessData: Bool
    let hasSystemData: Bool
    let recordedAt: Date
}

struct ExtractedRouterData {
    let devices: [ExtractedDevice]
    let wirelessNetworks: [ExtractedWirelessNetwork]
    let systemInfo: [ExtractedSystemInfo]
    let extractedAt: Date
    let totalPagesScanned: Int
}

struct ExtractedDevice: Identifiable {
    let id = UUID()
    let name: String
    let ipAddress: String
    let macAddress: String
    let deviceType: String
    let isOnline: Bool
    let source: String
}

struct ExtractedWirelessNetwork: Identifiable {
    let id = UUID()
    let ssid: String
    let band: String
    let security: String
    let isEnabled: Bool
    let source: String
}

struct ExtractedSystemInfo: Identifiable {
    let id = UUID()
    let parameter: String
    let value: String
    let source: String
}

// MARK: - Enhanced Session Delegate for SSL Bypass
class WebScannerSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        print("🔒 SSL Challenge: \(challenge.protectionSpace.authenticationMethod)")
        print("🔒 Host: \(challenge.protectionSpace.host)")
        
        // Handle server trust (SSL certificate) challenges
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                print("✅ Bypassing SSL certificate validation for router")
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
                return
            }
        }
        
        // Handle client certificate challenges
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            print("⚠️ Client certificate challenge - performing default handling")
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // Handle HTTP basic/digest authentication
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPBasic ||
           challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPDigest {
            print("🔑 HTTP authentication challenge")
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // For any other authentication method, try to use credential or perform default handling
        if let serverTrust = challenge.protectionSpace.serverTrust {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
    
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        print("🔄 HTTP Redirect: \(response.statusCode) -> \(request.url?.absoluteString ?? "unknown")")
        completionHandler(request)
    }
}

// MARK: - Enhanced SSL Bypass for Complete SPA Scanner
class SSLBypassSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        print("🔒 SPA Scanner SSL Challenge: \(challenge.protectionSpace.authenticationMethod)")
        
        // Handle server trust (SSL certificate) challenges
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                print("✅ SPA Scanner: Bypassing SSL certificate validation for router")
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
                return
            }
        }
        
        // Handle client certificate challenges
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            print("⚠️ SPA Scanner: Client certificate challenge - performing default handling")
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // Handle HTTP basic/digest authentication
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPBasic ||
           challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPDigest {
            print("🔑 SPA Scanner: HTTP authentication challenge")
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // For any other authentication method, try to use credential or perform default handling
        if let serverTrust = challenge.protectionSpace.serverTrust {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
    
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        print("🔄 SPA Scanner HTTP Redirect: \(response.statusCode) -> \(request.url?.absoluteString ?? "unknown")")
        completionHandler(request)
    }
}

// MARK: - WebView Delegate for SPA Scanning
class WebViewScanDelegate: NSObject, WKNavigationDelegate {
    private let completion: (String) -> Void
    private var hasCompleted = false
    
    init(completion: @escaping (String) -> Void) {
        self.completion = completion
        super.init()
    }
    
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard !hasCompleted else { return }
        
        // Wait for Angular/React to load
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            self.extractFinalContent(from: webView)
        }
    }
    
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
                return
            }
        }
        completionHandler(.performDefaultHandling, nil)
    }
    
    private func extractFinalContent(from webView: WKWebView) {
        guard !hasCompleted else { return }
        hasCompleted = true
        
        // Extract both HTML and evaluate some JavaScript
        let script = """
        (function() {
            var content = {
                html: document.documentElement.outerHTML,
                title: document.title,
                tables: [],
                devices: [],
                data: {}
            };
            
            // Look for data tables
            var tables = document.querySelectorAll('table');
            for (var i = 0; i < tables.length; i++) {
                var table = tables[i];
                if (table.innerText.length > 100) {
                    content.tables.push(table.outerHTML);
                }
            }
            
            // Look for device data in text
            var bodyText = document.body.innerText || '';
            var ipPattern = /\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/g;
            var ips = bodyText.match(ipPattern) || [];
            content.devices = ips;
            
            // Try to access any global router data
            if (window.routerData) content.data.routerData = window.routerData;
            if (window.deviceList) content.data.deviceList = window.deviceList;
            if (window.dhcpClients) content.data.dhcpClients = window.dhcpClients;
            
            return JSON.stringify(content);
        })();
        """
        
        webView.evaluateJavaScript(script) { result, error in
            if let jsonString = result as? String {
                self.completion(jsonString)
            } else {
                // Fallback to just HTML
                webView.evaluateJavaScript("document.documentElement.outerHTML") { htmlResult, _ in
                    self.completion(htmlResult as? String ?? "")
                }
            }
        }
    }
}



// MARK: - Enhanced Router API Manager with FIXED Data Extraction (KEEP YOUR WORKING CODE)
class RouterAPIManager: ObservableObject {
    static let shared = RouterAPIManager()
    
    @Published var isAuthenticated = false
    @Published var currentUser: String?
    @Published var routerInfo: RouterInfo?
    @Published var networkConfig: NetworkConfig?
    @Published var wirelessConfig: WirelessConfig?
    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var lastUpdateTime: Date?
    @Published var authenticationProgress: String = ""
    @Published var showGuidedAuth = false
    @Published var debugMode = false
    @Published var debugLogs: [String] = []
    
    private var authenticationHeaders: [String: String] = [:]
    private var authenticationCookies: [HTTPCookie] = []
    private let configManager = SecureConfigurationManager.shared
    var currentUsername: String?
    
    private var baseURL: String {
        return "https://\(configManager.routerIP)"
    }
    
    private let urlSession: URLSession
    
    private init() {
        let config = URLSessionConfiguration.default
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        
        self.urlSession = URLSession(
            configuration: config,
            delegate: RouterSessionDelegate(),
            delegateQueue: nil
        )
    }
    func addDebugLog(_ message: String) {
        guard debugMode else { return }
        
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let logEntry = "[\(timestamp)] \(message)"
        
        DispatchQueue.main.async {
            self.debugLogs.append(logEntry)
            if self.debugLogs.count > 100 {
                self.debugLogs.removeFirst()
            }
        }
    }
    
    // MARK: - Authentication (KEEP AS IS - IT WORKS)
    func authenticateWithRouter(username: String, password: String) async -> Bool {
        print("🔐 Starting authentication with session extraction for: \(username)")
        currentUsername = username
        
        await MainActor.run {
            isLoading = true
            errorMessage = nil
            authenticationProgress = "Connecting to router..."
        }
        
        // Step 1: Verify credentials
        let credentialsValid = await verifyCredentials(username: username, password: password)
        if !credentialsValid {
            await MainActor.run {
                isLoading = false
                errorMessage = "Invalid username or password"
            }
            return false
        }
        
        await MainActor.run {
            authenticationProgress = "Extracting authentication session..."
        }
        
        // Step 2: Get authenticated session from WebView
        let sessionExtracted = await extractAuthenticatedSession(username: username, password: password)
        
        if sessionExtracted {
            await MainActor.run {
                isAuthenticated = true
                currentUser = username
                authenticationProgress = "Session extracted successfully!"
            }
            // Add this after successful session extraction
            CompleteSPAScanner.shared.setAuthenticationData(
                cookies: authenticationCookies,
                headers: authenticationHeaders
            )
            _ = KeychainManager.shared.storePassword(password, for: username)
            
            // NEW: Pass authentication data to web scanner
            GigaSpireWebScanner.shared.setAuthenticationData(
                cookies: authenticationCookies,
                headers: authenticationHeaders
            )
            
            // Step 3: Load router data using FIXED extraction methods
            await loadAllRouterDataWithFixedExtraction()
        } else {
            await MainActor.run {
                errorMessage = "Could not extract authentication session. Try browser login."
            }
        }
        
        await MainActor.run {
            isLoading = false
        }
        
        return sessionExtracted
    }
    
    private func verifyCredentials(username: String, password: String) async -> Bool {
        print("🔐 Verifying credentials with router...")
        
        guard let url = URL(string: "\(baseURL)/login.cgi") else { return false }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15", forHTTPHeaderField: "User-Agent")
        
        let loginData = "username=\(username)&password=\(password)"
        request.httpBody = loginData.data(using: .utf8)
        
        do {
            let (_, response) = try await urlSession.data(for: request)
            
            if let httpResponse = response as? HTTPURLResponse {
                print("🔐 Credential verification response: \(httpResponse.statusCode)")
                return httpResponse.statusCode == 204
            }
        } catch {
            print("⚠️ Credential verification error: \(error.localizedDescription)")
        }
        
        return false
    }
    
    private func extractAuthenticatedSession(username: String, password: String) async -> Bool {
        print("🔍 Extracting authenticated session from WebView...")
        
        return await withCheckedContinuation { continuation in
            DispatchQueue.main.async {
                let webViewAuth = SessionExtractionAuthenticator(
                    username: username,
                    password: password,
                    onSuccess: { headers, cookies in
                        print("✅ Session extracted successfully")
                        print("📋 Headers: \(headers.keys.joined(separator: ", "))")
                        print("🍪 Cookies: \(cookies.count) cookies")
                        
                        self.authenticationHeaders = headers
                        self.authenticationCookies = cookies
                        continuation.resume(returning: true)
                    },
                    onFailure: { error in
                        print("❌ Session extraction failed: \(error)")
                        continuation.resume(returning: false)
                    }
                )
                
                webViewAuth.startAuthentication()
            }
        }
    }
    
    
    // MARK: - System Info Loading (KEEP AS IS - IT WORKS)
    private func loadRealSystemInfo() async -> RouterInfo? {
        print("🔍 === LOADING REAL SYSTEM INFO ===")
        
        let systemEndpoints = ["status_system.cmd", "system_info.cmd", "cgi_parameter_value.cmd", "board_capabilities.cmd"]
        
        for endpoint in systemEndpoints {
            var postData = "{}"
            if endpoint.contains("parameter_value") {
                postData = "ejGetOtherVal=sysInfo.modelNumber%2CsysInfo.firmwareVersion%2CsysInfo.uptime&action=get"
            }
            
            if let data = await callRouterAPI(endpoint: endpoint, postData: postData) {
                let html = String(data: data, encoding: .utf8) ?? ""
                
                if let parsed = parseRealCalixSystemData(html: html, endpoint: endpoint) {
                    print("✅ Successfully extracted REAL system data from \(endpoint)")
                    return parsed
                }
            }
        }
        
        return nil
    }
    
    // MARK: - Network Info Loading (KEEP AS IS - IT WORKS)
    private func loadRealNetworkInfo() async -> NetworkConfig? {
        print("🔍 === LOADING REAL NETWORK INFO ===")
        
        let networkEndpoints = ["network_status.cmd", "status_connection.cmd", "board_capabilities.cmd"]
        
        for endpoint in networkEndpoints {
            let postData = endpoint.contains("status") ? "action=getStatus" : "{}"
            
            if let data = await callRouterAPI(endpoint: endpoint, postData: postData) {
                let html = String(data: data, encoding: .utf8) ?? ""
                
                if let parsed = parseRealCalixNetworkData(html: html, endpoint: endpoint) {
                    print("✅ Successfully extracted REAL network data from \(endpoint)")
                    return parsed
                }
            }
        }
        
        return nil
    }
    
    // MARK: - Wireless Info Loading (KEEP AS IS - IT WORKS)
    private func loadRealWirelessInfo() async -> WirelessConfig? {
        print("🔍 === LOADING REAL WIRELESS INFO ===")
        
        let wirelessEndpoints = ["board_capabilities.cmd", "wlinfo.cmd", "wireless_status.cmd"]
        
        for endpoint in wirelessEndpoints {
            let postData = endpoint.contains("wlinfo") ? "action=get" : "{}"
            
            if let data = await callRouterAPI(endpoint: endpoint, postData: postData) {
                let html = String(data: data, encoding: .utf8) ?? ""
                
                if let parsed = parseRealCalixWirelessData(html: html, endpoint: endpoint) {
                    print("✅ Successfully extracted REAL wireless data from \(endpoint)")
                    return parsed
                }
            }
        }
        
        return nil
    }

    private func extractDevicesFromDeviceTableJSON(_ json: [String: Any], source: String) -> [DHCPClient] {
        var devices: [DHCPClient] = []
        
        // Common keys that might contain device arrays in Calix routers
        let deviceArrayKeys = [
            "devices", "clients", "dhcp_clients", "connected_devices", "lan_clients",
            "device_list", "client_list", "host_list", "stations", "endpoints",
            "network_devices", "dhcp_leases", "active_clients", "online_devices",
            "ethernet_clients", "wireless_clients", "all_devices", "device_table"
        ]
        
        for key in deviceArrayKeys {
            if let deviceArray = json[key] as? [[String: Any]] {
                addDebugLog("📋 Found device array '\(key)' with \(deviceArray.count) items")
                
                for deviceJson in deviceArray {
                    if let device = createDHCPClientFromJSON(deviceJson, source: "\(source).\(key)") {
                        devices.append(device)
                    }
                }
                break // Found devices, don't process other keys
            }
        }
        
        // Also check for nested structures
        for (key, value) in json {
            if let nestedDict = value as? [String: Any] {
                devices.append(contentsOf: extractDevicesFromDeviceTableJSON(nestedDict, source: "\(source).\(key)"))
            }
        }
        
        return devices
    }

    private func parseDeviceTableHTML(_ html: String, source: String) -> [DHCPClient] {
        var devices: [DHCPClient] = []
        
        addDebugLog("🔍 Parsing HTML/text content for device data...")
        
        // Enhanced patterns for Calix device tables
        let devicePatterns = [
            // Standard table row with device info
            #"<tr[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})</td>.*?<td[^>]*>([0-9A-Fa-f:]{17})</td>.*?</tr>"#,
            
            // Table with MAC first, then IP
            #"<tr[^>]*>.*?<td[^>]*>([0-9A-Fa-f:]{17})</td>.*?<td[^>]*>([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})</td>.*?<td[^>]*>([^<]+)</td>.*?</tr>"#,
            
            // Div-based layout
            #"<div[^>]*device[^>]*>.*?([^<]+).*?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*?([0-9A-Fa-f:]{17})"#,
            
            // JSON-like patterns in HTML
            #"hostname['""]?\s*:\s*['""']([^'""]+)['""'].*?ip['""]?\s*:\s*['""']([0-9\.]+)['""'].*?mac['""]?\s*:\s*['""']([0-9A-Fa-f:]+)['""']"#,
            
            # Line-based parsing (common in router outputs)
            #"([^\n\r]+)\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9A-Fa-f:]{17})"#
        ]
        
        for (index, pattern) in devicePatterns.enumerated() {
            addDebugLog("🔍 Trying pattern \(index + 1)...")
            
            do {
                let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive, .dotMatchesLineSeparators])
                let matches = regex.matches(in: html, range: NSRange(location: 0, length: html.count))
                
                addDebugLog("📊 Pattern \(index + 1) found \(matches.count) matches")
                
                for match in matches {
                    if match.numberOfRanges >= 4 {
                        var name = ""
                        var ip = ""
                        var mac = ""
                        
                        // Extract the three capture groups
                        for i in 1...3 {
                            if let range = Range(match.range(at: i), in: html) {
                                let value = String(html[range]).trimmingCharacters(in: .whitespacesAndNewlines)
                                
                                if isValidIPAddress(value) {
                                    ip = value
                                } else if isValidMACAddress(value) {
                                    mac = value
                                } else if !value.isEmpty && value.count >= 2 {
                                    name = value
                                }
                            }
                        }
                        
                        // Create device if we have required info
                        if !ip.isEmpty && !mac.isEmpty {
                            let device = DHCPClient(
                                deviceName: name.isEmpty ? "Device-\(ip.split(separator: ".").last ?? "Unknown")" : name,
                                ipAddress: ip,
                                macAddress: mac,
                                leaseTime: "Unknown",
                                deviceType: "Unknown"
                            )
                            devices.append(device)
                            addDebugLog("✅ Created device: \(device.deviceName) - \(device.ipAddress)")
                        }
                    }
                }
                
                if !devices.isEmpty {
                    addDebugLog("✅ Pattern \(index + 1) successfully found \(devices.count) devices")
                    break // Found devices with this pattern, stop trying others
                }
                
            } catch {
                addDebugLog("❌ Pattern \(index + 1) regex error: \(error)")
            }
        }
        
        // If no devices found with patterns, try simpler IP and MAC extraction
        if devices.isEmpty {
            addDebugLog("🔍 No devices found with patterns, trying simple extraction...")
            devices.append(contentsOf: extractDevicesFromSimplePatterns(html, source: source))
        }
        
        return devices
    }

    private func extractDevicesFromSimplePatterns(_ text: String, source: String) -> [DHCPClient] {
        var devices: [DHCPClient] = []
        
        // Find all IP addresses
        let ipPattern = #"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"#
        let ipAddresses = findAllMatches(in: text, pattern: ipPattern)
        
        // Find all MAC addresses
        let macPattern = #"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"#
        let macAddresses = findAllMatches(in: text, pattern: macPattern)
        
        addDebugLog("📊 Found \(ipAddresses.count) IP addresses and \(macAddresses.count) MAC addresses")
        
        // Try to pair IPs with MACs
        let validIPs = ipAddresses.filter { ip in
            let parts = ip.components(separatedBy: ".")
            if parts.count == 4,
               let lastOctet = Int(parts[3]),
               lastOctet > 1 && lastOctet < 255 {
                return !["0.0.0.0", "255.255.255.255", "127.0.0.1"].contains(ip)
            }
            return false
        }
        
        // Create devices by pairing IPs and MACs
        let maxDevices = min(validIPs.count, macAddresses.count)
        for i in 0..<maxDevices {
            let device = DHCPClient(
                deviceName: "Device-\(validIPs[i].split(separator: ".").last ?? "Unknown")",
                ipAddress: validIPs[i],
                macAddress: macAddresses[i],
                leaseTime: "Unknown",
                deviceType: "Unknown"
            )
            devices.append(device)
            addDebugLog("✅ Paired device: \(device.deviceName) - \(device.ipAddress) - \(device.macAddress)")
        }
        
        return devices
    }

    // MARK: - STEP 1: Add these methods to RouterAPIManager class
    // Find your RouterAPIManager class and add these methods before the closing brace

    // STEP 1A: Add the helper method for finding matches
    private func findAllMatches(in text: String, pattern: String) -> [String] {
        var matches: [String] = []
        
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
            let results = regex.matches(in: text, range: NSRange(location: 0, length: text.count))
            
            for result in results {
                if let range = Range(result.range, in: text) {
                    matches.append(String(text[range]))
                }
            }
        } catch {
            // Ignore regex errors
        }
        
        return Array(Set(matches)) // Remove duplicates
    }

    // STEP 1B: Add the device table parser
    private func parseDeviceTableResponse(_ response: String, source: String) -> [DHCPClient] {
        addDebugLog("🔍 === PARSING DEVICE TABLE ===")
        addDebugLog("📊 Response length: \(response.count)")
        
        var clients: [DHCPClient] = []
        
        // Try JSON parsing first
        if response.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") ||
           response.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("[") {
            
            addDebugLog("📋 Attempting JSON parsing...")
            
            if let data = response.data(using: .utf8) {
                do {
                    let json = try JSONSerialization.jsonObject(with: data)
                    
                    if let jsonDict = json as? [String: Any] {
                        addDebugLog("✅ Found JSON dictionary")
                        clients.append(contentsOf: extractDevicesFromJSON(jsonDict, source: source))
                        
                    } else if let jsonArray = json as? [[String: Any]] {
                        addDebugLog("✅ Found JSON array with \(jsonArray.count) items")
                        for item in jsonArray {
                            clients.append(contentsOf: extractDevicesFromJSON(item, source: source))
                        }
                    }
                    
                } catch {
                    addDebugLog("❌ JSON parsing failed: \(error)")
                    // Fall back to text parsing
                    clients.append(contentsOf: parseDeviceTableText(response, source: source))
                }
            }
        } else {
            addDebugLog("📄 Attempting text parsing...")
            clients.append(contentsOf: parseDeviceTableText(response, source: source))
        }
        
        addDebugLog("🎯 Found \(clients.count) devices from \(source)")
        return clients
    }

    // STEP 1C: Add the JSON extraction method
    private func extractDevicesFromJSON(_ json: [String: Any], source: String) -> [DHCPClient] {
        var devices: [DHCPClient] = []
        
        // Look for device arrays with common key names
        let deviceKeys = ["devices", "clients", "dhcp_clients", "connected_devices", "device_list"]
        
        for key in deviceKeys {
            if let deviceArray = json[key] as? [[String: Any]] {
                addDebugLog("📋 Found device array '\(key)' with \(deviceArray.count) items")
                
                for deviceJson in deviceArray {
                    if let device = createDeviceFromJSONData(deviceJson, source: source) {
                        devices.append(device)
                    }
                }
                break
            }
        }
        
        return devices
    }

    // STEP 1D: Add the text parsing method
    private func parseDeviceTableText(_ text: String, source: String) -> [DHCPClient] {
        var devices: [DHCPClient] = []
        
        // Find all IP addresses
        let ipAddresses = findAllMatches(in: text, pattern: #"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"#)
        
        // Find all MAC addresses
        let macAddresses = findAllMatches(in: text, pattern: #"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"#)
        
        addDebugLog("📊 Found \(ipAddresses.count) IPs and \(macAddresses.count) MACs")
        
        // Filter valid IPs (exclude common non-device IPs)
        let validIPs = ipAddresses.filter { ip in
            !["0.0.0.0", "255.255.255.255", "127.0.0.1", "192.168.1.1"].contains(ip)
        }
        
        // Create devices by pairing IPs and MACs
        let deviceCount = min(validIPs.count, macAddresses.count)
        for i in 0..<deviceCount {
            let device = DHCPClient(
                deviceName: "Device-\(validIPs[i].split(separator: ".").last ?? "Unknown")",
                ipAddress: validIPs[i],
                macAddress: macAddresses[i],
                leaseTime: "Unknown",
                deviceType: "Unknown"
            )
            devices.append(device)
            addDebugLog("✅ Created device: \(device.deviceName) - \(device.ipAddress)")
        }
        
        return devices
    }

    // STEP 1E: Add the JSON device creation method
    private func createDeviceFromJSONData(_ json: [String: Any], source: String) -> DHCPClient? {
        // Look for name fields
        let nameFields = ["hostname", "name", "device_name", "deviceName", "host"]
        var name: String?
        
        for field in nameFields {
            if let value = json[field] as? String, !value.isEmpty {
                name = value
                break
            }
        }
        
        // Look for IP fields
        let ipFields = ["ip", "ip_address", "ipAddress", "address"]
        var ip: String?
        
        for field in ipFields {
            if let value = json[field] as? String, !value.isEmpty, isValidIPAddress(value) {
                ip = value
                break
            }
        }
        
        // Look for MAC fields
        let macFields = ["mac", "mac_address", "macAddress", "hwaddr"]
        var mac: String?
        
        for field in macFields {
            if let value = json[field] as? String, !value.isEmpty, isValidMACAddress(value) {
                mac = value
                break
            }
        }
        
        // Create device if we have required info
        if let ip = ip, let mac = mac {
            return DHCPClient(
                deviceName: name ?? "Device-\(ip.split(separator: ".").last ?? "Unknown")",
                ipAddress: ip,
                macAddress: mac,
                leaseTime: "Unknown",
                deviceType: "Unknown"
            )
        }
        
        return nil
    }

    // STEP 1F: Add the test method
    @MainActor
    func testDeviceTableParsing() async {
        addDebugLog("🧪 === TESTING DEVICE TABLE PARSING ===")
        
        if let data = await callRouterAPI(endpoint: "device_table.cmd", postData: "action=get") {
            let response = String(data: data, encoding: .utf8) ?? ""
            addDebugLog("📊 device_table.cmd response: \(response.count) bytes")
            
            if response.count > 100 {
                // Show first 200 characters
                let preview = String(response.prefix(200))
                addDebugLog("📋 Response preview: \(preview)")
                
                // Parse and show results
                let clients = parseDeviceTableResponse(response, source: "device_table.cmd")
                addDebugLog("🎯 PARSING RESULTS: Found \(clients.count) devices")
                
                for client in clients {
                    addDebugLog("   📱 \(client.deviceName) - \(client.ipAddress) - \(client.macAddress)")
                }
            } else {
                addDebugLog("❌ Response too small: \(response)")
            }
        } else {
            addDebugLog("❌ Failed to get device_table.cmd response")
        }
    }

    private func extractRealDHCPClients() async {
        print("🔍 === EXTRACTING REAL DHCP CLIENTS ===")
        addDebugLog("🔍 Starting real DHCP client extraction...")
        
        var allFoundClients: [DHCPClient] = []
        
        // PRIORITY: Try device_table.cmd first
        addDebugLog("🎯 PRIORITY: Trying device_table.cmd")
        
        if let data = await callRouterAPI(endpoint: "device_table.cmd", postData: "action=get") {
            let response = String(data: data, encoding: .utf8) ?? ""
            addDebugLog("📊 device_table.cmd response: \(response.count) bytes")
            
            if response.count > 1000 {
                let clients = parseDeviceTableResponse(response, source: "device_table.cmd")
                allFoundClients.append(contentsOf: clients)
                addDebugLog("✅ device_table.cmd found \(clients.count) clients")
            }
        }
        
        // If no devices found, try other endpoints
        if allFoundClients.isEmpty {
            addDebugLog("🔄 Trying other endpoints...")
            
            let endpoints = [
                ("dhcp_clients.cmd", "action=get"),
                ("client_list.cmd", "action=get"),
                ("hosts.cmd", "action=get")
            ]
            
            for (endpoint, params) in endpoints {
                if let data = await callRouterAPI(endpoint: endpoint, postData: params) {
                    let response = String(data: data, encoding: .utf8) ?? ""
                    if response.count > 50 {
                        let clients = parseDeviceTableResponse(response, source: endpoint)
                        allFoundClients.append(contentsOf: clients)
                        addDebugLog("✅ Found \(clients.count) clients from \(endpoint)")
                    }
                }
            }
        }
        
        // Remove duplicates and update
        let uniqueClients = removeDuplicateDevices(allFoundClients)
        
        if !uniqueClients.isEmpty {
            await updateNetworkConfigWithDHCPClients(uniqueClients)
            addDebugLog("✅ Updated with \(uniqueClients.count) unique DHCP clients")
        } else {
            addDebugLog("❌ No DHCP clients found")
        }
    }
    /*
    Button("Test Device Parsing") {
        Task {
            await apiManager.testDeviceTableParsing()
        }
    }
    .foregroundColor(.green)
    .fontWeight(.semibold)
    */
    private func createDHCPClientFromJSON(_ json: [String: Any], source: String) -> DHCPClient? {
        // Enhanced field mapping for Calix routers
        let nameFields = [
            "hostname", "name", "device_name", "deviceName", "host", "client_name",
            "friendly_name", "alias", "description", "label", "device_alias"
        ]
        
        let ipFields = [
            "ip", "ip_address", "ipAddress", "address", "lan_ip", "local_ip",
            "ipv4", "ipv4_address", "current_ip", "assigned_ip"
        ]
        
        let macFields = [
            "mac", "mac_address", "macAddress", "hwaddr", "hw_addr", "physical_address",
            "ethernet_mac", "hardware_address", "mac_addr"
        ]
        
        var name: String?
        var ip: String?
        var mac: String?
        
        // Extract name
        for field in nameFields {
            if let value = json[field] as? String, !value.isEmpty {
                name = value
                break
            }
        }
        
        // Extract IP
        for field in ipFields {
            if let value = json[field] as? String, !value.isEmpty, isValidIPAddress(value) {
                ip = value
                break
            }
        }
        
        // Extract MAC
        for field in macFields {
            if let value = json[field] as? String, !value.isEmpty, isValidMACAddress(value) {
                mac = value
                break
            }
        }
        
        // Create device if we have required info
        if let ip = ip, let mac = mac {
            return DHCPClient(
                deviceName: name ?? "Device-\(ip.split(separator: ".").last ?? "Unknown")",
                ipAddress: ip,
                macAddress: mac,
                leaseTime: (json["lease_time"] as? String) ?? (json["lease"] as? String) ?? "Unknown",
                deviceType: (json["device_type"] as? String) ?? (json["type"] as? String) ?? "Unknown"
            )
        }
        
        return nil
    }

    
    // MARK: - FIXED: Real Device Count Extraction
    private func extractRealDeviceCount() async {
        print("🔍 === EXTRACTING REAL DEVICE COUNT ===")
        addDebugLog("🔍 Starting real device count extraction...")
        
        var realDeviceCount = 0
        
        // Method 1: Get main page and look for device count
        if let mainPageData = await callRouterAPI(endpoint: "", postData: nil, method: "GET") {
            let mainHtml = String(data: mainPageData, encoding: .utf8) ?? ""
            addDebugLog("📄 Got main page: \(mainHtml.count) bytes")
            
            // Improved device count patterns
            let deviceCountPatterns = [
                "([0-9]+)\\s*devices?\\s*connected",
                "connected\\s*devices?[^0-9]*([0-9]+)",
                "([0-9]+)\\s*connected\\s*devices?",
                "total[^0-9]*([0-9]+)[^0-9]*devices?",
                "([0-9]+)[^0-9]*active\\s*client",
                "([0-9]+)[^0-9]*client.*connected",
                "device.*count[^0-9]*([0-9]+)",
                "([0-9]+)[^0-9]*host.*online"
            ]
            
            for pattern in deviceCountPatterns {
                if let match = extractFirstMatch(from: mainHtml, pattern: pattern) {
                    if let count = Int(match), count > 0 {
                        realDeviceCount = count
                        addDebugLog("✅ Found device count: \(count)")
                        break
                    }
                }
            }
        }
        
        // Method 2: Try status endpoints
        let statusEndpoints = [
            ("device_count.cmd", "action=get"),
            ("connected_devices.cmd", "action=get"),
            ("lan_status.cmd", "action=get_device_count")
        ]
        
        for (endpoint, params) in statusEndpoints {
            if let data = await callRouterAPI(endpoint: endpoint, postData: params) {
                let response = String(data: data, encoding: .utf8) ?? ""
                
                if let deviceCount = extractDeviceCountFromResponse(response) {
                    realDeviceCount = max(realDeviceCount, deviceCount)
                    addDebugLog("✅ Found device count from \(endpoint): \(deviceCount)")
                }
            }
        }
        
        // Update network config with real device count
        if realDeviceCount > 0 {
            await updateNetworkConfigWithDeviceCount(realDeviceCount)
            addDebugLog("✅ Updated device count: \(realDeviceCount)")
        }
    }
    
    // MARK: - FIXED: Real Wireless Data Extraction
    private func extractRealWirelessInfo() async {
        print("🔍 === EXTRACTING REAL WIRELESS INFO ===")
        addDebugLog("🔍 Starting real wireless data extraction...")
        
        var realSSID: String?
        var realSignalStrength: Double?
        
        // Method 1: Try wireless-specific endpoints
        let wirelessEndpoints = [
            ("wireless_info.cmd", "action=get"),
            ("wifi_config.cmd", "action=get"),
            ("ssid_info.cmd", "action=get"),
            ("wl_status.cmd", "action=get")
        ]
        
        for (endpoint, params) in wirelessEndpoints {
            if let data = await callRouterAPI(endpoint: endpoint, postData: params) {
                let response = String(data: data, encoding: .utf8) ?? ""
                
                if response.count > 50 && !response.contains("#ERROR") {
                    addDebugLog("📊 Got wireless response from \(endpoint): \(response.count) bytes")
                    
                    // Extract SSID
                    if realSSID == nil {
                        if let ssid = extractSSIDFromResponse(response) {
                            realSSID = ssid
                            addDebugLog("✅ Found SSID from \(endpoint): \(ssid)")
                        }
                    }
                    
                    // Extract signal strength
                    if realSignalStrength == nil {
                        if let signal = extractSignalStrengthFromResponse(response) {
                            realSignalStrength = signal
                            addDebugLog("✅ Found signal strength: \(signal)%")
                        }
                    }
                }
            }
        }
        
        // Method 2: Get main page and wireless pages
        let pages = ["", "wireless.html", "wifi.html"]
        
        for page in pages {
            if let data = await callRouterAPI(endpoint: page, postData: nil, method: "GET") {
                let html = String(data: data, encoding: .utf8) ?? ""
                
                if html.count > 1000 && !html.contains("login") {
                    // Extract SSID from HTML
                    if realSSID == nil {
                        if let ssid = extractSSIDFromHTML(html) {
                            realSSID = ssid
                            addDebugLog("✅ Found SSID from \(page.isEmpty ? "main page" : page): \(ssid)")
                        }
                    }
                }
            }
        }
        
        // Update wireless config with real data
        if realSSID != nil || realSignalStrength != nil {
            await updateWirelessConfigWithRealData(
                ssid: realSSID,
                signalStrength: realSignalStrength
            )
            addDebugLog("✅ Updated wireless config with real data")
        }
    }
    
    // MARK: - FIXED Helper Methods for Data Extraction
    private func extractDHCPClientsFromResponse(_ response: String, source: String) -> [DHCPClient] {
        var clients: [DHCPClient] = []
        
        // Try JSON parsing first
        if response.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") {
            if let data = response.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                
                let clientKeys = ["dhcp_clients", "clients", "devices", "connected_devices", "lan_clients", "hosts"]
                
                for key in clientKeys {
                    if let clientArray = json[key] as? [[String: Any]] {
                        for client in clientArray {
                            if let device = extractDeviceFromJSON(client) {
                                clients.append(device)
                            }
                        }
                        break
                    }
                }
            }
        }
        
        return clients
    }
    
    private func extractDHCPClientsFromHTML(_ html: String, source: String) -> [DHCPClient] {
        var clients: [DHCPClient] = []
        
        // Look for device table patterns
        let tablePatterns = [
            // Standard table with name, IP, MAC
            "<tr[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})</td>.*?<td[^>]*>([0-9A-Fa-f:]{17})</td>.*?</tr>",
            // Alternative table format
            "<tr[^>]*>.*?([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}).*?([0-9A-Fa-f:]{17}).*?</tr>"
        ]
        
        for pattern in tablePatterns {
            let matches = extractAllMatches(from: html, pattern: pattern)
            for match in matches {
                if match.count >= 2 {
                    let ip = match.count >= 3 ? match[1] : match[0]
                    let mac = match.count >= 3 ? match[2] : match[1]
                    let name = match.count >= 3 ? match[0] : "Device"
                    
                    if isValidIPAddress(ip) && isValidMACAddress(mac) {
                        let client = DHCPClient(
                            deviceName: name.trimmingCharacters(in: .whitespacesAndNewlines),
                            ipAddress: ip,
                            macAddress: mac,
                            leaseTime: "Unknown",
                            deviceType: "Unknown"
                        )
                        clients.append(client)
                    }
                }
            }
        }
        
        return clients
    }
    
    private func extractDeviceCountFromResponse(_ response: String) -> Int? {
        // Look for device count in JSON response
        if response.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") {
            if let data = response.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                
                let countKeys = ["device_count", "connected_devices", "total_devices", "client_count"]
                
                for key in countKeys {
                    if let count = json[key] as? Int {
                        return count
                    }
                }
            }
        }
        
        return nil
    }
    
    private func extractSSIDFromResponse(_ response: String) -> String? {
        // Try JSON first
        if response.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") {
            if let data = response.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                
                if let ssid = json["ssid"] as? String {
                    return ssid
                }
                if let ssid = json["network_name"] as? String {
                    return ssid
                }
            }
        }
        
        // Try text patterns
        return extractFirstMatch(from: response, pattern: "ssid[\"']?[:\\s]*[\"']([^\"'\\n]{2,32})[\"']")
    }
    
    private func extractSSIDFromHTML(_ html: String) -> String? {
        let ssidPatterns = [
            "SSID[\"']?[:\\s]*[\"']([^\"'\\n]{2,32})[\"']",
            "Network[\\s]*Name[\"']?[:\\s]*[\"']([^\"'\\n]{2,32})[\"']",
            "wifi[\\s]*name[\"']?[:\\s]*[\"']([^\"'\\n]{2,32})[\"']"
        ]
        
        for pattern in ssidPatterns {
            if let ssid = extractFirstMatch(from: html, pattern: pattern) {
                return ssid
            }
        }
        
        return nil
    }
    
    private func extractSignalStrengthFromResponse(_ response: String) -> Double? {
        if let signal = extractFirstMatch(from: response, pattern: "signal[^0-9]*([0-9]+)") {
            return Double(signal)
        }
        return nil
    }
    
    // MARK: - Data Update Methods
    private func updateNetworkConfigWithDHCPClients(_ clients: [DHCPClient]) async {
        await MainActor.run {
            if var networkConfig = self.networkConfig {
                self.networkConfig = NetworkConfig(
                    wanStatus: networkConfig.wanStatus,
                    wanIP: networkConfig.wanIP,
                    lanIP: networkConfig.lanIP,
                    ipv6Status: networkConfig.ipv6Status,
                    ipv6IP: networkConfig.ipv6IP,
                    tr069Status: networkConfig.tr069Status,
                    connectedDevices: max(networkConfig.connectedDevices, clients.count),
                    dhcpEnabled: networkConfig.dhcpEnabled,
                    satellites: networkConfig.satellites,
                    dhcpClients: clients,
                    ethPorts: networkConfig.ethPorts,
                    gethPorts: networkConfig.gethPorts,
                    usbPorts: networkConfig.usbPorts,
                    wirelessPorts: networkConfig.wirelessPorts,
                    lastUpdated: Date()
                )
            }
        }
    }
    
    private func updateNetworkConfigWithDeviceCount(_ count: Int) async {
        await MainActor.run {
            if var networkConfig = self.networkConfig {
                self.networkConfig = NetworkConfig(
                    wanStatus: networkConfig.wanStatus,
                    wanIP: networkConfig.wanIP,
                    lanIP: networkConfig.lanIP,
                    ipv6Status: networkConfig.ipv6Status,
                    ipv6IP: networkConfig.ipv6IP,
                    tr069Status: networkConfig.tr069Status,
                    connectedDevices: count,
                    dhcpEnabled: networkConfig.dhcpEnabled,
                    satellites: networkConfig.satellites,
                    dhcpClients: networkConfig.dhcpClients,
                    ethPorts: networkConfig.ethPorts,
                    gethPorts: networkConfig.gethPorts,
                    usbPorts: networkConfig.usbPorts,
                    wirelessPorts: networkConfig.wirelessPorts,
                    lastUpdated: Date()
                )
            }
        }
    }
    
    private func updateWirelessConfigWithRealData(ssid: String?, signalStrength: Double?) async {
        await MainActor.run {
            if var wirelessConfig = self.wirelessConfig {
                self.wirelessConfig = WirelessConfig(
                    primarySSID: ssid ?? wirelessConfig.primarySSID,
                    primaryEnabled: wirelessConfig.primaryEnabled,
                    guestSSID: wirelessConfig.guestSSID,
                    connectedDevices: wirelessConfig.connectedDevices,
                    signalStrength: signalStrength ?? wirelessConfig.signalStrength,
                    wirelessPorts: wirelessConfig.wirelessPorts,
                    band24Ports: wirelessConfig.band24Ports,
                    band5Ports: wirelessConfig.band5Ports,
                    band6Ports: wirelessConfig.band6Ports,
                    band5Type: wirelessConfig.band5Type,
                    radioInfo: wirelessConfig.radioInfo,
                    wirelessNetworks: wirelessConfig.wirelessNetworks,
                    lastUpdated: Date()
                )
            }
        }
    }
    
    // MARK: - Helper Methods (KEEP AS IS)
    private func extractFirstMatch(from text: String, pattern: String) -> String? {
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive, .dotMatchesLineSeparators])
            if let match = regex.firstMatch(in: text, range: NSRange(location: 0, length: text.count)) {
                if match.numberOfRanges > 1 {
                    let range = Range(match.range(at: 1), in: text)!
                    return String(text[range]).trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
        } catch {
            return nil
        }
        return nil
    }
    
    private func extractAllMatches(from text: String, pattern: String) -> [[String]] {
        var results: [[String]] = []
        
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive, .dotMatchesLineSeparators])
            let matches = regex.matches(in: text, range: NSRange(location: 0, length: text.count))
            
            for match in matches {
                var matchGroup: [String] = []
                for i in 1..<match.numberOfRanges {
                    if let range = Range(match.range(at: i), in: text) {
                        matchGroup.append(String(text[range]).trimmingCharacters(in: .whitespacesAndNewlines))
                    }
                }
                if !matchGroup.isEmpty {
                    results.append(matchGroup)
                }
            }
        } catch {
            return []
        }
        
        return results
    }
    
    private func extractDeviceFromJSON(_ device: [String: Any]) -> DHCPClient? {
        let nameFields = ["hostname", "name", "device_name", "deviceName", "host", "client_name"]
        let ipFields = ["ip", "ip_address", "ipAddress", "address", "lan_ip"]
        let macFields = ["mac", "mac_address", "macAddress", "hwaddr", "hw_addr"]
        
        var name: String?
        var ip: String?
        var mac: String?
        
        for field in nameFields {
            if let value = device[field] as? String, !value.isEmpty {
                name = value
                break
            }
        }
        
        for field in ipFields {
            if let value = device[field] as? String, !value.isEmpty, isValidIPAddress(value) {
                ip = value
                break
            }
        }
        
        for field in macFields {
            if let value = device[field] as? String, !value.isEmpty, isValidMACAddress(value) {
                mac = value
                break
            }
        }
        
        if let ip = ip, let mac = mac {
            return DHCPClient(
                deviceName: name ?? "Device-\(ip.split(separator: ".").last ?? "Unknown")",
                ipAddress: ip,
                macAddress: mac,
                leaseTime: (device["lease_time"] as? String) ?? "Unknown",
                deviceType: (device["device_type"] as? String) ?? "Unknown"
            )
        }
        
        return nil
    }
    
    private func removeDuplicateDevices(_ devices: [DHCPClient]) -> [DHCPClient] {
        var uniqueDevices: [DHCPClient] = []
        var seenMACs: Set<String> = []
        
        for device in devices {
            if !seenMACs.contains(device.macAddress) {
                seenMACs.insert(device.macAddress)
                uniqueDevices.append(device)
            }
        }
        
        return uniqueDevices
    }
    
    private func isValidIPAddress(_ ip: String) -> Bool {
        let parts = ip.components(separatedBy: ".")
        guard parts.count == 4 else { return false }
        
        for part in parts {
            guard let num = Int(part), num >= 0 && num <= 255 else { return false }
        }
        
        return true
    }
    
    private func isValidMACAddress(_ mac: String) -> Bool {
        let pattern = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        do {
            let regex = try NSRegularExpression(pattern: pattern)
            return regex.firstMatch(in: mac, range: NSRange(location: 0, length: mac.count)) != nil
        } catch {
            return false
        }
    }
    
    // MARK: - API Calls (KEEP AS IS - THEY WORK)
    func callRouterAPI(endpoint: String, postData: String?, method: String = "POST") async -> Data? {
        let fullURL = endpoint.isEmpty ? baseURL : "\(baseURL)/\(endpoint)"
        
        guard let url = URL(string: fullURL) else {
            addDebugLog("⚠️ Invalid URL: \(fullURL)")
            return nil
        }
        
        print("📡 Calling API: \(method) \(endpoint)")
        addDebugLog("📡 Calling API: \(method) \(endpoint)")
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        
        // Add extracted authentication headers
        for (key, value) in authenticationHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        // Add standard headers
        request.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15", forHTTPHeaderField: "User-Agent")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue(baseURL, forHTTPHeaderField: "Origin")
        request.setValue(baseURL, forHTTPHeaderField: "Referer")
        
        if method == "POST" {
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            if let postData = postData {
                request.httpBody = postData.data(using: .utf8)
            }
        }
        
        // Add cookies to request
        if !authenticationCookies.isEmpty {
            let cookieHeaders = HTTPCookie.requestHeaderFields(with: authenticationCookies)
            for (key, value) in cookieHeaders {
                request.setValue(value, forHTTPHeaderField: key)
            }
        }
        
        do {
            let (data, response) = try await urlSession.data(for: request)
            
            if let httpResponse = response as? HTTPURLResponse {
                let isSuccess = httpResponse.statusCode == 200
                
                if isSuccess {
                    print("✅ Got data from \(endpoint): \(data.count) bytes")
                    addDebugLog("✅ Got data from \(endpoint): \(data.count) bytes")
                    return data
                } else {
                    print("❌ \(endpoint): HTTP \(httpResponse.statusCode)")
                    addDebugLog("❌ \(endpoint): HTTP \(httpResponse.statusCode)")
                }
            }
        } catch {
            print("⚠️ Error calling \(endpoint): \(error)")
            addDebugLog("⚠️ Error calling \(endpoint): \(error)")
        }
        
        return nil
    }
    
    // MARK: - Data Parsing Methods (KEEP AS IS - THEY WORK)
    private func parseRealCalixSystemData(html: String, endpoint: String) -> RouterInfo? {
        print("🔍 === PARSING SYSTEM DATA FROM \(endpoint) ===")
        
        var model = "Unknown"
        var firmware = "Unknown"
        var uptime = "Unknown"
        var serialNumber = "Unknown"
        var fsan = "Unknown"
        var hostName = "Unknown"
        var currentTime = "Unknown"
        var timeZone = "Unknown"
        var operationalMode = "Unknown"
        var operationalRole = "Unknown"
        var cpuUsage = 0.0
        var memoryUsage = 0.0
        
        if html.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") {
            if let jsonData = html.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] {
                
                if let systemInfo = json["system_info"] as? [[String: Any]] {
                    for item in systemInfo {
                        if let param = item["param"] as? String,
                           let value = item["value"] as? String {
                            
                            switch param {
                            case "Model Number":
                                model = "Calix GigaSpire \(value)"
                            case "EXOS Version":
                                firmware = value
                            case "Device Uptime":
                                uptime = value
                            case "Serial Number":
                                serialNumber = value
                            case "FSAN":
                                fsan = value
                            case "Host Name":
                                hostName = value
                            case "Current Local Time":
                                currentTime = value
                            case "Time Zone":
                                timeZone = value
                            case "Operational Mode":
                                operationalMode = value
                            case "Operational Role":
                                operationalRole = value
                            default:
                                break
                            }
                        }
                    }
                    
                    if model != "Unknown" || firmware != "Unknown" {
                        return RouterInfo(
                            modelName: model,
                            firmwareVersion: firmware,
                            uptime: uptime,
                            serialNumber: serialNumber,
                            fsan: fsan,
                            hostName: hostName,
                            currentTime: currentTime,
                            timeZone: timeZone,
                            operationalMode: operationalMode,
                            operationalRole: operationalRole,
                            cpuUsage: cpuUsage,
                            memoryUsage: memoryUsage,
                            lastUpdated: Date()
                        )
                    }
                }
            }
        }
        
        return nil
    }
    
    private func parseRealCalixNetworkData(html: String, endpoint: String) -> NetworkConfig? {
        print("🔍 === PARSING NETWORK DATA FROM \(endpoint) ===")
        
        var wanStatus = "Unknown"
        var wanIP = "Unknown"
        var ipv6Status = "Unknown"
        var ipv6IP = "Unknown"
        var tr069Status = "Unknown"
        var lanIP = configManager.routerIP
        var connectedDevices = 0
        var dhcpEnabled = true
        var satellites: [SatelliteInfo] = []
        var ethPorts = 0
        var gethPorts = 0
        var usbPorts = 0
        var wirelessPorts = 0
        
        if html.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") {
            if let jsonData = html.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] {
                
                if let rg = json["rg"] as? [[String]] {
                    for item in rg {
                        if item.count >= 2 {
                            let param = item[0]
                            let value = item[1]
                            
                            switch param {
                            case "IPv4 Connection":
                                if value.contains("Connected") {
                                    wanStatus = "Connected"
                                    let parts = value.components(separatedBy: " - ")
                                    if parts.count > 1 {
                                        wanIP = parts[1]
                                    }
                                } else {
                                    wanStatus = "Disconnected"
                                }
                            case "IPv6 Connection":
                                if value.contains("Connected") {
                                    ipv6Status = "Connected"
                                    let parts = value.components(separatedBy: " - ")
                                    if parts.count > 1 {
                                        ipv6IP = parts[1]
                                    }
                                } else {
                                    ipv6Status = "Disconnected"
                                    ipv6IP = "N/A"
                                }
                            case "TR-069 Status":
                                tr069Status = value
                            default:
                                break
                            }
                        }
                    }
                }
                
                if let sats = json["sats"] as? [[[String]]] {
                    for satData in sats {
                        if satData.count > 0 {
                            var satInfo = SatelliteInfo(
                                name: "Unknown",
                                macAddress: "Unknown",
                                ipAddress: "Unknown",
                                connectionType: "Unknown",
                                modelNumber: "Unknown",
                                exosVersion: "Unknown"
                            )
                            
                            for item in satData {
                                if item.count >= 2 {
                                    let param = item[0]
                                    let value = item[1]
                                    
                                    switch param {
                                    case let name where name.hasPrefix("Satellite-"):
                                        let parts = value.components(separatedBy: " / ")
                                        satInfo = SatelliteInfo(
                                            name: name,
                                            macAddress: parts[0],
                                            ipAddress: parts.count > 1 ? parts[1] : "Unknown",
                                            connectionType: satInfo.connectionType,
                                            modelNumber: satInfo.modelNumber,
                                            exosVersion: satInfo.exosVersion
                                        )
                                    case "Connection Type":
                                        satInfo = SatelliteInfo(
                                            name: satInfo.name,
                                            macAddress: satInfo.macAddress,
                                            ipAddress: satInfo.ipAddress,
                                            connectionType: value,
                                            modelNumber: satInfo.modelNumber,
                                            exosVersion: satInfo.exosVersion
                                        )
                                    case "Model Number":
                                        satInfo = SatelliteInfo(
                                            name: satInfo.name,
                                            macAddress: satInfo.macAddress,
                                            ipAddress: satInfo.ipAddress,
                                            connectionType: satInfo.connectionType,
                                            modelNumber: value,
                                            exosVersion: satInfo.exosVersion
                                        )
                                    case "EXOS Version":
                                        satInfo = SatelliteInfo(
                                            name: satInfo.name,
                                            macAddress: satInfo.macAddress,
                                            ipAddress: satInfo.ipAddress,
                                            connectionType: satInfo.connectionType,
                                            modelNumber: satInfo.modelNumber,
                                            exosVersion: value
                                        )
                                    default:
                                        break
                                    }
                                }
                            }
                            satellites.append(satInfo)
                        }
                    }
                }
                
                if let ethPortsValue = json["eth ports"] as? Int {
                    ethPorts = ethPortsValue
                }
                
                if let gethPortsValue = json["geth ports"] as? Int {
                    gethPorts = gethPortsValue
                }
                
                if let usbPortsValue = json["usb ports"] as? Int {
                    usbPorts = usbPortsValue
                }
                
                if let wlPortsValue = json["wl ports"] as? Int {
                    wirelessPorts = wlPortsValue
                }
                
                connectedDevices = satellites.count
                
                return NetworkConfig(
                    wanStatus: wanStatus,
                    wanIP: wanIP,
                    lanIP: lanIP,
                    ipv6Status: ipv6Status,
                    ipv6IP: ipv6IP,
                    tr069Status: tr069Status,
                    connectedDevices: connectedDevices,
                    dhcpEnabled: dhcpEnabled,
                    satellites: satellites,
                    dhcpClients: [],
                    ethPorts: ethPorts,
                    gethPorts: gethPorts,
                    usbPorts: usbPorts,
                    wirelessPorts: wirelessPorts,
                    lastUpdated: Date()
                )
            }
        }
        
        return nil
    }
    
    private func parseRealCalixWirelessData(html: String, endpoint: String) -> WirelessConfig? {
        print("🔍 === PARSING WIRELESS DATA FROM \(endpoint) ===")
        
        var primarySSID = "Unknown"
        var primaryEnabled = true
        var guestSSID: String? = nil
        var connectedDevices = 0
        var signalStrength = 85.0
        var wirelessPorts = 0
        var band24Ports = 0
        var band5Ports = 0
        var band6Ports = 0
        var band5Type = "Unknown"
        var radioInfo: [RadioInfo] = []
        
        if html.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") {
            if let jsonData = html.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] {
                
                if let wlPortsValue = json["wl ports"] as? Int {
                    wirelessPorts = wlPortsValue
                }
                
                if let band24PortsValue = json["2.4wl ports"] as? Int {
                    band24Ports = band24PortsValue
                }
                
                if let band5PortsValue = json["5wl ports"] as? Int {
                    band5Ports = band5PortsValue
                }
                
                if let band6PortsValue = json["6wl ports"] as? Int {
                    band6Ports = band6PortsValue
                }
                
                if let band5TypeValue = json["5wl type"] as? String {
                    band5Type = band5TypeValue
                }
                
                if let radioInfoArray = json["radioinfo"] as? [[String: Any]] {
                    for radio in radioInfoArray {
                        if let radioId = radio["radioid"] as? Int,
                           let band = radio["band"] as? String {
                            let radioItem = RadioInfo(radioId: radioId, band: band)
                            radioInfo.append(radioItem)
                        }
                    }
                }
                
                if endpoint.contains("board_capabilities") && wirelessPorts > 0 {
                    primarySSID = "WiFi Network"
                    primaryEnabled = true
                }
                
                if wirelessPorts > 0 || radioInfo.count > 0 || primarySSID != "Unknown" {
                    return WirelessConfig(
                        primarySSID: primarySSID,
                        primaryEnabled: primaryEnabled,
                        guestSSID: guestSSID,
                        connectedDevices: connectedDevices,
                        signalStrength: signalStrength,
                        wirelessPorts: wirelessPorts,
                        band24Ports: band24Ports,
                        band5Ports: band5Ports,
                        band6Ports: band6Ports,
                        band5Type: band5Type,
                        radioInfo: radioInfo,
                        wirelessNetworks: [],
                        lastUpdated: Date()
                    )
                }
            }
        }
        
        return nil
    }
    
    // MARK: - Manual Authentication (KEEP AS IS)
    func startGuidedAuthentication(username: String) {
        currentUsername = username
        showGuidedAuth = true
    }
    
    func authenticateWithManualCookie(_ token: String, username: String) {
        currentUser = username
        isAuthenticated = true
        
        Task {
            await loadAllRouterDataWithFixedExtraction()
        }
    }
    
    func openRouterInBrowser() {
        if let url = URL(string: baseURL) {
            DispatchQueue.main.async {
                UIApplication.shared.open(url)
            }
        }
    }
    
    func logout() {
        isAuthenticated = false
        currentUser = nil
        currentUsername = nil
        routerInfo = nil
        networkConfig = nil
        wirelessConfig = nil
        errorMessage = nil
        lastUpdateTime = nil
        authenticationProgress = ""
        authenticationHeaders.removeAll()
        authenticationCookies.removeAll()
        debugLogs.removeAll()
        
        KeychainManager.shared.clearAllData()
    }
    

    // Method 2: Simple pattern extractor
    private func extractMatches(from text: String, pattern: String) -> [String] {
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
            let matches = regex.matches(in: text, range: NSRange(location: 0, length: text.count))
            
            var results: [String] = []
            for match in matches {
                if let range = Range(match.range, in: text) {
                    results.append(String(text[range]))
                }
            }
            
            return Array(Set(results)) // Remove duplicates
        } catch {
            addDebugLog("❌ Regex error: \(error)")
            return []
        }
    }

   /*
    private func loadAllRouterDataWithFixedExtraction() async {
        await MainActor.run {
               lastUpdateTime = Date()
               isLoading = false
           }
        addDebugLog("🔍 === STARTING FIXED DATA EXTRACTION ===")
        
        // Load real system info
        if let systemInfo = await loadRealSystemInfo() {
            self.routerInfo = systemInfo
            addDebugLog("✅ System info loaded")
        }
        
        // Load real network info
        if let networkInfo = await loadRealNetworkInfo() {
            self.networkConfig = networkInfo
            addDebugLog("✅ Network info loaded")
        }
        
        // Load real wireless info
        if let wirelessInfo = await loadRealWirelessInfo() {
            self.wirelessConfig = wirelessInfo
            addDebugLog("✅ Wireless info loaded")
        }
        
        // Extract real DHCP clients
        await extractRealDHCPClients()
        
        // Extract real device count
        await extractRealDeviceCount()
        
        // Extract real wireless info
        await extractRealWirelessInfo()
        
        lastUpdateTime = Date()
        isLoading = false
        
        addDebugLog("✅ === FIXED DATA EXTRACTION COMPLETE ===")
    }
  */
    private func loadAllRouterDataWithFixedExtraction() async {
        addDebugLog("🔍 === STARTING FIXED DATA EXTRACTION ===")
        
        // Load real system info
        if let systemInfo = await loadRealSystemInfo() {
            await MainActor.run {
                self.routerInfo = systemInfo
            }
            addDebugLog("✅ System info loaded")
        }
        
        // Load real network info
        if let networkInfo = await loadRealNetworkInfo() {
            await MainActor.run {
                self.networkConfig = networkInfo
            }
            addDebugLog("✅ Network info loaded")
        }
        
        // Load real wireless info
        if let wirelessInfo = await loadRealWirelessInfo() {
            await MainActor.run {
                self.wirelessConfig = wirelessInfo
            }
            addDebugLog("✅ Wireless info loaded")
        }
        
        // Extract real DHCP clients
        await extractRealDHCPClients()
        
        // Extract real device count
        await extractRealDeviceCount()
        
        // Extract real wireless info
        await extractRealWirelessInfo()
        
        await MainActor.run {
            self.lastUpdateTime = Date()
            self.isLoading = false
        }
        
        addDebugLog("✅ === FIXED DATA EXTRACTION COMPLETE ===")
    }
    
}

// MARK: - Session Extraction Authenticator (KEEP AS IS - IT WORKS)
class SessionExtractionAuthenticator: NSObject, WKNavigationDelegate {
    private var webView: WKWebView?
    private var username: String
    private var password: String
    private var onSuccess: ([String: String], [HTTPCookie]) -> Void
    private var onFailure: (String) -> Void
    private var extractionTimer: Timer?
    private var timeoutTimer: Timer?
    private var extractionAttempts = 0
    private let maxAttempts = 10
    private let timeout: TimeInterval = 30
    
    init(username: String, password: String, onSuccess: @escaping ([String: String], [HTTPCookie]) -> Void, onFailure: @escaping (String) -> Void) {
        self.username = username
        self.password = password
        self.onSuccess = onSuccess
        self.onFailure = onFailure
        super.init()
    }
    
    func startAuthentication() {
        setupWebView()
        startTimeout()
    }
    
    private func setupWebView() {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        
        webView = WKWebView(frame: CGRect(x: 0, y: 0, width: 1, height: 1), configuration: config)
        webView?.navigationDelegate = self
        webView?.isHidden = true
        
        DispatchQueue.main.async {
            if let windowScene = UIApplication.shared.connectedScenes.first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene,
               let window = windowScene.windows.first(where: { $0.isKeyWindow }) {
                window.addSubview(self.webView!)
                
                if let url = URL(string: "https://192.168.1.1") {
                    let request = URLRequest(url: url)
                    self.webView?.load(request)
                }
            }
        }
    }
    
    private func startTimeout() {
        timeoutTimer = Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { _ in
            self.failAuthentication("Session extraction timeout")
        }
    }
    
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        let urlString = webView.url?.absoluteString ?? "unknown"
        print("🌐 Session extractor finished loading: \(urlString)")
        
        webView.evaluateJavaScript("document.title") { result, error in
            let title = result as? String ?? "Unknown"
            
            if title.lowercased().contains("login") {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                    self.injectCredentialsAndLogin()
                }
            } else if title.lowercased().contains("calix") || title.lowercased().contains("admin") {
                print("✅ Reached authenticated page, extracting session...")
                self.startSessionExtraction()
            }
        }
    }
    
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
                return
            }
        }
        completionHandler(.performDefaultHandling, nil)
    }
    
    private func injectCredentialsAndLogin() {
        guard let webView = webView else { return }
        
        let loginScript = """
        (function() {
            var usernameField = document.querySelector('input[name="username"], input[type="text"]');
            var passwordField = document.querySelector('input[name="password"], input[type="password"]');
            var submitButton = document.querySelector('input[type="submit"], button[type="submit"], button');
            
            if (usernameField && passwordField) {
                usernameField.value = '\(username)';
                passwordField.value = '\(password)';
                
                setTimeout(function() {
                    if (submitButton) {
                        submitButton.click();
                    } else {
                        var form = document.querySelector('form');
                        if (form) form.submit();
                    }
                }, 1000);
                
                return true;
            }
            return false;
        })();
        """
        
        webView.evaluateJavaScript(loginScript) { result, error in
            if let error = error {
                print("❌ Login script error: \(error)")
            }
        }
    }
    
    private func startSessionExtraction() {
        extractionTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            self.extractAuthenticationData()
        }
    }
    
    private func extractAuthenticationData() {
        guard let webView = webView else { return }
        
        extractionAttempts += 1
        
        if extractionAttempts >= maxAttempts {
            failAuthentication("Could not extract session after \(maxAttempts) attempts")
            return
        }
        
        webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
            var authHeaders: [String: String] = [:]
            authHeaders["User-Agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
            authHeaders["Accept"] = "*/*"
            authHeaders["Accept-Language"] = "en-US,en;q=0.9"
            authHeaders["Cache-Control"] = "no-cache"
            authHeaders["Pragma"] = "no-cache"
            
            if cookies.count > 0 {
                self.successExtraction(authHeaders, cookies)
            }
        }
    }
    
    private func successExtraction(_ headers: [String: String], _ cookies: [HTTPCookie]) {
        cleanup()
        onSuccess(headers, cookies)
    }
    
    private func failAuthentication(_ message: String) {
        cleanup()
        onFailure(message)
    }
    
    private func cleanup() {
        extractionTimer?.invalidate()
        extractionTimer = nil
        timeoutTimer?.invalidate()
        timeoutTimer = nil
        
        webView?.removeFromSuperview()
        webView = nil
    }
}

// MARK: - URL Session Delegate (KEEP AS IS)
class RouterSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
                return
            }
        }
        completionHandler(.performDefaultHandling, nil)
    }
}

// MARK: - NEW: Web Scanner UI Views (ADDED FUNCTIONALITY)
struct WebScannerView: View {
    @StateObject private var scanner = GigaSpireWebScanner.shared
    @State private var showingLogs = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                if scanner.isScanning {
                    VStack(spacing: 16) {
                        Text("Scanning GigaSpire Web Interface")
                            .font(.headline)
                        
                        ProgressView(value: scanner.scanProgress)
                            .progressViewStyle(LinearProgressViewStyle())
                        
                        Text(scanner.currentScanStatus)
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                        
                        Text("\(Int(scanner.scanProgress * 100))% Complete")
                            .font(.caption)
                            .foregroundColor(.blue)
                    }
                    .padding()
                } else {
                    VStack(spacing: 16) {
                        Image(systemName: "globe")
                            .font(.system(size: 60))
                            .foregroundColor(.blue)
                        
                        Text("GigaSpire Web Scanner")
                            .font(.title2)
                            .fontWeight(.bold)
                        
                        Text("Scan all available web pages and extract real device data")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                        
                        Button("Start Comprehensive Scan") {
                            Task {
                                await scanner.scanAllPages()
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                    }
                }
                
                if !scanner.discoveredPages.isEmpty {
                    VStack(spacing: 12) {
                        Text("Discovered Pages (\(scanner.discoveredPages.count))")
                            .font(.headline)
                        
                        ScrollView {
                            LazyVStack(spacing: 8) {
                                ForEach(scanner.discoveredPages) { page in
                                    PageSummaryView(page: page)
                                }
                            }
                        }
                        .frame(maxHeight: 200)
                    }
                }
                
                if let scrapedData = scanner.scrapedData {
                    VStack(spacing: 12) {
                        Text("Extracted Data")
                            .font(.headline)
                        
                        HStack(spacing: 20) {
                            DataSummaryCard(
                                title: "Devices",
                                count: scrapedData.devices.count,
                                color: .green
                            )
                            
                            DataSummaryCard(
                                title: "Wireless",
                                count: scrapedData.wirelessNetworks.count,
                                color: .blue
                            )
                            
                            DataSummaryCard(
                                title: "System Info",
                                count: scrapedData.systemInfo.count,
                                color: .orange
                            )
                        }
                    }
                }
                
                Spacer()
                
                HStack {
                    Button("View Logs") {
                        showingLogs = true
                    }
                    .foregroundColor(.secondary)
                    
                    Spacer()
                    
                    if let scrapedData = scanner.scrapedData {
                        Text("Last scan: \(scrapedData.extractedAt.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .padding()
            .navigationTitle("Web Scanner")
        }
        .sheet(isPresented: $showingLogs) {
            LogsView(logs: scanner.debugLogs)
        }
    }
}

struct PageSummaryView: View {
    let page: DiscoveredPage
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(page.title)
                    .font(.headline)
                    .lineLimit(1)
                
                Text(page.url)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                
                HStack {
                    Text(page.pageType.rawValue)
                        .font(.caption)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.blue.opacity(0.2))
                        .cornerRadius(4)
                    
                    Text("\(page.dataFound.count) data elements")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            Spacer()
            
            VStack(spacing: 2) {
                if page.hasDeviceData {
                    Image(systemName: "laptopcomputer")
                        .foregroundColor(.green)
                        .font(.caption)
                }
                
                if page.hasWirelessData {
                    Image(systemName: "wifi")
                        .foregroundColor(.blue)
                        .font(.caption)
                }
                
                if page.hasSystemData {
                    Image(systemName: "gear")
                        .foregroundColor(.orange)
                        .font(.caption)
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(8)
    }
}

struct DataSummaryCard: View {
    let title: String
    let count: Int
    let color: Color
    
    var body: some View {
        VStack(spacing: 4) {
            Text("\(count)")
                .font(.title2)
                .fontWeight(.bold)
                .foregroundColor(color)
            
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(color.opacity(0.1))
        .cornerRadius(8)
    }
}

struct LogsView: View {
    let logs: [String]
    
    var body: some View {
        NavigationView {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(logs, id: \.self) { log in
                        Text(log)
                            .font(.caption)
                            .foregroundColor(.primary)
                            .textSelection(.enabled)
                    }
                }
                .padding()
            }
            .navigationTitle("Scan Logs")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

// MARK: - Extracted Data Views (NEW FUNCTIONALITY)
struct ExtractedDataView: View {
    let scrapedData: ScrapedData
    
    var body: some View {
        TabView {
            ExtractedDevicesView(devices: scrapedData.devices)
                .tabItem {
                    Image(systemName: "laptopcomputer")
                    Text("Devices")
                }
            
            ExtractedWirelessView(networks: scrapedData.wirelessNetworks)
                .tabItem {
                    Image(systemName: "wifi")
                    Text("Wireless")
                }
            
            ExtractedSystemView(systemInfo: scrapedData.systemInfo)
                .tabItem {
                    Image(systemName: "gear")
                    Text("System")
                }
        }
    }
}
// MARK: - Complete SPA Scanner UI Views
struct CompleteSPAScannerView: View {
    @StateObject private var scanner = CompleteSPAScanner.shared
    @State private var showingRecordedPages = false
    @State private var showingExtractedData = false
    @State private var showingLogs = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                if scanner.isScanning {
                    scanningView
                } else {
                    mainView
                }
                
                if !scanner.recordedPages.isEmpty {
                    recordedPagesView
                }
                
                if let extractedData = scanner.extractedData {
                    extractedDataView(extractedData)
                }
                
                Spacer()
                
                bottomActionsView
            }
            .padding()
            .navigationTitle("Complete SPA Scanner")
        }
        .sheet(isPresented: $showingRecordedPages) {
            RecordedPagesView(pages: scanner.recordedPages)
        }
        .sheet(isPresented: $showingExtractedData) {
            if let extractedData = scanner.extractedData {
                ExtractedDataDetailView(data: extractedData)
            }
        }
        .sheet(isPresented: $showingLogs) {
            LogsView(logs: scanner.debugLogs)
        }
    }
    
    private var scanningView: some View {
        VStack(spacing: 16) {
            Text("Complete Page Recording")
                .font(.headline)
            
            ProgressView(value: scanner.scanProgress)
                .progressViewStyle(LinearProgressViewStyle())
            
            Text(scanner.currentScanStatus)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            
            Text("\(Int(scanner.scanProgress * 100))% Complete")
                .font(.caption)
                .foregroundColor(.blue)
            
            if scanner.scanProgress > 0.2 {
                Text("Recording page \(Int((scanner.scanProgress - 0.2) / 0.8 * 58))/58")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
    }
    
    private var mainView: some View {
        VStack(spacing: 16) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 60))
                .foregroundColor(.blue)
            
            Text("Complete SPA Scanner")
                .font(.title2)
                .fontWeight(.bold)
            
            VStack(spacing: 8) {
                Text("Records ALL 58 pages with complete Angular loading")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                
                Text("• Waits for full SPA rendering")
                    .font(.caption)
                    .foregroundColor(.blue)
                
                Text("• Captures final rendered content")
                    .font(.caption)
                    .foregroundColor(.blue)
                
                Text("• Extracts devices, wireless, system info")
                    .font(.caption)
                    .foregroundColor(.blue)
            }
            
            Button("Start Complete Recording") {
                Task {
                    await scanner.scanAllPagesCompletely()
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }
    
    private var recordedPagesView: some View {
        VStack(spacing: 12) {
            HStack {
                Text("Recorded Pages (\(scanner.recordedPages.count))")
                    .font(.headline)
                
                Spacer()
                
                Button("View All") {
                    showingRecordedPages = true
                }
                .font(.caption)
                .foregroundColor(.blue)
            }
            
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 12) {
                    ForEach(scanner.recordedPages.prefix(5)) { page in
                        PageRecordCard(page: page)
                    }
                    
                    if scanner.recordedPages.count > 5 {
                        VStack {
                            Text("+\(scanner.recordedPages.count - 5)")
                                .font(.title2)
                                .fontWeight(.bold)
                            Text("more")
                                .font(.caption)
                        }
                        .frame(width: 80, height: 60)
                        .background(Color.gray.opacity(0.2))
                        .cornerRadius(8)
                    }
                }
                .padding(.horizontal)
            }
        }
    }
    
    private func extractedDataView(_ data: ExtractedRouterData) -> some View {
        VStack(spacing: 12) {
            HStack {
                Text("Extracted Data")
                    .font(.headline)
                
                Spacer()
                
                Button("View Details") {
                    showingExtractedData = true
                }
                .font(.caption)
                .foregroundColor(.blue)
            }
            
            HStack(spacing: 16) {
                DataSummaryCard(
                    title: "Devices",
                    count: data.devices.count,
                    color: .green
                )
                
                DataSummaryCard(
                    title: "Wireless",
                    count: data.wirelessNetworks.count,
                    color: .blue
                )
                
                DataSummaryCard(
                    title: "System Info",
                    count: data.systemInfo.count,
                    color: .orange
                )
            }
        }
    }
    
    private var bottomActionsView: some View {
        HStack {
            Button("View Logs") {
                showingLogs = true
            }
            .foregroundColor(.secondary)
            
            Spacer()
            
            if let extractedData = scanner.extractedData {
                Text("Scanned: \(extractedData.totalPagesScanned) pages")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

struct PageRecordCard: View {
    let page: RecordedPage
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(page.pageName)
                .font(.caption)
                .fontWeight(.medium)
                .lineLimit(1)
            
            Text("\(page.finalContentSize) bytes")
                .font(.caption2)
                .foregroundColor(.secondary)
            
            Text("\(String(format: "%.1f", page.loadingTime))s")
                .font(.caption2)
                .foregroundColor(.blue)
            
            HStack(spacing: 2) {
                if page.hasDeviceData {
                    Circle()
                        .fill(Color.green)
                        .frame(width: 4, height: 4)
                }
                
                if page.hasWirelessData {
                    Circle()
                        .fill(Color.blue)
                        .frame(width: 4, height: 4)
                }
                
                if page.hasSystemData {
                    Circle()
                        .fill(Color.orange)
                        .frame(width: 4, height: 4)
                }
            }
        }
        .frame(width: 80, height: 60)
        .padding(8)
        .background(Color(.systemGray6))
        .cornerRadius(8)
    }
}

struct RecordedPagesView: View {
    let pages: [RecordedPage]
    @State private var selectedPage: RecordedPage?
    
    var body: some View {
        NavigationView {
            List(pages) { page in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(page.pageName)
                            .font(.headline)
                        
                        Spacer()
                        
                        Text("\(page.finalContentSize) bytes")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    
                    Text("Loading time: \(String(format: "%.1f", page.loadingTime))s")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("Recorded: \(page.recordedAt.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    HStack {
                        if page.hasDeviceData {
                            Label("Devices", systemImage: "laptopcomputer")
                                .font(.caption2)
                                .foregroundColor(.green)
                        }
                        
                        if page.hasWirelessData {
                            Label("Wireless", systemImage: "wifi")
                                .font(.caption2)
                                .foregroundColor(.blue)
                        }
                        
                        if page.hasSystemData {
                            Label("System", systemImage: "gear")
                                .font(.caption2)
                                .foregroundColor(.orange)
                        }
                    }
                }
                .padding(.vertical, 4)
                .onTapGesture {
                    selectedPage = page
                }
            }
            .navigationTitle("Recorded Pages")
        }
        .sheet(item: $selectedPage) { page in
            PageDetailView(page: page)
        }
    }
}

struct PageDetailView: View {
    let page: RecordedPage
    @State private var selectedTab = 0
    
    var body: some View {
        NavigationView {
            VStack {
                Picker("Content Type", selection: $selectedTab) {
                    Text("Final HTML").tag(0)
                    Text("Text Content").tag(1)
                    Text("JavaScript Data").tag(2)
                    Text("Initial HTML").tag(3)
                }
                .pickerStyle(SegmentedPickerStyle())
                .padding()
                
                ScrollView {
                    Text(selectedContent)
                        .font(.caption)
                        .textSelection(.enabled)
                        .padding()
                }
            }
            .navigationTitle(page.pageName)
            .navigationBarTitleDisplayMode(.inline)
        }
    }
    
    private var selectedContent: String {
        switch selectedTab {
        case 0:
            return page.finalHTMLContent
        case 1:
            return page.finalTextContent
        case 2:
            return page.javascriptData
        case 3:
            return page.initialHTMLContent
        default:
            return page.finalHTMLContent
        }
    }
}

struct ExtractedDataDetailView: View {
    let data: ExtractedRouterData
    
    var body: some View {
        NavigationView {
            TabView {
                ExtractedDevicesDetailView(devices: data.devices)
                    .tabItem {
                        Image(systemName: "laptopcomputer")
                        Text("Devices")
                    }
                
                ExtractedWirelessDetailView(networks: data.wirelessNetworks)
                    .tabItem {
                        Image(systemName: "wifi")
                        Text("Wireless")
                    }
                
                ExtractedSystemDetailView(systemInfo: data.systemInfo)
                    .tabItem {
                        Image(systemName: "gear")
                        Text("System")
                    }
            }
            .navigationTitle("Extracted Data")
        }
    }
}

struct ExtractedDevicesDetailView: View {
    let devices: [ExtractedDevice]
    
    var body: some View {
        List(devices) { device in
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(device.name)
                        .font(.headline)
                    
                    Spacer()
                    
                    Circle()
                        .fill(device.isOnline ? .green : .red)
                        .frame(width: 8, height: 8)
                }
                
                Text("IP: \(device.ipAddress)")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                Text("MAC: \(device.macAddress)")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                HStack {
                    Text("Type: \(device.deviceType)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Spacer()
                    
                    Text("Source: \(device.source)")
                        .font(.caption)
                        .foregroundColor(.blue)
                }
            }
            .padding(.vertical, 2)
        }
    }
}

struct ExtractedWirelessDetailView: View {
    let networks: [ExtractedWirelessNetwork]
    
    var body: some View {
        List(networks) { network in
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(network.ssid)
                        .font(.headline)
                    
                    Spacer()
                    
                    Text(network.band)
                        .font(.caption)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.blue.opacity(0.2))
                        .cornerRadius(4)
                }
                
                Text("Security: \(network.security)")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                HStack {
                    Text("Status: \(network.isEnabled ? "Enabled" : "Disabled")")
                        .font(.caption)
                        .foregroundColor(network.isEnabled ? .green : .red)
                    
                    Spacer()
                    
                    Text("Source: \(network.source)")
                        .font(.caption)
                        .foregroundColor(.blue)
                }
            }
            .padding(.vertical, 2)
        }
    }
}

struct ExtractedSystemDetailView: View {
    let systemInfo: [ExtractedSystemInfo]
    
    var body: some View {
        List(systemInfo) { info in
            HStack {
                Text(info.parameter)
                    .foregroundColor(.secondary)
                
                Spacer()
                
                Text(info.value)
                    .fontWeight(.medium)
                    .textSelection(.enabled)
            }
            .padding(.vertical, 2)
        }
    }
}

// MARK: - Add Complete Scanner to Main Router App View
struct EnhancedNativeRouterAppView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    @StateObject private var spaScanner = CompleteSPAScanner.shared
    
    var body: some View {
        TabView {
            EnhancedRouterDashboardView()
                .tabItem {
                    Image(systemName: "house.fill")
                    Text("Dashboard")
                }
            
            NetworkView()
                .tabItem {
                    Image(systemName: "network")
                    Text("Network")
                }
            
            WirelessView()
                .tabItem {
                    Image(systemName: "wifi")
                    Text("Wireless")
                }
            
            SatellitesView()
                .tabItem {
                    Image(systemName: "dot.radiowaves.left.and.right")
                    Text("Satellites")
                }
            
            DHCPClientsView()
                .tabItem {
                    Image(systemName: "laptopcomputer.and.iphone")
                    Text("Clients")
                }
            
            // Enhanced Complete SPA Scanner
            CompleteSPAScannerView()
                .tabItem {
                    Image(systemName: "doc.text.magnifyingglass")
                    Text("Complete Scanner")
                }
            
            ExtractedDataTabView()
                .tabItem {
                    Image(systemName: "tray.2.fill")
                    Text("Extracted Data")
                }
            
            EnhancedSettingsView()
                .tabItem {
                    Image(systemName: "gearshape.fill")
                    Text("Settings")
                }
        }
        .onAppear {
            // Pass authentication data to SPA scanner
            spaScanner.setAuthenticationData(
                cookies: [], // You'll need to pass actual cookies from apiManager
                headers: [:] // You'll need to pass actual headers from apiManager
            )
        }
    }
}

struct ExtractedDataTabView: View {
    @StateObject private var spaScanner = CompleteSPAScanner.shared
    
    var body: some View {
        if let extractedData = spaScanner.extractedData {
            ExtractedDataDetailView(data: extractedData)
        } else {
            VStack {
                Image(systemName: "tray")
                    .font(.system(size: 50))
                    .foregroundColor(.gray)
                Text("No extracted data yet")
                    .foregroundColor(.secondary)
                Text("Use the Complete Scanner tab to extract data")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

struct ExtractedDevicesView: View {
    let devices: [ScrapedDevice]
    
    var body: some View {
        NavigationView {
            List(devices) { device in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(device.name)
                            .font(.headline)
                        
                        Spacer()
                        
                        Circle()
                            .fill(device.isOnline ? .green : .red)
                            .frame(width: 8, height: 8)
                    }
                    
                    Text("IP: \(device.ipAddress)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("MAC: \(device.macAddress)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("Source: \(device.source)")
                        .font(.caption)
                        .foregroundColor(.blue)
                }
                .padding(.vertical, 2)
            }
            .navigationTitle("Extracted Devices")
        }
    }
}

struct ExtractedWirelessView: View {
    let networks: [ScrapedWirelessNetwork]
    
    var body: some View {
        NavigationView {
            List(networks) { network in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(network.ssid)
                            .font(.headline)
                        
                        Spacer()
                        
                        Text(network.band)
                            .font(.caption)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.blue.opacity(0.2))
                            .cornerRadius(4)
                    }
                    
                    Text("Channel: \(network.channel)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("Security: \(network.security)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("Source: \(network.source)")
                        .font(.caption)
                        .foregroundColor(.blue)
                }
                .padding(.vertical, 2)
            }
            .navigationTitle("Wireless Networks")
        }
    }
}

struct ExtractedSystemView: View {
    let systemInfo: [ScrapedSystemInfo]
    
    var body: some View {
        NavigationView {
            List(systemInfo) { info in
                HStack {
                    Text(info.parameter)
                        .foregroundColor(.secondary)
                    
                    Spacer()
                    
                    Text(info.value)
                        .fontWeight(.medium)
                }
                .padding(.vertical, 2)
            }
            .navigationTitle("System Information")
        }
    }
}

// MARK: - Main Content View (KEEP YOUR WORKING VIEWS)
struct ContentView: View {
    @StateObject private var apiManager = RouterAPIManager.shared
    @StateObject private var configManager = SecureConfigurationManager.shared
    
    var body: some View {
        Group {
            if apiManager.isAuthenticated {
                NativeRouterAppView()
                    .environmentObject(apiManager)
                    .environmentObject(configManager)
            } else {
                AuthenticationView()
                    .environmentObject(apiManager)
                    .environmentObject(configManager)
            }
        }
        .sheet(isPresented: $apiManager.showGuidedAuth) {
            GuidedAuthenticationView()
                .environmentObject(apiManager)
                .environmentObject(configManager)
        }
    }
}

// MARK: - Authentication View (KEEP AS IS)
struct AuthenticationView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    @EnvironmentObject var configManager: SecureConfigurationManager
    @State private var username = ""
    @State private var password = ""
    @State private var showPasswordInfo = false
    @State private var showAdvancedOptions = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 30) {
                Spacer()
                
                VStack(spacing: 20) {
                    Image(systemName: "wifi.router")
                        .font(.system(size: 80))
                        .foregroundColor(.blue)
                    
                    VStack(spacing: 8) {
                        Text("FTC RouterPilot")
                            .font(.largeTitle)
                            .fontWeight(.bold)
                        
                        Text("Enhanced Calix GigaSpire Management")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                }
                
                Spacer()
                
                VStack(spacing: 20) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Router Authentication")
                            .font(.headline)
                        
                        VStack(spacing: 16) {
                            TextField("Username", text: $username)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .autocapitalization(.none)
                                .disableAutocorrection(true)
                            
                            SecureField("Router Password", text: $password)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                            
                            HStack {
                                Button("admin") {
                                    username = "admin"
                                }
                                .font(.caption)
                                .foregroundColor(.blue)
                                
                                Button("support") {
                                    username = "support"
                                }
                                .font(.caption)
                                .foregroundColor(.orange)
                                
                                Spacer()
                                
                                Button("Find Password") {
                                    showPasswordInfo = true
                                }
                                .font(.caption)
                                .foregroundColor(.blue)
                            }
                            
                            if username == "support" {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Support User Features:")
                                        .font(.caption2)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.orange)
                                    
                                    Text("• Advanced ISP settings (TR-069, REGID)")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                    
                                    Text("• Additional diagnostic tools")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                    
                                    Text("• Enhanced configuration options")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                                .padding(.top, 4)
                            }
                        }
                    }
                    
                    if apiManager.isLoading {
                        VStack(spacing: 8) {
                            ProgressView()
                                .scaleEffect(1.2)
                            
                            Text(apiManager.authenticationProgress)
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        .padding()
                    }
                    
                    Button(action: authenticate) {
                        HStack {
                            if apiManager.isLoading {
                                ProgressView()
                                    .scaleEffect(0.8)
                            } else {
                                Image(systemName: "key.fill")
                            }
                            Text(apiManager.isLoading ? "Extracting Real Data..." : "Login & Extract Real Data")
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(canLogin ? Color.blue : Color.gray)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                    }
                    .disabled(!canLogin || apiManager.isLoading)
                    
                    if !apiManager.isLoading {
                        VStack(spacing: 12) {
                            Button("Use Browser Login") {
                                apiManager.startGuidedAuthentication(username: username.isEmpty ? "admin" : username)
                            }
                            .font(.subheadline)
                            .foregroundColor(.blue)
                            
                            Button(showAdvancedOptions ? "Hide Advanced Options" : "Show Advanced Options") {
                                withAnimation {
                                    showAdvancedOptions.toggle()
                                }
                            }
                            .font(.caption)
                            .foregroundColor(.secondary)
                            
                            if showAdvancedOptions {
                                VStack(spacing: 8) {
                                    Divider()
                                    
                                    Button("Open Router in Safari") {
                                        apiManager.openRouterInBrowser()
                                    }
                                    .font(.caption)
                                    .foregroundColor(.green)
                                    
                                    Button("Toggle Debug Mode") {
                                        apiManager.debugMode.toggle()
                                    }
                                    .font(.caption)
                                    .foregroundColor(.purple)
                                    
                                    Text("NEW: Web Scanner for real device data extraction!")
                                        .font(.caption2)
                                        .foregroundColor(.green)
                                        .multilineTextAlignment(.center)
                                        .fontWeight(.semibold)
                                }
                                .transition(.slide)
                            }
                        }
                    }
                }
                
                Spacer()
                
                if let errorMessage = apiManager.errorMessage {
                    VStack(spacing: 8) {
                        Text(errorMessage)
                            .foregroundColor(.red)
                            .font(.caption)
                            .multilineTextAlignment(.center)
                        
                        Text("💡 Try 'Use Browser Login' above for better compatibility")
                            .font(.caption2)
                            .foregroundColor(.blue)
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                    .background(Color.red.opacity(0.1))
                    .cornerRadius(8)
                }
            }
            .padding(32)
        }
        .alert("Router Password Location", isPresented: $showPasswordInfo) {
            Button("OK") { }
        } message: {
            Text("The router password is printed on a label on the bottom or back of your Calix GigaSpire router. Look for 'Password', 'Admin Password', or 'Default Password'.")
        }
        .onAppear {
            username = ""
            showAdvancedOptions = false
        }
    }
    
    private var canLogin: Bool {
        !username.isEmpty && !password.isEmpty
    }
    
    private func authenticate() {
        Task {
            await apiManager.authenticateWithRouter(username: username, password: password)
        }
    }
}

// MARK: - Guided Authentication View (KEEP AS IS)
struct GuidedAuthenticationView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    @EnvironmentObject var configManager: SecureConfigurationManager
    @Environment(\.dismiss) private var dismiss
    @State private var showWebView = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                Image(systemName: "safari")
                    .font(.system(size: 50))
                    .foregroundColor(.blue)
                
                Text("Browser-Guided Login")
                    .font(.title2)
                    .fontWeight(.bold)
                
                Text("This will open your router's login page where you can log in normally. After successful login, we'll extract the authentication session and REAL device data.")
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)
                
                Button("Open Router Login") {
                    showWebView = true
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.blue)
                .foregroundColor(.white)
                .cornerRadius(12)
                
                Spacer()
            }
            .padding()
            .navigationTitle("Router Authentication")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
        .sheet(isPresented: $showWebView) {
            VisibleWebViewAuth()
                .environmentObject(apiManager)
                .environmentObject(configManager)
        }
    }
}

// MARK: - Visible WebView Auth (KEEP AS IS)
struct VisibleWebViewAuth: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    @EnvironmentObject var configManager: SecureConfigurationManager
    @Environment(\.dismiss) private var dismiss
    @State private var showSuccess = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 16) {
                if !showSuccess {
                    VStack(spacing: 12) {
                        HStack {
                            Image(systemName: "info.circle.fill")
                                .foregroundColor(.blue)
                            Text("Please log in to your router below")
                                .font(.headline)
                        }
                        
                        Button("I'm Successfully Logged In") {
                            manualAuthSuccess()
                        }
                        .font(.caption)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
                        .background(Color.green)
                        .foregroundColor(.white)
                        .cornerRadius(8)
                    }
                    .padding()
                    .background(Color.blue.opacity(0.1))
                    .cornerRadius(12)
                    .padding()
                    
                    WebViewContainer()
                        .environmentObject(configManager)
                } else {
                    VStack(spacing: 20) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 60))
                            .foregroundColor(.green)
                        
                        Text("Extracting REAL Data!")
                            .font(.title2)
                            .fontWeight(.bold)
                        
                        Text("Authentication successful! Now extracting REAL device information from the router.")
                            .multilineTextAlignment(.center)
                            .foregroundColor(.secondary)
                    }
                    .padding(40)
                }
            }
            .navigationTitle("Router Login")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                
                if showSuccess {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button("Done") {
                            dismiss()
                        }
                        .fontWeight(.semibold)
                    }
                }
            }
        }
    }
    
    private func manualAuthSuccess() {
        showSuccess = true
        apiManager.authenticateWithManualCookie("manual_session_token", username: apiManager.currentUsername ?? "admin")
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            dismiss()
        }
    }
}

// MARK: - WebView Container (KEEP AS IS)
struct WebViewContainer: UIViewRepresentable {
    @EnvironmentObject var configManager: SecureConfigurationManager
    
    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        
        if let url = URL(string: "https://\(configManager.routerIP)") {
            let request = URLRequest(url: url)
            webView.load(request)
        }
        
        return webView
    }
    
    func updateUIView(_ webView: WKWebView, context: Context) {
        // No updates needed
    }
    
    func makeCoordinator() -> WebViewCoordinator {
        WebViewCoordinator()
    }
    
    class WebViewCoordinator: NSObject, WKNavigationDelegate {
        func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
                if let serverTrust = challenge.protectionSpace.serverTrust {
                    let credential = URLCredential(trust: serverTrust)
                    completionHandler(.useCredential, credential)
                    return
                }
            }
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

struct NativeRouterAppView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    
    var body: some View {
        TabView {
            EnhancedRouterDashboardView()
                .tabItem {
                    Image(systemName: "house.fill")
                    Text("Dashboard")
                }
            
            NetworkView()
                .tabItem {
                    Image(systemName: "network")
                    Text("Network")
                }
            
            WirelessView()
                .tabItem {
                    Image(systemName: "wifi")
                    Text("Wireless")
                }
            
            SatellitesView()
                .tabItem {
                    Image(systemName: "dot.radiowaves.left.and.right")
                    Text("Satellites")
                }
            
            DHCPClientsView()
                .tabItem {
                    Image(systemName: "laptopcomputer.and.iphone")
                    Text("Clients")
                }
            
            WebScannerView()
                .tabItem {
                    Image(systemName: "globe")
                    Text("Web Scanner")
                }
            
            CompleteSPAScannerView()
                .tabItem {
                    Image(systemName: "doc.text.magnifyingglass")
                    Text("Complete Scanner")
                }
            
            EnhancedSettingsView()
                .tabItem {
                    Image(systemName: "gearshape.fill")
                    Text("Settings")
                }
        }
    }
}
// MARK: - Enhanced Dashboard View (KEEP AS IS)
struct EnhancedRouterDashboardView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    
    var body: some View {
        NavigationView {
            ScrollView {
                LazyVStack(spacing: 20) {
                    if let routerInfo = apiManager.routerInfo {
                        InfoCard(title: "System Status") {
                            VStack(alignment: .leading, spacing: 8) {
                                InfoRow(label: "Model", value: routerInfo.modelName)
                                InfoRow(label: "Firmware", value: routerInfo.firmwareVersion)
                                InfoRow(label: "Uptime", value: routerInfo.uptime)
                                InfoRow(label: "Serial Number", value: routerInfo.serialNumber)
                                InfoRow(label: "FSAN", value: routerInfo.fsan)
                                InfoRow(label: "Host Name", value: routerInfo.hostName)
                            }
                        }
                    }
                    
                    if let networkConfig = apiManager.networkConfig {
                        InfoCard(title: "Network Status") {
                            VStack(alignment: .leading, spacing: 8) {
                                InfoRow(label: "WAN Status", value: networkConfig.wanStatus)
                                InfoRow(label: "WAN IP", value: networkConfig.wanIP)
                                InfoRow(label: "LAN IP", value: networkConfig.lanIP)
                                InfoRow(label: "Connected Devices", value: "\(networkConfig.connectedDevices)")
                                InfoRow(label: "DHCP Clients", value: "\(networkConfig.dhcpClients.count)")
                                InfoRow(label: "Satellites", value: "\(networkConfig.satellites.count)")
                            }
                        }
                    }
                    
                    if let wirelessConfig = apiManager.wirelessConfig {
                        InfoCard(title: "Wireless Status") {
                            VStack(alignment: .leading, spacing: 8) {
                                InfoRow(label: "Primary SSID", value: wirelessConfig.primarySSID)
                                InfoRow(label: "Status", value: wirelessConfig.primaryEnabled ? "Enabled" : "Disabled")
                                InfoRow(label: "Signal Strength", value: "\(Int(wirelessConfig.signalStrength))%")
                                InfoRow(label: "Networks", value: "\(wirelessConfig.wirelessNetworks.count)")
                                InfoRow(label: "Radio Count", value: "\(wirelessConfig.radioInfo.count)")
                            }
                        }
                    }
                    
                    // NEW: Web Scanner Status Card
                    InfoCard(title: "Web Scanner") {
                        VStack(alignment: .leading, spacing: 8) {
                            InfoRow(label: "Last Update", value: apiManager.lastUpdateTime?.formatted(date: .abbreviated, time: .shortened) ?? "Never")
                            InfoRow(label: "Method", value: "FIXED + Web Scraping")
                            InfoRow(label: "Scanner Status", value: GigaSpireWebScanner.shared.isScanning ? "Scanning..." : "Ready")
                            
                            Button("Go to Web Scanner") {
                                // This would switch to the web scanner tab
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                        }
                    }
                }
                .padding()
            }
            .navigationTitle("Dashboard")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Extract Real Data") {
                        Task {
                            await apiManager.loadAllRouterDataWithFixedExtraction()
                        }
                    }
                }
            }
        }
    }
}

// MARK: - All Other Views (Network, Wireless, Satellites, DHCP, Settings) KEEP AS IS
struct NetworkView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    
    var body: some View {
        NavigationView {
            ScrollView {
                LazyVStack(spacing: 16) {
                    if let networkConfig = apiManager.networkConfig {
                        InfoCard(title: "Connection Status") {
                            VStack(alignment: .leading, spacing: 8) {
                                InfoRow(label: "WAN Status", value: networkConfig.wanStatus)
                                InfoRow(label: "WAN IP", value: networkConfig.wanIP)
                                InfoRow(label: "IPv6 Status", value: networkConfig.ipv6Status)
                                InfoRow(label: "IPv6 IP", value: networkConfig.ipv6IP)
                                InfoRow(label: "TR-069 Status", value: networkConfig.tr069Status)
                            }
                        }
                        
                        InfoCard(title: "Network Configuration") {
                            VStack(alignment: .leading, spacing: 8) {
                                InfoRow(label: "LAN IP", value: networkConfig.lanIP)
                                InfoRow(label: "Connected Devices", value: "\(networkConfig.connectedDevices)")
                                InfoRow(label: "DHCP Clients", value: "\(networkConfig.dhcpClients.count)")
                                InfoRow(label: "DHCP Status", value: networkConfig.dhcpEnabled ? "Enabled" : "Disabled")
                            }
                        }
                        
                        InfoCard(title: "Port Information") {
                            VStack(alignment: .leading, spacing: 8) {
                                InfoRow(label: "Ethernet Ports", value: "\(networkConfig.ethPorts)")
                                InfoRow(label: "Gigabit Ethernet", value: "\(networkConfig.gethPorts)")
                                InfoRow(label: "USB Ports", value: "\(networkConfig.usbPorts)")
                                InfoRow(label: "Wireless Ports", value: "\(networkConfig.wirelessPorts)")
                            }
                        }
                    }
                }
                .padding()
            }
            .navigationTitle("Network")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Refresh") {
                        Task {
                            await apiManager.loadAllRouterDataWithFixedExtraction()
                        }
                    }
                }
            }
        }
    }
}

struct WirelessView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    
    var body: some View {
        NavigationView {
            ScrollView {
                LazyVStack(spacing: 16) {
                    if let wirelessConfig = apiManager.wirelessConfig {
                        InfoCard(title: "Wireless Network") {
                            VStack(alignment: .leading, spacing: 8) {
                                InfoRow(label: "Primary SSID", value: wirelessConfig.primarySSID)
                                InfoRow(label: "Status", value: wirelessConfig.primaryEnabled ? "Enabled" : "Disabled")
                                InfoRow(label: "Signal Strength", value: "\(Int(wirelessConfig.signalStrength))%")
                                InfoRow(label: "Connected Devices", value: "\(wirelessConfig.connectedDevices)")
                                if let guestSSID = wirelessConfig.guestSSID {
                                    InfoRow(label: "Guest SSID", value: guestSSID)
                                }
                            }
                        }
                        
                        InfoCard(title: "Radio Configuration") {
                            VStack(alignment: .leading, spacing: 8) {
                                InfoRow(label: "Wireless Ports", value: "\(wirelessConfig.wirelessPorts)")
                                InfoRow(label: "2.4GHz Ports", value: "\(wirelessConfig.band24Ports)")
                                InfoRow(label: "5GHz Ports", value: "\(wirelessConfig.band5Ports)")
                                InfoRow(label: "6GHz Ports", value: "\(wirelessConfig.band6Ports)")
                                InfoRow(label: "5GHz Type", value: wirelessConfig.band5Type)
                            }
                        }
                        
                        if !wirelessConfig.radioInfo.isEmpty {
                            InfoCard(title: "Radio Information") {
                                VStack(alignment: .leading, spacing: 8) {
                                    ForEach(wirelessConfig.radioInfo) { radio in
                                        InfoRow(label: "Radio \(radio.radioId)", value: "\(radio.band) GHz")
                                    }
                                }
                            }
                        }
                    }
                }
                .padding()
            }
            .navigationTitle("Wireless")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Refresh") {
                        Task {
                            await apiManager.loadAllRouterDataWithFixedExtraction()
                        }
                    }
                }
            }
        }
    }
}

struct SatellitesView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    
    var body: some View {
        NavigationView {
            List {
                if let networkConfig = apiManager.networkConfig {
                    if networkConfig.satellites.isEmpty {
                        Section("Satellites") {
                            Text("No satellites connected")
                                .foregroundColor(.secondary)
                        }
                    } else {
                        Section("Connected Satellites (\(networkConfig.satellites.count))") {
                            ForEach(networkConfig.satellites) { satellite in
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Text(satellite.name)
                                            .font(.headline)
                                        Spacer()
                                        Text(satellite.connectionType)
                                            .font(.caption)
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 2)
                                            .background(Color.blue)
                                            .foregroundColor(.white)
                                            .cornerRadius(4)
                                    }
                                    
                                    Text("IP: \(satellite.ipAddress)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    
                                    Text("MAC: \(satellite.macAddress)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    
                                    Text("Model: \(satellite.modelNumber)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    
                                    Text("EXOS: \(satellite.exosVersion)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                .padding(.vertical, 4)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Satellites")
        }
    }
}

struct DHCPClientsView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    
    var body: some View {
        NavigationView {
            List {
                if let networkConfig = apiManager.networkConfig {
                    if networkConfig.dhcpClients.isEmpty {
                        Section("DHCP Clients") {
                            VStack(spacing: 8) {
                                Text("No DHCP clients found yet")
                                    .foregroundColor(.secondary)
                                
                                Text("Try the Web Scanner tab for comprehensive device discovery!")
                                    .font(.caption)
                                    .foregroundColor(.green)
                                    .multilineTextAlignment(.center)
                                
                                Button("Go to Web Scanner") {
                                    // This would switch to the scanner tab
                                }
                                .font(.caption)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(Color.green)
                                .foregroundColor(.white)
                                .cornerRadius(6)
                            }
                        }
                    } else {
                        Section("DHCP Clients (\(networkConfig.dhcpClients.count))") {
                            ForEach(networkConfig.dhcpClients) { client in
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Text(client.deviceName)
                                            .font(.headline)
                                        Spacer()
                                        Text(client.deviceType)
                                            .font(.caption)
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 2)
                                            .background(Color.green)
                                            .foregroundColor(.white)
                                            .cornerRadius(4)
                                    }
                                    
                                    Text("IP: \(client.ipAddress)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    
                                    Text("MAC: \(client.macAddress)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    
                                    Text("Lease: \(client.leaseTime)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                .padding(.vertical, 4)
                            }
                        }
                    }
                }
            }
            .navigationTitle("DHCP Clients")
        }
    }
}

struct EnhancedSettingsView: View {
    @EnvironmentObject var apiManager: RouterAPIManager
    @EnvironmentObject var configManager: SecureConfigurationManager
    @State private var showingLogout = false
    
    var body: some View {
        NavigationView {
            List {
                if let routerInfo = apiManager.routerInfo {
                    Section("Router Information") {
                        InfoRow(label: "Model", value: routerInfo.modelName)
                        InfoRow(label: "Firmware", value: routerInfo.firmwareVersion)
                        InfoRow(label: "Host Name", value: routerInfo.hostName)
                    }
                }
                
                Section("Connection") {
                    InfoRow(label: "Router IP", value: configManager.routerIP)
                    InfoRow(label: "User", value: apiManager.currentUser ?? "Unknown")
                    InfoRow(label: "Method", value: "FIXED + Web Scanner")
                    InfoRow(label: "Last Update", value: apiManager.lastUpdateTime?.formatted(date: .abbreviated, time: .shortened) ?? "Never")
                }
                
                Section("Data Summary") {
                    if let networkConfig = apiManager.networkConfig {
                        InfoRow(label: "DHCP Clients", value: "\(networkConfig.dhcpClients.count)")
                        InfoRow(label: "Connected Devices", value: "\(networkConfig.connectedDevices)")
                        InfoRow(label: "Satellites", value: "\(networkConfig.satellites.count)")
                    }
                    
                    if let wirelessConfig = apiManager.wirelessConfig {
                        InfoRow(label: "Primary SSID", value: wirelessConfig.primarySSID)
                        InfoRow(label: "Wireless Networks", value: "\(wirelessConfig.wirelessNetworks.count)")
                    }
                }
                
                Section("Actions") {
                    Button("Extract REAL Data") {
                        Task {
                            await apiManager.loadAllRouterDataWithFixedExtraction()
                        }
                    }
                    .foregroundColor(.green)
                    .fontWeight(.semibold)
                    
                    Button("Scan Web Pages") {
                        Task {
                            await GigaSpireWebScanner.shared.scanAllPages()
                        }
                    }
                    .foregroundColor(.blue)
                    .fontWeight(.semibold)
                    
                    Button("Open Router in Browser") {
                        apiManager.openRouterInBrowser()
                    }
                    .foregroundColor(.blue)
                    
                    Button("Toggle Debug Mode") {
                        apiManager.debugMode.toggle()
                    }
                    .foregroundColor(apiManager.debugMode ? .orange : .secondary)
                }
                
                Section {
                    Button("Logout") {
                        showingLogout = true
                    }
                    .foregroundColor(.red)
                }
            }
            .navigationTitle("Settings")
        }
        .alert("Logout", isPresented: $showingLogout) {
            Button("Cancel") { }
            Button("Logout", role: .destructive) {
                apiManager.logout()
            }
        } message: {
            Text("Are you sure you want to logout?")
        }
    }
}

// MARK: - Utility Views
struct InfoCard<Content: View>: View {
    let title: String?
    let content: Content
    
    init(title: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let title = title {
                Text(title)
                    .font(.headline)
                    .foregroundColor(.primary)
            }
            
            content
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct InfoRow: View {
    let label: String
    let value: String
    
    var body: some View {
        HStack {
            Text(label)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
                .textSelection(.enabled)
        }
    }
}

// MARK: - App Entry Point
@main
struct FTCRouterPilotApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .preferredColorScheme(.automatic)
        }
    }
}
