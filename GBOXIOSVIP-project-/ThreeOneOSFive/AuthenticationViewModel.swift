import Foundation
import Combine
import SwiftUI
import Security

@MainActor
final class AuthenticationViewModel: ObservableObject {
    @Published var isAuthenticated = false
    @Published var isLoading = false
    @Published var isRevalidating = false
    @Published var showError = false
    @Published var errorMessage = ""
    @Published var enteredKey = ""

    private static let keychainService = "com.bypass7.proxy.local-access"
    private static let keychainAccount = "access-key"

    init() {
        // Local-only access: no network request and no remote key validation.
        isAuthenticated = Self.loadSavedKey()?.isEmpty == false
    }

    func login() async {
        let trimmed = enteredKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            errorMessage = "Por favor, digite sua key"
            showError = true
            return
        }

        isLoading = true
        defer { isLoading = false }
        Self.saveKey(trimmed)
        isAuthenticated = true
        isRevalidating = false
        showError = false
        errorMessage = ""
        enteredKey = ""
    }

    // Kept for App.swift compatibility. There is no remote revalidation.
    func revalidateInBackground() {
        guard isAuthenticated else { return }
        isRevalidating = false
    }

    func logout() {
        isAuthenticated = false
        isRevalidating = false
        enteredKey = ""
        errorMessage = ""
        showError = false
        Self.deleteSavedKey()
    }

    private static func saveKey(_ value: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        guard status == errSecItemNotFound else { return }
        var item = query
        attributes.forEach { item[$0.key] = $0.value }
        SecItemAdd(item as CFDictionary, nil)
    }

    private static func loadSavedKey() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func deleteSavedKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount
        ]
        SecItemDelete(query as CFDictionary)
    }
}
