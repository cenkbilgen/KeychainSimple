import Foundation
import Security
@preconcurrency import LocalAuthentication

public struct KeychainAccess: Sendable {

    // TODO: Have an LLM write some localizedDescriptions for these
    public enum Error: Swift.Error, Equatable {
        case notFound
        case notUTF8Encoded
        case unexpectedPasswordData
        case unexpectedItemData
        case securityError(CFError?)
        case systemError(OSStatus)
        case invalidAuthenticationState
        case noAuthenticationPolicyAvailable
    }
    
    private let itemNamePrefix: String
    
    // use something like "tools.xcode.translate_strings"
    // NOTE: do not include an extra dot a the end of the prefix, it will be added
    public init(itemNamePrefix: String) {
        self.itemNamePrefix = itemNamePrefix
    }

    private func accountString(_ key: String) -> String {
        itemNamePrefix + "." + key
    }
    
    // will not throw if does not exist
    public func delete(id: String) async throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: accountString(id),
        ]
        try await KeychainAccess.updateQueryWithLocalAuthentication(reasonText: "delete key with id \(itemNamePrefix).\(id)", query: &query)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            throw Error.systemError(status)
        }
    }

    public func save(id: String,
                     value: String,
                     updateExisting: Bool = true) async throws {
        guard let data = value.data(using: .utf8) else {
            throw Error.notUTF8Encoded
        }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: accountString(id),
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
        ]
        try await KeychainAccess.updateQueryWithLocalAuthentication(reasonText: "save key with id \(itemNamePrefix).\(id)", query: &query)
        let status = SecItemAdd(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            break
        case errSecDuplicateItem:
            if updateExisting {
                query.removeValue(forKey: kSecValueData as String)
                SecItemUpdate(
                    query as CFDictionary,
                    [kSecValueData as String: data] as CFDictionary
                )
            } else {
                fallthrough
            }
        default:
            throw Error.systemError(status)
        }
    }

    public func read(id: String) async throws -> String {
        let account = accountString(id)
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        try await KeychainAccess.updateQueryWithLocalAuthentication(reasonText: "read the value for keychain item \(account)", query: &query)
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw Error.notFound
            } else {
                throw Error.systemError(status)
            }
        }
        guard let data = item as? Data else {
            throw Error.unexpectedItemData
        }
        guard let string = String(data: data, encoding: .utf8) else {
            throw Error.notUTF8Encoded
        }
        return string
    }
    
    public func searchItems() async throws -> [String] {
        try await KeychainAccess.searchItems(prefix: itemNamePrefix)
    }
    
    // For searching with any prefix
    public static func searchItems(prefix: String) async throws -> [String] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            // kSecAttrAccount as String: prefix + "*",
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: kCFBooleanTrue!,
            kSecReturnData as String: kCFBooleanFalse!
        ]
        try await updateQueryWithLocalAuthentication(reasonText: "search for all keychain with id prefix \(prefix)", query: &query)
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw Error.notFound
            } else {
                throw Error.systemError(status)
            }
        }
        guard let items = result as? [[String: Any]] else {
            throw Error.unexpectedItemData
        }
        return items
            .compactMap { item in
                if let account = item[kSecAttrAccount as String] as? String,
                   account.hasPrefix(prefix) {
                    return account.replacingOccurrences(of: prefix + ".", with: "")
                } else {
                    return nil
                }
            }
    }
    
    // MARKING: Local Authentication
    
    static let policyOrder: [LAPolicy] = if #available(macOS 15, *) {
        [.deviceOwnerAuthenticationWithBiometrics,
         .deviceOwnerAuthenticationWithCompanion,
         .deviceOwnerAuthentication]
    } else {
        [.deviceOwnerAuthentication]
    }
    
    static func updateQueryWithLocalAuthentication(reasonText: String, query: inout [String: Any]) async throws {
        let context = LAContext()
        do {
            let policy = try highestAllowedPolicy(context: context)
            let didSucceed = try await context.evaluatePolicy(policy, localizedReason: reasonText)
            if didSucceed {
                query[kSecUseAuthenticationContext as String] = context
            } else {
                #if DEBUG
                print("Evaluate policy did not succeed.")
                #endif
                throw Error.invalidAuthenticationState
            }
        }
    }
    
    static func highestAllowedPolicy(context: LAContext) throws -> LAPolicy {
        for policy in policyOrder {
            do {
                var error: NSError?
                context.canEvaluatePolicy(policy, error: &error)
                if let error {
                    throw error
                }
                return policy
            } catch {
                #if DEBUG
                print("Policy \(policy) not available. \(error.localizedDescription)")
                #endif
            }
        }
        throw Error.noAuthenticationPolicyAvailable
    }

}


