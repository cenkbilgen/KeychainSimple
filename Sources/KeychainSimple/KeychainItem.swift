import Foundation
import Security
@preconcurrency import LocalAuthentication

public struct KeychainAccess: Sendable {

    public enum Error: Swift.Error, Equatable {
        case notFound
        case notUTF8Encoded
        case unexpectedPasswordData
        case unexpectedItemData
        case securityError(CFError?)
        case systemError(OSStatus)
        case invalidAuthenticationState
    }
    
    private let itemNamePrefix: String
    
    // use something like "tools.xcode.translate_strings"
    // NOTE: do not add an extra dot a the end of the prefix, it will be added
    public init(itemNamePrefix: String) {
        self.itemNamePrefix = itemNamePrefix
    }

    private func accountString(_ key: String) -> String {
        itemNamePrefix + "." + key
    }
    
    // will not throw if does not exist
    public func delete(id: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: accountString(id),
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            throw Error.systemError(status)
        }
    }

    public func save(id: String,
                     value: String,
                     updateExisting: Bool = true) throws {
        guard let data = value.data(using: .utf8) else {
            throw Error.notUTF8Encoded
        }
        // let accessControl = try createAccessControl()
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: accountString(id),
            kSecValueData as String: data,
        ]
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
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: accountString(id),
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        try await KeychainAccess.updateQueryWithLocalAuthentication(query: &query)
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
        try await updateQueryWithLocalAuthentication(query: &query)
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
                    return account.replacingOccurrences(of: prefix, with: "")
                } else {
                    return nil
                }
            }
    }
    
    // MARKING: Local Authentication
    
    static func updateQueryWithLocalAuthentication(query: inout [String: Any]) async throws {
        let context = LAContext()
        var authError: NSError?
        
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError)
        if canEvaluate {
            let didSucceed = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Authenticate to access secure data")
            if didSucceed {
                query[kSecUseAuthenticationContext as String] = context
            }
        } else if let authError {
            throw authError
        } else {
            throw Error.invalidAuthenticationState
        }
        
    }

}


