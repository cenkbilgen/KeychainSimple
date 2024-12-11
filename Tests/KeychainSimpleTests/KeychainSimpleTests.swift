import Testing
import Foundation
@testable import KeychainSimple


let id = "test1"
let value = "ABC123"
let keychainAccess = KeychainAccess(itemNamePrefix: "com.keychainsimple.test")

@Test func writeUpdating() throws {
    try keychainAccess.save(id: id, value: value)
}

@Test func writeNotUpdating() throws {
    // ensure it will fail
    try writeUpdating()
    
    // now it should fail instead of overwriting
    #expect(throws: KeychainAccess.Error.systemError(errSecDuplicateItem)) {
        try keychainAccess.save(id: id, value: value, updateExisting: false)
    }
}

@Test func read() throws {
    try writeUpdating()
    let keychainValue = try keychainAccess.read(id: id)
    #expect(keychainValue == value)
}

@Test func readMissing() throws {
    do {
        try keychainAccess.delete(id: id)
    } catch {
        // continue if delete fails because no key saved, we're just looking to reset things
    }
    
    #expect(throws: KeychainAccess.Error.notFound) {
        let keychainValue = try keychainAccess.read(id: id)
        print(keychainValue)
    }
}

