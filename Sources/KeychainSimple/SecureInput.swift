//
//  Utility.swift
//  translate_tool
//
//  Created by Cenk Bilgen on 2024-10-08.
//

// Gettings arguments related code

import Foundation

/*
A helper function when reading sensitive values from STDIN,
based on BSD/Unix/macOS function readpassphrase
*/

/*
 defaulting allowTTY to the stricter and safer false, so input must be from a terminal,
 no scripts or piping,
 to allow that, set to true
 */

public enum SecureInput {
    
    public enum Error: Swift.Error {
        case secureInputFailed
    }
    
    public static func read(prompt: String,
                            echoInput: Bool = false,
                            onlyInteractiveInput: Bool = true,
                            allowSTDIN: Bool = true,
                            allocationSize: Int = 512) throws -> String {
        var buffer: [Int8] = Array(repeating: 0, count: allocationSize)
        let echoMask = echoInput ? RPP_ECHO_ON : RPP_ECHO_OFF
        let ttyMask = onlyInteractiveInput ? RPP_REQUIRE_TTY : 0
        let allowSTDINMask = allowSTDIN ? RPP_STDIN : 0
        let options = echoMask | ttyMask | allowSTDINMask
        
        let result = readpassphrase(prompt.cString(using: .utf8),
                                    &buffer,
                                    allocationSize, // only reads up to this -1
                                    options)
        guard let result,
              let string = String(validatingCString: result) else {
            throw Error.secureInputFailed
        }
        return string
    }

}


