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
 defaulting allowTTY to the stricter and safer false, so input must be from a terminal but copy/past is allowed,
 no scripts or piping,
 to allow that, set to true
 */

public enum SecureInput {
    
    public enum Error: Swift.Error {
        case secureInputFailed
    }
    
    public static func read(prompt: String,
                            echoInput: Bool = false,
                            requireTTY: Bool = true,
                            allocationSize: Int = 512) throws -> String {
        var buffer: [Int8] = Array(repeating: 0, count: allocationSize)
        let options = (requireTTY ? RPP_REQUIRE_TTY : 0) | (echoInput ? RPP_ECHO_ON : RPP_ECHO_OFF)

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


