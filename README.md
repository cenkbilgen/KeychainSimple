# KeychainSimple

Just saves and reads back String type values to the Keychain.

```
let keychainAccess = KeychainAccess(itemNamePrefix: "com.myname.myapp")

/* Save a value */
try keychainAccess.save(id: "key1", value: "ABC123")

/* Read it back later */
let value = keychainAccess.read(id: "key1")
```

NOTE: The intended target for this package is macOS command-line tools, but it works fine with UI apps also. 

For iOS and other platforms the LocalAuthentication code may need some updates, but maybe not. Certainly some Info.plist values related to LocalAuthentication need to be added to the host app though.

