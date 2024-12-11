# KeychainSimple

Just saves and reads back String type values to the Keychain.

```
let keychainAccess = KeychainAccess(itemNamePrefix: "com.myname.myapp")

/* Save a value */
try keychainAccess.save(id: "key1", value: "ABC123")

/* Read it back later */
let value = keychainAccess.read(id: "key1")
```
