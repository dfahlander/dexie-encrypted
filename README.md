# Dexie-encrypted

This lets you transparently encrypt an IndexedDB database using [Dexie.js](https://dexie.org/) and [tweetnacl.js](https://tweetnacl.js.org).

## Basic Usage

Create a Dexie database and call `encrypt` on it with your encryption key in a Uint8Array.

_Note: dexie-encrypted creates a database table to hold configuration so you must also bump your database version._

```javascript
import Dexie from 'dexie';
import encrypt, { cryptoOptions } from 'dexie-encrypted';

const db = new Dexie('MyDatabase');

// set the key and provide a configuration of how to encrypt at a table level.
encrypt(db, symmetricKey, {
    friends: cryptoOptions.DATA,
});

// everything else is like normal.
db.version(2).stores({
    friends: '++id, name, age',
});

await db.open();

const friend = {
    name: 'Camilla',
    age: 25,
    street: 'East 13:th Street',
    picture: 'camilla.png',
};

await db.friends.add(friend);
```

## Arguments

```javascript
encrypt(db, key, config);
```

-   `db` - a Dexie database that has not had .version called.
-   `key` - a Uint8Array of length 32 that will be used for both encryption and decryption.
-   `config` - a configuration that determines how dexie-encrypted will encrypt the data of each table.

## Configuration

Dexie-encrypted can be configured to encrypt all the data of a table, to whitelist fields that are non-sensitive, or to blacklist sensitive fields.

-   `cryptoOptions.DATA` - all data other than indices will be encrypted.
-   `cryptoOptions.WHITELIST` - all data other than indices and whitelisted fields will be encrypted.
-   `cryptoOptions.BLACKLIST` - listed fields will be encrypted.

```javascript
db.setCrypto(keyPair.publicKey, {
    friends: cryptoOptions.DATA,
    friendsWithWhitelist: {
        type: cryptoOptions.WHITELIST,
        fields: ['street', 'picture'],
    },
    friendsWithBlacklist: {
        type: cryptoOptions.BLACKLIST,
        fields: ['picture'],
    },
});
```

## Upgrades

Dexie-encrypted saves your configuration to a database table, if you change your encryption configuration it will automatically reencrypt the database the next time it's open.

## Notes

-   You cannot encrypt indices. In the future it may be possible, but doing so would require overriding Dexie's `where` function and more. A PR adding this functionality would be accepted.
-   The shape of objects does not change; if `name` is a string that must be encrypted it will be an empty string in the database. Numbers are saved as 0, and booleans as false. This is an optimization that prevents the browser from needing to create hidden classes.
-   Tables missing from your configuration will not be encrypted.
