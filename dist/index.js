'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var Dexie = _interopDefault(require('dexie'));
var nacl = _interopDefault(require('tweetnacl'));
var Typeson = _interopDefault(require('typeson'));
var builtinTypes = _interopDefault(require('typeson-registry/presets/builtin'));

// Import some usable helper functions
const override = Dexie.override;
const Promise = Dexie.Promise;

const cryptoOptions = {
    DATA: 'DATA',
    // DATA_AND_INDICES: 'DATA_AND_INDICES', // not implemented.
    WHITELIST: 'WHITELIST',
    BLACKLIST: 'BLACKLIST',
};

/* options example: 
{
	table1: cryptoOptions.DATA,
	table2: {
		type: cryptoOptions.WHITELIST,
		fields: ['harmlessData1', 'harmlessId']
	},
	table3: {
		type: cryptoOptions.BLACKLIST,
		fields: ['sensitiveField1', 'sensitiveField2']
	}
}
*/

const tson = new Typeson().register([builtinTypes]);

function overrideParseStoresSpec(origFunc) {
    return function(stores, dbSchema) {
        stores._encryptionSettings = '++id';
        origFunc.call(this, stores, dbSchema);
    };
}

function compareArrays(a, b) {
    if (a.length !== b.length) {
        return false;
    }

    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}


const encoder = new TextEncoder();
const decoder = new TextDecoder();

function encryptObject(key, object, nonce) {
    nonce = nonce || nacl.randomBytes(nacl.secretbox.nonceLength);
    const stringToEncrypt = tson.stringify(object);
    const encoded = encoder.encode(stringToEncrypt);
    const encrypted = nacl.secretbox(encoded, nonce, key);
    const data = new Uint8Array(nonce.length + encrypted.length);
    data.set(nonce);
    data.set(encrypted, nonce.length);
    return data;
}

// this prevents changing the shape of the object so
// the underlying engine can optimize the hidden class
function hideValue(input) {
    switch (typeof input) {
        case 'number':
            return 0;
        case 'string':
            return '';
        case 'boolean':
            return false;
        case 'undefined':
            return undefined;
        case 'symbol':
            return undefined;
    }
    return {};
}

function encrypt(db, key, cryptoSettings, nonceOverride) {
    db.Version.prototype._parseStoresSpec = override(
        db.Version.prototype._parseStoresSpec,
        overrideParseStoresSpec
    );

    function encryptWithRule(table, entity, rule) {
        if (rule === undefined) {
            return entity;
        }

        const toEncrypt = {};

        if (rule.type === cryptoOptions.BLACKLIST) {
            for (let i = 0; i < rule.fields.length; i++) {
                toEncrypt[rule.fields[i]] = entity[rule.fields[i]];
                entity[rule.fields[i]] = hideValue(entity[rule.fields[i]]);
            }
        } else {
            Object.assign(toEncrypt, entity);
            const indices = table.schema.indexes.map(index => index.name);
            const whitelist = rule.type === cryptoOptions.WHITELIST ? rule.fields : [];
            for (const key in entity) {
                if (
                    key !== table.schema.primKey.name &&
                    entity.hasOwnProperty(key) &&
                    indices.includes(key) === false &&
                    whitelist.includes(key) === false
                ) {
                    toEncrypt[key] = entity[key];
                    entity[key] = hideValue(entity[key]);
                }
            }
        }

        entity.__encryptedData = encryptObject(key, toEncrypt, nonceOverride);
        return entity;
    }

    function decryptWithRule(entity, rule) {
        if (rule === undefined) {
            return entity;
        }
        if (entity.__encryptedData) {
            const nonce = entity.__encryptedData.slice(0, nacl.secretbox.nonceLength);
            const message = entity.__encryptedData.slice(
                nacl.secretbox.nonceLength,
                entity.__encryptedData.length
            );
            const rawDecrypted = nacl.secretbox.open(message, nonce, key);
            const stringified = decoder.decode(rawDecrypted);
            const decrypted = tson.parse(stringified);
            const toReturn = {};
            for (const k in entity) {
                if (decrypted.hasOwnProperty(k)) {
                    toReturn[k] = decrypted[k];
                } else if (entity.hasOwnProperty(k) && k !== '__encryptedData') {
                    toReturn[k] = entity[k];
                }
            }
            return toReturn;
        }
        return entity;
    }

    db.on('ready', function() {
        return db._encryptionSettings
            .toCollection()
            .last()
            .then(oldSettings => {
                return Promise.all(
                    db.tables.map(function(table) {
                        const oldSetting = oldSettings ? oldSettings[table.name] : undefined;
                        const newSetting = cryptoSettings[table.name];

                        if (oldSetting === newSetting) {
                            return;
                        }
                        if (oldSetting === undefined || newSetting === undefined) ; else if (
                            typeof oldSetting !== 'string' &&
                            typeof newSetting !== 'string'
                        ) {
                            // both non-strings. Figure out if they're the same.
                            if (newSetting.type === oldSetting.type) {
                                if (compareArrays(newSetting.fields, oldSetting.fields)) {
                                    return;
                                }
                            }
                        }
                        return table
                            .toCollection()
                            .modify(function(entity, ref) {
                                const decrypted = decryptWithRule(entity, oldSetting);
                                ref.value = encryptWithRule(table, decrypted, newSetting);
                                return true;
                            })
                            .then(function() {
                                if (newSetting) {
                                    table.hook('creating', function(primKey, obj) {
                                        encryptWithRule(table, obj, newSetting);
                                    });
                                    table.hook('updating', function(modifications, primKey, obj) {
                                        return encryptWithRule(table, { ...obj }, newSetting);
                                    });
                                    table.hook('reading', function(obj) {
                                        return decryptWithRule(obj, newSetting);
                                    });
                                }
                            });
                    })
                );
            })
            .then(function() {
                return db._encryptionSettings.put(cryptoSettings);
            });
    });
}

exports.cryptoOptions = cryptoOptions;
exports.default = encrypt;
