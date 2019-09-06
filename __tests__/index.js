import 'fake-indexeddb/auto';
import '../test-utils/encoder';

import Dexie from 'dexie';
import 'dexie-export-import';

import nacl from 'tweetnacl';

import encrypt, { cryptoOptions } from '../index';

const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32));

const dbToJson = (db) => {
    return new Promise(async resolve => {
        const blob = await db.export();
        const reader = new FileReader();
        reader.addEventListener('loadend', () => {
            const data = JSON.parse(reader.result);
            resolve(data);
        });
        reader.readAsText(blob);
    });
};

describe('Encrypting', () => {
	it('should encrypt data', async (done) => {
		const db = new Dexie('MyDatabase');
		encrypt(db, keyPair.publicKey, {
			friends: cryptoOptions.DATA
		}, new Uint8Array(24))

		// Declare tables, IDs and indexes
		db.version(1).stores({
			friends: '++id, name, age'
		});
		
		await db.open();

		const original = {
			name: 'Camilla',
			age: 25,
			street: 'East 13:th Street',
			picture: 'camilla.png'
		};

		await db.friends.add(original);


		const readingDb = new Dexie('MyDatabase');
		readingDb.version(1).stores({
			friends: '++id, name, age'
		});
		await readingDb.open();

		const data = await dbToJson(readingDb);
		expect(data).toMatchSnapshot();
		done();

	});

	it('should encrypt whitelist', async (done) => {
		const db = new Dexie('whitelist');
		encrypt(db, keyPair.publicKey, {
			friends: {
				type: cryptoOptions.WHITELIST,
				fields: ['picture']
			}
		}, new Uint8Array(24))

		// Declare tables, IDs and indexes
		db.version(1).stores({
			friends: '++id, name, age'
		});
		
		await db.open();

		const original = {
			name: 'Camilla',
			age: 25,
			street: 'East 13:th Street',
			picture: 'camilla.png'
		};

		await db.friends.add(original);


		const readingDb = new Dexie('whitelist');
		readingDb.version(1).stores({
			friends: '++id, name, age'
		});
		await readingDb.open();

		const data = await dbToJson(readingDb);
		expect(data).toMatchSnapshot();
		done();

	});
	it('should encrypt blacklist', async (done) => {
		const db = new Dexie('blacklist');
		encrypt(db, keyPair.publicKey, {
			friends: {
				type: cryptoOptions.BLACKLIST,
				fields: ['street']
			}
		}, new Uint8Array(24))

		// Declare tables, IDs and indexes
		db.version(1).stores({
			friends: '++id, name, age'
		});
		
		await db.open();

		const original = {
			name: 'Camilla',
			age: 25,
			street: 'East 13:th Street',
			picture: 'camilla.png'
		};

		await db.friends.add(original);


		const readingDb = new Dexie('blacklist');
		readingDb.version(1).stores({
			friends: '++id, name, age'
		});
		await readingDb.open();

		const data = await dbToJson(readingDb);
		expect(data).toMatchSnapshot();
		done();

	});
	it('should decrypt', async (done) => {
		const db = new Dexie('decrypt-test');
		encrypt(db, keyPair.publicKey, {
			friends: cryptoOptions.DATA
		}, new Uint8Array(24))

		// Declare tables, IDs and indexes
		db.version(1).stores({
			friends: '++id, name, age'
		});
		
		await db.open();

		const original = {
			name: 'Camilla',
			age: 25,
			street: 'East 13:th Street',
			picture: 'camilla.png'
		};

		await db.friends.add({...original});

		const out = await db.friends.get(1);
		delete out.id;
		expect(original).toEqual(out);
		done();

	});

	it('should upgrade', async (done) => {
		const db = new Dexie('upgrade-db');
		encrypt(db, keyPair.publicKey, {
			friends: {
				type: cryptoOptions.WHITELIST,
				fields: ['street']
			}
		}, new Uint8Array(24))

		// Declare tables, IDs and indexes
		db.version(1).stores({
			friends: '++id, name, age'
		});
		
		await db.open();

		const original = {
			name: 'Camilla',
			age: 25,
			street: 'East 13:th Street',
			picture: 'camilla.png'
		};

		await db.friends.add(original);
		await db.close();


		const upgraded = new Dexie('upgrade-db');
		encrypt(upgraded, keyPair.publicKey, {
			friends: {
				type: cryptoOptions.WHITELIST,
				fields: ['picture']
			}
		}, new Uint8Array(24))

		upgraded.version(1).stores({
			friends: '++id, name, age'
		});

		await upgraded.open();
		
		const readingDb = new Dexie('upgrade-db');
		readingDb.version(1).stores({
			friends: '++id, name, age'
		});
		await readingDb.open();

		const data = await dbToJson(readingDb);
		expect(data).toMatchSnapshot();
		done();
	});
})