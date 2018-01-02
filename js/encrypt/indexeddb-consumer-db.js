/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

// Don't require modules since this is meant for the browser, not Node.js.

/**
 * IndexedDbConsumerDb extends ConsumerDb to implement the storage of decryption
 * keys for the consumer using the browser's IndexedDB service.
 * Create an IndexedDbConsumerDb to use the given IndexedDB database name.
 * @param {string} databaseName IndexedDB database name.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var IndexedDbConsumerDb = function IndexedDbConsumerDb(databaseName)
{
  ConsumerDb.call(this);

  this.database = new Dexie(databaseName);
  this.database.version(1).stores({
    // "keyName" is the key name URI // string
    //   (Note: In SQLite3, the key name is the TLV encoded bytes, but we can't
    //   index on a byte array in IndexedDb.)
    // "key" is the key bytes // Uint8Array
    decryptionKeys: "keyName"
  });
  this.database.open();
};

IndexedDbConsumerDb.prototype = new ConsumerDb();
IndexedDbConsumerDb.prototype.name = "IndexedDbConsumerDb";

/**
 * Get the key with keyName from the database.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns a Blob with the encoded key (or an
 * isNull Blob if cannot find the key with keyName), or that is
 * rejected with ConsumerDb.Error for a database error.
 */
IndexedDbConsumerDb.prototype.getKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new ConsumerDb.Error(new Error
      ("IndexedDbConsumerDb.getKeyPromise is only supported for async")));

  return this.database.decryptionKeys.get(keyName.toUri())
  .then(function(decryptionKeysEntry) {
    if (decryptionKeysEntry)
      return Promise.resolve(new Blob(decryptionKeysEntry.key));
    else
      return Promise.resolve(new Blob());
  })
  .catch(function(ex) {
    return Promise.reject(new ConsumerDb.Error(new Error
      ("IndexedDbConsumerDb.getKeyPromise: Error: " + ex)));
  });
};

/**
 * Add the key with keyName and keyBlob to the database.
 * @param {Name} keyName The key name.
 * @param {Blob} keyBlob The encoded key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the key is added, or that
 * is rejected with ConsumerDb.Error if a key with the same keyName already
 * exists, or other database error.
 */
IndexedDbConsumerDb.prototype.addKeyPromise = function(keyName, keyBlob, useSync)
{
  if (useSync)
    return Promise.reject(new ConsumerDb.Error(new Error
      ("IndexedDbConsumerDb.addKeyPromise is only supported for async")));

  // Add rejects if the primary key already exists.
  return this.database.decryptionKeys.add
    ({ keyName: keyName.toUri(), key: keyBlob.buf() })
  .catch(function(ex) {
    return Promise.reject(new ConsumerDb.Error(new Error
      ("IndexedDbConsumerDb.addKeyPromise: Error: " + ex)));
  });
};

/**
 * Delete the key with keyName from the database. If there is no key with
 * keyName, do nothing.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the key is deleted (or there
 * is no such key), or that is rejected with ConsumerDb.Error for a database
 * error.
 */
IndexedDbConsumerDb.prototype.deleteKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new ConsumerDb.Error(new Error
      ("IndexedDbConsumerDb.deleteKeyPromise is only supported for async")));

  return this.database.decryptionKeys.delete(keyName.toUri())
  .catch(function(ex) {
    return Promise.reject(new ConsumerDb.Error(new Error
      ("IndexedDbConsumerDb.deleteKeyPromise: Error: " + ex)));
  });
};
