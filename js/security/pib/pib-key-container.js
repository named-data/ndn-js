/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/key-container.cpp
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

/** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var PibKey = require('./pib-key.js').PibKey; /** @ignore */
var PibKeyImpl = require('./detail/pib-key-impl.js').PibKeyImpl; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * A PibKeyContainer is used to search/enumerate the keys of an identity. (A
 * PibKeyContainer object can only be created by PibIdentity.)
 *
 * You should not call this private constructor. Instead, use
 * PibKeyContainer.makePromise().
 *
 * @param {Name} identityName The name of the identity, which is copied.
 * @param {PibImpl} pibImpl The PIB backend implementation.
 * @param {Array<Name>} keyNames The set of key names as an array of Name, as
 * returned by getKeysOfIdentityPromise.
 * @constructor
 */
var PibKeyContainer = function PibKeyContainer(identityName, pibImpl, keyNames)
{
  // Cache of loaded PibKeyImpl objects. Name URI string => PibKeyImpl.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.keys_ = {};

  // Copy the Name.
  this.identityName_ = new Name(identityName);
  this.pibImpl_ = pibImpl;

  if (pibImpl == null)
    throw new Error("The pibImpl is null");

  // A set of Name URI string.
  // (Use a string because we can't use indexOf with a Name object.)
  this.keyNameUris_ = [];
  for (var i in keyNames)
    this.keyNameUris_.push(keyNames[i].toUri());
};

exports.PibKeyContainer = PibKeyContainer;

/**
 * Create a PibKeyContainer for an identity with identityName.
 * This method that returns a Promise is needed instead of a normal constructor
 * since it uses asynchronous PibImpl methods to initialize the object.
 * This method should only be called by PibIdentityImpl.
 *
 * @param {Name} identityName The name of the identity, which is copied.
 * @param {PibImpl} pibImpl The PIB backend implementation.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @param {Promise|SyncPromise} A promise which returns the new
 * PibKeyContainer.
 */
PibKeyContainer.makePromise = function(identityName, pibImpl, useSync)
{
  if (pibImpl == null)
    return SyncPromise.reject(new Error("The pibImpl is null"));

  return pibImpl.getKeysOfIdentityPromise(identityName, useSync)
  .then(function(keyNames) {
    return SyncPromise.resolve(new PibKeyContainer
      (identityName, pibImpl, keyNames));
  });
};

/**
 * Get the number of keys in the container.
 * @return {number} The number of keys.
 */
PibKeyContainer.prototype.size = function()
{
  return this.keyNameUris_.length;
};

/**
 * Add a key with name keyName into the container. If a key with the same name
 * already exists, this replaces it.
 * @param {Buffer} key The buffer of encoded key bytes.
 * @param {Name} keyName The name of the key, which is copied.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibKey object, or a
 * promise rejected with Error if the name of the key does not match the
 * identity name.
 */
PibKeyContainer.prototype.addPromise = function(key, keyName, useSync)
{
  if (!this.identityName_.equals(PibKey.extractIdentityFromKeyName(keyName)))
    return SyncPromise.reject(new Error("The key name `" + keyName.toUri() +
      "` does not match the identity name `" +
      this.identityName_.toUri() + "`"));

  var keyNameUri = keyName.toUri();
  if (this.keyNameUris_.indexOf(keyNameUri) < 0)
    // Not already in the set.
    this.keyNameUris_.push(keyNameUri);

  var thisContainer = this;

  return PibKeyImpl.makePromise(keyName, key, this.pibImpl_, useSync)
  .then(function(pibKeyImpl) {
    thisContainer.keys_[keyNameUri] = pibKeyImpl;

    return thisContainer.getPromise(keyName, useSync);
  });
};

/**
 * Remove the key with name keyName from the container, and its related
 * certificates. If the key does not exist, do nothing.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with Error if keyName does not match the identity name.
 */
PibKeyContainer.prototype.removePromise = function(keyName, useSync)
{
  if (!this.identityName_.equals(PibKey.extractIdentityFromKeyName(keyName)))
    return SyncPromise.reject(new Error("Key name `" + keyName.toUri() +
      "` does not match identity `" + this.identityName_.toUri() + "`"));

  var keyNameUri = keyName.toUri();
  var index = this.keyNameUris_.indexOf(keyNameUri);
  // Do nothing if it doesn't exist.
  if (index >= 0)
    this.keyNameUris_.splice(index, 1);

  delete this.keys_[keyNameUri];

  return this.pibImpl_.removeKeyPromise(keyName, useSync);
};

/**
 * Get the key with name keyName from the container.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibKey object, or a
 * promise rejected with Error if keyName does not match the identity name, or a
 * promise rejected with Pib.Error if the key does not exist.
 */
PibKeyContainer.prototype.getPromise = function(keyName, useSync)
{
  if (!this.identityName_.equals(PibKey.extractIdentityFromKeyName(keyName)))
    return SyncPromise.reject(new Error("Key name `" + keyName.toUri() +
      "` does not match identity `" + this.identityName_.toUri() + "`"));

  var keyNameUri = keyName.toUri();
  var pibKeyImpl = this.keys_[keyNameUri];

  if (pibKeyImpl == undefined) {
    var thisContainer = this;

    return PibKeyImpl.makePromise(keyName, this.pibImpl_, useSync)
    .then(function(pibKeyImpl) {
      thisContainer.keys_[keyNameUri] = pibKeyImpl;

      return SyncPromise.resolve(new PibKey(pibKeyImpl));
    });
  }
  else
    return SyncPromise.resolve(new PibKey(pibKeyImpl));
};

/**
 * Get the names of all the keys in the container.
 * @return {Array<Name>} A new list of Name.
 */
PibKeyContainer.prototype.getKeyNames = function()
{
  var result = [];

  for (var nameUri in this.keys_)
    result.push(new Name(nameUri));

  return result;
};
