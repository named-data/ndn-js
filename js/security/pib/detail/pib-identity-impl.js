/**
 * Copyright (C) 2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/detail/identity-impl.cpp
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
var Name = require('../../../name.js').Name; /** @ignore */
var Pib = require('../pib.js').Pib; /** @ignore */
var PibKeyContainer = require('../pib-key-container.js').PibKeyContainer; /** @ignore */
var SyncPromise = require('../../../util/sync-promise.js').SyncPromise;

/**
 * A PibIdentityImpl provides the backend implementation for PibIdentity. A
 * PibIdentity has only one backend instance, but may have multiple frontend
 * handles. Each frontend handle is associated with the only one backend
 * PibIdentityImpl.
 *
 * You should not call this private constructor. Instead, use
 * PibIdentityImpl.makePromise().
 *
 * @constructor
 */
var PibIdentityImpl = function PibIdentityImpl()
{
  // makePromise will set the fields.
};

exports.PibIdentityImpl = PibIdentityImpl;

/**
 * Create a PibIdentityImpl with identityName.
 * This method that returns a Promise is needed instead of a normal constructor
 * since it uses asynchronous PibImpl methods to initialize the object.
 *
 * @param {Name} identityName The name of the identity, which is copied.
 * @param {PibImpl) pibImpl: The Pib backend implementation.
 * @param {boolean} needInit If true and the identity does not exist in the
 * pibImpl back end, then create it (and If no default identity has been set,
 * identityName becomes the default). If false, then throw Pib.Error if the
 * identity does not exist in the pibImpl back end.
 * @param {Promise|SyncPromise} A promise which returns the new PibIdentityImpl, 
 * or a promise which is rejected with Pib.Error if the identity does not exist
 * in the pibImpl back end and needInit is false.
 */
PibIdentityImpl.makePromise = function(identityName, pibImpl, needInit)
{
  var pibIdentityImpl = new PibIdentityImpl();

  return PibKeyContainer.makePromise(identityName, pibImpl)
  .then(function(container) {
    pibIdentityImpl.defaultKey_ = null;

    // Copy the Name.
    pibIdentityImpl.identityName_ = new Name(identityName);
    pibIdentityImpl.keys_ = container;
    pibIdentityImpl.pibImpl_ = pibImpl;

    if (pibImpl == null)
      return SyncPromise.reject(new Error("The pibImpl is null"));

    if (needInit) {
      return pibImpl.addIdentityPromise(pibIdentityImpl.identityName_)
      .then(function() {
        return SyncPromise.resolve(pibIdentityImpl);
      });
    }
    else {
      return pibImpl.hasIdentityPromise(pibIdentityImpl.identityName_)
      .then(function(hasIdentity) {
        if (!hasIdentity)
          return SyncPromise.reject(new Pib.Error(new Error
            ("Identity " + pibIdentityImpl.identityName_.toUri() +
            " does not exist")));
        else
          return SyncPromise.resolve(pibIdentityImpl);
      });
    }
  });
};

/**
 * Get the name of the identity.
 * @return {Name} The name of the identity. You must not change the Name object.
 * If you need to change it then make a copy.
 */
PibIdentityImpl.prototype.getName = function() { return this.identityName_; };

/**
 * Add the key. If a key with the same name already exists, overwrite the key.
 * If no default key for the identity has been set, then set the added key as
 * default for the identity.
 * @param {Buffer} key The public key bits. This copies the buffer.
 * @param {Name} keyName The name of the key. This copies the name.
 * @return {Promise|SyncPromise} A promise which returns the PibKey object.
 */
PibIdentityImpl.prototype.addKeyPromise = function(key, keyName)
{
  return this.keys_.addPromise(key, keyName);
};

/**
 * Remove the key with keyName and its related certificates. If the key does not
 * exist, do nothing.
 * @param {Name} keyName The name of the key.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
PibIdentityImpl.prototype.removeKeyPromise = function(keyName)
{
  if (this.defaultKey_ !== null && this.defaultKey_.getName().equals(keyName))
    this.defaultKey_ = null;

  return this.keys_.removePromise(keyName);
};

/**
 * Get the key with name keyName.
 * @param {Name} keyName The name of the key.
 * @return {Promise|SyncPromise} A promise which returns the PibKey object, or a
 * promise rejected with Pib.Error if the key does not exist.
 */
PibIdentityImpl.prototype.getKeyPromise = function(keyName)
{
  return this.keys_.getPromise(keyName);
};

/**
 * setDefaultKey has two forms:
 * setDefaultKey(keyName) - Set the key with name keyName as the default key of
 * the identity.
 * setDefaultKey(key, keyName) - Add a key with name keyName and set it as the
 * default key of the identity.
 * @param {Buffer} key The buffer of encoded key bytes. (This is only used when
 * calling setDefaultKey(key, keyName). )
 * @param {Name} keyName The name of the key. This copies the name.
 * @return {SyncPromise} A promise which returns the PibKey object of the 
 * default key, or a promise rejected with Error the name of the key does not
 * match the identity name, or a promise rejected with Pib.Error if calling
 * setDefaultKey(keyName) and the key does not exist, or if calling
 * setDefaultKey(key, keyName) and a key with the same name already exists.
 */
PibIdentityImpl.prototype.setDefaultKeyPromise = function(keyOrKeyName, arg2)
{
  var thisImpl = this;

  if (keyOrKeyName instanceof Name) {
    var keyName = keyOrKeyName;

    return this.keys_.getPromise(keyName)
    .then(function(key) {
      thisImpl.defaultKey_ = key;
      return thisImpl.pibImpl_.setDefaultKeyOfIdentityPromise
        (thisImpl.identityName_, keyName);
    })
    .then(function() {
      return SyncPromise.resolve(thisImpl.defaultKey_);
    });
  }
  else {
    var key = keyOrKeyName;
    var keyName = arg2;

    return this.addKeyPromise(key, keyName)
    .then(function() {
      return thisImpl.setDefaultKeyPromise(keyName);
    });
  }
};

/**
 * Get the default key of this Identity.
 * @return {SyncPromise} A promise which returns the default PibKey, or a
 * promise rejected with Pib.Error if the default key has not been set.
 */
PibIdentityImpl.prototype.getDefaultKeyPromise = function()
{
  var thisImpl = this;

  if (this.defaultKey_ === null) {
    return this.pibImpl_.getDefaultKeyOfIdentityPromise(this.identityName_)
    .then(function(keyName) {
      return thisImpl.keys_.getPromise(keyName);
    })
    .then(function(key) {
      thisImpl.defaultKey_ = key;
      return SyncPromise.resolve(thisImpl.defaultKey_);
    });
  }
  else
    return SyncPromise.resolve(this.defaultKey_);
};
