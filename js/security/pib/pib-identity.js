/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/identity.cpp
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
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * A PibIdentity is at the top level in PIB's Identity-Key-Certificate hierarchy.
 * An identity has a Name, and contains zero or more keys, at most one of which
 * is set as the default key of this identity. Properties of a key can be
 * accessed after obtaining a PibKey object.
 *
 * Create a PibIdentity which uses the impl backend implementation. This
 * constructor should only be called by PibIdentityContainer.
 *
 * @param {PibIdentityImpl} impl The PibIdentityImpl.
 * @constructor
 */
var PibIdentity = function PibIdentity(impl)
{
  this.impl_ = impl;
};

exports.PibIdentity = PibIdentity;

/**
 * Get the name of the identity.
 * @return {Name} The name of the identity. You must not change the Name object.
 * If you need to change it then make a copy.
 * @throws Error if the backend implementation instance is invalid.
 */
PibIdentity.prototype.getName = function()
{
  return this.lock_().getName();
};

/**
 * Get the key with name keyName.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibKey object, or a
 * promise rejected with Pib.Error if the key does not exist, or a promise
 * rejected with Error if the backend implementation instance is invalid.
 */
PibIdentity.prototype.getKeyPromise = function(keyName, useSync)
{
  try {
    return this.lock_().getKeyPromise(keyName, useSync);
  } catch (ex) {
    return SyncPromise.reject(ex);
  }
};

/**
 * Get the key with name keyName.
 * @param {Name} keyName The name of the key.
 * @param {function} onComplete (optional) This calls onComplete(key) with the
 * PibKey object. If omitted, the return value is described below. (Some
 * database libraries only use a callback, so onComplete is required to use
 * these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {PibKey} If onComplete is omitted, return the PibKey object.
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 * @throws Pib.Error if the key does not exist, or Error if the backend
 * implementation instance is invalid. However, if onComplete and onError are
 * defined, then if there is an exception return undefined and call
 * onError(exception).
 */
PibIdentity.prototype.getKey = function(keyName, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.getKeyPromise(keyName, !onComplete));
};

/**
 * Get the default key of this Identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibKey object of
 * the default key, or a promise rejected with Pib.Error if the default key has
 * not been set, or a promise rejected with Error if the backend implementation
 * instance is invalid.
 */
PibIdentity.prototype.getDefaultKeyPromise = function(useSync)
{
  try {
    return this.lock_().getDefaultKeyPromise(useSync);
  } catch (ex) {
    return SyncPromise.reject(ex);
  }
};

/**
 * Get the default key of this Identity.
 * @param {function} onComplete (optional) This calls onComplete(key) with the
 * PibKey object of the default key. If omitted, the return value is described
 * below. (Some database libraries only use a callback, so onComplete is
 * required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {PibKey} If onComplete is omitted, return the PibKey object of the
 * default key. Otherwise, if onComplete is supplied then return undefined and
 * use onComplete as described above.
 * @throws Pib.Error if the default key has not been set, or Error if the
 * backend implementation instance is invalid. However, if onComplete and
 * onError are defined, then if there is an exception return undefined and call
 * onError(exception).
 */
PibIdentity.prototype.getDefaultKey = function(onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.getDefaultKeyPromise(!onComplete));
};

/**
 * Add the key. If a key with the same name already exists, overwrite the key.
 * If no default key for the identity has been set, then set the added key as
 * default for the identity. This should only be called by KeyChain.
 * @param {Buffer} key The public key bits. This copies the buffer.
 * @param {Name} keyName The name of the key. This copies the name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibKey object, or a
 * promise rejected with Error if the backend implementation instance is invalid.
 */
PibIdentity.prototype.addKeyPromise_ = function(key, keyName, useSync)
{
  try {
    return this.lock_().addKeyPromise(key, keyName, useSync);
  } catch (ex) {
    return SyncPromise.reject(ex);
  }
};

/**
 * Remove the key with keyName and its related certificates. If the key does not
 * exist, do nothing. This should only be called by KeyChain.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with Error if the backend implementation instance is invalid.
 */
PibIdentity.prototype.removeKeyPromise_ = function(keyName, useSync)
{
  try {
    return this.lock_().removeKeyPromise(keyName, useSync);
  } catch (ex) {
    return SyncPromise.reject(ex);
  }
};

/**
 * setDefaultKey has two forms:
 * setDefaultKey(keyName, useSync) - Set the key with name keyName as the
 * default key of the identity.
 * setDefaultKey(key, keyName, useSync) - Add a key with name keyName and set it
 * as the default key of the identity.
 * This should only be called by KeyChain.
 * @param {Buffer} key The buffer of encoded key bytes. (This is only used when
 * calling setDefaultKey(key, keyName). )
 * @param {Name} keyName The name of the key. This copies the name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {SyncPromise} A promise which returns the PibKey object of the
 * default key, or a promise rejected with Error the name of the key does not
 * match the identity name (or if the backend implementation instance is
 * invalid), or a promise rejected with Pib.Error if calling
 * setDefaultKey(keyName) and the key does not exist, or if calling
 * setDefaultKey(key, keyName) and a key with the same name already exists.
 */
PibIdentity.prototype.setDefaultKeyPromise_ = function(keyOrKeyName, arg2, arg3)
{
  try {
    return this.lock_().setDefaultKeyPromise(keyOrKeyName, arg2, arg3);
  } catch (ex) {
    return SyncPromise.reject(ex);
  }
};

/**
 * Get the PibKeyContainer in the PibIdentityImpl. This should only be called by
 * KeyChain.
 * @return {PibKeyContainer} The PibKeyContainer.
 */
PibIdentity.prototype.getKeys_ = function()
{
  return this.lock_().keys_;
};

/**
 * Check the validity of the impl_ instance.
 * @return {PibIdentityImpl} The PibIdentityImpl when the instance is valid.
 * @throws Error if the backend implementation instance is invalid.
 */
PibIdentity.prototype.lock_ = function()
{
  if (this.impl_ == null)
    throw new Error("Invalid key instance");

  return this.impl_;
};
