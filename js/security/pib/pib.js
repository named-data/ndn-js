/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib.cpp
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
var ConfigFile = require('../../util/config-file.js').ConfigFile; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * In general, a PIB (Public Information Base) stores the public portion of a
 * user's cryptography keys. The format and location of stored information is
 * indicated by the PIB locator. A PIB is designed to work with a TPM (Trusted
 * Platform Module) which stores private keys. There is a one-to-one association
 * between a PIB and a TPM, and therefore the TPM locator is recorded by the PIB
 * to enforce this association and prevent one from operating on mismatched PIB
 * and TPM.
 *
 * Information in the PIB is organized in a hierarchy of
 * Identity-Key-Certificate. At the top level, this Pib class provides access to
 * identities, and allows setting a default identity. Properties of an identity
 * (such as PibKey objects) can be accessed after obtaining a PibIdentity object.
 * (Likewise, CertificateV2 objects can be obtained from a PibKey object.)
 *
 * Note: A Pib instance is created and managed only by the KeyChain, and is
 * returned by the KeyChain getPib() method.
 *
 * Create a Pib instance. This constructor should only be called by KeyChain.
 *
 * @param {string} scheme The scheme for the PIB.
 * @param {string} location The location for the PIB.
 * @param {PibImpl} pibImpl The PIB backend implementation.
 * @constructor
 */
var Pib = function Pib(scheme, location, pibImpl)
{
  this.defaultIdentity_ = null;
  this.scheme_ = scheme;
  this.location_ = location;
  // Must call initializePromise_ before accessing this.
  this.identities_ = null;
  this.pibImpl_ = pibImpl;
  this.initializeTpm_ = null;
  this.initializePibLocator_ = null;
  this.initializeTpmLocator_ = null;
  this.initializeAllowReset_ = false;
  this.isInitialized_ = false;

  if (pibImpl == null)
    throw new Error("The pibImpl is null");
};

exports.Pib = Pib;

/**
 * Create a Pib.Error which represents a semantic error in PIB processing.
 * Call with: throw new Pib.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
Pib.Error = function PibError(error)
{
  if (error) {
    error.__proto__ = Pib.Error.prototype;
    return error;
  }
};

Pib.Error.prototype = new Error();
Pib.Error.prototype.name = "PibError";

/**
 * Get the scheme of the PIB locator.
 * @return {string} The scheme string.
 */
Pib.prototype.getScheme = function() { return this.scheme_; };

/**
 * Get the PIB locator.
 * @return {string} The PIB locator.
 */
Pib.prototype.getPibLocator = function()
{
  return this.scheme_ + ":" + this.location_;
};

/**
 * Set the corresponding TPM information to tpmLocator. If the tpmLocator is
 * different from the existing one, the PIB will be reset. Otherwise, nothing
 * will be changed.
 * @param {string} tpmLocator The TPM locator.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
Pib.prototype.setTpmLocatorPromise = function(tpmLocator, useSync)
{
  var thisPib = this;
  return this.initializePromise_(useSync)
  .then(function() {
    return thisPib.doSetTpmLocatorPromise_(tpmLocator, useSync);
  })
};

/**
 * Do the work of setTpmLocatorPromise without calling initializePromise_.
 * @param {string} tpmLocator The TPM locator.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
Pib.prototype.doSetTpmLocatorPromise_ = function(tpmLocator, useSync)
{
  var thisPib = this;

  return this.pibImpl_.getTpmLocatorPromise(useSync)
  .then(function(pibTpmLocator) {
    if (tpmLocator == pibTpmLocator)
      return SyncPromise.resolve();
    else {
      return thisPib.resetPromise_(useSync)
      .then(function() {
        return thisPib.pibImpl_.setTpmLocatorPromise(tpmLocator, useSync);
      });
    }
  });
};

/**
 * Get the TPM Locator.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the TPM locator string,
 * or a promise rejected with Pib.Error if the TPM locator is empty.
 */
Pib.prototype.getTpmLocatorPromise = function(useSync)
{
  var thisPib = this;

  return this.initializePromise_(useSync)
  .then(function() {
    return thisPib.pibImpl_.getTpmLocatorPromise(useSync);
  })
  .then(function(tpmLocator) {
    if (tpmLocator == "")
      return SyncPromise.reject(new Pib.Error(new Error
        ("TPM info does not exist")));

    return SyncPromise.resolve(tpmLocator);
  });
};

/**
 * Get the identity with name identityName.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibIdentity object,
 * or a promise rejected with Pib.Error if the identity does not exist.
 */
Pib.prototype.getIdentityPromise = function(identityName, useSync)
{
  var thisPib = this;

  return this.initializePromise_(useSync)
  .then(function() {
    return thisPib.identities_.getPromise(identityName, useSync);
  });
};

/**
 * Get the identity with name identityName.
 * @param {Name} identityName The name of the identity.
 * @param {function} onComplete (optional) This calls
 * onComplete(identity) with the PibIdentity object. If omitted, the return
 * value is described below. (Some database libraries only use a callback, so
 * onComplete is required to use these.)
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
 * @return {PibIdentity} If onComplete is omitted, return the PibIdentity object.
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 * @throws Pib.Error if the identity does not exist. However, if onComplete and
 * onError are defined, then if there is an exception return undefined and call
 * onError(exception).
 */
Pib.prototype.getIdentity = function(identityName, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.getIdentityPromise(identityName, !onComplete));
};

/**
 * Get the default identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibIdentity object
 * of the default identity, or a promise rejected with Pib.Error for no default
 * identity.
 */
Pib.prototype.getDefaultIdentityPromise = function(useSync)
{
  if (this.defaultIdentity_ == null) {
    var thisPib = this;

    return this.initializePromise_(useSync)
    .then(function() {
      return thisPib.pibImpl_.getDefaultIdentityPromise(useSync);
    })
    .then(function(defaultIdentity) {
      return thisPib.identities_.getPromise(defaultIdentity, useSync);
    })
    .then(function(identity) {
      thisPib.defaultIdentity_ = identity;
      return SyncPromise.resolve(thisPib.defaultIdentity_);
    });
  }
  else
    return SyncPromise.resolve(this.defaultIdentity_);
};

/**
 * Get the default identity.
 * @param {function} onComplete (optional) This calls
 * onComplete(identity) with the PibIdentity object. If omitted, the return
 * value is described below. (Some database libraries only use a callback, so
 * onComplete is required to use these.)
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
 * @return {PibIdentity} If onComplete is omitted, return the PibIdentity object.
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 * @throws Pib.Error for no default identity. However, if onComplete and onError
 * are defined, then if there is an exception return undefined and call
 * onError(exception).
 */
Pib.prototype.getDefaultIdentity = function(onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.getDefaultIdentityPromise(!onComplete));
};

/**
 * Reset the content in the PIB, including a reset of the TPM locator. This
 * should only be called by initializeFromLocatorsPromise_.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
Pib.prototype.resetPromise_ = function(useSync)
{
  var thisPib = this;

  // Don't call initializePromise_ since this is already being called by it.
  return this.pibImpl_.clearIdentitiesPromise(useSync)
  .then(function() {
    return thisPib.pibImpl_.setTpmLocatorPromise("", useSync);
  })
  .then(function() {
    thisPib.defaultIdentity_ = null;

    // Call PibIdentityContainer.makePromise the same as initializePromise_ .
    return PibIdentityContainer.makePromise(thisPib.pibImpl_, useSync);
  })
  .then(function(container) {
    thisPib.identities_ = container;
    return thisPib.identities_.resetPromise(useSync);
  });
};

/**
 * Add an identity with name identityName. Create the identity if it does not
 * exist. This should only be called by KeyChain.
 * @param {Name} identityName The name of the identity, which is copied.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibIdentity object
 * of the added identity.
 */
Pib.prototype.addIdentityPromise_ = function(identityName, useSync)
{
  var thisPib = this;
  return this.initializePromise_(useSync)
  .then(function() {
    return thisPib.identities_.addPromise(identityName, useSync);
  });
};

/**
 * Remove the identity with name identityName, and its related keys and
 * certificates. If the default identity is being removed, no default identity
 * will be selected.  If the identity does not exist, do nothing. This should
 * only be called by KeyChain.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
Pib.prototype.removeIdentityPromise_ = function(identityName, useSync)
{
  if (this.defaultIdentity_ != null &&
      this.defaultIdentity_.getName().equals(identityName))
    this.defaultIdentity_ = null;

  var thisPib = this;
  return this.initializePromise_(useSync)
  .then(function() {
    return thisPib.identities_.removePromise(identityName, useSync);
  });
};

/**
 * Set the identity with name identityName as the default identity. Create the
 * identity if it does not exist. This should only be called by KeyChain.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibIdentity object
 * of the default identity.
 */
Pib.prototype.setDefaultIdentityPromise_ = function(identityName, useSync)
{
  var thisPib = this;

  return this.initializePromise_(useSync)
  .then(function() {
    return thisPib.identities_.addPromise(identityName, useSync);
  })
  .then(function(identity) {
    thisPib.defaultIdentity_ = identity;

    return thisPib.pibImpl_.setDefaultIdentityPromise(identityName);
  })
  .then(function() {
    return SyncPromise.resolve(thisPib.defaultIdentity_);
  });
};

/**
 * If isInitialized_ is false, initialize identities_ using
 * PibIdentityContainer.makePromise and set isInitialized_. However, if
 * isInitialized_ is already true, do nothing. This must be called by each
 * method before using this object. This is necessary because the constructor
 * cannot perform async operations.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
Pib.prototype.initializePromise_ = function(useSync)
{
  if (this.isInitialized_)
    return SyncPromise.resolve();

  var thisPib = this;
  return PibIdentityContainer.makePromise(this.pibImpl_, useSync)
  .then(function(container) {
    thisPib.identities_ = container;

    if (thisPib.initializeTpm_ != null)
      return thisPib.initializeFromLocatorsPromise_(useSync);
    else
      return SyncPromise.resolve();
  })
  .then(function() {
    thisPib.isInitialized_ = true;
    return SyncPromise.resolve();
  });
};

/**
 * Initialize from initializePibLocator_ and initializeTpmLocator_ in the same
 * way that the KeyChain constructor would if it could do async operations. Set
 * up initializeTpm_ and set its isInitialized_ true.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
Pib.prototype.initializeFromLocatorsPromise_ = function(useSync)
{
  // Repeat this from the KeyChain constructor.
  var pibScheme = [null];
  var pibLocation = [null];
  KeyChain.parseAndCheckPibLocator_
    (this.initializePibLocator_, pibScheme, pibLocation);
  var canonicalPibLocator = pibScheme[0] + ":" + pibLocation[0];

  var canonicalTpmLocator;
  var thisPib = this;
  return this.pibImpl_.getTpmLocatorPromise(useSync)
  .then(function(oldTpmLocator) {
    // TPM locator.
    var tpmScheme = [null];
    var tpmLocation = [null];
    KeyChain.parseAndCheckTpmLocator_
      (thisPib.initializeTpmLocator_, tpmScheme, tpmLocation);
    canonicalTpmLocator = tpmScheme[0] + ":" + tpmLocation[0];

    var resetPib = false;
    var config;
    if (ConfigFile)
      // Assume we are not in the browser.
      config = new ConfigFile();
    if (ConfigFile && canonicalPibLocator == KeyChain.getDefaultPibLocator_(config)) {
      // The default PIB must use the default TPM.
      if (oldTpmLocator != "" &&
          oldTpmLocator != KeyChain.getDefaultTpmLocator_(config)) {
        resetPib = true;
        canonicalTpmLocator = KeyChain.getDefaultTpmLocator_(config);
      }
    }
    else {
      // Check the consistency of the non-default PIB.
      if (oldTpmLocator != "" && oldTpmLocator != canonicalTpmLocator) {
        if (thisPib.initializeAllowReset_)
          resetPib = true;
        else
          return SyncPromise.reject(new LocatorMismatchError(new Error
            ("The supplied TPM locator does not match the TPM locator in the PIB: " +
             oldTpmLocator + " != " + canonicalTpmLocator)));
      }
    }

    if (resetPib)
      return thisPib.resetPromise_(useSync);
    else
      return SyncPromise.resolve();
  })
  .then(function() {
    // Note that a key mismatch may still happen if the TPM locator is initially
    // set to a wrong one or if the PIB was shared by more than one TPM before.
    // This is due to the old PIB not having TPM info. The new PIB should not
    // have this problem.
    KeyChain.setUpTpm_(thisPib.initializeTpm_, canonicalTpmLocator);
    thisPib.initializeTpm_.isInitialized_ = true;
    return thisPib.doSetTpmLocatorPromise_(canonicalTpmLocator, useSync);
  });
};

// Put these last to avoid a require loop.
/** @ignore */
var KeyChain = require('../key-chain.js').KeyChain; /** @ignore */
var LocatorMismatchError = require('../key-chain.js').LocatorMismatchError; /** @ignore */
var PibIdentityContainer = require('./pib-identity-container.js').PibIdentityContainer;
