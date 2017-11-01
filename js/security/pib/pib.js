/**
 * Copyright (C) 2017 Regents of the University of California.
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
  // Must access this through getIdentitiesPromise_.
  this.identities_ = null;
  this.pibImpl_ = pibImpl;

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
 * @returns {Promise|SyncPromise} A promise which fulfills when finished.
 */
Pib.prototype.setTpmLocatorPromise = function(tpmLocator)
{
  var thisPib = this;

  return this.pibImpl_.getTpmLocatorPromise()
  .then(function(pibTpmLocator) {
    if (tpmLocator == pibTpmLocator)
      return SyncPromise.resolve();

    return thisPib.resetPromise_();
  })
  .then(function() {
    return thisPib.pibImpl_.setTpmLocatorPromise(tpmLocator);
  });
};

/**
 * Get the TPM Locator.
 * @return {Promise|SyncPromise} A promise which returns the TPM locator string,
 * or a promise rejected with Pib.Error if the TPM locator is empty.
 */
Pib.prototype.getTpmLocatorPromise = function()
{
  return this.pibImpl_.getTpmLocatorPromise()
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
 * @return {Promise|SyncPromise} A promise which returns the PibIdentity object,
 * or a promise rejected with Pib.Error if the identity does not exist.
 */
Pib.prototype.getIdentityPromise = function(identityName)
{
  return this.getIdentitiesPromise_()
  .then(function(identities) {
    return identities.getPromise(identityName);
  });
};

/**
 * Get the default identity.
 * @return {Promise|SyncPromise} A promise which returns the PibIdentity object
 * of the default identity, or a promise rejected with Pib.Error for no default
 * identity.
 */
Pib.prototype.getDefaultIdentityPromise = function()
{
  if (this.defaultIdentity_ == null) {
    var thisPib = this;
    var identities;

    return this.getIdentitiesPromise_()
    .then(function(localIdentities) {
      identities = localIdentities;
      return thisPib.pibImpl_.getDefaultIdentityPromise();
    })
    .then(function(defaultIdentity) {
      return identities.getPromise(defaultIdentity);
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
 * Reset the content in the PIB, including a reset of the TPM locator. This
 * should only be called by KeyChain.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
Pib.prototype.resetPromise_ = function()
{
  var thisPib = this;

  return this.pibImpl_.clearIdentitiesPromise()
  .then(function() {
    return thisPib.pibImpl_.setTpmLocatorPromise("");
  })
  .then(function() {
    thisPib.defaultIdentity_ = null;
    return thisPib.getIdentitiesPromise_()
  })
  .then(function(identities) {
    return identities.resetPromise();
  });
};

/**
 * Add an identity with name identityName. Create the identity if it does not
 * exist. This should only be called by KeyChain.
 * @param {Name} identityName The name of the identity, which is copied.
 * @return {Promise|SyncPromise} A promise which returns the PibIdentity object
 * of the added identity.
 */
Pib.prototype.addIdentityPromise_ = function(identityName)
{
  return this.getIdentitiesPromise_()
  .then(function(identities) {
    return identities.addPromise(identityName);
  });
};

/**
 * Remove the identity with name identityName, and its related keys and
 * certificates. If the default identity is being removed, no default identity
 * will be selected.  If the identity does not exist, do nothing. This should
 * only be called by KeyChain.
 * @param {Name} identityName The name of the identity.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
Pib.prototype.removeIdentityPromise_ = function(identityName)
{
  if (this.defaultIdentity_ != null &&
      this.defaultIdentity_.getName().equals(identityName))
    this.defaultIdentity_ = null;

  return this.getIdentitiesPromise_()
  .then(function(identities) {
    return identities.removePromise(identityName);
  });
};

/**
 * Set the identity with name identityName as the default identity. Create the
 * identity if it does not exist. This should only be called by KeyChain.
 * @param {Name} identityName The name of the identity.
 * @return {Promise|SyncPromise} A promise which returns the PibIdentity object
 * of the default identity.
 */
Pib.prototype.setDefaultIdentityPromise_ = function(identityName)
{
  var thisPib = this;

  return this.getIdentitiesPromise_()
  .then(function(identities) {
    return identities.addPromise(identityName);
  })
  .then(function(identity) {
    thisPib.defaultIdentity_ = identity;

    return thisPib.pibImpl_.setDefaultIdentity(identityName);
  })
  .then(function() {
    return SyncPromise.resolve(thisPib.defaultIdentity_);
  });
};

/**
 * If this.identities_ is not null, return it. Otherwise, set it using
 * PibIdentityContainer.makePromise.
 * return {Promise|SyncPromise} A promise which returns the PibIdentityContainer.
 */
Pib.prototype.getIdentitiesPromise_ = function()
{
  if (this.identities_ != null)
    return SyncPromise.resolve(this.identities_);

  var thisPib = this;
  return PibIdentityContainer.makePromise(this.pibImpl_)
  .then(function(container) {
    thisPib.identities_ = container;
    return SyncPromise.resolve(container);
  });
};

// Put this last to avoid a require loop.
 /** @ignore */
var PibIdentityContainer = require('./pib-identity-container.js').PibIdentityContainer;
