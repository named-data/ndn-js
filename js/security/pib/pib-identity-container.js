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
var PibIdentity = require('./pib-identity.js').PibIdentity; /** @ignore */
var PibIdentityImpl = require('./detail/pib-identity-impl.js').PibIdentityImpl; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * A PibIdentityContainer is used to search/enumerate the identities in a PIB.
 * (A PibIdentityContainer object can only be created by the Pib class.)
 *
 * You should not call this private constructor. Instead, use
 * PibIdentityContainer.makePromise().
 *
 * @param {PibImpl} pibImpl The PIB backend implementation.
 * @param {Array<Name>} identityNames The set of identity names as an array of
 * Name, as returned by getIdentitiesPromise.
 * @constructor
 */
var PibIdentityContainer = function PibIdentityContainer(pibImpl, identityNames)
{
  // Cache of loaded PibIdentityImpl objects. Name URI string => PibIdentityImpl.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.identities_ = {};

  this.pibImpl_ = pibImpl;

  if (pibImpl == null)
    throw new Error("The pibImpl is null");

  // A set of Name URI string.
  // (Use a string because we can't use indexOf with a Name object.)
  this.identityNameUris_ = [];
  for (var i in identityNames)
    this.identityNameUris_.push(identityNames[i].toUri());
};

exports.PibIdentityContainer = PibIdentityContainer;

/**
 * Create a PibIdentityContainer using to use the pibImpl backend implementation.
 * This method that returns a Promise is needed instead of a normal constructor
 * since it uses asynchronous PibImpl methods to initialize the object.
 * This method should only be called by Pib.
 *
 * @param {PibImpl} pibImpl The PIB backend implementation.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @param {Promise|SyncPromise} A promise which returns the new
 * PibIdentityContainer.
 */
PibIdentityContainer.makePromise = function(pibImpl, useSync)
{
  if (pibImpl == null)
    return SyncPromise.reject(new Error("The pibImpl is null"));

  return pibImpl.getIdentitiesPromise(useSync)
  .then(function(identityNames) {
    return SyncPromise.resolve(new PibIdentityContainer(pibImpl, identityNames));
  });
};

/**
 * Get the number of identities in the container.
 * @return {number} The number of identities.
 */
PibIdentityContainer.prototype.size = function()
{
  return this.identityNameUris_.length;
};

/**
 * Add an identity with name identityName into the container. Create the
 * identity if it does not exist.
 * @param {Name} identityName The name of the identity, which is copied.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the PibIdentity object.
 */
PibIdentityContainer.prototype.addPromise = function(identityName, useSync)
{
  var identityNameUri = identityName.toUri();
  if (this.identityNameUris_.indexOf(identityNameUri) < 0) {
    var thisContainer = this;

    this.identityNameUris_.push(identityNameUri);
    return PibIdentityImpl.makePromise(identityName, this.pibImpl_, true, useSync)
    .then(function(pibIdentityImpl) {
      thisContainer.identities_[identityNameUri] = pibIdentityImpl;
      return thisContainer.getPromise(identityName, useSync);
    });
  }
  else
    return this.getPromise(identityName, useSync);
};

/**
 * Remove the identity with name identityName from the container, and its
 * related keys and certificates. If the default identity is being removed, no
 * default identity will be selected. If the identity does not exist, do nothing.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
PibIdentityContainer.prototype.removePromise = function(identityName, useSync)
{
  var identityNameUri = identityName.toUri();
  var index = this.identityNameUris_.indexOf(identityNameUri);
  // Do nothing if it doesn't exist.
  if (index >= 0)
    this.identityNameUris_.splice(index, 1);

  delete this.identities_[identityNameUri];

  return this.pibImpl_.removeIdentityPromise(identityName, useSync);
};

/**
 * Get the identity with name identityName from the container.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {SyncPromise} A promise which returns the PibIdentity object, or a
 * promise rejected with Pib.Error if the identity does not exist.
 */
PibIdentityContainer.prototype.getPromise = function(identityName, useSync)
{
  var identityNameUri = identityName.toUri();
  var pibIdentityImpl = this.identities_[identityNameUri];

  if (pibIdentityImpl == undefined) {
    var thisContainer = this;

    return PibIdentityImpl.makePromise(identityName, this.pibImpl_, false, useSync)
    .then(function(pibIdentityImpl) {
      thisContainer.identities_[identityNameUri] = pibIdentityImpl;

      return SyncPromise.resolve(new PibIdentity(pibIdentityImpl));
    });
  }
  else
    return SyncPromise.resolve(new PibIdentity(pibIdentityImpl));
};

/**
 * Reset the state of the container. This method removes all loaded identities
 * and retrieves identity names from the PIB implementation.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {SyncPromise} A promise which fulfills when finished.
 */
PibIdentityContainer.prototype.resetPromise = function(useSync)
{
  var thisContainer = this;

  this.identities_ = {};
  return this.pibImpl_.getIdentitiesPromise(useSync)
  .then(function(identityNames) {
    thisContainer.identityNameUris_ = [];
    for (var i in identityNames)
      thisContainer.identityNameUris_.push(identityNames[i].toUri());

    return SyncPromise.resolve();
  });
};
