/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/trust-anchor-container.cpp
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
var StaticTrustAnchorGroup = require('./static-trust-anchor-group.js').StaticTrustAnchorGroup; /** @ignore */
var DynamicTrustAnchorGroup = require('./dynamic-trust-anchor-group.js').DynamicTrustAnchorGroup; /** @ignore */
var CertificateV2 = require('./certificate-v2.js').CertificateV2; /** @ignore */
var CertificateContainerInterface = require('./certificate-container-interface.js').CertificateContainerInterface;

/**
 * A TrustAnchorContainer represents a container for trust anchors.
 *
 * There are two kinds of anchors:
 * static anchors that are permanent for the lifetime of the container, and
 * dynamic anchors that are periodically updated.
 *
 * Trust anchors are organized in groups. Each group has a unique group id.
 * The same anchor certificate (same name without considering the implicit
 * digest) can be inserted into multiple groups, but no more than once into each.
 *
 * Dynamic groups are created using the appropriate TrustAnchorContainer.insert
 * method. Once created, the dynamic anchor group cannot be updated.
 *
 * The returned pointer to Certificate from `find` methods is only guaranteed to
 * be valid until the next invocation of `find` and may be invalidated
 * afterwards.
 *
 * Create an empty TrustAnchorContainer.
 * @constructor
 */
var TrustAnchorContainer = function TrustAnchorContainer()
{
  // The key is the group ID string. The value is the TrustAnchorGroup.
  this.groups_ = {};
  this.anchors_ = new TrustAnchorContainer.AnchorContainer_();
};

exports.TrustAnchorContainer = TrustAnchorContainer;

/**
 * Create a TrustAnchorContainer.Error.
 * Call with: throw new TrustAnchorContainer.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
TrustAnchorContainer.Error = function TrustAnchorContainerError(error)
{
  if (error) {
    error.__proto__ = TrustAnchorContainer.Error.prototype;
    return error;
  }
};

TrustAnchorContainer.Error.prototype = new Error();
TrustAnchorContainer.Error.prototype.name = "TrustAnchorContainerError";

/**
 * There are two forms of insert:
 * insert(groupId, certificate) - Insert a static trust anchor. If the
 * certificate (having the same name without considering implicit digest)
 * already exists in the group with groupId, then do nothing.
 * insert(groupId, path, refreshPeriod, isDirectory) - Insert dynamic trust
 * anchors from the path.
 * @param {String} groupId The certificate group id.
 * @param {CertificateV2} certificate The certificate to insert, which is copied.
 * @param {String} path The path to load the trust anchors.
 * @param {number} refreshPeriod  The refresh time in milliseconds for the
 * anchors under path. This must be positive. The relevant trust anchors will
 * only be updated when find is called.
 * @param {boolean} isDirectory (optional) If true, then path is a directory. If
 * false or omitted, it is a single file.
 * @throws TrustAnchorContainer.Error If inserting a static trust anchor and
 * groupId is for a dynamic anchor group , or if inserting a dynamic trust
 * anchor and a group with groupId already exists.
 * @throws Error If refreshPeriod is not positive.
 */
TrustAnchorContainer.prototype.insert = function
  (groupId, certificateOrPath, refreshPeriod, isDirectory)
{
  if (certificateOrPath instanceof CertificateV2) {
    var certificate = certificateOrPath;

    var group = this.groups_[groupId];
    if (group === undefined) {
      group = new StaticTrustAnchorGroup(this.anchors_, groupId);
      this.groups_[groupId] = group;
    }

    if (!(group instanceof StaticTrustAnchorGroup))
      throw new TrustAnchorContainer.Error(new Error
        ("Cannot add a static anchor to the non-static anchor group " + groupId));

    group.add(certificate);
  }
  else {
    var path = certificateOrPath;

    if (isDirectory == null)
      isDirectory = false;

    if (this.groups_[groupId] !== undefined)
      throw new TrustAnchorContainer.Error(new Error
        ("Cannot create the dynamic group, because group " + groupId +
        " already exists"));

    this.groups_[groupId] = new DynamicTrustAnchorGroup
      (this.anchors_, groupId, path, refreshPeriod, isDirectory);
  }
};

/**
 * Remove all static and dynamic anchors.
 */
TrustAnchorContainer.prototype.clear = function()
{
  this.groups_ = {};
  this.anchors_.clear();
};

/**
 * There are two forms of find:
 * find(keyName) - Search for a certificate across all groups (longest prefix
 * match).
 * find(interest) - Find a certificate for the given interest. Note: Interests
 * with implicit digest are not supported.
 * @param {Name} keyName The key name prefix for searching for the certificate.
 * @param {Interest} interest The input interest packet.
 * @return {CertificateV2} The found certificate, or null if not found.
 */
TrustAnchorContainer.prototype.find = function(keyNameOrInterest)
{
  if (keyNameOrInterest instanceof Name) {
    var keyName = keyNameOrInterest;

    this.refresh_();

    var i = this.anchors_.findFirstByName_(keyName);
    if (i < 0)
      return null;
    var certificate = this.anchors_.anchorsByName_[i].certificate;
    if (!keyName.isPrefixOf(certificate.getName()))
      return null;
    return certificate;
  }
  else {
    var interest = keyNameOrInterest;

    this.refresh_();

    var i = this.anchors_.findFirstByName_(interest.getName());
    if (i < 0)
      return null;

    for (; i < this.anchors_.anchorsByName_.length; ++i) {
      var certificate = this.anchors_.anchorsByName_[i].certificate;
      if (!interest.getName().isPrefixOf(certificate.getName()))
        break;
      if (interest.matchesData(certificate))
        return certificate;
    }

    return null;
  }
};

/**
 * Get the trust anchor group for the groupId.
 * @param {String} groupId The group ID.
 * @return {TrustAnchorGroup} The trust anchor group.
 * @throws TrustAnchorContainer.Error if the groupId does not exist.
 */
TrustAnchorContainer.prototype.getGroup = function(groupId)
{
  var group = this.groups_[groupId];
  if (group === undefined)
    throw new TrustAnchorContainer.Error(new Error
      ("Trust anchor group " + groupId + " does not exist"));

  return group;
};

/**
 * Get the number of trust anchors across all groups.
 * @return {number} The number of trust anchors.
 */
TrustAnchorContainer.prototype.size = function()
{
  return this.anchors_.size();
};

TrustAnchorContainer.AnchorContainer_ = function TrustAnchorContainerAnchorContainer()
{
  // Array of objects with fields "name" of type Name and "certificate" of type
  // CertificateV2. We can't use an {} object since the Name key itself is an
  // object, and also it needs to be sorted by Name.
  this.anchorsByName_ = [];
};

TrustAnchorContainer.AnchorContainer_.prototype = new CertificateContainerInterface();
TrustAnchorContainer.AnchorContainer_.prototype.name = "TrustAnchorContainerAnchorContainer";

/**
 * Add the certificate to the container.
 * @param {CertificateV2} certificate The certificate to add, which is copied.
 */
TrustAnchorContainer.AnchorContainer_.prototype.add = function(certificate)
{
  var certificateCopy = new CertificateV2(certificate);

  var name = certificateCopy.getName();
  var i = this.findFirstByName_(name);
  if (i < 0)
    // Not found, so set to insert at the end of the list.
    i = this.anchorsByName_.length;
  else {
    if (this.anchorsByName_[i].name.equals(name)) {
      // Just replace the existing entry value.
      this.anchorsByName_[i].certificate = certificateCopy;
      return;
    }
  }

  this.anchorsByName_.splice(i, 0, {name: name, certificate: certificateCopy});
};

/**
 * Remove the certificate with the given name. If the name does not exist, do
 * nothing.
 * @param {Name} certificateName The name of the certificate.
 */
TrustAnchorContainer.AnchorContainer_.prototype.remove = function(certificateName)
{
  for (var i = 0; i < this.anchorsByName_.length; ++i) {
    if (this.anchorsByName_[i].name.equals(certificateName)) {
      this.anchorsByName_.splice(i, 1);
      return;
    }
  }
};

/**
 * Clear all certificates.
 */
TrustAnchorContainer.AnchorContainer_.prototype.clear = function()
{
  this.anchorsByName_ = [];
};

TrustAnchorContainer.AnchorContainer_.prototype.size = function()
{
  return this.anchorsByName_.length;
};

/**
 * A private helper method to get the first entry in anchorsByName_ whose
 * name is greater than or equal to the given name.
 * @param {Name} name The name to search for.
 * @return {number} The index of the found anchorsByName_ entry, or -1 if
 * not found.
 */
TrustAnchorContainer.AnchorContainer_.prototype.findFirstByName_ = function(name)
{
  for (var i = 0; i < this.anchorsByName_.length; ++i) {
    if (this.anchorsByName_[i].name.compare(name) >= 0)
      return i;
  }

  return -1;
};

TrustAnchorContainer.prototype.refresh_ = function()
{
  for (var groupId in this.groups_)
    this.groups_[groupId].refresh();
};
