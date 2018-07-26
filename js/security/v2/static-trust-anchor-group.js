/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/trust-anchor-group.cpp
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
var TrustAnchorGroup = require('./trust-anchor-group.js').TrustAnchorGroup;

/**
 * The StaticTrustAnchorGroup class extends TrustAnchorGroup to implement a
 * static trust anchor group.
 *
 * Create a StaticTrustAnchorGroup to use an existing container.
 * @param {CertificateContainer} certificateContainer The existing certificate
 * container which implements the CertificateContainer interface.
 * @param {string} id The group ID.
 * @constructor
 */
var StaticTrustAnchorGroup = function StaticTrustAnchorGroup
  (certificateContainer, id)
{
  // Call the base constructor.
  TrustAnchorGroup.call(this, certificateContainer, id);
};

StaticTrustAnchorGroup.prototype = new TrustAnchorGroup();
StaticTrustAnchorGroup.prototype.name = "StaticTrustAnchorGroup";

exports.StaticTrustAnchorGroup = StaticTrustAnchorGroup;

/**
 * Load the static anchor certificate. If a certificate with the name is already
 * added, do nothing.
 * @param {CertificateV2} certificate The certificate to add, which is copied.
 */
StaticTrustAnchorGroup.prototype.add = function(certificate)
{
  var certificateNameUri = certificate.getName().toUri();
  if (this.anchorNameUris_[certificateNameUri])
    return;

  this.anchorNameUris_[certificateNameUri] = true;
  // This copies the certificate.
  this.certificates_.add(certificate);
};

/**
 * Remove the static anchor with the certificate name.
 * @param {Name} certificateName The certificate name.
 */
StaticTrustAnchorGroup.prototype.remove = function(certificateName)
{
  delete this.anchorNameUris_[certificateName.toUri()];
  this.certificates_.remove(certificateName);
};
