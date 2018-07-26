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
var fs = require('fs'); /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var CertificateV2 = require('./certificate-v2.js').CertificateV2;

/**
 * TrustAnchorGroup represents a group of trust anchors which implement the
 * CertificateContainer interface.
 *
 * Create a TrustAnchorGroup to use an existing container.
 * @param {CertificateContainer} certificateContainer The existing certificate
 * container which implements the CertificateContainer interface.
 * @param {string} id The group ID.
 * @constructor
 */
var TrustAnchorGroup = function TrustAnchorGroup(certificateContainer, id)
{
  this.certificates_ = certificateContainer;
  this.id_ = id;

  // The object keys are the set of anchor name URIs, and each value is true.
  this.anchorNameUris_ = {};
};

exports.TrustAnchorGroup = TrustAnchorGroup;

/**
 * Get the group id given to the constructor.
 * @return {string} The group id.
 */
TrustAnchorGroup.prototype.getId = function() { return this.id_; };

/**
 * Get the number of certificates in the group.
 * @return {number} The number of certificates.
 */
TrustAnchorGroup.prototype.size = function()
{
  return Object.keys(this.anchorNameUris_).length;
};

/**
 * Request a certificate refresh. The base method does nothing.
 */
TrustAnchorGroup.prototype.refresh = function() {};

/**
 * Read a base-64-encoded certificate from a file.
 * @param {string} filePath The certificate file path.
 * @return {CertificateV2} The decoded certificate, or null if there is an
 * error.
 */
TrustAnchorGroup.readCertificate = function(filePath)
{
  try {
    var encodedData = fs.readFileSync(filePath).toString();
    var decodedData = new Buffer(encodedData, 'base64');
    var result = new CertificateV2();
    result.wireDecode(new Blob(decodedData, false));
    return result;
  } catch (ex) {
    return null;
  }
};

