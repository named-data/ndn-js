/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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
var DerNode = require('../../encoding/der/der-node.js').DerNode; /** @ignore */
var OID = require('../../encoding/oid.js').OID;

/**
 * A CertificateExtension represents the Extension entry in a certificate.
 * Create a new CertificateExtension.
 * @param {string|OID} oid The oid of subject description entry.
 * @param {boolean} isCritical If true, the extension must be handled.
 * @param {Blob} value The extension value.
 * @constructor
 */
var CertificateExtension = function CertificateExtension(oid, isCritical, value)
{
  if (typeof oid === 'string')
    this.extensionId = new OID(oid);
  else
    // Assume oid is already an OID.
    this.extensionId = oid;

  this.isCritical = isCritical;
  this.extensionValue = value;
};

exports.CertificateExtension = CertificateExtension;

/**
 * Encode the object into a DER syntax tree.
 * @return {DerNode} The encoded DER syntax tree.
 */
CertificateExtension.prototype.toDer = function()
{
  var root = new DerNode.DerSequence();

  var extensionId = new DerNode.DerOid(this.extensionId);
  var isCritical = new DerNode.DerBoolean(this.isCritical);
  var extensionValue = new DerNode.DerOctetString(this.extensionValue.buf());

  root.addChild(extensionId);
  root.addChild(isCritical);
  root.addChild(extensionValue);

  root.getSize();

  return root;
};

CertificateExtension.prototype.toDerBlob = function()
{
  return this.toDer().encode();
};

CertificateExtension.prototype.getOid = function()
{
  return this.extensionId;
};

CertificateExtension.prototype.getIsCritical = function()
{
  return this.isCritical;
};

CertificateExtension.prototype.getValue = function()
{
  return this.extensionValue;
};
