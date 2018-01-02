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
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var OID = require('../../encoding/oid.js').OID; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode;

/**
 * A CertificateSubjectDescription represents the SubjectDescription entry in a
 * Certificate.
 * Create a new CertificateSubjectDescription.
 * @param {string|OID} oid The oid of the subject description entry.
 * @param {string} value The value of the subject description entry.
 * @constructor
 */
var CertificateSubjectDescription = function CertificateSubjectDescription
  (oid, value)
{
  if (typeof oid === 'string')
    this.oid = new OID(oid);
  else
    // Assume oid is already an OID.
    this.oid = oid;

  this.value = value;
};

exports.CertificateSubjectDescription = CertificateSubjectDescription;

/**
 * Encode the object into a DER syntax tree.
 * @return {DerNode} The encoded DER syntax tree.
 */
CertificateSubjectDescription.prototype.toDer = function()
{
  var root = new DerNode.DerSequence();

  var oid = new DerNode.DerOid(this.oid);
  // Use Blob to convert the String to a ByteBuffer.
  var value = new DerNode.DerPrintableString(new Blob(this.value).buf());

  root.addChild(oid);
  root.addChild(value);

  return root;
};

CertificateSubjectDescription.prototype.getOidString = function()
{
  return this.oid.toString();
};

CertificateSubjectDescription.prototype.getValue = function()
{
  return this.value;
};
