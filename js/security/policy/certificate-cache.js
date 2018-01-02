/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN certificate_cache.py by Adeola Bannis.
 * Originally from Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>.
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
var IdentityCertificate = require('../certificate/identity-certificate.js').IdentityCertificate;

/**
 * A CertificateCache is used to save other users' certificate during
 * verification.
 * @constructor
 */
var CertificateCache = function CertificateCache()
{
  // The key is the certificate name URI. The value is the wire encoding Blob.
  this.cache = {};
};

exports.CertificateCache = CertificateCache;

/**
 * Insert the certificate into the cache. Assumes the timestamp is not yet
 * removed from the name.
 * @param {IdentityCertificate} certificate The certificate to insert.
 */
CertificateCache.prototype.insertCertificate = function(certificate)
{
  var certName = certificate.getName().getPrefix(-1);
  this.cache[certName.toUri()] = certificate.wireEncode();
};

/**
 * Remove a certificate from the cache. This does nothing if it is not present.
 * @param {Name} certificateName The name of the certificate to remove. This
 * assumes there is no timestamp in the name.
 */
CertificateCache.prototype.deleteCertificate = function(certificateName)
{
  delete this.cache[certificateName.toUri()];
};

/**
 * Fetch a certificate from the cache.
 * @param {Name} certificateName The name of the certificate to remove. This
 * assumes there is no timestamp in the name.
 * @return {IdentityCertificate} A new copy of the IdentityCertificate, or null
 * if not found.
 */
CertificateCache.prototype.getCertificate = function(certificateName)
{
  var certData = this.cache[certificateName.toUri()];
  if (certData === undefined)
    return null;

  var cert = new IdentityCertificate();
  cert.wireDecode(certData);
  return cert;
};

/**
 * Clear all certificates from the store.
 */
CertificateCache.prototype.reset = function()
{
  this.cache = {};
};
