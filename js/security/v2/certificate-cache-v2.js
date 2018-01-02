/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-cache.cpp
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
var CertificateV2 = require('./certificate-v2.js').CertificateV2;

/**
 * A CertificateCacheV2 holds other user's verified certificates in security v2
 * format CertificateV2. A certificate is removed no later than its NotAfter
 * time, or maxLifetime after it has been added to the cache.
 *
 * Create a CertificateCacheV2.
 * @param {number} maxLifetimeMilliseconds (optional) The maximum time that
 * certificates can live inside the cache, in milliseconds. If omitted, use
 * getDefaultLifetime().
 * @constructor
 */
var CertificateCacheV2 = function CertificateCacheV2(maxLifetimeMilliseconds)
{
  // Array of objects with fields "name" of type Name and "certificate" of type
  // CertificateV2. We can't use an {} object since the Name key itself is an
  // object, and also it needs to be sorted by Name.
  this.certificatesByName_ = [];
  this.maxLifetimeMilliseconds_ = (maxLifetimeMilliseconds == undefined ?
    CertificateCacheV2.getDefaultLifetime() : maxLifetimeMilliseconds);
};

exports.CertificateCacheV2 = CertificateCacheV2;

/**
 * Insert the certificate into the cache. The inserted certificate will be
 * removed no later than its NotAfter time, or maxLifetimeMilliseconds given to
 * the constructor.
 * @param {CertificateV2} certificate The certificate object, which is copied.
 */
CertificateCacheV2.prototype.insert = function(certificate)
{
  // TODO: Implement certificatesByTime_ to support refresh(). There can be
  // multiple certificate for the same removalTime, and adding the same
  // certificate again should update the removalTime.

  var certificateCopy = new CertificateV2(certificate);

  var name = certificateCopy.getName();
  var i = this.findFirstByName_(name);
  if (i < 0)
    // Not found, so set to insert at the end of the list.
    i = this.certificatesByName_.length;
  else {
    if (this.certificatesByName_[i].name.equals(name)) {
      // Just replace the existing entry value.
      this.certificatesByName_[i].certificate = certificateCopy;
      return;
    }
  }

  this.certificatesByName_.splice(i, 0, {name: name, certificate: certificateCopy});
};

/**
 * Find the certificate by the given prefix or interest.
 * @param {Name|Interest} prefixOrInterest If a Name, return the first
 * certificate (ordered by name) where the Name is a prefix of the certificate
 * name. If an Interest, return the first certificate (ordered by Name) where
 * interest.matchesData(certificate) .
 * @return {CertificateV2}  The found certificate, or null if not found. You 
 * must not modify the returned object. If you need to modify it, then make a
 * copy.
 * @note ChildSelector is not supported.
 */
CertificateCacheV2.prototype.find = function(prefixOrInterest)
{
  if (prefixOrInterest instanceof Name) {
    var certificatePrefix = prefixOrInterest;

    if (certificatePrefix.size() > 0 &&
        certificatePrefix.get(-1).isImplicitSha256Digest())
      console.log
        ("Certificate search using a name with an implicit digest is not yet supported");

    // TODO: refresh();

    var i = this.findFirstByName_(certificatePrefix);
    if (i < 0)
      return null;

    var entry = this.certificatesByName_[i];
    if (!certificatePrefix.isPrefixOf(entry.certificate.getName()))
      return null;
    return entry.certificate;
  }
  else {
    var interest = prefixOrInterest;

    if (interest.getChildSelector() >= 0)
      console.log
        ("Certificate search using a ChildSelector is not supported. Searching as if this selector not specified");

    if (interest.getName().size() > 0 &&
        interest.getName().get(-1).isImplicitSha256Digest())
      console.log
        ("Certificate search using a name with an implicit digest is not yet supported");

    // TODO: refresh();

    var i = this.findFirstByName_(interest.getName());
    if (i < 0)
      return null;

    // Search the remaining entries.
    for (; i < this.certificatesByName_.length; ++i) {
      var certificate = this.certificatesByName_[i].certificate;
      if (!interest.getName().isPrefixOf(certificate.getName()))
        break;

      if (interest.matchesData(certificate))
        return certificate;
    }

    return null;
  }
};

/**
 * Remove the certificate whose name equals the given name. If no such
 * certificate is in the cache, do nothing.
 * @param {Name} certificateName The name of the certificate.
 */
CertificateCacheV2.prototype.deleteCertificate = function(certificateName)
{
  for (var i = 0; i < this.certificatesByName_.length; ++i) {
    if (this.certificatesByName_[i].name.equals(certificateName)) {
      this.certificatesByName_.splice(i, 1);
      return;
    }
  }

  // TODO: Delete from certificatesByTime_.
};

/**
 * Clear all certificates from the cache.
 */
CertificateCacheV2.prototype.clear = function()
{
  this.certificatesByName_ = [];
  // TODO: certificatesByTime_.clear();
};
/**
 * Get the default maximum lifetime (1 hour).
 * @return {number} The lifetime in milliseconds.
 */
CertificateCacheV2.getDefaultLifetime = function() { return 3600.0 * 1000; };

/**
 * A private helper method to get the first entry in certificatesByName_ whose
 * name is greater than or equal to the given name.
 * @param {Name} name The name to search for.
 * @return {number} The index of the found certificatesByName_ entry, or -1 if
 * not found.
 */
CertificateCacheV2.prototype.findFirstByName_ = function(name)
{
  for (var i = 0; i < this.certificatesByName_.length; ++i) {
    if (this.certificatesByName_[i].name.compare(name) >= 0)
      return i;
  }

  return -1;
};
