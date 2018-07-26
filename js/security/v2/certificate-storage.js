/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-storage.hpp
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
var TrustAnchorContainer = require('./trust-anchor-container.js').TrustAnchorContainer; /** @ignore */
var CertificateV2 = require('./certificate-v2.js').CertificateV2; /** @ignore */
var CertificateCacheV2 = require('./certificate-cache-v2.js').CertificateCacheV2;

/**
 * The CertificateStorage class stores trusted anchors and has a verified
 * certificate cache, and an unverified certificate cache.
 *
 * @constructor
 */
var CertificateStorage = function CertificateStorage()
{
  this.trustAnchors_ = new TrustAnchorContainer();
  this.verifiedCertificateCache_ = new CertificateCacheV2(3600 * 1000.0);
  this.unverifiedCertificateCache_ = new CertificateCacheV2(300 * 1000.0);
};

exports.CertificateStorage = CertificateStorage;

/**
 * Find a trusted certificate in the trust anchor container or in the
 * verified cache.
 * @param {Interest} interestForCertificate The Interest for the certificate.
 * @return {CertificateV2} The found certificate, or null if not found.
 */
CertificateStorage.prototype.findTrustedCertificate = function
  (interestForCertificate)
{
  var certificate = this.trustAnchors_.find(interestForCertificate);
  if (certificate != null)
    return certificate;

  certificate = this.verifiedCertificateCache_.find(interestForCertificate);
  return certificate;
};

/**
 * Check if the certificate with the given name prefix exists in the verified
 * cache, the unverified cache, or in the set of trust anchors.
 * @param {Name} certificatePrefix The certificate name prefix.
 * @return {boolean} True if the certificate is known.
 */
CertificateStorage.prototype.isCertificateKnown = function(certificatePrefix)
{
  return this.trustAnchors_.find(certificatePrefix) != null ||
         this.verifiedCertificateCache_.find(certificatePrefix) != null ||
         this.unverifiedCertificateCache_.find(certificatePrefix) != null;
};

/**
 * Cache the unverified certificate for a period of time (5 minutes).
 * @param {CertificateV2} certificate The certificate packet, which is copied.
 */
CertificateStorage.prototype.cacheUnverifiedCertificate = function(certificate)
{
  this.unverifiedCertificateCache_.insert(certificate);
};

/**
 * Get the trust anchor container.
 * @return {TrustAnchorContainer} The trust anchor container.
 */
CertificateStorage.prototype.getTrustAnchors = function()
{
  return this.trustAnchors_;
};

/**
 * Get the verified certificate cache.
 * @return {CertificateCacheV2} The verified certificate cache.
 */
CertificateStorage.prototype.getVerifiedCertificateCache = function()
{
  return this.verifiedCertificateCache_;
};

/**
 * Get the unverified certificate cache.
 * @return {CertificateCacheV2} The unverified certificate cache.
 */
CertificateStorage.prototype.getUnverifiedCertificateCache = function()
{
  return this.unverifiedCertificateCache_;
};

/**
 * There are two forms of loadAnchor:
 * loadAnchor(groupId, certificate) - Load a static trust anchor. Static trust
 * anchors are permanently associated with the validator and never expire.
 * loadAnchor(groupId, path, refreshPeriod, isDirectory) - Load dynamic trust
 * anchors. Dynamic trust anchors are associated with the validator for as long
 * as the underlying trust anchor file (or set of files) exists.
 * @param {String} groupId The certificate group id.
 * @param {CertificateV2} certificate The certificate to load as a trust anchor,
 * which is copied.
 * @param {String} path The path to load the trust anchors.
 * @param {number} refreshPeriod  The refresh time in milliseconds for the
 * anchors under path. This must be positive. The relevant trust anchors will
 * only be updated when find is called.
 * @param {boolean} isDirectory (optional) If true, then path is a directory.
 * If false or omitted, it is a single file.
 */
CertificateStorage.prototype.loadAnchor = function
  (groupId, certificateOrPath, refreshPeriod, isDirectory)
{
  this.trustAnchors_.insert
    (groupId, certificateOrPath, refreshPeriod, isDirectory);
};

/**
 * Remove any previously loaded static or dynamic trust anchors.
 */
CertificateStorage.prototype.resetAnchors = function()
{
  this.trustAnchors_.clear();
};

/**
 * Cache the verified certificate a period of time (1 hour).
 * @param {CertificateV2} certificate The certificate object, which is copied.
 */
CertificateStorage.prototype.cacheVerifiedCertificate = function(certificate)
{
  this.verifiedCertificateCache_.insert(certificate);
};

/**
 * Remove any cached verified certificates.
 */
CertificateStorage.prototype.resetVerifiedCertificates = function()
{
  this.verifiedCertificateCache_.clear();
};

/**
 * Set the offset when the cache insert() and refresh() get the current time,
 * which should only be used for testing.
 * @param {number} nowOffsetMilliseconds The offset in milliseconds.
 */
CertificateStorage.prototype.setCacheNowOffsetMilliseconds_ = function
  (nowOffsetMilliseconds)
{
  this.verifiedCertificateCache_.setNowOffsetMilliseconds_(nowOffsetMilliseconds);
  this.unverifiedCertificateCache_.setNowOffsetMilliseconds_(nowOffsetMilliseconds);
};
