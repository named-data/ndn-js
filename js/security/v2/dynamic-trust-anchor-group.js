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
var path = require('path'); /** @ignore */
var TrustAnchorGroup = require('./trust-anchor-group.js').TrustAnchorGroup; /** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var LOG = require('../../log.js').Log.LOG;

/**
 * The DynamicTrustAnchorGroup class extends TrustAnchorGroup to implement a
 * dynamic trust anchor group.
 *
 * Create a DynamicTrustAnchorGroup to use an existing container.
 * @param {CertificateContainer} certificateContainer The existing certificate
 * container which implements the CertificateContainer interface.
 * @param {string} id The group ID.
 * @param {string} path The file path for trust anchor(s), which could be a
 * directory or a file. If it is a directory, all the certificates in the
 * directory will be loaded.
 * @param {number} refreshPeriod  The refresh time in milliseconds for the
 * anchors under path. This must be positive.
 * @param {boolean} isDirectory If true, then path is a directory. If false, it
 * is a single file.
 * @throws Error If refreshPeriod is not positive.
 * @constructor
 */
var DynamicTrustAnchorGroup = function DynamicTrustAnchorGroup
  (certificateContainer, id, path, refreshPeriod, isDirectory)
{
  // Call the base constructor.
  TrustAnchorGroup.call(this, certificateContainer, id);

  this.isDirectory_ = isDirectory;
  this.path_ = path;
  this.refreshPeriod_ = refreshPeriod;
  this.expireTime_ = 0;
  if (refreshPeriod <= 0)
    throw new Error("Refresh period for the dynamic group must be positive");

  if (LOG > 0)
    console.log("Create a dynamic trust anchor group " + id + " for file/dir " +
      path + " with refresh time " + refreshPeriod);
  this.refresh();
};

DynamicTrustAnchorGroup.prototype = new TrustAnchorGroup();
DynamicTrustAnchorGroup.prototype.name = "DynamicTrustAnchorGroup";

exports.DynamicTrustAnchorGroup = DynamicTrustAnchorGroup;

/**
 * Request a certificate refresh.
 */
DynamicTrustAnchorGroup.prototype.refresh = function()
{
  var now = new Date().getTime();
  if (this.expireTime_ > now)
    return;

  this.expireTime_ = now + this.refreshPeriod_;
  if (LOG > 0)
    console.log("Reloading the dynamic trust anchor group");

  // Save a copy of anchorNameUris_ .
  var oldAnchorNameUris = {};
  for (var uri in this.anchorNameUris_)
    oldAnchorNameUris[uri] = true;

  if (!this.isDirectory_)
    this.loadCertificate_(this.path_, oldAnchorNameUris);
  else {
    var allFiles;
    try {
      allFiles = fs.readdirSync(this.path_);
    }
    catch (e) {
      throw new Error("Cannot list files in directory " + this.path_);
    }

    for (var i = 0; i < allFiles.length; ++i)
      this.loadCertificate_(path.join(this.path_, allFiles[i]), oldAnchorNameUris);
  }

  // Remove old certificates.
  for (var uri in oldAnchorNameUris) {
    delete this.anchorNameUris_[uri];
    this.certificates_.remove(new Name(uri));
  }
};

/**
 * @param {string} file
 * @param {object} oldAnchorNameUris The keys are the set of anchor name URIs,
 * and each value is true.
 */
DynamicTrustAnchorGroup.prototype.loadCertificate_ = function
  (file, oldAnchorNameUris)
{
  var certificate = TrustAnchorGroup.readCertificate(file);
  if (certificate != null) {
    var certificateNameUri = certificate.getName().toUri();

    if (!this.anchorNameUris_[certificateNameUri]) {
      this.anchorNameUris_[certificateNameUri] = true;
      this.certificates_.add(certificate);
    }
    else
      delete oldAnchorNameUris[certificateNameUri];
  }
};
