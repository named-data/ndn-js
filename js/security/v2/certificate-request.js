/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-request.hpp
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
var Interest = require('../../interest.js').Interest;

/**
 * A CertificateRequest represents a request for a certificate, associated with
 * the number of retries left. The interest_ and nRetriesLeft_ fields are public
 * so that you can modify them. interest_ is the Interest for the requested Data
 * packet or Certificate, and nRetriesLeft_ is the number of remaining retries
 * after a timeout or NACK.
 *
 * Create a CertificateRequest with an optional Interest.
 * @param {Interest} interest (optional) If supplied, create a
 * CertificateRequest with a copy of the interest and 3 retries left. Of omitted,
 * create a CertificateRequest with a default Interest object and 0 retries left.
 * @constructor
 */
var CertificateRequest = function CertificateRequest(interest)
{
  if (interest != undefined) {
    this.interest_ = new Interest(interest);
    this.nRetriesLeft_ = 3;
  }
  else {
    this.interest_ = new Interest();
    this.nRetriesLeft_ = 0;
  }
};

exports.CertificateRequest = CertificateRequest;

