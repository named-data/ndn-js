/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-fetcher-offline.hpp
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
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var CertificateFetcher = require('./certificate-fetcher.js').CertificateFetcher;

/**
 * CertificateFetcherOffline extends CertificateFetcher to implement a fetcher
 * that does not fetch certificates (always offline).
 * @constructor
 */
var CertificateFetcherOffline = function CertificateFetcherOffline()
{
  // Call the base constructor.
  CertificateFetcher.call(this);
};

CertificateFetcherOffline.prototype = new CertificateFetcher();
CertificateFetcherOffline.prototype.name = "CertificateFetcherOffline";

exports.CertificateFetcherOffline = CertificateFetcherOffline;

CertificateFetcherOffline.prototype.doFetch_ = function
  (certificateRequest, state, continueValidation)
{
  state.fail(new ValidationError
    (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
     "Cannot fetch certificate " +
     certificateRequest.interest_.getName().toUri() + " in offline mode"));
};
