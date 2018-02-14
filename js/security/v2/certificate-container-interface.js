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

/**
 * @constructor
 */
var CertificateContainerInterface = function CertificateContainerInterface()
{
};

exports.CertificateContainerInterface = CertificateContainerInterface;

/**
 * Add the certificate to the container.
 * @param {CertificateV2} certificate The certificate to add, which is copied.
 */
CertificateContainerInterface.prototype.add = function(certificate)
{
  throw new Error("CertificateContainerInterface.add is unimplemented");
};

/**
 * Remove the certificate with the given name. If the name does not exist,
 * do nothing.
 * @param {Name} certificateName The name of the certificate.
 */
CertificateContainerInterface.prototype.remove = function(certificateName)
{
  throw new Error("CertificateContainerInterface.remove is unimplemented");
};
