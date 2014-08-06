/**
 * Copyright (C) 2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var IdentityCertificate = function IdentityCertificate()
{
};

exports.IdentityCertificate = IdentityCertificate;

/**
 * Get the public key name from the full certificate name.
 * @param {Name} certificateName The full certificate name.
 * @returns {Name} The related public key name.
 */
IdentityCertificate.certificateNameToPublicKeyName = function(certificateName)
{
  var i = certificateName.size() - 1;
  var idString = "ID-CERT";
  while (i >= 0) {
    if (certificateName.get(i).toEscapedString() == idString)
      break;
    i -= 1;
  }

  var tmpName = certificateName.getSubName(0, i);
  var keyString = "KEY";
  for (var i = 0; i < tmpName.size(); ++i) {
    if (tmpName.get(i).toEscapedString() == keyString)
      break;
  }

  return tmpName.getSubName(0, i).append
    (tmpName.getSubName(i + 1, tmpName.size() - i - 1));
};
