/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/decrypt-key https://github.com/named-data/ndn-group-encrypt
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
var Blob = require('../util/blob.js').Blob;

/**
 * A DecryptKey supplies the key for decrypt.
 * Create a DecryptKey with the given key value.
 * @param {Blob|DecryptKey} value If value is another DecryptKey then copy it.
 * Otherwise, value is the key value.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var DecryptKey = function DecryptKey(value)
{
  if (typeof value === 'object' && value instanceof DecryptKey) {
    // Make a deep copy.
    this.keyBits_ = value.keyBits_;
  }
  else {
    var keyBits = value;
    this.keyBits_ = typeof keyBits === 'object' && keyBits instanceof Blob ?
      keyBits : new Blob(keyBits);
  }
};

exports.DecryptKey = DecryptKey;

/**
 * Get the key value.
 * @return {Blob} The key value.
 */
DecryptKey.prototype.getKeyBits = function() { return this.keyBits_; };
