/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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
 * A Blob holds an immutable byte array implemented as a Buffer.  This should be
 * treated like a string which is a pointer to an immutable string. (It is OK to
 * pass a pointer to the string because the new owner can’t change the bytes of
 * the string.)  Blob does not inherit from Buffer. Instead you must call buf()
 * to get the byte array which reminds you that you should not change the
 * contents.  Also remember that buf() can return null.
 * @param {Blob|Buffer|Array<number>} value (optional) If value is a Blob, take
 * another pointer to the Buffer without copying. If value is a Buffer or byte
 * array, copy to create a new Buffer.  If omitted, buf() will return null.
 * @param {boolean} copy (optional) If true, copy the contents of
 * value into a new Buffer.  If false, just use the existing value without
 * copying. If omitted, then copy the contents (unless value is already a Blob).
 * IMPORTANT: If copy is false, if you keep a pointer to the value then you must
 * treat the value as immutable and promise not to change it.
 * @constructor
 */
var Blob = function Blob(value, copy)
{
  if (copy == null)
    copy = true;

  if (value == null)
    this.buffer = null;
  else if (typeof value === 'object' && value instanceof Blob)
    // Use the existing buffer.  Don't need to check for copy.
    this.buffer = value.buffer;
  else {
    if (typeof value === 'string')
      // Convert from a string to utf-8 byte encoding.
      this.buffer = new Buffer(value, 'utf8');
    else {
      if (copy)
        // We are copying, so just make another Buffer.
        this.buffer = new Buffer(value);
      else {
        if (Buffer.isBuffer(value))
          // We can use as-is.
          this.buffer = value;
        else
          // We need a Buffer, so copy.
          this.buffer = new Buffer(value);
      }
    }
  }

  // Set the length to be "JavaScript-like".
  this.length = this.buffer != null ? this.buffer.length : 0;
};

exports.Blob = Blob;

/**
 * Return the length of the immutable byte array.
 * @return {number} The length of the array.  If buf() is null, return 0.
 */
Blob.prototype.size = function()
{
  if (this.buffer != null)
    return this.buffer.length;
  else
    return 0;
};

/**
 * Return the immutable byte array.  DO NOT change the contents of the Buffer.
 * If you need to change it, make a copy.
 * @return {Buffer} The Buffer holding the immutable byte array, or null.
 */
Blob.prototype.buf = function()
{
  return this.buffer;
};

/**
 * Return true if the array is null, otherwise false.
 * @return {boolean} True if the array is null.
 */
Blob.prototype.isNull = function()
{
  return this.buffer == null;
};

/**
 * Return the hex representation of the bytes in the byte array.
 * @return {string} The hex string.
 */
Blob.prototype.toHex = function()
{
  if (this.buffer == null)
    return "";
  else
    return this.buffer.toString('hex');
};

/**
 * Decode the byte array as UTF8 and return the Unicode string.
 * @return A unicode string, or "" if the buffer is null.
 */
Blob.prototype.toString = function()
{
  if (this.buffer == null)
    return "";
  else
    return this.buffer.toString('utf8');
};

/**
 * Check if the value of this Blob equals the other blob.
 * @param {Blob} other The other Blob to check.
 * @return {boolean} if this isNull and other isNull or if the bytes of this
 * blob equal the bytes of the other.
 */
Blob.prototype.equals = function(other)
{
  if (this.isNull())
    return other.isNull();
  else if (other.isNull())
    return false;
  else {
    if (this.buffer.length != other.buffer.length)
      return false;

    for (var i = 0; i < this.buffer.length; ++i) {
      if (this.buffer[i] != other.buffer[i])
        return false;
    }

    return true;
  }
};
