/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

/**
 * A Blob holds an immutable byte array implemented as a Buffer.  This should be treated like a string which is a pointer to an immutable string.  
 * (It is OK to pass a pointer to the string because the new owner can’t change the bytes of the string.)  Blob does not inherit from Buffer.
 * Instead you must call buf() to get the byte array which reminds you that you should not change the contents.  Also remember that buf() can return null.
 * @param {Blob|Buffer|Array<number>} value (optional) If value is a Blob, take another pointer to the Buffer without copying.
 * If value is a Buffer or byte array, copy to create a new Buffer.  If omitted, buf() will return a null pointer.
 */
var Blob = function Blob(value) 
{
  if (value) {
    if (typeof value == 'object' && value instanceof Blob)
      // Just take another pointer.
      this.buffer = value.buffer;
    else if (typeof value == 'object' && value instanceof Buffer)
      // Copy.
      this.buffer = new Buffer(value);
    else if (typeof value == 'object')
      // Assume component is a byte array.  We can't check instanceof Array because
      //   this doesn't work in JavaScript if the array comes from a different module.
      this.buffer = new Buffer(value);
    else
      throw new Error('Blob constructor: unknown value type.');
  }
  else
    this.buffer = null;
};

/**
 * Return the length of the immutable byte array.
 * @returns {number} The length of the array.  If the pointer to the array is null, return 0.
 */
Blob.prototype.size = function()
{
  if (this.buffer)
    return this.buffer.length;
  else
    return 0;
};

/**
 * Return the immutable byte array.  DO NOT change the contents of the Buffer.  If you need to change it, make a copy.
 * @returns {Buffer} The Buffer holding the immutable byte array, or null.
 */
Blob.prototype.buf = function()
{
  return this.buffer;
};

exports.Blob = Blob;
