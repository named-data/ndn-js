/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

var Blob = require('./blob.js').Blob;

/**
 * A SignedBlob extends Blob to keep the offsets of a signed portion (e.g., the bytes of Data packet). 
 * This inherits from Blob, including Blob.size and Blob.buf.
 * @param {Blob|Buffer|Array<number>} value (optional) If value is a Blob, take another pointer to the Buffer without copying.
 * If value is a Buffer or byte array, copy to create a new Buffer.  If omitted, buf() will return a null pointer.
 * @param {number} signedPortionBeginOffset (optional) The offset in the encoding of the beginning of the signed portion.
 * If omitted, set to 0.
 * @param {number} signedPortionEndOffset (optional) The offset in the encoding of the end of the signed portion.
 * If omitted, set to 0.
 */
var SignedBlob = function SignedBlob(value, signedPortionBeginOffset, signedPortionEndOffset) 
{
  // Call the base constructor.
  Blob.call(this, value);
  
  this.signedPortionBeginOffset = signedPortionBeginOffset || 0;
  this.signedPortionEndOffset = signedPortionEndOffset || 0;
};

SignedBlob.prototype = new Blob();
SignedBlob.prototype.name = "SignedBlob";

exports.SignedBlob = SignedBlob;

/**
 * Return the length of the signed portion of the immutable byte array.
 * @returns {number} The length of the signed portion.  If the pointer to the array is null, return 0.
 */
SignedBlob.prototype.signedSize = function()
{
  if (this.buffer)
    return this.signedPortionEndOffset - this.signedPortionBeginOffset;
  else
    return 0;
};

/**
 * Return a the signed portion of the immutable byte array.
 * @returns {Buffer} A slice into the Buffer which is the signed portion.  If the pointer to the array is null, return null.
 */
SignedBlob.prototype.signedBuf = function()
{
  if (this.buffer)
    return this.buffer.slice(this.signedPortionBeginOffset, this.signedPortionEndOffset);
  else
    return null;
};

/**
 * Return the offset in the array of the beginning of the signed portion.
 * @returns {number} The offset in the array.
 */
SignedBlob.prototype.getSignedPortionBeginOffset = function()
{
  return this.signedPortionBeginOffset;
};

/**
 * Return the offset in the array of the end of the signed portion.
 * @returns {number} The offset in the array.
 */
SignedBlob.prototype.getSignedPortionEndOffset = function()
{
  return this.signedPortionEndOffset;
};
