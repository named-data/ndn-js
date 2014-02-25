/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * Encapsulate a Buffer and support dynamic reallocation.
 */

/**
 * Create a DynamicBuffer where this.array is a Buffer of size length.
 * To access the array, use this.array or call slice.
 * @constructor
 * @param {number} length the initial length of the array.  If null, use a default.
 */
var DynamicBuffer = function DynamicBuffer(length) 
{
  if (!length)
    length = 16;
    
  this.array = new Buffer(length);
};

exports.DynamicBuffer = DynamicBuffer;

/**
 * Ensure that this.array has the length, reallocate and copy if necessary.
 * Update the length of this.array which may be greater than length.
 * @param {number} length The minimum length for the array.
 */
DynamicBuffer.prototype.ensureLength = function(length) 
{
  if (this.array.length >= length)
    return;
    
  // See if double is enough.
  var newLength = this.array.length * 2;
  if (length > newLength)
    // The needed length is much greater, so use it.
    newLength = length;
    
  var newArray = new Buffer(newLength);
  this.array.copy(newArray);
  this.array = newArray;
};

/**
 * Copy the value to this.array at offset, reallocating if necessary. 
 * @param {Buffer} value The buffer to copy.
 * @param {number} offset The offset in the buffer to start copying into.
 */
DynamicBuffer.prototype.copy = function(value, offset) 
{
  this.ensureLength(value.length + offset);
    
  if (typeof value == 'object' && value instanceof Buffer)
    value.copy(this.array, offset);
  else
    // Need to make value a Buffer to copy.
    new Buffer(value).copy(this.array, offset);
};

/**
 * Ensure that this.array has the length. If necessary, reallocate the array
 *   and shift existing data to the back of the new array.
 * Update the length of this.array which may be greater than length.
 * @param {number} length The minimum length for the array.
 */
DynamicBuffer.prototype.ensureLengthFromBack = function(length) 
{
  if (this.array.length >= length)
    return;
    
  // See if double is enough.
  var newLength = this.array.length * 2;
  if (length > newLength)
    // The needed length is much greater, so use it.
    newLength = length;
    
  var newArray = new Buffer(newLength);
  // Copy to the back of newArray.
  this.array.copy(newArray, newArray.length - this.array.length);
  this.array = newArray;
};

/**
 * First call ensureLengthFromBack to make sure the bytearray has
 * offsetFromBack bytes, then copy value into the array starting
 * offsetFromBack bytes from the back of the array.
 * @param {Buffer} value The buffer to copy.
 * @param {offsetFromBack} offset The offset from the back of the array to start
 * copying.
 */
DynamicBuffer.prototype.copyFromBack = function(value, offsetFromBack) 
{
  this.ensureLengthFromBack(offsetFromBack);

  if (typeof value == 'object' && value instanceof Buffer)
    value.copy(this.array, this.array.length - offsetFromBack);
  else
    // Need to make value a Buffer to copy.
    new Buffer(value).copy(this.array, this.array.length - offsetFromBack);
};

/**
 * Return this.array.slice(begin, end);
 * @param {number} begin The begin index for the slice.
 * @param {number} end The end index for the slice.
 * @returns {Buffer} The buffer slice.
 */
DynamicBuffer.prototype.slice = function(begin, end) 
{
  return this.array.slice(begin, end);
};
