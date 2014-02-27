/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * This class represents Interest Objects
 */

/**
 * Create a WireFormat base class where the encode and decode methods throw an error. You should use a derived class like TlvWireFormat.
 * @constructor
 */
var WireFormat = function WireFormat() {
};

exports.WireFormat = WireFormat;

/**
 * Encode interest and return the encoding.  Your derived class should override.
 * @param {Interest} interest The Interest to encode.
 * @returns {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeInterest = function(interest) 
{
  throw new Error("encodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode input as an interest and set the fields of the interest object. 
 * Your derived class should override.
 * @param {Interest} interest The Interest object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeInterest = function(interest, input) 
{
  throw new Error("decodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode data and return the encoding and signed offsets. Your derived class 
 * should override.
 * @param {Data} data The Data object to encode.
 * @returns {object with (Blob, int, int)} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding 
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in 
 * the encoding of the beginning of the signed portion, and 
 * signedPortionEndOffset is the offset in the encoding of the end of the 
 * signed portion.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeData = function(data) 
{
  throw new Error("encodeData is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode input as a data packet, set the fields in the data object, and return 
 * the signed offsets.  Your derived class should override.
 * @param {Data} data The Data object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @returns {object with (int, int)} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where 
 * signedPortionBeginOffset is the offset in the encoding of the beginning of 
 * the signed portion, and signedPortionEndOffset is the offset in the encoding 
 * of the end of the signed portion.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeData = function(data, input) 
{
  throw new Error("decodeData is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Set the static default WireFormat used by default encoding and decoding 
 * methods.
 * @param wireFormat {a subclass of WireFormat} An object of a subclass of 
 * WireFormat.
 */
WireFormat.setDefaultWireFormat = function(wireFormat)
{
  WireFormat.defaultWireFormat = wireFormat;
};

/**
 * Return the default WireFormat used by default encoding and decoding methods 
 * which was set with setDefaultWireFormat.
 * @returns {a subclass of WireFormat} The WireFormat object.
 */
WireFormat.getDefaultWireFormat = function()
{
  return WireFormat.defaultWireFormat;
};

// Invoke TlvWireFormat to set the default format.
// Since tlv-wire-format.js includes this file, put this at the bottom 
// to avoid problems with cycles of require.
var TlvWireFormat = require('./tlv-wire-format.js').TlvWireFormat;
