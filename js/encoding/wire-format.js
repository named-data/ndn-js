/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * This class represents Interest Objects
 */

/**
 * Create a WireFormat base class where the encode and decode methods throw an error. You should use a derived class like BinaryXmlWireFormat.
 * @constructor
 */
var WireFormat = function WireFormat() {
};

exports.WireFormat = WireFormat;

/**
 * The override method in the derived class should encode the interest and return a Buffer.
 * @param {Interest} interest
 * @returns {Buffer}
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeInterest = function(interest) 
{
  throw new Error("encodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * The override method in the derived class should decode the input and put the result in interest.
 * @param {Interest} interest
 * @param {Buffer} input
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeInterest = function(interest, input) 
{
  throw new Error("decodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * The override method in the derived class should encode the data and return a Buffer. 
 * @param {Data} data
 * @returns {Buffer}
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeData = function(data) 
{
  throw new Error("encodeData is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * The override method in the derived class should decode the input and put the result in data.
 * @param {Data} data
 * @param {Buffer} input
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

// Invoke BinaryXmlWireFormat to set the default format.
// Since binary-xml-wire-format.js includes this file, put this at the bottom 
// to avoid problems with cycles of require.
var BinaryXmlWireFormat = require('./binary-xml-wire-format.js').BinaryXmlWireFormat;
