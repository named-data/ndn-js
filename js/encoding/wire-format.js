/**
 * Copyright (C) 2013-2018 Regents of the University of California.
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
 * Create a WireFormat base class where the encode and decode methods throw an error. You should use a derived class like TlvWireFormat.
 * @constructor
 */
var WireFormat = function WireFormat() {
};

exports.WireFormat = WireFormat;

/**
 * Encode name and return the encoding.  Your derived class should override.
 * @param {Name} name The Name to encode.
 * @return {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeName = function(name)
{
  throw new Error("encodeName is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode input as a name and set the fields of the Name object.
 * Your derived class should override.
 * @param {Name} name The Name object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeName = function(name, input, copy)
{
  throw new Error("decodeName is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode interest and return the encoding.  Your derived class should override.
 * @param {Interest} interest The Interest to encode.
 * @return {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the signed
 * portion. The signed portion starts from the first name component and ends
 * just before the final name component (which is assumed to be a signature for
 * a signed interest).
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
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @return {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeInterest = function(interest, input, copy)
{
  throw new Error("decodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode data and return the encoding and signed offsets. Your derived class
 * should override.
 * @param {Data} data The Data object to encode.
 * @return {object} An associative array with fields
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
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @return {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeData = function(data, input, copy)
{
  throw new Error("decodeData is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode controlParameters and return the encoding.  Your derived class should
 * override.
 * @param {ControlParameters} controlParameters The ControlParameters object to
 * encode.
 * @return {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeControlParameters = function(controlParameters)
{
  throw new Error("encodeControlParameters is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode input as a controlParameters and set the fields of the
 * controlParameters object. Your derived class should override.
 * @param {ControlParameters} controlParameters The ControlParameters object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeControlParameters = function
  (controlParameters, input, copy)
{
  throw new Error("decodeControlParameters is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode controlResponse and return the encoding.  Your derived class should
 * override.
 * @param {ControlResponse} controlResponse The ControlResponse object to
 * encode.
 * @return {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeControlResponse = function(controlResponse)
{
  throw new Error("encodeControlResponse is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode input as a controlResponse and set the fields of the
 * controlResponse object. Your derived class should override.
 * @param {ControlResponse} controlResponse The ControlResponse object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeControlResponse = function
  (controlResponse, input, copy)
{
  throw new Error("decodeControlResponse is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode signature as a SignatureInfo and return the encoding. Your derived
 * class should override.
 * @param {Signature} signature An object of a subclass of Signature to encode.
 * @return {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeSignatureInfo = function(signature)
{
  throw new Error("encodeSignatureInfo is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode signatureInfo as a signature info and signatureValue as the related
 * SignatureValue, and return a new object which is a subclass of Signature.
 * Your derived class should override.
 * @param {Buffer} signatureInfo The buffer with the signature info bytes to
 * decode.
 * @param {Buffer} signatureValue The buffer with the signature value to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @return {Signature} A new object which is a subclass of Signature.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeSignatureInfoAndValue = function
  (signatureInfo, signatureValue, copy)
{
  throw new Error("decodeSignatureInfoAndValue is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode the signatureValue in the Signature object as a SignatureValue (the
 * signature bits) and return the encoding. Your derived class should override.
 * @param {Signature} signature An object of a subclass of Signature with the
 * signature value to encode.
 * @return {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeSignatureValue = function(signature)
{
  throw new Error("encodeSignatureValue is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode input as an NDN-TLV LpPacket and set the fields of the lpPacket object.
 * Your derived class should override.
 * @param {LpPacket} lpPacket The LpPacket object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @throws Error This always throws an "unimplemented" error. The derived class
 * should override.
 */
WireFormat.prototype.decodeLpPacket = function(lpPacket, input, copy)
{
  throw new Error
    ("decodeLpPacket is unimplemented in the base WireFormat class. You should use a derived class.");
};

/**
 * Encode the DelegationSet and return the encoding.  Your derived class
 * should override.
 * @param {DelegationSet} delegationSet The DelegationSet object to
 * encode.
 * @return {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class
 * should override.
 */
WireFormat.prototype.encodeDelegationSet = function(delegationSet)
{
  throw new Error
    ("encodeDelegationSet is unimplemented in the base WireFormat class. You should use a derived class.");
};

/**
 * Decode input as an DelegationSet and set the fields of the
 * delegationSet object. Your derived class should override.
 * @param {DelegationSet} delegationSet The DelegationSet object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @throws Error This always throws an "unimplemented" error. The derived class
 * should override.
 */
WireFormat.prototype.decodeDelegationSet = function(delegationSet, input, copy)
{
  throw new Error
    ("decodeDelegationSet is unimplemented in the base WireFormat class. You should use a derived class.");
};

/**
 * Encode the EncryptedContent and return the encoding.  Your derived class
 * should override.
 * @param {EncryptedContent} encryptedContent The EncryptedContent object to
 * encode.
 * @return {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class
 * should override.
 */
WireFormat.prototype.encodeEncryptedContent = function(encryptedContent)
{
  throw new Error
    ("encodeEncryptedContent is unimplemented in the base WireFormat class. You should use a derived class.");
};

/**
 * Decode input as an EncryptedContent and set the fields of the
 * encryptedContent object. Your derived class should override.
 * @param {EncryptedContent} encryptedContent The EncryptedContent object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @throws Error This always throws an "unimplemented" error. The derived class
 * should override.
 */
WireFormat.prototype.decodeEncryptedContent = function
  (encryptedContent, input, copy)
{
  throw new Error
    ("decodeEncryptedContent is unimplemented in the base WireFormat class. You should use a derived class.");
};

/**
 * Set the static default WireFormat used by default encoding and decoding
 * methods.
 * @param {WireFormat} wireFormat An object of a subclass of WireFormat.
 */
WireFormat.setDefaultWireFormat = function(wireFormat)
{
  WireFormat.defaultWireFormat = wireFormat;
};

/**
 * Return the default WireFormat used by default encoding and decoding methods
 * which was set with setDefaultWireFormat.
 * @return {WireFormat} An object of a subclass of WireFormat.
 */
WireFormat.getDefaultWireFormat = function()
{
  return WireFormat.defaultWireFormat;
};

// Invoke TlvWireFormat to set the default format.
// Since tlv-wire-format.js includes this file, put this at the bottom
// to avoid problems with cycles of require.
var TlvWireFormat = require('./tlv-wire-format.js').TlvWireFormat;
