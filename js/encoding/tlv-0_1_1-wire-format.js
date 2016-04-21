/**
 * Copyright (C) 2013-2016 Regents of the University of California.
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

/** @ignore */
var Crypto = require('../crypto.js'); /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var Name = require('../name.js').Name; /** @ignore */
var ForwardingFlags = require('../forwarding-flags').ForwardingFlags; /** @ignore */
var Tlv = require('./tlv/tlv.js').Tlv; /** @ignore */
var TlvEncoder = require('./tlv/tlv-encoder.js').TlvEncoder; /** @ignore */
var TlvDecoder = require('./tlv/tlv-decoder.js').TlvDecoder; /** @ignore */
var WireFormat = require('./wire-format.js').WireFormat; /** @ignore */
var Exclude = require('../exclude.js').Exclude; /** @ignore */
var ContentType = require('../meta-info.js').ContentType; /** @ignore */
var KeyLocatorType = require('../key-locator.js').KeyLocatorType; /** @ignore */
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var GenericSignature = require('../generic-signature.js').GenericSignature; /** @ignore */
var HmacWithSha256Signature = require('../hmac-with-sha256-signature.js').HmacWithSha256Signature; /** @ignore */
var DigestSha256Signature = require('../digest-sha256-signature.js').DigestSha256Signature; /** @ignore */
var ControlParameters = require('../control-parameters.js').ControlParameters; /** @ignore */
var ForwardingFlags = require('../forwarding-flags.js').ForwardingFlags; /** @ignore */
var DecodingException = require('./decoding-exception.js').DecodingException;

/**
 * A Tlv0_1_1WireFormat implements the WireFormat interface for encoding and
 * decoding with the NDN-TLV wire format, version 0.1.1.
 * @constructor
 */
var Tlv0_1_1WireFormat = function Tlv0_1_1WireFormat()
{
  // Inherit from WireFormat.
  WireFormat.call(this);
};

Tlv0_1_1WireFormat.prototype = new WireFormat();
Tlv0_1_1WireFormat.prototype.name = "Tlv0_1_1WireFormat";

exports.Tlv0_1_1WireFormat = Tlv0_1_1WireFormat;

// Default object.
Tlv0_1_1WireFormat.instance = null;

/**
 * Encode interest as NDN-TLV and return the encoding.
 * @param {Name} interest The Name to encode.
 * @returns {Blobl} A Blob containing the encoding.
 */
Tlv0_1_1WireFormat.prototype.encodeName = function(name)
{
  var encoder = new TlvEncoder();
  Tlv0_1_1WireFormat.encodeName(name, encoder);
  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode input as a NDN-TLV name and set the fields of the Name object.
 * @param {Name} name The Name object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 */
Tlv0_1_1WireFormat.prototype.decodeName = function(name, input)
{
  var decoder = new TlvDecoder(input);
  Tlv0_1_1WireFormat.decodeName(name, decoder);
};

/**
 * Encode the interest using NDN-TLV and return a Buffer.
 * @param {Interest} interest The Interest object to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the signed
 * portion. The signed portion starts from the first name component and ends
 * just before the final name component (which is assumed to be a signature for
 * a signed interest).
 */
Tlv0_1_1WireFormat.prototype.encodeInterest = function(interest)
{
  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.SelectedDelegation, interest.getSelectedDelegationIndex());
  var linkWireEncoding = interest.getLinkWireEncoding(this);
  if (!linkWireEncoding.isNull())
    // Encode the entire link as is.
    encoder.writeBuffer(linkWireEncoding.buf());

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds());

  // Encode the Nonce as 4 bytes.
  if (interest.getNonce().isNull() || interest.getNonce().size() == 0)
    // This is the most common case. Generate a nonce.
    encoder.writeBlobTlv(Tlv.Nonce, Crypto.randomBytes(4));
  else if (interest.getNonce().size() < 4) {
    var nonce = Buffer(4);
    // Copy existing nonce bytes.
    interest.getNonce().buf().copy(nonce);

    // Generate random bytes for remaining bytes in the nonce.
    for (var i = interest.getNonce().size(); i < 4; ++i)
      nonce[i] = Crypto.randomBytes(1)[0];

    encoder.writeBlobTlv(Tlv.Nonce, nonce);
  }
  else if (interest.getNonce().size() == 4)
    // Use the nonce as-is.
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf());
  else
    // Truncate.
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf().slice(0, 4));

  Tlv0_1_1WireFormat.encodeSelectors(interest, encoder);
  var tempOffsets = Tlv0_1_1WireFormat.encodeName(interest.getName(), encoder);
  var signedPortionBeginOffsetFromBack =
    encoder.getLength() - tempOffsets.signedPortionBeginOffset;
  var signedPortionEndOffsetFromBack =
    encoder.getLength() - tempOffsets.signedPortionEndOffset;

  encoder.writeTypeAndLength(Tlv.Interest, encoder.getLength() - saveLength);
  var signedPortionBeginOffset =
    encoder.getLength() - signedPortionBeginOffsetFromBack;
  var signedPortionEndOffset =
    encoder.getLength() - signedPortionEndOffsetFromBack;

  return { encoding: new Blob(encoder.getOutput(), false),
           signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Decode input as an NDN-TLV interest and set the fields of the interest
 * object.
 * @param {Interest} interest The Interest object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
Tlv0_1_1WireFormat.prototype.decodeInterest = function(interest, input)
{
  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
  var offsets = Tlv0_1_1WireFormat.decodeName(interest.getName(), decoder);
  if (decoder.peekType(Tlv.Selectors, endOffset))
    Tlv0_1_1WireFormat.decodeSelectors(interest, decoder);
  // Require a Nonce, but don't force it to be 4 bytes.
  var nonce = decoder.readBlobTlv(Tlv.Nonce);
  interest.setInterestLifetimeMilliseconds
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.InterestLifetime, endOffset));

  if (decoder.peekType(Tlv.Data, endOffset)) {
    // Get the bytes of the Link TLV.
    var linkBeginOffset = decoder.getOffset();
    var linkEndOffset = decoder.readNestedTlvsStart(Tlv.Data);
    decoder.seek(linkEndOffset);

    interest.setLinkWireEncoding
      (new Blob(decoder.getSlice(linkBeginOffset, linkEndOffset), true), this);
  }
  else
    interest.unsetLink();
  interest.setSelectedDelegationIndex
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.SelectedDelegation, endOffset));
  if (interest.getSelectedDelegationIndex() != null &&
      interest.getSelectedDelegationIndex() >= 0 && !interest.hasLink())
    throw new Error("Interest has a selected delegation, but no link object");

  // Set the nonce last because setting other interest fields clears it.
  interest.setNonce(nonce);

  decoder.finishNestedTlvs(endOffset);
  return offsets;
};

/**
 * Encode data as NDN-TLV and return the encoding and signed offsets.
 * @param {Data} data The Data object to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the
 * signed portion.
 */
Tlv0_1_1WireFormat.prototype.encodeData = function(data)
{
  var encoder = new TlvEncoder(1500);
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeBlobTlv(Tlv.SignatureValue, data.getSignature().getSignature().buf());
  var signedPortionEndOffsetFromBack = encoder.getLength();

  Tlv0_1_1WireFormat.encodeSignatureInfo_(data.getSignature(), encoder);
  encoder.writeBlobTlv(Tlv.Content, data.getContent().buf());
  Tlv0_1_1WireFormat.encodeMetaInfo(data.getMetaInfo(), encoder);
  Tlv0_1_1WireFormat.encodeName(data.getName(), encoder);
  var signedPortionBeginOffsetFromBack = encoder.getLength();

  encoder.writeTypeAndLength(Tlv.Data, encoder.getLength() - saveLength);
  var signedPortionBeginOffset =
    encoder.getLength() - signedPortionBeginOffsetFromBack;
  var signedPortionEndOffset = encoder.getLength() - signedPortionEndOffsetFromBack;

  return { encoding: new Blob(encoder.getOutput(), false),
           signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Decode input as an NDN-TLV data packet, set the fields in the data object,
 * and return the signed offsets.
 * @param {Data} data The Data object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 */
Tlv0_1_1WireFormat.prototype.decodeData = function(data, input)
{
  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Data);
  var signedPortionBeginOffset = decoder.getOffset();

  Tlv0_1_1WireFormat.decodeName(data.getName(), decoder);
  Tlv0_1_1WireFormat.decodeMetaInfo(data.getMetaInfo(), decoder);
  data.setContent(decoder.readBlobTlv(Tlv.Content));
  Tlv0_1_1WireFormat.decodeSignatureInfo(data, decoder);

  var signedPortionEndOffset = decoder.getOffset();
  data.getSignature().setSignature
    (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), true));

  decoder.finishNestedTlvs(endOffset);
  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Encode controlParameters as NDN-TLV and return the encoding.
 * @param {ControlParameters} controlParameters The ControlParameters object to
 * encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1_1WireFormat.prototype.encodeControlParameters = function(controlParameters)
{
  var encoder = new TlvEncoder(256);
  Tlv0_1_1WireFormat.encodeControlParameters(controlParameters, encoder);
  return new Blob(encoder.getOutput(), false);
};

/**
  * Decode controlParameters in NDN-TLV and return the encoding.
  * @param {ControlParameters} controlParameters The ControlParameters object to
  * encode.
  * @param {Buffer} input The buffer with the bytes to decode.
  * @throws EncodingException For invalid encoding
  */
Tlv0_1_1WireFormat.prototype.decodeControlParameters = function(controlParameters, input)
{
  var decoder = new TlvDecoder(input);
  Tlv0_1_1WireFormat.decodeControlParameters(controlParameters, decoder);
};

/**
 * Encode controlResponse as NDN-TLV and return the encoding.
 * @param {ControlResponse} controlResponse The ControlResponse object to
 * encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1_1WireFormat.prototype.encodeControlResponse = function(controlResponse)
{
  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.

  // Encode the body.
  if (controlResponse.getBodyAsControlParameters() != null)
    Tlv0_1_1WireFormat.encodeControlParameters
      (controlResponse.getBodyAsControlParameters(), encoder);

  encoder.writeBlobTlv
    (Tlv.NfdCommand_StatusText, new Blob(controlResponse.getStatusText()).buf());
  encoder.writeNonNegativeIntegerTlv
    (Tlv.NfdCommand_StatusCode, controlResponse.getStatusCode());

  encoder.writeTypeAndLength
    (Tlv.NfdCommand_ControlResponse, encoder.getLength() - saveLength);

  return new Blob(encoder.getOutput(), false);
};

/**
  * Decode controlResponse in NDN-TLV and return the encoding.
  * @param {ControlResponse} controlResponse The ControlResponse object to
  * encode.
  * @param {Buffer} input The buffer with the bytes to decode.
  * @throws EncodingException For invalid encoding
  */
Tlv0_1_1WireFormat.prototype.decodeControlResponse = function(controlResponse, input)
{
  var decoder = new TlvDecoder(input);
  var endOffset = decoder.readNestedTlvsStart(Tlv.NfdCommand_ControlResponse);

  controlResponse.setStatusCode(decoder.readNonNegativeIntegerTlv
    (Tlv.NfdCommand_StatusCode));
  var statusText = new Blob
    (decoder.readBlobTlv(Tlv.NfdCommand_StatusText), false);
  controlResponse.setStatusText(statusText.toString());

  // Decode the body.
  if (decoder.peekType(Tlv.ControlParameters_ControlParameters, endOffset)) {
    controlResponse.setBodyAsControlParameters(new ControlParameters());
    // Decode into the existing ControlParameters to avoid copying.
    Tlv0_1_1WireFormat.decodeControlParameters
      (controlResponse.getBodyAsControlParameters(), decoder);
  }
  else
    controlResponse.setBodyAsControlParameters(null);

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode signature as a SignatureInfo and return the encoding.
 * @param {Signature} signature An object of a subclass of Signature to encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1_1WireFormat.prototype.encodeSignatureInfo = function(signature)
{
  var encoder = new TlvEncoder(256);
  Tlv0_1_1WireFormat.encodeSignatureInfo_(signature, encoder);

  return new Blob(encoder.getOutput(), false);
};

// SignatureHolder is used by decodeSignatureInfoAndValue.
Tlv0_1_1WireFormat.SignatureHolder = function Tlv0_1_1WireFormatSignatureHolder()
{
};

Tlv0_1_1WireFormat.SignatureHolder.prototype.setSignature = function(signature)
{
  this.signature = signature;
};

Tlv0_1_1WireFormat.SignatureHolder.prototype.getSignature = function()
{
  return this.signature;
};

/**
 * Decode signatureInfo as a signature info and signatureValue as the related
 * SignatureValue, and return a new object which is a subclass of Signature.
 * @param {Buffer} signatureInfo The buffer with the signature info bytes to
 * decode.
 * @param {Buffer} signatureValue The buffer with the signature value to decode.
 * @returns {Signature} A new object which is a subclass of Signature.
 */
Tlv0_1_1WireFormat.prototype.decodeSignatureInfoAndValue = function
  (signatureInfo, signatureValue)
{
  // Use a SignatureHolder to imitate a Data object for decodeSignatureInfo.
  var signatureHolder = new Tlv0_1_1WireFormat.SignatureHolder();
  var decoder = new TlvDecoder(signatureInfo);
  Tlv0_1_1WireFormat.decodeSignatureInfo(signatureHolder, decoder);

  decoder = new TlvDecoder(signatureValue);
  signatureHolder.getSignature().setSignature
    (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), true));

  return signatureHolder.getSignature();
};

/**
 * Encode the signatureValue in the Signature object as a SignatureValue (the
 * signature bits) and return the encoding.
 * @param {Signature} signature An object of a subclass of Signature with the
 * signature value to encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1_1WireFormat.prototype.encodeSignatureValue = function(signature)
{
  var encoder = new TlvEncoder(256);
  encoder.writeBlobTlv(Tlv.SignatureValue, signature.getSignature().buf());

  return new Blob(encoder.getOutput(), false);
};

/**
 * Encode delegationSet as a sequence of NDN-TLV Delegation, and return the
 * encoding. Note that the sequence of Delegation does not have an outer TLV
 * type and length because it is intended to use the type and length of a Data
 * packet's Content.
 * @param {DelegationSet} delegationSet The DelegationSet object to encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1_1WireFormat.prototype.encodeDelegationSet = function(delegationSet)
{
  var encoder = new TlvEncoder(256);

  // Encode backwards.
  for (var i = delegationSet.size() - 1; i >= 0; --i) {
    var saveLength = encoder.getLength();

    Tlv0_1_1WireFormat.encodeName(delegationSet.get(i).getName(), encoder);
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Link_Preference, delegationSet.get(i).getPreference());

    encoder.writeTypeAndLength
      (Tlv.Link_Delegation, encoder.getLength() - saveLength);
  }

  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode input as a sequence of NDN-TLV Delegation and set the fields of the
 * delegationSet object. Note that the sequence of Delegation does not have an
 * outer TLV type and length because it is intended to use the type and length
 * of a Data packet's Content. This ignores any elements after the sequence
 * of Delegation.
 * @param {DelegationSet} delegationSet The DelegationSet object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 */
Tlv0_1_1WireFormat.prototype.decodeDelegationSet = function(delegationSet, input)
{
  var decoder = new TlvDecoder(input);
  var endOffset = input.length;

  delegationSet.clear();
  while (decoder.getOffset() < endOffset) {
    decoder.readTypeAndLength(Tlv.Link_Delegation);
    var preference = decoder.readNonNegativeIntegerTlv(Tlv.Link_Preference);
    var name = new Name();
    Tlv0_1_1WireFormat.decodeName(name, decoder);

    // Add unsorted to preserve the order so that Interest selected delegation
    // index will work.
    delegationSet.addUnsorted(preference, name);
  }
};

/**
 * Encode the EncryptedContent in NDN-TLV and return the encoding.
 * @param {EncryptedContent} encryptedContent The EncryptedContent object to
 * encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1_1WireFormat.prototype.encodeEncryptedContent = function(encryptedContent)
{
  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeBlobTlv
    (Tlv.Encrypt_EncryptedPayload, encryptedContent.getPayload().buf());
  encoder.writeOptionalBlobTlv
    (Tlv.Encrypt_InitialVector, encryptedContent.getInitialVector().buf());
  // Assume the algorithmType value is the same as the TLV type.
  encoder.writeNonNegativeIntegerTlv
    (Tlv.Encrypt_EncryptionAlgorithm, encryptedContent.getAlgorithmType());
  Tlv0_1_1WireFormat.encodeKeyLocator
    (Tlv.KeyLocator, encryptedContent.getKeyLocator(), encoder);

  encoder.writeTypeAndLength
    (Tlv.Encrypt_EncryptedContent, encoder.getLength() - saveLength);

  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode input as an EncryptedContent in NDN-TLV and set the fields of the
 * encryptedContent object.
 * @param {EncryptedContent} encryptedContent The EncryptedContent object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 */
Tlv0_1_1WireFormat.prototype.decodeEncryptedContent = function
  (encryptedContent, input)
{
  var decoder = new TlvDecoder(input);
  var endOffset = decoder.
    readNestedTlvsStart(Tlv.Encrypt_EncryptedContent);

  Tlv0_1_1WireFormat.decodeKeyLocator
    (Tlv.KeyLocator, encryptedContent.getKeyLocator(), decoder);
  encryptedContent.setAlgorithmType
    (decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_EncryptionAlgorithm));
  encryptedContent.setInitialVector
    (new Blob(decoder.readOptionalBlobTlv
     (Tlv.Encrypt_InitialVector, endOffset), true));
  encryptedContent.setPayload
    (new Blob(decoder.readBlobTlv(Tlv.Encrypt_EncryptedPayload), true));

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Get a singleton instance of a Tlv0_1_1WireFormat.  To always use the
 * preferred version NDN-TLV, you should use TlvWireFormat.get().
 * @returns {Tlv0_1_1WireFormat} The singleton instance.
 */
Tlv0_1_1WireFormat.get = function()
{
  if (Tlv0_1_1WireFormat.instance === null)
    Tlv0_1_1WireFormat.instance = new Tlv0_1_1WireFormat();
  return Tlv0_1_1WireFormat.instance;
};

/**
 * Encode the name to the encoder.
 * @param {Name} name The name to encode.
 * @param {TlvEncoder} encoder The encoder to receive the encoding.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
Tlv0_1_1WireFormat.encodeName = function(name, encoder)
{
  var saveLength = encoder.getLength();

  // Encode the components backwards.
  var signedPortionEndOffsetFromBack;
  for (var i = name.size() - 1; i >= 0; --i) {
    encoder.writeBlobTlv(Tlv.NameComponent, name.get(i).getValue().buf());
    if (i == name.size() - 1)
      signedPortionEndOffsetFromBack = encoder.getLength();
  }

  var signedPortionBeginOffsetFromBack = encoder.getLength();
  encoder.writeTypeAndLength(Tlv.Name, encoder.getLength() - saveLength);

  var signedPortionBeginOffset =
    encoder.getLength() - signedPortionBeginOffsetFromBack;
  var signedPortionEndOffset;
  if (name.size() == 0)
    // There is no "final component", so set signedPortionEndOffset arbitrarily.
    signedPortionEndOffset = signedPortionBeginOffset;
  else
    signedPortionEndOffset = encoder.getLength() - signedPortionEndOffsetFromBack;

  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Clear the name, decode a Name from the decoder and set the fields of the name
 * object.
 * @param {Name} name The name object whose fields are updated.
 * @param {TlvDecoder} decoder The decoder with the input.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
Tlv0_1_1WireFormat.decodeName = function(name, decoder)
{
  name.clear();

  var endOffset = decoder.readNestedTlvsStart(Tlv.Name);
  var signedPortionBeginOffset = decoder.getOffset();
  // In case there are no components, set signedPortionEndOffset arbitrarily.
  var signedPortionEndOffset = signedPortionBeginOffset;

  while (decoder.getOffset() < endOffset) {
    signedPortionEndOffset = decoder.getOffset();
    name.append(decoder.readBlobTlv(Tlv.NameComponent));
  }

  decoder.finishNestedTlvs(endOffset);

  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Encode the interest selectors.  If no selectors are written, do not output a
 * Selectors TLV.
 */
Tlv0_1_1WireFormat.encodeSelectors = function(interest, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (interest.getMustBeFresh())
    encoder.writeTypeAndLength(Tlv.MustBeFresh, 0);
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.ChildSelector, interest.getChildSelector());
  if (interest.getExclude().size() > 0)
    Tlv0_1_1WireFormat.encodeExclude(interest.getExclude(), encoder);

  if (interest.getKeyLocator().getType() != null)
    Tlv0_1_1WireFormat.encodeKeyLocator
      (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), encoder);

  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents());
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MinSuffixComponents, interest.getMinSuffixComponents());

  // Only output the type and length if values were written.
  if (encoder.getLength() != saveLength)
    encoder.writeTypeAndLength(Tlv.Selectors, encoder.getLength() - saveLength);
};

Tlv0_1_1WireFormat.decodeSelectors = function(interest, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Selectors);

  interest.setMinSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MinSuffixComponents, endOffset));
  interest.setMaxSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MaxSuffixComponents, endOffset));

  if (decoder.peekType(Tlv.PublisherPublicKeyLocator, endOffset))
    Tlv0_1_1WireFormat.decodeKeyLocator
      (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), decoder);
  else
    interest.getKeyLocator().clear();

  if (decoder.peekType(Tlv.Exclude, endOffset))
    Tlv0_1_1WireFormat.decodeExclude(interest.getExclude(), decoder);
  else
    interest.getExclude().clear();

  interest.setChildSelector(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ChildSelector, endOffset));
  interest.setMustBeFresh(decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset));

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1_1WireFormat.encodeExclude = function(exclude, encoder)
{
  var saveLength = encoder.getLength();

  // TODO: Do we want to order the components (except for ANY)?
  // Encode the entries backwards.
  for (var i = exclude.size() - 1; i >= 0; --i) {
    var entry = exclude.get(i);

    if (entry == Exclude.ANY)
      encoder.writeTypeAndLength(Tlv.Any, 0);
    else
      encoder.writeBlobTlv(Tlv.NameComponent, entry.getValue().buf());
  }

  encoder.writeTypeAndLength(Tlv.Exclude, encoder.getLength() - saveLength);
};

Tlv0_1_1WireFormat.decodeExclude = function(exclude, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Exclude);

  exclude.clear();
  while (true) {
    if (decoder.peekType(Tlv.NameComponent, endOffset))
      exclude.appendComponent(decoder.readBlobTlv(Tlv.NameComponent));
    else if (decoder.readBooleanTlv(Tlv.Any, endOffset))
      exclude.appendAny();
    else
      // Else no more entries.
      break;
  }

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1_1WireFormat.encodeKeyLocator = function(type, keyLocator, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (keyLocator.getType() != null) {
    if (keyLocator.getType() == KeyLocatorType.KEYNAME)
      Tlv0_1_1WireFormat.encodeName(keyLocator.getKeyName(), encoder);
    else if (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
             keyLocator.getKeyData().size() > 0)
      encoder.writeBlobTlv(Tlv.KeyLocatorDigest, keyLocator.getKeyData().buf());
    else
      throw new Error("Unrecognized KeyLocatorType " + keyLocator.getType());
  }

  encoder.writeTypeAndLength(type, encoder.getLength() - saveLength);
};

Tlv0_1_1WireFormat.decodeKeyLocator = function
  (expectedType, keyLocator, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(expectedType);

  keyLocator.clear();

  if (decoder.getOffset() == endOffset)
    // The KeyLocator is omitted, so leave the fields as none.
    return;

  if (decoder.peekType(Tlv.Name, endOffset)) {
    // KeyLocator is a Name.
    keyLocator.setType(KeyLocatorType.KEYNAME);
    Tlv0_1_1WireFormat.decodeName(keyLocator.getKeyName(), decoder);
  }
  else if (decoder.peekType(Tlv.KeyLocatorDigest, endOffset)) {
    // KeyLocator is a KeyLocatorDigest.
    keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    keyLocator.setKeyData(decoder.readBlobTlv(Tlv.KeyLocatorDigest));
  }
  else
    throw new DecodingException(new Error
      ("decodeKeyLocator: Unrecognized key locator type"));

  decoder.finishNestedTlvs(endOffset);
};

/**
 * An internal method to encode signature as the appropriate form of
 * SignatureInfo in NDN-TLV.
 * @param {Signature} signature An object of a subclass of Signature to encode.
 * @param {TlvEncoder} encoder The encoder.
 */
Tlv0_1_1WireFormat.encodeSignatureInfo_ = function(signature, encoder)
{
  if (signature instanceof GenericSignature) {
    // Handle GenericSignature separately since it has the entire encoding.
    var encoding = signature.getSignatureInfoEncoding();

    // Do a test decoding to sanity check that it is valid TLV.
    try {
      var decoder = new TlvDecoder(encoding.buf());
      var endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);
      decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
      decoder.finishNestedTlvs(endOffset);
    } catch (ex) {
      throw new Error
        ("The GenericSignature encoding is not a valid NDN-TLV SignatureInfo: " +
         ex.message);
    }

    encoder.writeBuffer(encoding.buf());
    return;
  }

  var saveLength = encoder.getLength();

  // Encode backwards.
  if (signature instanceof Sha256WithRsaSignature) {
    Tlv0_1_1WireFormat.encodeKeyLocator
      (Tlv.KeyLocator, signature.getKeyLocator(), encoder);
    encoder.writeNonNegativeIntegerTlv
      (Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithRsa);
  }
  else if (signature instanceof HmacWithSha256Signature) {
    Tlv0_1_1WireFormat.encodeKeyLocator
      (Tlv.KeyLocator, signature.getKeyLocator(), encoder);
    encoder.writeNonNegativeIntegerTlv
      (Tlv.SignatureType, Tlv.SignatureType_SignatureHmacWithSha256);
  }
  else if (signature instanceof DigestSha256Signature)
    encoder.writeNonNegativeIntegerTlv
      (Tlv.SignatureType, Tlv.SignatureType_DigestSha256);
  else
    throw new Error("encodeSignatureInfo: Unrecognized Signature object type");

  encoder.writeTypeAndLength(Tlv.SignatureInfo, encoder.getLength() - saveLength);
};

Tlv0_1_1WireFormat.decodeSignatureInfo = function(data, decoder)
{
  var beginOffset = decoder.getOffset();
  var endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);

  var signatureType = decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
  if (signatureType == Tlv.SignatureType_SignatureSha256WithRsa) {
    data.setSignature(new Sha256WithRsaSignature());
    // Modify data's signature object because if we create an object
    //   and set it, then data will have to copy all the fields.
    var signatureInfo = data.getSignature();
    Tlv0_1_1WireFormat.decodeKeyLocator
      (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder);
  }
  else if (signatureType == Tlv.SignatureType_SignatureHmacWithSha256) {
    data.setSignature(new HmacWithSha256Signature());
    var signatureInfo = data.getSignature();
    Tlv0_1_1WireFormat.decodeKeyLocator
      (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder);
  }
  else if (signatureType == Tlv.SignatureType_DigestSha256)
    data.setSignature(new DigestSha256Signature());
  else {
    data.setSignature(new GenericSignature());
    var signatureInfo = data.getSignature();

    // Get the bytes of the SignatureInfo TLV.
    signatureInfo.setSignatureInfoEncoding
      (new Blob(decoder.getSlice(beginOffset, endOffset), true), signatureType);
  }

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1_1WireFormat.encodeMetaInfo = function(metaInfo, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  var finalBlockIdBuf = metaInfo.getFinalBlockId().getValue().buf();
  if (finalBlockIdBuf != null && finalBlockIdBuf.length > 0) {
    // FinalBlockId has an inner NameComponent.
    var finalBlockIdSaveLength = encoder.getLength();
    encoder.writeBlobTlv(Tlv.NameComponent, finalBlockIdBuf);
    encoder.writeTypeAndLength
      (Tlv.FinalBlockId, encoder.getLength() - finalBlockIdSaveLength);
  }

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod());
  if (metaInfo.getType() != ContentType.BLOB) {
    // Not the default, so we need to encode the type.
    if (metaInfo.getType() == ContentType.LINK ||
        metaInfo.getType() == ContentType.KEY)
      // The ContentType enum is set up with the correct integer for
      // each NDN-TLV ContentType.
      encoder.writeNonNegativeIntegerTlv(Tlv.ContentType, metaInfo.getType());
    else
      throw new Error("unrecognized TLV ContentType");
  }

  encoder.writeTypeAndLength(Tlv.MetaInfo, encoder.getLength() - saveLength);
};

Tlv0_1_1WireFormat.decodeMetaInfo = function(metaInfo, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.MetaInfo);

  // The ContentType enum is set up with the correct integer for each
  // NDN-TLV ContentType.  If readOptionalNonNegativeIntegerTlv returns
  // None, then setType will convert it to BLOB.
  metaInfo.setType(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ContentType, endOffset));
  metaInfo.setFreshnessPeriod
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.FreshnessPeriod, endOffset));
  if (decoder.peekType(Tlv.FinalBlockId, endOffset)) {
    var finalBlockIdEndOffset = decoder.readNestedTlvsStart(Tlv.FinalBlockId);
    metaInfo.setFinalBlockId(decoder.readBlobTlv(Tlv.NameComponent));
    decoder.finishNestedTlvs(finalBlockIdEndOffset);
  }
  else
    metaInfo.setFinalBlockId(null);

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1_1WireFormat.encodeControlParameters = function(controlParameters, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_ExpirationPeriod,
     controlParameters.getExpirationPeriod());

  if (controlParameters.getStrategy().size() > 0){
    var strategySaveLength = encoder.getLength();
    Tlv0_1_1WireFormat.encodeName(controlParameters.getStrategy(), encoder);
    encoder.writeTypeAndLength(Tlv.ControlParameters_Strategy,
      encoder.getLength() - strategySaveLength);
  }

  var flags = controlParameters.getForwardingFlags().getNfdForwardingFlags();
  if (flags != new ForwardingFlags().getNfdForwardingFlags())
      // The flags are not the default value.
      encoder.writeNonNegativeIntegerTlv
        (Tlv.ControlParameters_Flags, flags);

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_Cost, controlParameters.getCost());
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_Origin, controlParameters.getOrigin());
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_LocalControlFeature,
     controlParameters.getLocalControlFeature());

  if (controlParameters.getUri().length != 0)
    encoder.writeBlobTlv
      (Tlv.ControlParameters_Uri, new Blob(controlParameters.getUri()).buf());

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_FaceId, controlParameters.getFaceId());
  if (controlParameters.getName() != null)
    Tlv0_1_1WireFormat.encodeName(controlParameters.getName(), encoder);

  encoder.writeTypeAndLength
    (Tlv.ControlParameters_ControlParameters, encoder.getLength() - saveLength);
};

Tlv0_1_1WireFormat.decodeControlParameters = function(controlParameters, decoder)
{
  controlParameters.clear();
  var endOffset = decoder.
    readNestedTlvsStart(Tlv.ControlParameters_ControlParameters);

  // decode name
  if (decoder.peekType(Tlv.Name, endOffset)) {
    var name = new Name();
    Tlv0_1_1WireFormat.decodeName(name, decoder);
    controlParameters.setName(name);
  }

  // decode face ID
  controlParameters.setFaceId(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_FaceId, endOffset));

  // decode URI
  if (decoder.peekType(Tlv.ControlParameters_Uri, endOffset)) {
    var uri = new Blob
      (decoder.readOptionalBlobTlv(Tlv.ControlParameters_Uri, endOffset), false);
    controlParameters.setUri(uri.toString());
  }

  // decode integers
  controlParameters.setLocalControlFeature(decoder.
    readOptionalNonNegativeIntegerTlv(
      Tlv.ControlParameters_LocalControlFeature, endOffset));
  controlParameters.setOrigin(decoder.
    readOptionalNonNegativeIntegerTlv(Tlv.ControlParameters_Origin,
      endOffset));
  controlParameters.setCost(decoder.readOptionalNonNegativeIntegerTlv(
    Tlv.ControlParameters_Cost, endOffset));

  // set forwarding flags
  if (decoder.peekType(Tlv.ControlParameters_Flags, endOffset)) {
    var flags = new ForwardingFlags();
    flags.setNfdForwardingFlags(decoder.
      readNonNegativeIntegerTlv(Tlv.ControlParameters_Flags, endOffset));
    controlParameters.setForwardingFlags(flags);
  }

  // decode strategy
  if (decoder.peekType(Tlv.ControlParameters_Strategy, endOffset)) {
    var strategyEndOffset = decoder.readNestedTlvsStart(Tlv.ControlParameters_Strategy);
    Tlv0_1_1WireFormat.decodeName(controlParameters.getStrategy(), decoder);
    decoder.finishNestedTlvs(strategyEndOffset);
  }

  // decode expiration period
  controlParameters.setExpirationPeriod(
    decoder.readOptionalNonNegativeIntegerTlv(
      Tlv.ControlParameters_ExpirationPeriod, endOffset));

  decoder.finishNestedTlvs(endOffset);
};
