/**
 * Copyright (C) 2013-2019 Regents of the University of California.
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
var ComponentType = require('../name.js').ComponentType; /** @ignore */
var RegistrationOptions = require('../registration-options').RegistrationOptions; /** @ignore */
var Tlv = require('./tlv/tlv.js').Tlv; /** @ignore */
var TlvEncoder = require('./tlv/tlv-encoder.js').TlvEncoder; /** @ignore */
var TlvDecoder = require('./tlv/tlv-decoder.js').TlvDecoder; /** @ignore */
var WireFormat = require('./wire-format.js').WireFormat; /** @ignore */
var Exclude = require('../exclude.js').Exclude; /** @ignore */
var ContentType = require('../meta-info.js').ContentType; /** @ignore */
var KeyLocatorType = require('../key-locator.js').KeyLocatorType; /** @ignore */
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var Sha256WithEcdsaSignature = require('../sha256-with-ecdsa-signature.js').Sha256WithEcdsaSignature; /** @ignore */
var GenericSignature = require('../generic-signature.js').GenericSignature; /** @ignore */
var HmacWithSha256Signature = require('../hmac-with-sha256-signature.js').HmacWithSha256Signature; /** @ignore */
var DigestSha256Signature = require('../digest-sha256-signature.js').DigestSha256Signature; /** @ignore */
var ControlParameters = require('../control-parameters.js').ControlParameters; /** @ignore */
var NetworkNack = require('../network-nack.js').NetworkNack; /** @ignore */
var Schedule = require('../encrypt/schedule.js').Schedule; /** @ignore */
var IncomingFaceId = require('../lp/incoming-face-id.js').IncomingFaceId; /** @ignore */
var CongestionMark = require('../lp/congestion-mark.js').CongestionMark; /** @ignore */
var DecodingException = require('./decoding-exception.js').DecodingException;

/**
 * A Tlv0_2WireFormat implements the WireFormat interface for encoding and
 * decoding with the NDN-TLV wire format, version 0.2.
 * @constructor
 */
var Tlv0_2WireFormat = function Tlv0_2WireFormat()
{
  // Inherit from WireFormat.
  WireFormat.call(this);
};

Tlv0_2WireFormat.prototype = new WireFormat();
Tlv0_2WireFormat.prototype.name = "Tlv0_2WireFormat";

exports.Tlv0_2WireFormat = Tlv0_2WireFormat;

// Default object.
Tlv0_2WireFormat.instance = null;

Tlv0_2WireFormat.didCanBePrefixWarning_ = false;

/**
 * Encode name as an NDN-TLV Name and return the encoding.
 * @param {Name} name The Name to encode.
 * @return {Blobl} A Blob containing the encoding.
 */
Tlv0_2WireFormat.prototype.encodeName = function(name)
{
  var encoder = new TlvEncoder();
  Tlv0_2WireFormat.encodeName(name, encoder);
  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode input as a NDN-TLV name and set the fields of the Name object.
 * @param {Name} name The Name object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 */
Tlv0_2WireFormat.prototype.decodeName = function(name, input, copy)
{
  if (copy == null)
    copy = true;

  var decoder = new TlvDecoder(input);
  Tlv0_2WireFormat.decodeName(name, decoder, copy);
};

/**
 * Encode the interest using NDN-TLV and return a Buffer.
 * @param {Interest} interest The Interest object to encode.
 * @return {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the signed
 * portion. The signed portion starts from the first name component and ends
 * just before the final name component (which is assumed to be a signature for
 * a signed interest).
 */
Tlv0_2WireFormat.prototype.encodeInterest = function(interest)
{
  if (!interest.didSetCanBePrefix_ && !Tlv0_2WireFormat.didCanBePrefixWarning_) {
    console.log
      ("WARNING: The default CanBePrefix will change. See Interest.setDefaultCanBePrefix() for details.");
    Tlv0_2WireFormat.didCanBePrefixWarning_ = true;
  }

  return Tlv0_2WireFormat.encodeInterestV03_(interest);
};

/**
 * Decode input as an NDN-TLV interest and set the fields of the interest
 * object.
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
 */
Tlv0_2WireFormat.prototype.decodeInterest = function(interest, input, copy)
{
  try {
    return this.decodeInterestV02_(interest, input, copy);
  } catch (exceptionV02) {
    try {
      // Failed to decode as format v0.2. Try to decode as v0.3.
      return Tlv0_2WireFormat.decodeInterestV03_(interest, input, copy);
    } catch (ex) {
      // Ignore the exception decoding as format v0.3 and throw the exception
      // from trying to decode as format as format v0.2.
      throw exceptionV02;
    }
  }
};

/**
 * Do the work of decodeInterest to decode strictly as format v0.2.
 */
Tlv0_2WireFormat.prototype.decodeInterestV02_ = function(interest, input, copy)
{
  if (copy == null)
    copy = true;

  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
  var offsets = Tlv0_2WireFormat.decodeName(interest.getName(), decoder, copy);
  if (decoder.peekType(Tlv.Selectors, endOffset))
    Tlv0_2WireFormat.decodeSelectors(interest, decoder, copy);
  else {
    // Set selectors to none.
    interest.setMinSuffixComponents(null);
    interest.setMaxSuffixComponents(null);
    interest.getKeyLocator().clear();
    interest.getExclude().clear();
    interest.setChildSelector(null);
    interest.setMustBeFresh(false);
  }
  // Require a Nonce, but don't force it to be 4 bytes.
  var nonce = decoder.readBlobTlv(Tlv.Nonce);
  interest.setInterestLifetimeMilliseconds
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.InterestLifetime, endOffset));

  if (decoder.peekType(Tlv.ForwardingHint, endOffset)) {
    var forwardingHintEndOffset = decoder.readNestedTlvsStart
      (Tlv.ForwardingHint);
    Tlv0_2WireFormat.decodeDelegationSet_
      (interest.getForwardingHint(), forwardingHintEndOffset, decoder, copy);
    decoder.finishNestedTlvs(forwardingHintEndOffset);
  }

  if (decoder.peekType(Tlv.Data, endOffset)) {
    // Get the bytes of the Link TLV.
    var linkBeginOffset = decoder.getOffset();
    var linkEndOffset = decoder.readNestedTlvsStart(Tlv.Data);
    decoder.seek(linkEndOffset);

    interest.setLinkWireEncoding
      (new Blob(decoder.getSlice(linkBeginOffset, linkEndOffset), copy), this);
  }
  else
    interest.unsetLink();
  interest.setSelectedDelegationIndex
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.SelectedDelegation, endOffset));
  if (interest.getSelectedDelegationIndex() != null &&
      interest.getSelectedDelegationIndex() >= 0 && !interest.hasLink())
    throw new Error("Interest has a selected delegation, but no link object");

  // Format v0.2 doesn't have application parameters.
  interest.setApplicationParameters(new Blob());

  // Set the nonce last because setting other interest fields clears it.
  interest.setNonce(new Blob(nonce, copy));

  decoder.finishNestedTlvs(endOffset);
  return offsets;
};

/**
 * Encode data as NDN-TLV and return the encoding and signed offsets.
 * @param {Data} data The Data object to encode.
 * @return {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the
 * signed portion.
 */
Tlv0_2WireFormat.prototype.encodeData = function(data)
{
  var encoder = new TlvEncoder(1500);
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeBlobTlv(Tlv.SignatureValue, data.getSignature().getSignature().buf());
  var signedPortionEndOffsetFromBack = encoder.getLength();

  Tlv0_2WireFormat.encodeSignatureInfo_(data.getSignature(), encoder);
  encoder.writeBlobTlv(Tlv.Content, data.getContent().buf());
  Tlv0_2WireFormat.encodeMetaInfo(data.getMetaInfo(), encoder);
  Tlv0_2WireFormat.encodeName(data.getName(), encoder);
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
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @return {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 */
Tlv0_2WireFormat.prototype.decodeData = function(data, input, copy)
{
  if (copy == null)
    copy = true;

  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Data);
  var signedPortionBeginOffset = decoder.getOffset();

  Tlv0_2WireFormat.decodeName(data.getName(), decoder, copy);
  if (decoder.peekType(Tlv.MetaInfo, endOffset))
    Tlv0_2WireFormat.decodeMetaInfo(data.getMetaInfo(), decoder, copy);
  else
    data.getMetaInfo().clear();
  data.setContent(new Blob(decoder.readOptionalBlobTlv(Tlv.Content, endOffset), copy));
  Tlv0_2WireFormat.decodeSignatureInfo(data, decoder, copy);

  var signedPortionEndOffset = decoder.getOffset();
  data.getSignature().setSignature
    (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), copy));

  decoder.finishNestedTlvs(endOffset);
  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Encode controlParameters as NDN-TLV and return the encoding.
 * @param {ControlParameters} controlParameters The ControlParameters object to
 * encode.
 * @return {Blob} A Blob containing the encoding.
 */
Tlv0_2WireFormat.prototype.encodeControlParameters = function(controlParameters)
{
  var encoder = new TlvEncoder(256);
  Tlv0_2WireFormat.encodeControlParameters(controlParameters, encoder);
  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode controlParameters in NDN-TLV and set the fields of the
 * controlParameters object.
 * @param {ControlParameters} controlParameters The ControlParameters object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @throws DecodingException For invalid encoding
 */
Tlv0_2WireFormat.prototype.decodeControlParameters = function
  (controlParameters, input, copy)
{
  if (copy == null)
    copy = true;

  var decoder = new TlvDecoder(input);
  Tlv0_2WireFormat.decodeControlParameters(controlParameters, decoder, copy);
};

/**
 * Encode controlResponse as NDN-TLV and return the encoding.
 * @param {ControlResponse} controlResponse The ControlResponse object to
 * encode.
 * @return {Blob} A Blob containing the encoding.
 */
Tlv0_2WireFormat.prototype.encodeControlResponse = function(controlResponse)
{
  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.

  // Encode the body.
  if (controlResponse.getBodyAsControlParameters() != null)
    Tlv0_2WireFormat.encodeControlParameters
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
 * Decode controlResponse in NDN-TLV and set the fields of the controlResponse
 * object
 * @param {ControlResponse} controlResponse The ControlResponse object whose
 * fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @throws DecodingException For invalid encoding
 */
Tlv0_2WireFormat.prototype.decodeControlResponse = function
  (controlResponse, input, copy)
{
  if (copy == null)
    copy = true;

  var decoder = new TlvDecoder(input);
  var endOffset = decoder.readNestedTlvsStart(Tlv.NfdCommand_ControlResponse);

  controlResponse.setStatusCode(decoder.readNonNegativeIntegerTlv
    (Tlv.NfdCommand_StatusCode));
  // Set copy false since we just immediately get a string.
  var statusText = new Blob
    (decoder.readBlobTlv(Tlv.NfdCommand_StatusText), false);
  controlResponse.setStatusText(statusText.toString());

  // Decode the body.
  if (decoder.peekType(Tlv.ControlParameters_ControlParameters, endOffset)) {
    controlResponse.setBodyAsControlParameters(new ControlParameters());
    // Decode into the existing ControlParameters to avoid copying.
    Tlv0_2WireFormat.decodeControlParameters
      (controlResponse.getBodyAsControlParameters(), decoder, copy);
  }
  else
    controlResponse.setBodyAsControlParameters(null);

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode signature as an NDN-TLV SignatureInfo and return the encoding.
 * @param {Signature} signature An object of a subclass of Signature to encode.
 * @return {Blob} A Blob containing the encoding.
 */
Tlv0_2WireFormat.prototype.encodeSignatureInfo = function(signature)
{
  var encoder = new TlvEncoder(256);
  Tlv0_2WireFormat.encodeSignatureInfo_(signature, encoder);

  return new Blob(encoder.getOutput(), false);
};

// SignatureHolder is used by decodeSignatureInfoAndValue.
Tlv0_2WireFormat.SignatureHolder = function Tlv0_2WireFormatSignatureHolder()
{
};

Tlv0_2WireFormat.SignatureHolder.prototype.setSignature = function(signature)
{
  this.signature = signature;
};

Tlv0_2WireFormat.SignatureHolder.prototype.getSignature = function()
{
  return this.signature;
};

/**
 * Decode signatureInfo as an NDN-TLV SignatureInfo and signatureValue as the
 * related SignatureValue, and return a new object which is a subclass of Signature.
 * @param {Buffer} signatureInfo The buffer with the signature info bytes to
 * decode.
 * @param {Buffer} signatureValue The buffer with the signature value to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @return {Signature} A new object which is a subclass of Signature.
 */
Tlv0_2WireFormat.prototype.decodeSignatureInfoAndValue = function
  (signatureInfo, signatureValue, copy)
{
  if (copy == null)
    copy = true;

  // Use a SignatureHolder to imitate a Data object for decodeSignatureInfo.
  var signatureHolder = new Tlv0_2WireFormat.SignatureHolder();
  var decoder = new TlvDecoder(signatureInfo);
  Tlv0_2WireFormat.decodeSignatureInfo(signatureHolder, decoder, copy);

  decoder = new TlvDecoder(signatureValue);
  signatureHolder.getSignature().setSignature
    (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), copy));

  return signatureHolder.getSignature();
};

/**
 * Encode the signatureValue in the Signature object as an NDN-TLV
 * SignatureValue (the signature bits) and return the encoding.
 * @param {Signature} signature An object of a subclass of Signature with the
 * signature value to encode.
 * @return {Blob} A Blob containing the encoding.
 */
Tlv0_2WireFormat.prototype.encodeSignatureValue = function(signature)
{
  var encoder = new TlvEncoder(256);
  encoder.writeBlobTlv(Tlv.SignatureValue, signature.getSignature().buf());

  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode input as an NDN-TLV LpPacket and set the fields of the lpPacket object.
 * @param {LpPacket} lpPacket The LpPacket object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 */
Tlv0_2WireFormat.prototype.decodeLpPacket = function(lpPacket, input, copy)
{
  if (copy == null)
    copy = true;

  lpPacket.clear();

  var decoder = new TlvDecoder(input);
  var endOffset = decoder.readNestedTlvsStart(Tlv.LpPacket_LpPacket);

  while (decoder.getOffset() < endOffset) {
    // Imitate TlvDecoder.readTypeAndLength.
    var fieldType = decoder.readVarNumber();
    var fieldLength = decoder.readVarNumber();
    var fieldEndOffset = decoder.getOffset() + fieldLength;
    if (fieldEndOffset > input.length)
      throw new DecodingException(new Error("TLV length exceeds the buffer length"));

    if (fieldType == Tlv.LpPacket_Fragment) {
      // Set the fragment to the bytes of the TLV value.
      lpPacket.setFragmentWireEncoding
        (new Blob(decoder.getSlice(decoder.getOffset(), fieldEndOffset), copy));
      decoder.seek(fieldEndOffset);

      // The fragment is supposed to be the last field.
      break;
    }
    else if (fieldType == Tlv.LpPacket_Nack) {
      var networkNack = new NetworkNack();
      var code = decoder.readOptionalNonNegativeIntegerTlv
        (Tlv.LpPacket_NackReason, fieldEndOffset);
      var reason;
      // The enum numeric values are the same as this wire format, so use as is.
      if (code < 0 || code == NetworkNack.Reason.NONE)
        // This includes an omitted NackReason.
        networkNack.setReason(NetworkNack.Reason.NONE);
      else if (code == NetworkNack.Reason.CONGESTION ||
               code == NetworkNack.Reason.DUPLICATE ||
               code == NetworkNack.Reason.NO_ROUTE)
        networkNack.setReason(code);
      else {
        // Unrecognized reason.
        networkNack.setReason(NetworkNack.Reason.OTHER_CODE);
        networkNack.setOtherReasonCode(code);
      }

      lpPacket.addHeaderField(networkNack);
    }
    else if (fieldType == Tlv.LpPacket_IncomingFaceId) {
      var incomingFaceId = new IncomingFaceId();
      incomingFaceId.setFaceId(decoder.readNonNegativeInteger(fieldLength));
      lpPacket.addHeaderField(incomingFaceId);
    }
    else if (fieldType == Tlv.LpPacket_CongestionMark) {
      var congestionMark = new CongestionMark();
      congestionMark.setCongestionMark(decoder.readNonNegativeInteger
        (fieldLength));
      lpPacket.addHeaderField(congestionMark);
    }
    else {
      // Unrecognized field type. The conditions for ignoring are here:
      // http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
      var canIgnore =
        (fieldType >= Tlv.LpPacket_IGNORE_MIN &&
         fieldType <= Tlv.LpPacket_IGNORE_MAX &&
         (fieldType & 0x03) == 0);
      if  (!canIgnore)
        throw new DecodingException(new Error("Did not get the expected TLV type"));

      // Ignore.
      decoder.seek(fieldEndOffset);
    }

    decoder.finishNestedTlvs(fieldEndOffset);
  }

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode delegationSet as a sequence of NDN-TLV Delegation, and return the
 * encoding. Note that the sequence of Delegation does not have an outer TLV
 * type and length because it is intended to use the type and length of a Data
 * packet's Content.
 * @param {DelegationSet} delegationSet The DelegationSet object to encode.
 * @return {Blob} A Blob containing the encoding.
 */
Tlv0_2WireFormat.prototype.encodeDelegationSet = function(delegationSet)
{
  var encoder = new TlvEncoder(256);
  Tlv0_2WireFormat.encodeDelegationSet_(delegationSet, encoder);

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
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 */
Tlv0_2WireFormat.prototype.decodeDelegationSet = function
  (delegationSet, input, copy)
{
  if (copy == null)
    copy = true;

  var decoder = new TlvDecoder(input);
  Tlv0_2WireFormat.decodeDelegationSet_
    (delegationSet, input.length, decoder, copy);
};

/**
 * Encode the EncryptedContent v1 in NDN-TLV and return the encoding.
 * @param {EncryptedContent} encryptedContent The EncryptedContent object to
 * encode.
 * @return {Blob} A Blob containing the encoding.
 */
Tlv0_2WireFormat.prototype.encodeEncryptedContent = function(encryptedContent)
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
  Tlv0_2WireFormat.encodeKeyLocator
    (Tlv.KeyLocator, encryptedContent.getKeyLocator(), encoder);

  encoder.writeTypeAndLength
    (Tlv.Encrypt_EncryptedContent, encoder.getLength() - saveLength);

  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode input as an EncryptedContent v1 in NDN-TLV and set the fields of the
 * encryptedContent object.
 * @param {EncryptedContent} encryptedContent The EncryptedContent object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 */
Tlv0_2WireFormat.prototype.decodeEncryptedContent = function
  (encryptedContent, input, copy)
{
  if (copy == null)
    copy = true;

  var decoder = new TlvDecoder(input);
  var endOffset = decoder.
    readNestedTlvsStart(Tlv.Encrypt_EncryptedContent);

  encryptedContent.clear();
  Tlv0_2WireFormat.decodeKeyLocator
    (Tlv.KeyLocator, encryptedContent.getKeyLocator(), decoder, copy);
  encryptedContent.setAlgorithmType
    (decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_EncryptionAlgorithm));
  encryptedContent.setInitialVector
    (new Blob(decoder.readOptionalBlobTlv
     (Tlv.Encrypt_InitialVector, endOffset), copy));
  encryptedContent.setPayload
    (new Blob(decoder.readBlobTlv(Tlv.Encrypt_EncryptedPayload), copy));

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode the EncryptedContent v2 (used in Name-based Access Control v2) in
 * NDN-TLV and return the encoding.
 * @param {EncryptedContent} encryptedContent The EncryptedContent object to
 * encode.
 * @return {Blob} A Blob containing the encoding.
 */
Tlv0_2WireFormat.prototype.encodeEncryptedContentV2 = function(encryptedContent)
{
  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (encryptedContent.getKeyLocator().getType() == KeyLocatorType.KEYNAME)
    Tlv0_2WireFormat.encodeName
      (encryptedContent.getKeyLocator().getKeyName(), encoder);
  encoder.writeOptionalBlobTlv
    (Tlv.Encrypt_EncryptedPayloadKey, encryptedContent.getPayloadKey().buf());
  encoder.writeOptionalBlobTlv
    (Tlv.Encrypt_InitialVector, encryptedContent.getInitialVector().buf());
  encoder.writeBlobTlv
    (Tlv.Encrypt_EncryptedPayload, encryptedContent.getPayload().buf());

  encoder.writeTypeAndLength
    (Tlv.Encrypt_EncryptedContent, encoder.getLength() - saveLength);

  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode input as an EncryptedContent v2 (used in Name-based Access Control
 * v2) in NDN-TLV and set the fields of the encryptedContent object.
 * See https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst .
 * @param {EncryptedContent} encryptedContent The EncryptedContent object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 */
Tlv0_2WireFormat.prototype.decodeEncryptedContentV2 = function
  (encryptedContent, input, copy)
{
  if (copy == null)
    copy = true;

  var decoder = new TlvDecoder(input);
  var endOffset = decoder.
    readNestedTlvsStart(Tlv.Encrypt_EncryptedContent);

  encryptedContent.clear();
  encryptedContent.setPayload
    (new Blob(decoder.readBlobTlv(Tlv.Encrypt_EncryptedPayload), copy));
  encryptedContent.setInitialVector
    (new Blob(decoder.readOptionalBlobTlv
     (Tlv.Encrypt_InitialVector, endOffset), copy));
  encryptedContent.setPayloadKey
    (new Blob(decoder.readOptionalBlobTlv
     (Tlv.Encrypt_EncryptedPayloadKey, endOffset), copy));

  if (decoder.peekType(Tlv.Name, endOffset)) {
    Tlv0_2WireFormat.decodeName
      (encryptedContent.getKeyLocator().getKeyName(), decoder, copy);
    encryptedContent.getKeyLocator().setType(KeyLocatorType.KEYNAME);
  }

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Get a singleton instance of a Tlv0_2WireFormat.  To always use the
 * preferred version NDN-TLV, you should use TlvWireFormat.get().
 * @return {Tlv0_2WireFormat} The singleton instance.
 */
Tlv0_2WireFormat.get = function()
{
  if (Tlv0_2WireFormat.instance === null)
    Tlv0_2WireFormat.instance = new Tlv0_2WireFormat();
  return Tlv0_2WireFormat.instance;
};

/**
 * Encode the name component to the encoder as NDN-TLV. This handles different
 * component types such as ImplicitSha256DigestComponent.
 * @param {Name.Component} component The name component to encode.
 * @param {TlvEncoder} encoder The encoder to receive the encoding.
 */
Tlv0_2WireFormat.encodeNameComponent = function(component, encoder)
{
  var type;
  if (component.getType() === ComponentType.OTHER_CODE)
    type = component.getOtherTypeCode();
  else
    // The enum values are the same as the TLV type codes.
    type = component.getType();

  encoder.writeBlobTlv(type, component.getValue().buf());
};

/**
 * Decode the name component as NDN-TLV and return the component. This handles
 * different component types such as ImplicitSha256DigestComponent.
 * @param {TlvDecoder} decoder The decoder with the input.
 * @param {boolean} copy (optional) If true, copy from the input when making new
 * Blob values. If false, then Blob values share memory with the input, which
 * must remain unchanged while the Blob values are used. If omitted, use true.
 * @return {Name.Component} A new Name.Component.
 */
Tlv0_2WireFormat.decodeNameComponent = function(decoder, copy)
{
  if (copy == null)
    copy = true;

  var savePosition = decoder.getOffset();
  var type = decoder.readVarNumber();
  // Restore the position.
  decoder.seek(savePosition);

  var value = new Blob(decoder.readBlobTlv(type), copy);
  if (type === Tlv.ImplicitSha256DigestComponent)
    return Name.Component.fromImplicitSha256Digest(value);
  else if (type === Tlv.ParametersSha256DigestComponent)
    return Name.Component.fromParametersSha256Digest(value);
  else if (type === Tlv.NameComponent)
    return new Name.Component(value);
  else
    // Unrecognized type code.
    return new Name.Component(value, ComponentType.OTHER_CODE, type);
};

/**
 * Encode the name to the encoder.
 * @param {Name} name The name to encode.
 * @param {TlvEncoder} encoder The encoder to receive the encoding.
 * @return {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
Tlv0_2WireFormat.encodeName = function(name, encoder)
{
  var saveLength = encoder.getLength();

  // Encode the components backwards.
  var signedPortionEndOffsetFromBack;
  for (var i = name.size() - 1; i >= 0; --i) {
    Tlv0_2WireFormat.encodeNameComponent(name.get(i), encoder);
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
 * @return {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
Tlv0_2WireFormat.decodeName = function(name, decoder, copy)
{
  name.clear();

  var endOffset = decoder.readNestedTlvsStart(Tlv.Name);
  var signedPortionBeginOffset = decoder.getOffset();
  // In case there are no components, set signedPortionEndOffset arbitrarily.
  var signedPortionEndOffset = signedPortionBeginOffset;

  while (decoder.getOffset() < endOffset) {
    signedPortionEndOffset = decoder.getOffset();
    name.append(Tlv0_2WireFormat.decodeNameComponent(decoder, copy));
  }

  decoder.finishNestedTlvs(endOffset);

  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Encode the interest selectors.  If no selectors are written, do not output a
 * Selectors TLV.
 */
Tlv0_2WireFormat.encodeSelectors = function(interest, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (interest.getMustBeFresh())
    encoder.writeTypeAndLength(Tlv.MustBeFresh, 0);
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.ChildSelector, interest.getChildSelector());
  if (interest.getExclude().size() > 0)
    Tlv0_2WireFormat.encodeExclude(interest.getExclude(), encoder);

  if (interest.getKeyLocator().getType() != null)
    Tlv0_2WireFormat.encodeKeyLocator
      (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), encoder);

  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents());
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MinSuffixComponents, interest.getMinSuffixComponents());

  // Only output the type and length if values were written.
  if (encoder.getLength() != saveLength)
    encoder.writeTypeAndLength(Tlv.Selectors, encoder.getLength() - saveLength);
};

Tlv0_2WireFormat.decodeSelectors = function(interest, decoder, copy)
{
  if (copy == null)
    copy = true;

  var endOffset = decoder.readNestedTlvsStart(Tlv.Selectors);

  interest.setMinSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MinSuffixComponents, endOffset));
  interest.setMaxSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MaxSuffixComponents, endOffset));

  if (decoder.peekType(Tlv.PublisherPublicKeyLocator, endOffset))
    Tlv0_2WireFormat.decodeKeyLocator
      (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), decoder, copy);
  else
    interest.getKeyLocator().clear();

  if (decoder.peekType(Tlv.Exclude, endOffset))
    Tlv0_2WireFormat.decodeExclude(interest.getExclude(), decoder, copy);
  else
    interest.getExclude().clear();

  interest.setChildSelector(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ChildSelector, endOffset));
  interest.setMustBeFresh(decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset));

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_2WireFormat.encodeExclude = function(exclude, encoder)
{
  var saveLength = encoder.getLength();

  // TODO: Do we want to order the components (except for ANY)?
  // Encode the entries backwards.
  for (var i = exclude.size() - 1; i >= 0; --i) {
    var entry = exclude.get(i);

    if (entry == Exclude.ANY)
      encoder.writeTypeAndLength(Tlv.Any, 0);
    else
      Tlv0_2WireFormat.encodeNameComponent(entry, encoder);
  }

  encoder.writeTypeAndLength(Tlv.Exclude, encoder.getLength() - saveLength);
};

Tlv0_2WireFormat.decodeExclude = function(exclude, decoder, copy)
{
  if (copy == null)
    copy = true;

  var endOffset = decoder.readNestedTlvsStart(Tlv.Exclude);

  exclude.clear();
  while (decoder.getOffset() < endOffset) {
    if (decoder.peekType(Tlv.Any, endOffset)) {
      // Read past the Any TLV.
      decoder.readBooleanTlv(Tlv.Any, endOffset);
      exclude.appendAny();
    }
    else
      exclude.appendComponent(Tlv0_2WireFormat.decodeNameComponent(decoder, copy));
  }

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_2WireFormat.encodeKeyLocator = function(type, keyLocator, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (keyLocator.getType() != null) {
    if (keyLocator.getType() == KeyLocatorType.KEYNAME)
      Tlv0_2WireFormat.encodeName(keyLocator.getKeyName(), encoder);
    else if (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
             keyLocator.getKeyData().size() > 0)
      encoder.writeBlobTlv(Tlv.KeyLocatorDigest, keyLocator.getKeyData().buf());
    else
      throw new Error("Unrecognized KeyLocatorType " + keyLocator.getType());
  }

  encoder.writeTypeAndLength(type, encoder.getLength() - saveLength);
};

Tlv0_2WireFormat.decodeKeyLocator = function
  (expectedType, keyLocator, decoder, copy)
{
  if (copy == null)
    copy = true;

  var endOffset = decoder.readNestedTlvsStart(expectedType);

  keyLocator.clear();

  if (decoder.getOffset() == endOffset)
    // The KeyLocator is omitted, so leave the fields as none.
    return;

  if (decoder.peekType(Tlv.Name, endOffset)) {
    // KeyLocator is a Name.
    keyLocator.setType(KeyLocatorType.KEYNAME);
    Tlv0_2WireFormat.decodeName(keyLocator.getKeyName(), decoder, copy);
  }
  else if (decoder.peekType(Tlv.KeyLocatorDigest, endOffset)) {
    // KeyLocator is a KeyLocatorDigest.
    keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    keyLocator.setKeyData
      (new Blob(decoder.readBlobTlv(Tlv.KeyLocatorDigest), copy));
  }
  else
    throw new DecodingException(new Error
      ("decodeKeyLocator: Unrecognized key locator type"));

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_2WireFormat.encodeValidityPeriod_ = function(validityPeriod, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeBlobTlv(Tlv.ValidityPeriod_NotAfter,
    new Blob(Schedule.toIsoString(validityPeriod.getNotAfter())).buf());
  encoder.writeBlobTlv(Tlv.ValidityPeriod_NotBefore,
    new Blob(Schedule.toIsoString(validityPeriod.getNotBefore())).buf());

  encoder.writeTypeAndLength
    (Tlv.ValidityPeriod_ValidityPeriod, encoder.getLength() - saveLength);
};

Tlv0_2WireFormat.decodeValidityPeriod_ = function(validityPeriod, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.ValidityPeriod_ValidityPeriod);

  validityPeriod.clear();

  // Set copy false since we just immediately get the string.
  var isoString = new Blob
    (decoder.readBlobTlv(Tlv.ValidityPeriod_NotBefore), false);
  var notBefore = Schedule.fromIsoString(isoString.toString());
  isoString = new Blob
    (decoder.readBlobTlv(Tlv.ValidityPeriod_NotAfter), false);
  var notAfter = Schedule.fromIsoString(isoString.toString());

  validityPeriod.setPeriod(notBefore, notAfter);

  decoder.finishNestedTlvs(endOffset);
};

/**
 * An internal method to encode signature as the appropriate form of
 * SignatureInfo in NDN-TLV.
 * @param {Signature} signature An object of a subclass of Signature to encode.
 * @param {TlvEncoder} encoder The encoder.
 */
Tlv0_2WireFormat.encodeSignatureInfo_ = function(signature, encoder)
{
  if (signature instanceof GenericSignature) {
    // Handle GenericSignature separately since it has the entire encoding.
    var encoding = signature.getSignatureInfoEncoding();

    // Do a test decoding to sanity check that it is valid TLV.
    try {
      var decoder = new TlvDecoder(encoding.buf());
      var endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);
      decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
      // Skip unrecognized TLVs, even if they have a critical type code.
      decoder.finishNestedTlvs(endOffset, true);
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
    if (signature.getValidityPeriod().hasPeriod())
      Tlv0_2WireFormat.encodeValidityPeriod_
        (signature.getValidityPeriod(), encoder);
    Tlv0_2WireFormat.encodeKeyLocator
      (Tlv.KeyLocator, signature.getKeyLocator(), encoder);
    encoder.writeNonNegativeIntegerTlv
      (Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithRsa);
  }
  else if (signature instanceof Sha256WithEcdsaSignature) {
    if (signature.getValidityPeriod().hasPeriod())
      Tlv0_2WireFormat.encodeValidityPeriod_
        (signature.getValidityPeriod(), encoder);
    Tlv0_2WireFormat.encodeKeyLocator
      (Tlv.KeyLocator, signature.getKeyLocator(), encoder);
    encoder.writeNonNegativeIntegerTlv
      (Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithEcdsa);
  }
  else if (signature instanceof HmacWithSha256Signature) {
    Tlv0_2WireFormat.encodeKeyLocator
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

Tlv0_2WireFormat.decodeSignatureInfo = function(data, decoder, copy)
{
  if (copy == null)
    copy = true;

  var beginOffset = decoder.getOffset();
  var endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);

  var signatureType = decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
  if (signatureType == Tlv.SignatureType_SignatureSha256WithRsa) {
    data.setSignature(new Sha256WithRsaSignature());
    // Modify data's signature object because if we create an object
    //   and set it, then data will have to copy all the fields.
    var signatureInfo = data.getSignature();
    Tlv0_2WireFormat.decodeKeyLocator
      (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder, copy);
    if (decoder.peekType(Tlv.ValidityPeriod_ValidityPeriod, endOffset))
      Tlv0_2WireFormat.decodeValidityPeriod_
        (signatureInfo.getValidityPeriod(), decoder);
  }
  else if (signatureType == Tlv.SignatureType_SignatureSha256WithEcdsa) {
    data.setSignature(new Sha256WithEcdsaSignature());
    var signatureInfo = data.getSignature();
    Tlv0_2WireFormat.decodeKeyLocator
      (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder, copy);
    if (decoder.peekType(Tlv.ValidityPeriod_ValidityPeriod, endOffset))
      Tlv0_2WireFormat.decodeValidityPeriod_
        (signatureInfo.getValidityPeriod(), decoder);
  }
  else if (signatureType == Tlv.SignatureType_SignatureHmacWithSha256) {
    data.setSignature(new HmacWithSha256Signature());
    var signatureInfo = data.getSignature();
    Tlv0_2WireFormat.decodeKeyLocator
      (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder, copy);
  }
  else if (signatureType == Tlv.SignatureType_DigestSha256)
    data.setSignature(new DigestSha256Signature());
  else {
    data.setSignature(new GenericSignature());
    var signatureInfo = data.getSignature();

    // Get the bytes of the SignatureInfo TLV.
    signatureInfo.setSignatureInfoEncoding
      (new Blob(decoder.getSlice(beginOffset, endOffset), copy), signatureType);
    // Skip the remaining TLVs now, allowing unrecognized critical type codes.
    decoder.finishNestedTlvs(endOffset, true);
  }

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_2WireFormat.encodeMetaInfo = function(metaInfo, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  var finalBlockIdBuf = metaInfo.getFinalBlockId().getValue().buf();
  if (finalBlockIdBuf != null && finalBlockIdBuf.length > 0) {
    // FinalBlockId has an inner NameComponent.
    var finalBlockIdSaveLength = encoder.getLength();
    Tlv0_2WireFormat.encodeNameComponent(metaInfo.getFinalBlockId(), encoder);
    encoder.writeTypeAndLength
      (Tlv.FinalBlockId, encoder.getLength() - finalBlockIdSaveLength);
  }

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod());
  if (metaInfo.getType() != ContentType.BLOB) {
    // Not the default, so we need to encode the type.
    if (metaInfo.getType() == ContentType.LINK ||
        metaInfo.getType() == ContentType.KEY ||
        metaInfo.getType() == ContentType.NACK)
      // The ContentType enum is set up with the correct integer for
      // each NDN-TLV ContentType.
      encoder.writeNonNegativeIntegerTlv(Tlv.ContentType, metaInfo.getType());
    else if (metaInfo.getType() == ContentType.OTHER_CODE)
      encoder.writeNonNegativeIntegerTlv
        (Tlv.ContentType, metaInfo.getOtherTypeCode());
    else
      // We don't expect this to happen.
      throw new Error("unrecognized TLV ContentType");
  }

  encoder.writeTypeAndLength(Tlv.MetaInfo, encoder.getLength() - saveLength);
};

Tlv0_2WireFormat.decodeMetaInfo = function(metaInfo, decoder, copy)
{
  if (copy == null)
    copy = true;

  var endOffset = decoder.readNestedTlvsStart(Tlv.MetaInfo);

  var type = decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ContentType, endOffset);
  if (type == null || type < 0 || type === ContentType.BLOB)
    metaInfo.setType(ContentType.BLOB);
  else if (type === ContentType.LINK ||
           type === ContentType.KEY ||
           type === ContentType.NACK)
    // The ContentType enum is set up with the correct integer for each NDN-TLV
    // ContentType.
    metaInfo.setType(type);
  else {
    // Unrecognized content type.
    metaInfo.setType(ContentType.OTHER_CODE);
    metaInfo.setOtherTypeCode(type);
  }

  metaInfo.setFreshnessPeriod
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.FreshnessPeriod, endOffset));
  if (decoder.peekType(Tlv.FinalBlockId, endOffset)) {
    var finalBlockIdEndOffset = decoder.readNestedTlvsStart(Tlv.FinalBlockId);
    metaInfo.setFinalBlockId(Tlv0_2WireFormat.decodeNameComponent(decoder, copy));
    decoder.finishNestedTlvs(finalBlockIdEndOffset);
  }
  else
    metaInfo.setFinalBlockId(null);

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_2WireFormat.encodeControlParameters = function(controlParameters, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_ExpirationPeriod,
     controlParameters.getExpirationPeriod());

  if (controlParameters.getStrategy().size() > 0){
    var strategySaveLength = encoder.getLength();
    Tlv0_2WireFormat.encodeName(controlParameters.getStrategy(), encoder);
    encoder.writeTypeAndLength(Tlv.ControlParameters_Strategy,
      encoder.getLength() - strategySaveLength);
  }

  var flags = controlParameters.getForwardingFlags().getNfdForwardingFlags();
  if (flags != new RegistrationOptions().getNfdForwardingFlags())
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
    Tlv0_2WireFormat.encodeName(controlParameters.getName(), encoder);

  encoder.writeTypeAndLength
    (Tlv.ControlParameters_ControlParameters, encoder.getLength() - saveLength);
};

Tlv0_2WireFormat.decodeControlParameters = function
  (controlParameters, decoder, copy)
{
  if (copy == null)
    copy = true;

  controlParameters.clear();
  var endOffset = decoder.
    readNestedTlvsStart(Tlv.ControlParameters_ControlParameters);

  // decode name
  if (decoder.peekType(Tlv.Name, endOffset)) {
    var name = new Name();
    Tlv0_2WireFormat.decodeName(name, decoder, copy);
    controlParameters.setName(name);
  }

  // decode face ID
  controlParameters.setFaceId(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_FaceId, endOffset));

  // decode URI
  if (decoder.peekType(Tlv.ControlParameters_Uri, endOffset)) {
    // Set copy false since we just immediately get the string.
    var uri = new Blob
      (decoder.readOptionalBlobTlv(Tlv.ControlParameters_Uri, endOffset), false);
    controlParameters.setUri(uri.toString());
  }

  decoder.skipOptionalTlv(Tlv.ControlParameters_LocalUri, endOffset);

  // decode integers
  controlParameters.setLocalControlFeature(decoder.
    readOptionalNonNegativeIntegerTlv(
      Tlv.ControlParameters_LocalControlFeature, endOffset));
  controlParameters.setOrigin(decoder.
    readOptionalNonNegativeIntegerTlv(Tlv.ControlParameters_Origin,
      endOffset));
  controlParameters.setCost(decoder.readOptionalNonNegativeIntegerTlv(
    Tlv.ControlParameters_Cost, endOffset));

  decoder.skipOptionalTlv(Tlv.ControlParameters_Capacity, endOffset);
  decoder.skipOptionalTlv(Tlv.ControlParameters_Count, endOffset);
  decoder.skipOptionalTlv
    (Tlv.ControlParameters_BaseCongestionMarkingInterval, endOffset);
  decoder.skipOptionalTlv
    (Tlv.ControlParameters_DefaultCongestionThreshold, endOffset);
  decoder.skipOptionalTlv(Tlv.ControlParameters_Mtu, endOffset);

  // set forwarding flags
  if (decoder.peekType(Tlv.ControlParameters_Flags, endOffset)) {
    var flags = new RegistrationOptions();
    flags.setNfdForwardingFlags(decoder.
      readNonNegativeIntegerTlv(Tlv.ControlParameters_Flags, endOffset));
    controlParameters.setForwardingFlags(flags);
  }

  decoder.skipOptionalTlv(Tlv.ControlParameters_Mask, endOffset);

  // decode strategy
  if (decoder.peekType(Tlv.ControlParameters_Strategy, endOffset)) {
    var strategyEndOffset = decoder.readNestedTlvsStart(Tlv.ControlParameters_Strategy);
    Tlv0_2WireFormat.decodeName(controlParameters.getStrategy(), decoder, copy);
    decoder.finishNestedTlvs(strategyEndOffset);
  }

  // decode expiration period
  controlParameters.setExpirationPeriod(
    decoder.readOptionalNonNegativeIntegerTlv(
      Tlv.ControlParameters_ExpirationPeriod, endOffset));

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode delegationSet to the encoder as a sequence of NDN-TLV Delegation.
 * Note that the sequence of Delegation does not have an outer TLV type and
 * length because (when used in a Link object) it is intended to use the type
 * and length of a Data packet's Content.
 * @param {DelegationSet} delegationSet The DelegationSet object to encode.
 * @param {TlvEncoder} encoder The TlvEncoder to receive the encoding.
 */
Tlv0_2WireFormat.encodeDelegationSet_ = function(delegationSet, encoder)
{
  // Encode backwards.
  for (var i = delegationSet.size() - 1; i >= 0; --i) {
    var saveLength = encoder.getLength();

    Tlv0_2WireFormat.encodeName(delegationSet.get(i).getName(), encoder);
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Link_Preference, delegationSet.get(i).getPreference());

    encoder.writeTypeAndLength
      (Tlv.Link_Delegation, encoder.getLength() - saveLength);
  }
};

/**
 * Decode input as a sequence of NDN-TLV Delegation and set the fields of the
 * delegationSet object. Note that the sequence of Delegation does not have an
 * outer TLV type and length because (when used in a Link object) it is intended
 * to use the type and length of a Data packet's Content.
 * @param {DelegationSet} delegationSet The DelegationSet object whose fields
 * are updated.
 * @param {number} endOffset Decode elements up to endOffset in the input. This
 * does not call finishNestedTlvs.
 * @param {TlvDecoder} decoder The decoder with the input to decode.
 * @param {boolean} copy If true, copy from the input when making new Blob
 * values. If false, then Blob values share memory with the input, which must
 * remain unchanged while the Blob values are used.
 */
Tlv0_2WireFormat.decodeDelegationSet_ = function
  (delegationSet, endOffset, decoder, copy)
{
  delegationSet.clear();
  while (decoder.getOffset() < endOffset) {
    decoder.readTypeAndLength(Tlv.Link_Delegation);
    var preference = decoder.readNonNegativeIntegerTlv(Tlv.Link_Preference);
    var name = new Name();
    Tlv0_2WireFormat.decodeName(name, decoder, copy);

    // Add unsorted to preserve the order so that Interest selected delegation
    // index will work.
    delegationSet.addUnsorted(preference, name);
  }
};

/**
 * Encode interest in NDN-TLV format v0.3 and return the encoding.
 * @param {Interest} interest The Interest object to encode.
 * @return {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the signed
 * portion. The signed portion starts from the first name component and ends
 * just before the final name component (which is assumed to be a signature for
 * a signed interest).
 */
Tlv0_2WireFormat.encodeInterestV03_ = function(interest)
{
  // TODO: Throw an exception if the interest speficies V02 fields.

  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeOptionalBlobTlv
    (Tlv.ApplicationParameters, interest.getApplicationParameters().buf());
  // TODO: HopLimit.
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

  if (interest.getForwardingHint().size() > 0) {
    if (interest.getSelectedDelegationIndex() != null)
      throw new Error
        ("An Interest may not have a selected delegation when encoding a forwarding hint");
    if (interest.hasLink())
      throw new Error
        ("An Interest may not have a link object when encoding a forwarding hint");

    var forwardingHintSaveLength = encoder.getLength();
    Tlv0_2WireFormat.encodeDelegationSet_(interest.getForwardingHint(), encoder);
    encoder.writeTypeAndLength(
      Tlv.ForwardingHint, encoder.getLength() - forwardingHintSaveLength);
  }

  if (interest.getMustBeFresh())
    encoder.writeTypeAndLength(Tlv.MustBeFresh, 0);
  if (interest.getCanBePrefix())
    encoder.writeTypeAndLength(Tlv.CanBePrefix, 0);

  var tempOffsets = Tlv0_2WireFormat.encodeName(interest.getName(), encoder);
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
 * Decode input as an Interest in NDN-TLV format v0.3 and set the fields of
 * the Interest object. This private method is called if the main decodeInterest
 * fails to decode as v0.2. This ignores HopLimit and interprets CanBePrefix
 * using MaxSuffixComponents.
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
 */
Tlv0_2WireFormat.decodeInterestV03_ = function(interest, input, copy)
{
  if (copy == null)
    copy = true;

  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
  var offsets = Tlv0_2WireFormat.decodeName(interest.getName(), decoder, copy);

  // In v0.2 semantics, this calls setMaxSuffixComponents.
  interest.setCanBePrefix(decoder.readBooleanTlv(Tlv.CanBePrefix, endOffset));

  interest.setMustBeFresh(decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset));

  if (decoder.peekType(Tlv.ForwardingHint, endOffset)) {
    var forwardingHintEndOffset = decoder.readNestedTlvsStart
      (Tlv.ForwardingHint);
    Tlv0_2WireFormat.decodeDelegationSet_
      (interest.getForwardingHint(), forwardingHintEndOffset, decoder, copy);
    decoder.finishNestedTlvs(forwardingHintEndOffset);
  }
  else
    interest.getForwardingHint().clear();

  var nonce = decoder.readOptionalBlobTlv(Tlv.Nonce, endOffset);
  interest.setInterestLifetimeMilliseconds
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.InterestLifetime, endOffset));

  // Clear the unused fields.
  interest.setMinSuffixComponents(null);
  interest.getKeyLocator().clear();
  interest.getExclude().clear();
  interest.setChildSelector(null);
  interest.unsetLink();
  interest.setSelectedDelegationIndex(null);

  // Ignore the HopLimit.
  decoder.readOptionalBlobTlv(Tlv.HopLimit, endOffset);

  interest.setApplicationParameters(new Blob(decoder.readOptionalBlobTlv
    (Tlv.ApplicationParameters, endOffset), copy));

  // Set the nonce last because setting other interest fields clears it.
  interest.setNonce(nonce == null ? new Blob() : new Blob(nonce, copy));

  decoder.finishNestedTlvs(endOffset);
  return offsets;
};
