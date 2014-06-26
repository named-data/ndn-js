/**
 * Copyright (C) 2013-2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var crypto = require('../crypto.js');
var Blob = require('../util/blob.js').Blob;
var Tlv = require('./tlv/tlv.js').Tlv;
var TlvEncoder = require('./tlv/tlv-encoder.js').TlvEncoder;
var TlvDecoder = require('./tlv/tlv-decoder.js').TlvDecoder;
var WireFormat = require('./wire-format.js').WireFormat;
var Exclude = require('../exclude.js').Exclude;
var ContentType = require('../meta-info.js').ContentType;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;
var Signature = require('../signature.js').Signature;
var DecodingException = require('./decoding-exception.js').DecodingException;

/**
 * A Tlv0_1WireFormat implements the WireFormat interface for encoding and
 * decoding with the NDN-TLV wire format, version 0.1a2.
 * @constructor
 */
var Tlv0_1WireFormat = function Tlv0_1WireFormat()
{
  // Inherit from WireFormat.
  WireFormat.call(this);
};

Tlv0_1WireFormat.prototype = new WireFormat();
Tlv0_1WireFormat.prototype.name = "Tlv0_1WireFormat";

exports.Tlv0_1WireFormat = Tlv0_1WireFormat;

// Default object.
Tlv0_1WireFormat.instance = null;

/**
 * Encode the interest using NDN-TLV and return a Buffer.
 * @param {Interest} interest The Interest object to encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1WireFormat.prototype.encodeInterest = function(interest)
{
  var encoder = new TlvEncoder();
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds());
  encoder.writeOptionalNonNegativeIntegerTlv(Tlv.Scope, interest.getScope());

  // Encode the Nonce as 4 bytes.
  if (interest.getNonce().isNull() || interest.getNonce().size() == 0)
    // This is the most common case. Generate a nonce.
    encoder.writeBlobTlv(Tlv.Nonce, require("crypto").randomBytes(4));
  else if (interest.getNonce().size() < 4) {
    var nonce = Buffer(4);
    // Copy existing nonce bytes.
    interest.getNonce().buf().copy(nonce);

    // Generate random bytes for remaining bytes in the nonce.
    for (var i = interest.getNonce().size(); i < 4; ++i)
      nonce[i] = require("crypto").randomBytes(1)[0];

    encoder.writeBlobTlv(Tlv.Nonce, nonce);
  }
  else if (interest.getNonce().size() == 4)
    // Use the nonce as-is.
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf());
  else
    // Truncate.
<<<<<<< HEAD
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().slice(0, 4));

=======
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf().slice(0, 4));
  
>>>>>>> 7e351e8f3cb356c8e95b8ba271540bef46c43648
  Tlv0_1WireFormat.encodeSelectors(interest, encoder);
  Tlv0_1WireFormat.encodeName(interest.getName(), encoder);

  encoder.writeTypeAndLength(Tlv.Interest, encoder.getLength() - saveLength);

  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode input as an NDN-TLV interest and set the fields of the interest
 * object.
 * @param {Interest} interest The Interest object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 */
Tlv0_1WireFormat.prototype.decodeInterest = function(interest, input)
{
  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
  Tlv0_1WireFormat.decodeName(interest.getName(), decoder);
  if (decoder.peekType(Tlv.Selectors, endOffset))
    Tlv0_1WireFormat.decodeSelectors(interest, decoder);
  // Require a Nonce, but don't force it to be 4 bytes.
  var nonce = decoder.readBlobTlv(Tlv.Nonce);
  interest.setScope(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.Scope, endOffset));
  interest.setInterestLifetimeMilliseconds
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.InterestLifetime, endOffset));

  // Set the nonce last because setting other interest fields clears it.
  interest.setNonce(nonce);

  decoder.finishNestedTlvs(endOffset);
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
Tlv0_1WireFormat.prototype.encodeData = function(data)
{
  var encoder = new TlvEncoder(1500);
  var saveLength = encoder.getLength();

  // Encode backwards.
  // TODO: The library needs to handle other signature types than
  //   SignatureSha256WithRsa.
  encoder.writeBlobTlv(Tlv.SignatureValue, data.getSignature().getSignature().buf());
  var signedPortionEndOffsetFromBack = encoder.getLength();

  // Use getSignatureOrMetaInfoKeyLocator for the transition of moving
  //   the key locator from the MetaInfo to the Signauture object.
  Tlv0_1WireFormat.encodeSignatureSha256WithRsaValue
    (data.getSignature(), encoder, data.getSignatureOrMetaInfoKeyLocator());
  encoder.writeBlobTlv(Tlv.Content, data.getContent().buf());
  Tlv0_1WireFormat.encodeMetaInfo(data.getMetaInfo(), encoder);
  Tlv0_1WireFormat.encodeName(data.getName(), encoder);
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
Tlv0_1WireFormat.prototype.decodeData = function(data, input)
{
  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Data);
  var signedPortionBeginOffset = decoder.getOffset();

  Tlv0_1WireFormat.decodeName(data.getName(), decoder);
  Tlv0_1WireFormat.decodeMetaInfo(data.getMetaInfo(), decoder);
  data.setContent(decoder.readBlobTlv(Tlv.Content));
  Tlv0_1WireFormat.decodeSignatureInfo(data, decoder);
  if (data.getSignature() != null &&
      data.getSignature().getKeyLocator() != null &&
      data.getMetaInfo() != null)
    // Copy the key locator pointer to the MetaInfo object for the transition of
    //   moving the key locator from the MetaInfo to the Signature object.
    data.getMetaInfo().locator = data.getSignature().getKeyLocator();

  var signedPortionEndOffset = decoder.getOffset();
  // TODO: The library needs to handle other signature types than
  //   SignatureSha256WithRsa.
  data.getSignature().setSignature(decoder.readBlobTlv(Tlv.SignatureValue));

  decoder.finishNestedTlvs(endOffset);
  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Get a singleton instance of a Tlv1_0a2WireFormat.  To always use the
 * preferred version NDN-TLV, you should use TlvWireFormat.get().
 * @returns {Tlv0_1WireFormat} The singleton instance.
 */
Tlv0_1WireFormat.get = function()
{
  if (Tlv0_1WireFormat.instance === null)
    Tlv0_1WireFormat.instance = new Tlv0_1WireFormat();
  return Tlv0_1WireFormat.instance;
};

Tlv0_1WireFormat.encodeName = function(name, encoder)
{
  var saveLength = encoder.getLength();

  // Encode the components backwards.
  for (var i = name.size() - 1; i >= 0; --i)
    encoder.writeBlobTlv(Tlv.NameComponent, name.get(i).getValue().buf());

  encoder.writeTypeAndLength(Tlv.Name, encoder.getLength() - saveLength);
};

Tlv0_1WireFormat.decodeName = function(name, decoder)
{
  name.clear();

  var endOffset = decoder.readNestedTlvsStart(Tlv.Name);
  while (decoder.getOffset() < endOffset)
      name.append(decoder.readBlobTlv(Tlv.NameComponent));

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode the interest selectors.  If no selectors are written, do not output a
 * Selectors TLV.
 */
Tlv0_1WireFormat.encodeSelectors = function(interest, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (interest.getMustBeFresh())
    encoder.writeTypeAndLength(Tlv.MustBeFresh, 0);
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.ChildSelector, interest.getChildSelector());
  if (interest.getExclude().size() > 0)
    Tlv0_1WireFormat.encodeExclude(interest.getExclude(), encoder);

  if (interest.getKeyLocator().getType() != null)
    Tlv0_1WireFormat.encodeKeyLocator
      (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), encoder);
  else {
    // There is no keyLocator. If there is a publisherPublicKeyDigest, then
    //   encode as KEY_LOCATOR_DIGEST. (When we remove the deprecated
    //   publisherPublicKeyDigest, we don't need this.)
    if (null != interest.publisherPublicKeyDigest) {
      var savePublisherPublicKeyDigestLength = encoder.getLength();
      encoder.writeBlobTlv
        (Tlv.KeyLocatorDigest,
         interest.publisherPublicKeyDigest.publisherPublicKeyDigest);
      encoder.writeTypeAndLength
        (Tlv.PublisherPublicKeyLocator,
         encoder.getLength() - savePublisherPublicKeyDigestLength);
    }
  }

  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents());
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MinSuffixComponents, interest.getMinSuffixComponents());

  // Only output the type and length if values were written.
  if (encoder.getLength() != saveLength)
    encoder.writeTypeAndLength(Tlv.Selectors, encoder.getLength() - saveLength);
};

Tlv0_1WireFormat.decodeSelectors = function(interest, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Selectors);

  interest.setMinSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MinSuffixComponents, endOffset));
  interest.setMaxSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MaxSuffixComponents, endOffset));

  // Initially set publisherPublicKeyDigest to none.
  interest.publisherPublicKeyDigest = null;
  if (decoder.peekType(Tlv.PublisherPublicKeyLocator, endOffset)) {
    Tlv0_1WireFormat.decodeKeyLocator
      (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), decoder);
    if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST) {
      // For backwards compatibility, also set the publisherPublicKeyDigest.
      interest.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
      interest.publisherPublicKeyDigest.publisherPublicKeyDigest =
        interest.getKeyLocator().getKeyData().buf();
    }
  }
  else
    interest.getKeyLocator().clear();

  if (decoder.peekType(Tlv.Exclude, endOffset))
    Tlv0_1WireFormat.decodeExclude(interest.getExclude(), decoder);
  else
    interest.getExclude().clear();

  interest.setChildSelector(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ChildSelector, endOffset));
  interest.setMustBeFresh(decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset));

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1WireFormat.encodeExclude = function(exclude, encoder)
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

Tlv0_1WireFormat.decodeExclude = function(exclude, decoder)
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

Tlv0_1WireFormat.encodeKeyLocator = function(type, keyLocator, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (keyLocator.getType() != null) {
    if (keyLocator.getType() == KeyLocatorType.KEYNAME)
      Tlv0_1WireFormat.encodeName(keyLocator.getKeyName(), encoder);
    else if (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
             keyLocator.getKeyData().size() > 0)
      encoder.writeBlobTlv(Tlv.KeyLocatorDigest, keyLocator.getKeyData().buf());
    else
      throw new Error("Unrecognized KeyLocatorType " + keyLocator.getType());
  }

  encoder.writeTypeAndLength(type, encoder.getLength() - saveLength);
};

Tlv0_1WireFormat.decodeKeyLocator = function
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
    Tlv0_1WireFormat.decodeName(keyLocator.getKeyName(), decoder);
  }
  else if (decoder.peekType(Tlv.KeyLocatorDigest, endOffset)) {
    // KeyLocator is a KeyLocatorDigest.
    keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    keyLocator.setKeyData(decoder.readBlobTlv(Tlv.KeyLocatorDigest));
  }
  else
    throw new DecodingException
      ("decodeKeyLocator: Unrecognized key locator type");

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode the signature object in TLV, using the given keyLocator instead of the
 * locator in this object.
 * @param {Signature} signature The Signature object to encode.
 * @param {TlvEncoder} encoder The encoder.
 * @param {KeyLocator} keyLocator The key locator to use (from
 * Data.getSignatureOrMetaInfoKeyLocator).
 */
Tlv0_1WireFormat.encodeSignatureSha256WithRsaValue = function
  (signature, encoder, keyLocator)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  Tlv0_1WireFormat.encodeKeyLocator(Tlv.KeyLocator, keyLocator, encoder);
  encoder.writeNonNegativeIntegerTlv
    (Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithRsa);

  encoder.writeTypeAndLength(Tlv.SignatureInfo, encoder.getLength() - saveLength);
};

Tlv0_1WireFormat.decodeSignatureInfo = function(data, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);

  var signatureType = decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
  // TODO: The library needs to handle other signature types than
  //     SignatureSha256WithRsa.
  if (signatureType == Tlv.SignatureType_SignatureSha256WithRsa) {
      data.setSignature(Signature());
      // Modify data's signature object because if we create an object
      //   and set it, then data will have to copy all the fields.
      var signatureInfo = data.getSignature();
      Tlv0_1WireFormat.decodeKeyLocator
        (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder);
  }
  else
      throw new DecodingException
       ("decodeSignatureInfo: unrecognized SignatureInfo type" + signatureType);

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1WireFormat.encodeMetaInfo = function(metaInfo, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  var finalBlockIdBuf = metaInfo.getFinalBlockID().getValue().buf();
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

Tlv0_1WireFormat.decodeMetaInfo = function(metaInfo, decoder)
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
    metaInfo.setFinalBlockID(decoder.readBlobTlv(Tlv.NameComponent));
    decoder.finishNestedTlvs(finalBlockIdEndOffset);
  }
  else
    metaInfo.setFinalBlockID(null);

  decoder.finishNestedTlvs(endOffset);
};
