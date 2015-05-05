/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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

var Blob = require('../util/blob.js').Blob;
var NDNProtocolDTags = require('../util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var BinaryXMLEncoder = require('./binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./binary-xml-decoder.js').BinaryXMLDecoder;
var WireFormat = require('./wire-format.js').WireFormat;
var Name = require('../name.js').Name;
var Exclude = require('../exclude.js').Exclude;
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature;
var MetaInfo = require('../meta-info.js').MetaInfo;
var PublisherPublicKeyDigest = require('../publisher-public-key-digest.js').PublisherPublicKeyDigest;
var DataUtils = require('./data-utils.js').DataUtils;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;

/**
 * A BinaryXmlWireFormat implements the WireFormat interface for encoding and decoding in binary XML.
 * @constructor
 */
var BinaryXmlWireFormat = function BinaryXmlWireFormat()
{
  // Inherit from WireFormat.
  WireFormat.call(this);

  if (!WireFormat.ENABLE_NDNX)
    throw new Error
      ("BinaryXmlWireFormat (NDNx) is deprecated. To enable while you upgrade your code to use NDN-TLV, set WireFormat.ENABLE_NDNX = true");
};

exports.BinaryXmlWireFormat = BinaryXmlWireFormat;

// Default object.
BinaryXmlWireFormat.instance = null;

/**
 * Encode interest as Binary XML and return the encoding.
 * @param {Name} interest The Name to encode.
 * @returns {Blobl} A Blob containing the encoding.
 */
BinaryXmlWireFormat.prototype.encodeName = function(name)
{
  var encoder = new BinaryXMLEncoder();
  name.to_ndnb(encoder);
  return new Blob(encoder.getReducedOstream(), false);
};

/**
 * Decode input as a Binary XML name and set the fields of the Name object.
 * @param {Name} name The Name object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 */
BinaryXmlWireFormat.prototype.decodeName = function(name, input)
{
  var decoder = new BinaryXMLDecoder(input);
  name.from_ndnb(decoder);
};

/**
 * Encode interest as Binary XML and return the encoding.
 * @param {Interest} interest The Interest to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the signed
 * portion. The signed portion starts from the first name component and ends
 * just before the final name component (which is assumed to be a signature for
 * a signed interest).
 */
BinaryXmlWireFormat.prototype.encodeInterest = function(interest)
{
  var encoder = new BinaryXMLEncoder();
  var offsets = BinaryXmlWireFormat.encodeInterest(interest, encoder);
  return { encoding: new Blob(encoder.getReducedOstream(), false),
           signedPortionBeginOffset: offsets.signedPortionBeginOffset,
           signedPortionEndOffset: offsets.signedPortionEndOffset };
};

/**
 * Decode input as a Binary XML interest and set the fields of the interest object.
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
BinaryXmlWireFormat.prototype.decodeInterest = function(interest, input)
{
  var decoder = new BinaryXMLDecoder(input);
  return BinaryXmlWireFormat.decodeInterest(interest, decoder);
};

/**
 * Encode data as Binary XML and return the encoding and signed offsets.
 * @param {Data} data The Data object to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the
 * signed portion.
 */
BinaryXmlWireFormat.prototype.encodeData = function(data)
{
  var encoder = new BinaryXMLEncoder(1500);
  var result = BinaryXmlWireFormat.encodeData(data, encoder);
  result.encoding = new Blob(encoder.getReducedOstream(), false);
  return result;
};

/**
 * @deprecated Use encodeData(data).
 */
BinaryXmlWireFormat.prototype.encodeContentObject = function(data)
{
  return this.encodeData(data);
};

/**
 * Decode input as a Binary XML data packet, set the fields in the data object, and return
 * the signed offsets.
 * @param {Data} data The Data object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 */
BinaryXmlWireFormat.prototype.decodeData = function(data, input)
{
  var decoder = new BinaryXMLDecoder(input);
  return BinaryXmlWireFormat.decodeData(data, decoder);
};

/**
 * @deprecated Use decodeData(data, input).
 */
BinaryXmlWireFormat.prototype.decodeContentObject = function(data, input)
{
  this.decodeData(data, input);
};

/**
 * Get a singleton instance of a BinaryXmlWireFormat.  Assuming that the default
 * wire format was set with
 * WireFormat.setDefaultWireFormat(BinaryXmlWireFormat.get()), you can check if
 * this is the default wire encoding with
 * if WireFormat.getDefaultWireFormat() == BinaryXmlWireFormat.get().
 * @returns {BinaryXmlWireFormat} The singleton instance.
 */
BinaryXmlWireFormat.get = function()
{
  if (BinaryXmlWireFormat.instance === null)
    BinaryXmlWireFormat.instance = new BinaryXmlWireFormat();
  return BinaryXmlWireFormat.instance;
};

/**
 * Encode the interest by calling the operations on the encoder.
 * @param {Interest} interest
 * @param {BinaryXMLEncoder} encoder
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
BinaryXmlWireFormat.encodeInterest = function(interest, encoder)
{
  encoder.writeElementStartDTag(NDNProtocolDTags.Interest);

  var offsets = interest.getName().to_ndnb(encoder);

  if (null != interest.getMinSuffixComponents())
    encoder.writeDTagElement(NDNProtocolDTags.MinSuffixComponents, interest.getMinSuffixComponents());

  if (null != interest.getMaxSuffixComponents())
    encoder.writeDTagElement(NDNProtocolDTags.MaxSuffixComponents, interest.getMaxSuffixComponents());

  if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
      !interest.getKeyLocator().getKeyData().isNull() &&
      interest.getKeyLocator().getKeyData().size() > 0)
    // There is a KEY_LOCATOR_DIGEST. Use this instead of the publisherPublicKeyDigest.
    encoder.writeDTagElement
      (NDNProtocolDTags.PublisherPublicKeyDigest,
       interest.getKeyLocator().getKeyData());
  else {
    if (null != interest.publisherPublicKeyDigest)
      interest.publisherPublicKeyDigest.to_ndnb(encoder);
  }

  if (null != interest.getExclude())
    interest.getExclude().to_ndnb(encoder);

  if (null != interest.getChildSelector())
    encoder.writeDTagElement(NDNProtocolDTags.ChildSelector, interest.getChildSelector());

  if (interest.DEFAULT_ANSWER_ORIGIN_KIND != interest.getAnswerOriginKind() && interest.getAnswerOriginKind()!=null)
    encoder.writeDTagElement(NDNProtocolDTags.AnswerOriginKind, interest.getAnswerOriginKind());

  if (null != interest.getScope())
    encoder.writeDTagElement(NDNProtocolDTags.Scope, interest.getScope());

  if (null != interest.getInterestLifetimeMilliseconds())
    encoder.writeDTagElement(NDNProtocolDTags.InterestLifetime,
                DataUtils.nonNegativeIntToBigEndian((interest.getInterestLifetimeMilliseconds() / 1000.0) * 4096));

  if (interest.getNonce().size() > 0)
    encoder.writeDTagElement(NDNProtocolDTags.Nonce, interest.getNonce());

  encoder.writeElementClose();
  return offsets;
};

/**
 * Use the decoder to place the result in interest.
 * @param {Interest} interest
 * @param {BinaryXMLDecoder} decoder
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
BinaryXmlWireFormat.decodeInterest = function(interest, decoder)
{
  decoder.readElementStartDTag(NDNProtocolDTags.Interest);

  interest.setName(new Name());
  var offsets = interest.getName().from_ndnb(decoder);

  if (decoder.peekDTag(NDNProtocolDTags.MinSuffixComponents))
    interest.setMinSuffixComponents(decoder.readIntegerDTagElement(NDNProtocolDTags.MinSuffixComponents));
  else
    interest.setMinSuffixComponents(null);

  if (decoder.peekDTag(NDNProtocolDTags.MaxSuffixComponents))
    interest.setMaxSuffixComponents(decoder.readIntegerDTagElement(NDNProtocolDTags.MaxSuffixComponents));
  else
    interest.setMaxSuffixComponents(null);

  // Initially clear the keyLocator.
  interest.getKeyLocator().clear();
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    interest.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
    interest.publisherPublicKeyDigest.from_ndnb(decoder);
  }
  else
    interest.publisherPublicKeyDigest = null;
  if (interest.publisherPublicKeyDigest != null &&
      interest.publisherPublicKeyDigest.publisherPublicKeyDigest != null &&
      interest.publisherPublicKeyDigest.publisherPublicKeyDigest.length > 0) {
    // We keep the deprecated publisherPublicKeyDigest for backwards
    //   compatibility.  Also set the key locator.
    interest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    interest.getKeyLocator().setKeyData
      (interest.publisherPublicKeyDigest.publisherPublicKeyDigest);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Exclude)) {
    interest.setExclude(new Exclude());
    interest.getExclude().from_ndnb(decoder);
  }
  else
    interest.setExclude(new Exclude());

  if (decoder.peekDTag(NDNProtocolDTags.ChildSelector))
    interest.setChildSelector(decoder.readIntegerDTagElement(NDNProtocolDTags.ChildSelector));
  else
    interest.setChildSelector(null);

  if (decoder.peekDTag(NDNProtocolDTags.AnswerOriginKind))
    interest.setAnswerOriginKind(decoder.readIntegerDTagElement(NDNProtocolDTags.AnswerOriginKind));
  else
    interest.setAnswerOriginKind(null);

  if (decoder.peekDTag(NDNProtocolDTags.Scope))
    interest.setScope(decoder.readIntegerDTagElement(NDNProtocolDTags.Scope));
  else
    interest.setScope(null);

  if (decoder.peekDTag(NDNProtocolDTags.InterestLifetime))
    interest.setInterestLifetimeMilliseconds(1000.0 * DataUtils.bigEndianToUnsignedInt
               (decoder.readBinaryDTagElement(NDNProtocolDTags.InterestLifetime)) / 4096);
  else
    interest.setInterestLifetimeMilliseconds(null);

  if (decoder.peekDTag(NDNProtocolDTags.Nonce))
    interest.setNonce(decoder.readBinaryDTagElement(NDNProtocolDTags.Nonce));
  else
    interest.setNonce(null);

  decoder.readElementClose();
  return offsets;
};

/**
 * Encode the data by calling the operations on the encoder.
 * @param {Data} data
 * @param {BinaryXMLEncoder} encoder
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 */
BinaryXmlWireFormat.encodeData = function(data, encoder)
{
  //TODO verify name, MetaInfo and Signature is present
  encoder.writeElementStartDTag(data.getElementLabel());

  if (null != data.getSignature())
    data.getSignature().to_ndnb(encoder);

  var signedPortionBeginOffset = encoder.offset;

  if (null != data.getName())
    data.getName().to_ndnb(encoder);

  if (null != data.getMetaInfo())
    // Use getSignatureOrMetaInfoKeyLocator for the transition of moving
    //   the key locator from the MetaInfo to the Signauture object.
    data.getMetaInfo().to_ndnb(encoder, data.getSignatureOrMetaInfoKeyLocator());

  encoder.writeDTagElement(NDNProtocolDTags.Content, data.getContent().buf());

  var signedPortionEndOffset = encoder.offset;

  encoder.writeElementClose();

  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Use the decoder to place the result in data.
 * @param {Data} data
 * @param {BinaryXMLDecoder} decoder
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 */
BinaryXmlWireFormat.decodeData = function(data, decoder)
{
  // TODO VALIDATE THAT ALL FIELDS EXCEPT SIGNATURE ARE PRESENT
  decoder.readElementStartDTag(data.getElementLabel());

  if (decoder.peekDTag(NDNProtocolDTags.Signature)) {
    data.setSignature(new Sha256WithRsaSignature());
    data.getSignature().from_ndnb(decoder);
  }
  else
    data.setSignature(new Sha256WithRsaSignature());

  var signedPortionBeginOffset = decoder.offset;

  data.setName(new Name());
  data.getName().from_ndnb(decoder);

  if (decoder.peekDTag(NDNProtocolDTags.SignedInfo)) {
    data.setMetaInfo(new MetaInfo());
    data.getMetaInfo().from_ndnb(decoder);
    if (data.getMetaInfo().locator != null && data.getSignature() != null)
      // Copy the key locator pointer to the Signature object for the transition
      //   of moving the key locator from the MetaInfo to the Signature object.
      data.getSignature().setKeyLocator(data.getMetaInfo().locator);
  }
  else
    data.setMetaInfo(new MetaInfo());

  data.setContent(decoder.readBinaryDTagElement(NDNProtocolDTags.Content, true));

  var signedPortionEndOffset = decoder.offset;

  decoder.readElementClose();

  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};
