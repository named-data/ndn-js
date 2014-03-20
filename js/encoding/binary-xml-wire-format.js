/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

var Blob = require('../util/blob.js').Blob;
var NDNProtocolDTags = require('../util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var BinaryXMLEncoder = require('./binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./binary-xml-decoder.js').BinaryXMLDecoder;
var WireFormat = require('./wire-format.js').WireFormat;
var Name = require('../name.js').Name;
var Exclude = require('../exclude.js').Exclude;
var Signature = require('../signature.js').Signature;
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
};

exports.BinaryXmlWireFormat = BinaryXmlWireFormat;

// Default object.
BinaryXmlWireFormat.instance = null;

/**
 * Encode interest as Binary XML and return the encoding.
 * @param {Interest} interest The Interest to encode.
 * @returns {Blob} A Blob containing the encoding.
 */
BinaryXmlWireFormat.prototype.encodeInterest = function(interest) 
{
  var encoder = new BinaryXMLEncoder();
  BinaryXmlWireFormat.encodeInterest(interest, encoder);  
  return new Blob(encoder.getReducedOstream(), false);  
};

/**
 * Decode input as a Binary XML interest and set the fields of the interest object. 
 * @param {Interest} interest The Interest object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 */
BinaryXmlWireFormat.prototype.decodeInterest = function(interest, input) 
{
  var decoder = new BinaryXMLDecoder(input);
  BinaryXmlWireFormat.decodeInterest(interest, decoder);
};

/**
 * Encode data as Binary XML and return the encoding and signed offsets.
 * @param {Data} data The Data object to encode.
 * @returns {object with (Blob, int, int)} An associative array with fields
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
 * @returns {object with (int, int)} An associative array with fields
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
 */
BinaryXmlWireFormat.encodeInterest = function(interest, encoder) 
{
  encoder.writeElementStartDTag(NDNProtocolDTags.Interest);
    
  interest.name.to_ndnb(encoder);
  
  if (null != interest.minSuffixComponents) 
    encoder.writeDTagElement(NDNProtocolDTags.MinSuffixComponents, interest.minSuffixComponents);  

  if (null != interest.maxSuffixComponents) 
    encoder.writeDTagElement(NDNProtocolDTags.MaxSuffixComponents, interest.maxSuffixComponents);

  if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST && 
      interest.getKeyLocator().getKeyData() != null &&
      interest.getKeyLocator().getKeyData().length > 0)
    // There is a KEY_LOCATOR_DIGEST. Use this instead of the publisherPublicKeyDigest.
    encoder.writeDTagElement
      (NDNProtocolDTags.PublisherPublicKeyDigest, 
       interest.getKeyLocator().getKeyData());
  else {
    if (null != interest.publisherPublicKeyDigest)
      interest.publisherPublicKeyDigest.to_ndnb(encoder);
  }
    
  if (null != interest.exclude)
    interest.exclude.to_ndnb(encoder);
    
  if (null != interest.childSelector) 
    encoder.writeDTagElement(NDNProtocolDTags.ChildSelector, interest.childSelector);

  if (interest.DEFAULT_ANSWER_ORIGIN_KIND != interest.answerOriginKind && interest.answerOriginKind!=null) 
    encoder.writeDTagElement(NDNProtocolDTags.AnswerOriginKind, interest.answerOriginKind);
    
  if (null != interest.scope) 
    encoder.writeDTagElement(NDNProtocolDTags.Scope, interest.scope);
    
  if (null != interest.interestLifetime) 
    encoder.writeDTagElement(NDNProtocolDTags.InterestLifetime, 
                DataUtils.nonNegativeIntToBigEndian((interest.interestLifetime / 1000.0) * 4096));
    
  if (null != interest.nonce)
    encoder.writeDTagElement(NDNProtocolDTags.Nonce, interest.nonce);
    
  encoder.writeElementClose();
};

/**
 * Use the decoder to place the result in interest.
 * @param {Interest} interest
 * @param {BinaryXMLDecoder} decoder
 */
BinaryXmlWireFormat.decodeInterest = function(interest, decoder) 
{
  decoder.readElementStartDTag(NDNProtocolDTags.Interest);

  interest.name = new Name();
  interest.name.from_ndnb(decoder);

  if (decoder.peekDTag(NDNProtocolDTags.MinSuffixComponents))
    interest.minSuffixComponents = decoder.readIntegerDTagElement(NDNProtocolDTags.MinSuffixComponents);
  else
    interest.minSuffixComponents = null;

  if (decoder.peekDTag(NDNProtocolDTags.MaxSuffixComponents)) 
    interest.maxSuffixComponents = decoder.readIntegerDTagElement(NDNProtocolDTags.MaxSuffixComponents);
  else
    interest.maxSuffixComponents = null;
      
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
    interest.exclude = new Exclude();
    interest.exclude.from_ndnb(decoder);
  }
  else
    interest.exclude = null;
    
  if (decoder.peekDTag(NDNProtocolDTags.ChildSelector))
    interest.childSelector = decoder.readIntegerDTagElement(NDNProtocolDTags.ChildSelector);
  else
    interest.childSelector = null;
    
  if (decoder.peekDTag(NDNProtocolDTags.AnswerOriginKind))
    interest.answerOriginKind = decoder.readIntegerDTagElement(NDNProtocolDTags.AnswerOriginKind);
  else
    interest.answerOriginKind = null;
    
  if (decoder.peekDTag(NDNProtocolDTags.Scope))
    interest.scope = decoder.readIntegerDTagElement(NDNProtocolDTags.Scope);
  else
    interest.scope = null;

  if (decoder.peekDTag(NDNProtocolDTags.InterestLifetime))
    interest.interestLifetime = 1000.0 * DataUtils.bigEndianToUnsignedInt
               (decoder.readBinaryDTagElement(NDNProtocolDTags.InterestLifetime)) / 4096;
  else
    interest.interestLifetime = null;              
    
  if (decoder.peekDTag(NDNProtocolDTags.Nonce))
    interest.nonce = decoder.readBinaryDTagElement(NDNProtocolDTags.Nonce);
  else
    interest.nonce = null;
    
  decoder.readElementClose();
};

/**
 * Encode the data by calling the operations on the encoder.
 * @param {Data} data
 * @param {BinaryXMLEncoder} encoder
 * @returns {object with (int, int)} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where 
 * signedPortionBeginOffset is the offset in the encoding of the beginning of 
 * the signed portion, and signedPortionEndOffset is the offset in the encoding 
 * of the end of the signed portion.
 */
BinaryXmlWireFormat.encodeData = function(data, encoder)  
{
  //TODO verify name, MetaInfo and Signature is present
  encoder.writeElementStartDTag(data.getElementLabel());

  if (null != data.signature) 
    data.signature.to_ndnb(encoder);
    
  var signedPortionBeginOffset = encoder.offset;

  if (null != data.name) 
    data.name.to_ndnb(encoder);
  
  if (null != data.signedInfo) 
    // Use getSignatureOrMetaInfoKeyLocator for the transition of moving
    //   the key locator from the MetaInfo to the Signauture object.
    data.signedInfo.to_ndnb(encoder, data.getSignatureOrMetaInfoKeyLocator());

  encoder.writeDTagElement(NDNProtocolDTags.Content, data.content);
  
  var signedPortionEndOffset = encoder.offset;
  
  encoder.writeElementClose();
  
  return { signedPortionBeginOffset: signedPortionBeginOffset, 
           signedPortionEndOffset: signedPortionEndOffset };  
};

/**
 * Use the decoder to place the result in data.
 * @param {Data} data
 * @param {BinaryXMLDecoder} decoder
 * @returns {object with (int, int)} An associative array with fields
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
    data.signature = new Signature();
    data.signature.from_ndnb(decoder);
  }
  else
    data.signature = null;
    
  var signedPortionBeginOffset = decoder.offset;

  data.name = new Name();
  data.name.from_ndnb(decoder);
    
  if (decoder.peekDTag(NDNProtocolDTags.SignedInfo)) {
    data.signedInfo = new MetaInfo();
    data.signedInfo.from_ndnb(decoder);
    if (data.signedInfo.locator != null && data.getSignature() != null)
      // Copy the key locator pointer to the Signature object for the transition 
      //   of moving the key locator from the MetaInfo to the Signature object.
      data.getSignature().keyLocator = data.signedInfo.locator;
  }
  else
    data.signedInfo = null;

  data.content = decoder.readBinaryDTagElement(NDNProtocolDTags.Content, true);
    
  var signedPortionEndOffset = decoder.offset;
    
  decoder.readElementClose();
    
  return { signedPortionBeginOffset: signedPortionBeginOffset, 
           signedPortionEndOffset: signedPortionEndOffset };  
};
