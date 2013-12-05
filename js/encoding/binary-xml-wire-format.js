/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

var NDNProtocolDTags = require('../util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var BinaryXMLEncoder = require('./binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./binary-xml-decoder.js').BinaryXMLDecoder;
var WireFormat = require('./wire-format.js').WireFormat;
var Name = require('../name.js').Name;
var PublisherPublicKeyDigest = require('../publisher-public-key-digest.js').PublisherPublicKeyDigest;
var DataUtils = require('./data-utils.js').DataUtils;

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
BinaryXmlWireFormat.instance = new BinaryXmlWireFormat();

/**
 * Encode the interest and return a Buffer.
 * @param {Interest} interest
 * @returns {Buffer}
 */
BinaryXmlWireFormat.prototype.encodeInterest = function(interest) 
{
  var encoder = new BinaryXMLEncoder();
  BinaryXmlWireFormat.encodeInterest(interest, encoder);  
  return encoder.getReducedOstream();  
};

/**
 * Decode the input and put the result in interest.
 * @param {Interest} interest
 * @param {Buffer} input
 */
BinaryXmlWireFormat.prototype.decodeInterest = function(interest, input) 
{
  var decoder = new BinaryXMLDecoder(input);
  BinaryXmlWireFormat.decodeInterest(interest, decoder);
};

/**
 * Encode the data and return a Buffer. 
 * @param {Data} data
 * @returns {Buffer}
 */
BinaryXmlWireFormat.prototype.encodeData = function(data) 
{
  var encoder = new BinaryXMLEncoder();
  BinaryXmlWireFormat.encodeData(data, encoder);  
  return encoder.getReducedOstream();  
};

/**
 * @deprecated Use encodeData(data).
 */
BinaryXmlWireFormat.prototype.encodeContentObject = function(data)
{
  return this.encodeData(data);
}

/**
 * Decode the input and put the result in data.
 * @param {Data} data
 * @param {Buffer} input
 */
BinaryXmlWireFormat.prototype.decodeData = function(data, input) 
{
  var decoder = new BinaryXMLDecoder(input);
  BinaryXmlWireFormat.decodeData(data, decoder);
};

/**
 * @deprecated Use decodeData(data, input).
 */
BinaryXmlWireFormat.prototype.decodeContentObject = function(data, input) 
{
  this.decodeData(data, input);
}

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
    encoder.writeElement(NDNProtocolDTags.MinSuffixComponents, interest.minSuffixComponents);  

  if (null != interest.maxSuffixComponents) 
    encoder.writeElement(NDNProtocolDTags.MaxSuffixComponents, interest.maxSuffixComponents);

  if (null != interest.publisherPublicKeyDigest)
    interest.publisherPublicKeyDigest.to_ndnb(encoder);
    
  if (null != interest.exclude)
    interest.exclude.to_ndnb(encoder);
    
  if (null != interest.childSelector) 
    encoder.writeElement(NDNProtocolDTags.ChildSelector, interest.childSelector);

  if (interest.DEFAULT_ANSWER_ORIGIN_KIND != interest.answerOriginKind && interest.answerOriginKind!=null) 
    encoder.writeElement(NDNProtocolDTags.AnswerOriginKind, interest.answerOriginKind);
    
  if (null != interest.scope) 
    encoder.writeElement(NDNProtocolDTags.Scope, interest.scope);
    
  if (null != interest.interestLifetime) 
    encoder.writeElement(NDNProtocolDTags.InterestLifetime, 
                DataUtils.nonNegativeIntToBigEndian((interest.interestLifetime / 1000.0) * 4096));
    
  if (null != interest.nonce)
    encoder.writeElement(NDNProtocolDTags.Nonce, interest.nonce);
    
  encoder.writeElementClose();
};

var Exclude = require('../interest.js').Exclude;

/**
 * Use the decoder to place the result in interest.
 * @param {Interest} interest
 * @param {BinaryXMLDecoder} decoder
 */
BinaryXmlWireFormat.decodeInterest = function(interest, decoder) 
{
  decoder.readStartElement(NDNProtocolDTags.Interest);

  interest.name = new Name();
  interest.name.from_ndnb(decoder);

  if (decoder.peekStartElement(NDNProtocolDTags.MinSuffixComponents))
    interest.minSuffixComponents = decoder.readIntegerElement(NDNProtocolDTags.MinSuffixComponents);
  else
    interest.minSuffixComponents = null;

  if (decoder.peekStartElement(NDNProtocolDTags.MaxSuffixComponents)) 
    interest.maxSuffixComponents = decoder.readIntegerElement(NDNProtocolDTags.MaxSuffixComponents);
  else
    interest.maxSuffixComponents = null;
      
  if (decoder.peekStartElement(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    interest.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
    interest.publisherPublicKeyDigest.from_ndnb(decoder);
  }
  else
    interest.publisherPublicKeyDigest = null;

  if (decoder.peekStartElement(NDNProtocolDTags.Exclude)) {
    interest.exclude = new Exclude();
    interest.exclude.from_ndnb(decoder);
  }
  else
    interest.exclude = null;
    
  if (decoder.peekStartElement(NDNProtocolDTags.ChildSelector))
    interest.childSelector = decoder.readIntegerElement(NDNProtocolDTags.ChildSelector);
  else
    interest.childSelector = null;
    
  if (decoder.peekStartElement(NDNProtocolDTags.AnswerOriginKind))
    interest.answerOriginKind = decoder.readIntegerElement(NDNProtocolDTags.AnswerOriginKind);
  else
    interest.answerOriginKind = null;
    
  if (decoder.peekStartElement(NDNProtocolDTags.Scope))
    interest.scope = decoder.readIntegerElement(NDNProtocolDTags.Scope);
  else
    interest.scope = null;

  if (decoder.peekStartElement(NDNProtocolDTags.InterestLifetime))
    interest.interestLifetime = 1000.0 * DataUtils.bigEndianToUnsignedInt
               (decoder.readBinaryElement(NDNProtocolDTags.InterestLifetime)) / 4096;
  else
    interest.interestLifetime = null;              
    
  if (decoder.peekStartElement(NDNProtocolDTags.Nonce))
    interest.nonce = decoder.readBinaryElement(NDNProtocolDTags.Nonce);
  else
    interest.nonce = null;
    
  decoder.readEndElement();
};

/**
 * Encode the data by calling the operations on the encoder.
 * @param {Data} data
 * @param {BinaryXMLEncoder} encoder
 */
BinaryXmlWireFormat.encodeData = function(data, encoder)  
{
  //TODO verify name, SignedInfo and Signature is present
  encoder.writeElementStartDTag(data.getElementLabel());

  if (null != data.signature) 
    data.signature.to_ndnb(encoder);
    
  data.startSIG = encoder.offset;

  if (null != data.name) 
    data.name.to_ndnb(encoder);
  
  if (null != data.signedInfo) 
    data.signedInfo.to_ndnb(encoder);

  encoder.writeElement(NDNProtocolDTags.Content, data.content);
  
  data.endSIG = encoder.offset;
  
  encoder.writeElementClose();
  
  data.saveRawData(encoder.ostream);  
};

var Signature = require('../data.js').Signature;
var SignedInfo = require('../data.js').SignedInfo;

/**
 * Use the decoder to place the result in data.
 * @param {Data} data
 * @param {BinaryXMLDecoder} decoder
 */
BinaryXmlWireFormat.decodeData = function(data, decoder) 
{
  // TODO VALIDATE THAT ALL FIELDS EXCEPT SIGNATURE ARE PRESENT
  decoder.readStartElement(data.getElementLabel());

  if (decoder.peekStartElement(NDNProtocolDTags.Signature)) {
    data.signature = new Signature();
    data.signature.from_ndnb(decoder);
  }
  else
    data.signature = null;
    
  data.startSIG = decoder.offset;

  data.name = new Name();
  data.name.from_ndnb(decoder);
    
  if (decoder.peekStartElement(NDNProtocolDTags.SignedInfo)) {
    data.signedInfo = new SignedInfo();
    data.signedInfo.from_ndnb(decoder);
  }
  else
    data.signedInfo = null;

  data.content = decoder.readBinaryElement(NDNProtocolDTags.Content, null, true);
    
  data.endSIG = decoder.offset;
    
  decoder.readEndElement();
    
  data.saveRawData(decoder.input);
};
