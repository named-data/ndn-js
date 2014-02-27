/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * This class represents an NDN Data MetaInfo object.
 */

var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var Blob = require('./util/blob.js').Blob;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var KeyLocator = require('./key-locator.js').KeyLocator;
var KeyLocatorType = require('./key-locator.js').KeyLocatorType;
var Name = require('./name.js').Name;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;
var NDNTime = require('./util/ndn-time.js').NDNTime;
var globalKeyManager = require('./security/key-manager.js').globalKeyManager;
var LOG = require('./log.js').Log.LOG;

var ContentType = {
  BLOB:0,
  // ContentType DATA is deprecated.  Use ContentType.BLOB .
  DATA:0, 
  LINK:1, 
  KEY: 2, 
  // ContentType ENCR, GONE and NACK are not supported in NDN-TLV encoding and are deprecated.
  ENCR:3, 
  GONE:4, 
  NACK:5
};

exports.ContentType = ContentType;

/**
 * Create a new MetaInfo with the optional values.
 * @constructor
 */
var MetaInfo = function MetaInfo(publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockID, skipSetFields) 
{
  if (typeof publisherOrMetaInfo === 'object' && 
      publisherOrMetaInfo instanceof MetaInfo) {
    // Copy values.
    var metaInfo = publisherOrMetaInfo;
    this.publisher = metaInfo.publisher;
    this.timestamp = metaInfo.timestamp;
    this.type = metaInfo.type;
    this.locator = metaInfo.locator == null ? 
      new KeyLocator() : new KeyLocator(metaInfo.locator);
    this.freshnessSeconds = metaInfo.freshnessSeconds;
    this.finalBlockID = metaInfo.finalBlockID;
  }
  else {
    this.publisher = publisherOrMetaInfo; //publisherPublicKeyDigest
    this.timestamp = timestamp; // NDN Time
    this.type = type; // ContentType
    this.locator = locator == null ? new KeyLocator() : new KeyLocator(locator);
    this.freshnessSeconds = freshnessSeconds; // Integer
    this.finalBlockID = finalBlockID; //byte array

    if (!skipSetFields)
      this.setFields();
  }
};

exports.MetaInfo = MetaInfo;

/**
 * Get the content type.
 * @returns {an int from ContentType} The content type.
 */
MetaInfo.prototype.getType = function()
{
  return this.type;
};

/**
 * Get the freshness period.
 * @returns {number} The freshness period in milliseconds, or null if not 
 * specified.
 */
MetaInfo.prototype.getFreshnessPeriod = function()
{
  // Use attribute freshnessSeconds for backwards compatibility.
  if (this.freshnessSeconds == null || this.freshnessSeconds < 0)
    return null;
  else
    // Convert to milliseconds.
    return this.freshnessSeconds * 1000.0;
};

/**
 * Get the final block ID.
 * @returns {Buffer} The final block ID or null if not specified.
 */
MetaInfo.prototype.getFinalBlockID = function()
{
  // TODO: finalBlockID should be a Name.Component, not Buffer.
  return this.finalBlockID;
};

/**
 * Set the content type.
 * @param {an int from ContentType} type The content type.  If null, this 
 * uses ContentType.BLOB.
 */
MetaInfo.prototype.setType = function(type)
{
  this.type = type == null || type < 0 ? ContentType.BLOB : type;
};

/**
 * Set the freshness period.
 * @param {type} freshnessPeriod The freshness period in milliseconds, or null
 * for not specified.
 */
MetaInfo.prototype.setFreshnessPeriod = function(freshnessPeriod)
{
  // Use attribute freshnessSeconds for backwards compatibility.
  if (freshnessPeriod == null || freshnessPeriod < 0)
    this.freshnessSeconds = null;
  else
    // Convert from milliseconds.
    this.freshnessSeconds = freshnessPeriod / 1000.0;
};

MetaInfo.prototype.setFinalBlockID = function(finalBlockID)
{
  // TODO: finalBlockID should be a Name.Component, not Buffer.
  if (finalBlockID == null)
    this.finalBlockID = null;
  else if (typeof finalBlockID === 'object' && finalBlockID instanceof Blob)
    this.finalBlockID = finalBlockID.buf();
  else if (typeof finalBlockID === 'object' && finalBlockID instanceof Name.Component)
    this.finalBlockID = finalBlockID.getValue();
  else 
    this.finalBlockID = new Buffer(finalBlockID);
};

MetaInfo.prototype.setFields = function() 
{
  var key = globalKeyManager.getKey();
  this.publisher = new PublisherPublicKeyDigest(key.getKeyID());

  var d = new Date();
    
  var time = d.getTime();  

  this.timestamp = new NDNTime(time);
    
  if (LOG > 4) console.log('TIME msec is');

  if (LOG > 4) console.log(this.timestamp.msec);

  //DATA
  this.type = ContentType.BLOB;
  
  if (LOG > 4) console.log('PUBLIC KEY TO WRITE TO DATA PACKET IS ');
  if (LOG > 4) console.log(key.publicToDER().toString('hex'));

  this.locator = new KeyLocator(key.getKeyID(), KeyLocatorType.KEY_LOCATOR_DIGEST);
};

MetaInfo.prototype.from_ndnb = function(decoder) 
{
  decoder.readElementStartDTag(this.getElementLabel());
  
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    if (LOG > 4) console.log('DECODING PUBLISHER KEY');
    this.publisher = new PublisherPublicKeyDigest();
    this.publisher.from_ndnb(decoder);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Timestamp)) {
    if (LOG > 4) console.log('DECODING TIMESTAMP');
    this.timestamp = decoder.readDateTimeDTagElement(NDNProtocolDTags.Timestamp);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Type)) {
    var binType = decoder.readBinaryDTagElement(NDNProtocolDTags.Type);
    
    if (LOG > 4) console.log('Binary Type of of Signed Info is '+binType);

    this.type = binType;
    
    //TODO Implement type of Key Reading
    if (null == this.type)
      throw new Error("Cannot parse signedInfo type: bytes.");
  } 
  else
    this.type = ContentType.DATA; // default
  
  if (decoder.peekDTag(NDNProtocolDTags.FreshnessSeconds)) {
    this.freshnessSeconds = decoder.readIntegerDTagElement(NDNProtocolDTags.FreshnessSeconds);
    if (LOG > 4) console.log('FRESHNESS IN SECONDS IS '+ this.freshnessSeconds);
  }
  
  if (decoder.peekDTag(NDNProtocolDTags.FinalBlockID)) {
    if (LOG > 4) console.log('DECODING FINAL BLOCKID');
    this.finalBlockID = decoder.readBinaryDTagElement(NDNProtocolDTags.FinalBlockID);
  }
  
  if (decoder.peekDTag(NDNProtocolDTags.KeyLocator)) {
    if (LOG > 4) console.log('DECODING KEY LOCATOR');
    this.locator = new KeyLocator();
    this.locator.from_ndnb(decoder);
  }
      
  decoder.readElementClose();
};

/**
 * Encode this MetaInfo in ndnb, using the given keyLocator instead of the
 * locator in this object.
 * @param {BinaryXMLEncoder} encoder The encoder.
 * @param {KeyLocator} keyLocator The key locator to use (from 
 * Data.getSignatureOrMetaInfoKeyLocator).
 */
MetaInfo.prototype.to_ndnb = function(encoder, keyLocator)  {
  if (!this.validate())
    throw new Error("Cannot encode : field values missing.");

  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (null != this.publisher) {
    // We have a publisherPublicKeyDigest, so use it.
    if (LOG > 3) console.log('ENCODING PUBLISHER KEY' + this.publisher.publisherPublicKeyDigest);
    this.publisher.to_ndnb(encoder);
  }
  else {
    if (null != keyLocator &&
        keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST && 
        keyLocator.getKeyData() != null &&
        keyLocator.getKeyData().length > 0)
      // We have a TLV-style KEY_LOCATOR_DIGEST, so encode as the
      //   publisherPublicKeyDigest.
      encoder.writeDTagElement
        (NDNProtocolDTags.PublisherPublicKeyDigest, keyLocator.getKeyData());
  }

  if (null != this.timestamp)
    encoder.writeDateTimeDTagElement(NDNProtocolDTags.Timestamp, this.timestamp);
  
  if (null != this.type && this.type != 0)
    encoder.writeDTagElement(NDNProtocolDTags.type, this.type);
  
  if (null != this.freshnessSeconds)
    encoder.writeDTagElement(NDNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);

  if (null != this.finalBlockID)
    encoder.writeDTagElement(NDNProtocolDTags.FinalBlockID, this.finalBlockID);

  if (null != keyLocator)
    keyLocator.to_ndnb(encoder);

  encoder.writeElementClose();       
};
  
MetaInfo.prototype.valueToType = function() 
{
  return null;  
};

MetaInfo.prototype.getElementLabel = function() { 
  return NDNProtocolDTags.SignedInfo;
};

MetaInfo.prototype.validate = function() 
{
  // We don't do partial matches any more, even though encoder/decoder
  // is still pretty generous.
  if (null == this.timestamp)
    return false;
  return true;
};

/**
 * @deprecated Use new MetaInfo.
 */
var SignedInfo = function SignedInfo(publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockID) 
{
  // Call the base constructor.
  MetaInfo.call(this, publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockID); 
}

// Set skipSetFields true since we only need the prototype functions.
SignedInfo.prototype = new MetaInfo(null, null, null, null, null, null, true);

exports.SignedInfo = SignedInfo;
