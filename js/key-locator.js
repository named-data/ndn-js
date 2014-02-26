/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * This class represents an NDN KeyLocator object.
 */

var Name = require('./name.js').Name;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var PublisherID = require('./publisher-id.js').PublisherID;
var LOG = require('./log.js').Log.LOG;

/**
 * KeyLocator
 */
var KeyLocatorType = {
  KEY:1,
  CERTIFICATE:2,
  KEYNAME:3
};

exports.KeyLocatorType = KeyLocatorType;

/**
 * @constructor
 */
var KeyLocator = function KeyLocator(input,type) 
{ 
  this.type = type;
    
  if (type == KeyLocatorType.KEYNAME) {
    if (LOG > 3) console.log('KeyLocator: SET KEYNAME');
    this.keyName = input;
  }
  else if (type == KeyLocatorType.KEY) {
    if (LOG > 3) console.log('KeyLocator: SET KEY');
    this.publicKey = input;
  }
  else if (type == KeyLocatorType.CERTIFICATE) {
    if (LOG > 3) console.log('KeyLocator: SET CERTIFICATE');
    this.certificate = input;
  }
};

exports.KeyLocator = KeyLocator;

KeyLocator.prototype.from_ndnb = function(decoder) {

  decoder.readElementStartDTag(this.getElementLabel());

  if (decoder.peekDTag(NDNProtocolDTags.Key)) 
  {
    try {
      var encodedKey = decoder.readBinaryDTagElement(NDNProtocolDTags.Key);
      // This is a DER-encoded SubjectPublicKeyInfo.
      
      //TODO FIX THIS, This should create a Key Object instead of keeping bytes

      this.publicKey =   encodedKey;//CryptoUtil.getPublicKey(encodedKey);
      this.type = KeyLocatorType.KEY;    

      if (LOG > 4) console.log('PUBLIC KEY FOUND: '+ this.publicKey);
    } 
    catch (e) {
      throw new Error("Cannot parse key: ", e);
    } 

    if (null == this.publicKey)
      throw new Error("Cannot parse key: ");
  } 
  else if (decoder.peekDTag(NDNProtocolDTags.Certificate)) {
    try {
      var encodedCert = decoder.readBinaryDTagElement(NDNProtocolDTags.Certificate);
      
      /*
       * Certificates not yet working
       */
      
      this.certificate = encodedCert;
      this.type = KeyLocatorType.CERTIFICATE;

      if (LOG > 4) console.log('CERTIFICATE FOUND: '+ this.certificate);      
    } 
    catch (e) {
      throw new Error("Cannot decode certificate: " +  e);
    }
    if (null == this.certificate)
      throw new Error("Cannot parse certificate! ");
  } else  {
    this.type = KeyLocatorType.KEYNAME;
    
    this.keyName = new KeyName();
    this.keyName.from_ndnb(decoder);
  }
  decoder.readElementClose();
};  

KeyLocator.prototype.to_ndnb = function(encoder) 
{
  if (LOG > 4) console.log('type is is ' + this.type);
  //TODO Check if Name is missing
  if (!this.validate())
    throw new Error("Cannot encode " + this.getClass().getName() + ": field values missing.");

  //TODO FIX THIS TOO
  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (this.type == KeyLocatorType.KEY) {
    if (LOG > 5) console.log('About to encode a public key' +this.publicKey);
    encoder.writeDTagElement(NDNProtocolDTags.Key, this.publicKey);  
  } 
  else if (this.type == KeyLocatorType.CERTIFICATE) {  
    try {
      encoder.writeDTagElement(NDNProtocolDTags.Certificate, this.certificate);
    } 
    catch (e) {
      throw new Error("CertificateEncodingException attempting to write key locator: " + e);
    }    
  } 
  else if (this.type == KeyLocatorType.KEYNAME)
    this.keyName.to_ndnb(encoder);

  encoder.writeElementClose();
};

KeyLocator.prototype.getElementLabel = function() 
{
  return NDNProtocolDTags.KeyLocator; 
};

KeyLocator.prototype.validate = function() 
{
  return null != this.keyName || null != this.publicKey || null != this.certificate;
};

/**
 * KeyName is only used by KeyLocator.
 * @constructor
 */
var KeyName = function KeyName() 
{
  this.contentName = this.contentName;  //contentName
  this.publisherID = this.publisherID;  //publisherID
};

exports.KeyName = KeyName;

KeyName.prototype.from_ndnb = function(decoder) 
{
  decoder.readElementStartDTag(this.getElementLabel());

  this.contentName = new Name();
  this.contentName.from_ndnb(decoder);
  
  if (LOG > 4) console.log('KEY NAME FOUND: ');
  
  if (PublisherID.peek(decoder)) {
    this.publisherID = new PublisherID();
    this.publisherID.from_ndnb(decoder);
  }
  
  decoder.readElementClose();
};

KeyName.prototype.to_ndnb = function(encoder)
{
  if (!this.validate())
    throw new Error("Cannot encode : field values missing.");
  
  encoder.writeElementStartDTag(this.getElementLabel());
  
  this.contentName.to_ndnb(encoder);
  if (null != this.publisherID)
    this.publisherID.to_ndnb(encoder);

  encoder.writeElementClose();       
};
  
KeyName.prototype.getElementLabel = function() { return NDNProtocolDTags.KeyName; };

KeyName.prototype.validate = function() 
{
    // DKS -- do we do recursive validation?
    // null signedInfo ok
    return (null != this.contentName);
};
