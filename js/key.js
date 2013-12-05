/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Key Objects
 */

var Name = require('./name.js').Name;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var PublisherID = require('./publisher-id.js').PublisherID;
var LOG = require('./log.js').Log.LOG;

/**
 * @constructor
 */
/**
 * Key
 */
var Key = function Key() 
{
  this.publicKeyDer = null;     // Buffer
  this.publicKeyDigest = null;  // Buffer
  this.publicKeyPem = null;     // String
  this.privateKeyPem = null;    // String
};

exports.Key = Key;

/**
 * Helper functions to read Key fields
 * TODO: generateRSA()
 */

Key.prototype.publicToDER = function() 
{
  return this.publicKeyDer;  // Buffer
};

Key.prototype.privateToDER = function() 
{
  // Remove the '-----XXX-----' from the beginning and the end of the key
  // and also remove any \n in the key string
  var lines = this.privateKeyPem.split('\n');
  priKey = "";
  for (var i = 1; i < lines.length - 1; i++)
    priKey += lines[i];
  
  return new Buffer(priKey, 'base64');    
};

Key.prototype.publicToPEM = function() 
{
  return this.publicKeyPem;
};

Key.prototype.privateToPEM = function() 
{
  return this.privateKeyPem;
};

Key.prototype.getKeyID = function() 
{
  return this.publicKeyDigest;
};

exports.Key = Key;

Key.prototype.readDerPublicKey = function(/*Buffer*/pub_der) 
{
  if (LOG > 4) console.log("Encode DER public key:\n" + pub_der.toString('hex'));

  this.publicKeyDer = pub_der;

  var hash = require("crypto").createHash('sha256');
  hash.update(this.publicKeyDer);
  this.publicKeyDigest = new Buffer(hash.digest());
    
  var keyStr = pub_der.toString('base64'); 
  var keyPem = "-----BEGIN PUBLIC KEY-----\n";
  for (var i = 0; i < keyStr.length; i += 64)
  keyPem += (keyStr.substr(i, 64) + "\n");
  keyPem += "-----END PUBLIC KEY-----";
  this.publicKeyPem = keyPem;

  if (LOG > 4) console.log("Convert public key to PEM format:\n" + this.publicKeyPem);
};

/**
 * Load RSA key pair from PEM-encoded strings.
 * Will throw an Error if both 'pub' and 'pri' are null.
 */
Key.prototype.fromPemString = function(pub, pri) 
{
  if (pub == null && pri == null)
    throw new Error('Cannot create Key object if both public and private PEM string is empty.');

  // Read public key
  if (pub != null) {
    this.publicKeyPem = pub;
    if (LOG > 4) console.log("Key.publicKeyPem: \n" + this.publicKeyPem);
  
    // Remove the '-----XXX-----' from the beginning and the end of the public key
    // and also remove any \n in the public key string
    var lines = pub.split('\n');
    pub = "";
    for (var i = 1; i < lines.length - 1; i++)
      pub += lines[i];
    this.publicKeyDer = new Buffer(pub, 'base64');
    if (LOG > 4) console.log("Key.publicKeyDer: \n" + this.publicKeyDer.toString('hex'));
  
    var hash = require("crypto").createHash('sha256');
    hash.update(this.publicKeyDer);
    this.publicKeyDigest = new Buffer(hash.digest());
    if (LOG > 4) console.log("Key.publicKeyDigest: \n" + this.publicKeyDigest.toString('hex'));
  }
    
  // Read private key
  if (pri != null) {
    this.privateKeyPem = pri;
    if (LOG > 4) console.log("Key.privateKeyPem: \n" + this.privateKeyPem);
  }
};

Key.prototype.fromPem = Key.prototype.fromPemString;

/**
 * Static method that create a Key object.
 * Parameter 'obj' is a JSON object that has two properties:
 *   pub: the PEM string for the public key
 *   pri: the PEM string for the private key
 * Will throw an Error if both obj.pub and obj.pri are null.
 */
Key.createFromPEM = function(obj) 
{
    var key = new Key();
    key.fromPemString(obj.pub, obj.pri);
    return key;
};

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
      var encodedKey = decoder.readBinaryElement(NDNProtocolDTags.Key);
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
      var encodedCert = decoder.readBinaryElement(NDNProtocolDTags.Certificate);
      
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
    throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");

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
