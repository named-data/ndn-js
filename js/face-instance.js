/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Face Instances
 */

var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;

/**
 * @constructor
 */
var FaceInstance  = function FaceInstance(action, publisherPublicKeyDigest, faceID, ipProto, host, port, multicastInterface,
    multicastTTL, freshnessSeconds) 
{
  this.action = action;
  this.publisherPublicKeyDigest = publisherPublicKeyDigest;
  this.faceID = faceID;
  this.ipProto = ipProto;
  this.host = host;
  this.Port = port;
  this.multicastInterface =multicastInterface;
  this.multicastTTL =multicastTTL;
  this.freshnessSeconds = freshnessSeconds;
};

exports.FaceInstance = FaceInstance;

FaceInstance.NetworkProtocol = { TCP:6, UDP:17};

/**
 * Used by NetworkObject to decode the object from a network stream.
 */
FaceInstance.prototype.from_ndnb = function(
  //XMLDecoder 
  decoder) 
{
  decoder.readStartElement(this.getElementLabel());
  
  if (decoder.peekStartElement(NDNProtocolDTags.Action))   
    this.action = decoder.readUTF8Element(NDNProtocolDTags.Action);
  if (decoder.peekStartElement(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    this.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
    this.publisherPublicKeyDigest.from_ndnb(decoder);
  }
  if (decoder.peekStartElement(NDNProtocolDTags.FaceID))
    this.faceID = decoder.readIntegerElement(NDNProtocolDTags.FaceID);
  if (decoder.peekStartElement(NDNProtocolDTags.IPProto)) {
    //int
    var pI = decoder.readIntegerElement(NDNProtocolDTags.IPProto);
    
    this.ipProto = null;
    
    if (FaceInstance.NetworkProtocol.TCP == pI)
      this.ipProto = FaceInstance.NetworkProtocol.TCP;
    else if (FaceInstance.NetworkProtocol.UDP == pI)
      this.ipProto = FaceInstance.NetworkProtocol.UDP;
    else
      throw new Error("FaceInstance.decoder.  Invalid " + NDNProtocolDTags.tagToString(NDNProtocolDTags.IPProto) + " field: " + pI);
  }
  
  if (decoder.peekStartElement(NDNProtocolDTags.Host))
    this.host = decoder.readUTF8Element(NDNProtocolDTags.Host);
  if (decoder.peekStartElement(NDNProtocolDTags.Port))
    this.Port = decoder.readIntegerElement(NDNProtocolDTags.Port); 
  if (decoder.peekStartElement(NDNProtocolDTags.MulticastInterface))
    this.multicastInterface = decoder.readUTF8Element(NDNProtocolDTags.MulticastInterface); 
  if (decoder.peekStartElement(NDNProtocolDTags.MulticastTTL))
    this.multicastTTL = decoder.readIntegerElement(NDNProtocolDTags.MulticastTTL); 
  if (decoder.peekStartElement(NDNProtocolDTags.FreshnessSeconds))
    this.freshnessSeconds = decoder.readIntegerElement(NDNProtocolDTags.FreshnessSeconds); 

  decoder.readEndElement();
};

/**
 * Used by NetworkObject to encode the object to a network stream.
 */
FaceInstance.prototype.to_ndnb = function(
  //XMLEncoder
  encoder) 
{
  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (null != this.action && this.action.length != 0)
    encoder.writeElement(NDNProtocolDTags.Action, this.action);  
  if (null != this.publisherPublicKeyDigest)
    this.publisherPublicKeyDigest.to_ndnb(encoder);
  if (null != this.faceID)
    encoder.writeElement(NDNProtocolDTags.FaceID, this.faceID);
  if (null != this.ipProto)
    encoder.writeElement(NDNProtocolDTags.IPProto, this.ipProto);
  if (null != this.host && this.host.length != 0)
    encoder.writeElement(NDNProtocolDTags.Host, this.host);  
  if (null != this.Port)
    encoder.writeElement(NDNProtocolDTags.Port, this.Port);
  if (null != this.multicastInterface && this.multicastInterface.length != 0)
    encoder.writeElement(NDNProtocolDTags.MulticastInterface, this.multicastInterface);
  if (null !=  this.multicastTTL)
    encoder.writeElement(NDNProtocolDTags.MulticastTTL, this.multicastTTL);
  if (null != this.freshnessSeconds)
    encoder.writeElement(NDNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);

  encoder.writeElementClose();         
};

FaceInstance.prototype.getElementLabel = function() 
{
  return NDNProtocolDTags.FaceInstance;
};

