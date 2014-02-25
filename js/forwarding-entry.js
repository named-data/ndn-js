/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Forwarding Entries
 */

var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;
var Name = require('./name.js').Name;

/**
 * Create a new ForwardingEntry with the optional arguments.
 * @constructor
 * @param {String} action
 * @param {Name} prefixName
 * @param {PublisherPublicKeyDigest} ndndId
 * @param {number} faceID
 * @param {number} flags
 * @param {number} lifetime in seconds
 */
var ForwardingEntry = function ForwardingEntry(action, prefixName, ndndId, faceID, flags, lifetime) 
{
  this.action = action;
  this.prefixName = prefixName;
  this.ndndID = ndndId;
  this.faceID = faceID;
  this.flags = flags;
  this.lifetime = lifetime;
};

exports.ForwardingEntry = ForwardingEntry;

ForwardingEntry.ACTIVE         = 1;
ForwardingEntry.CHILD_INHERIT  = 2;
ForwardingEntry.ADVERTISE      = 4;
ForwardingEntry.LAST           = 8;
ForwardingEntry.CAPTURE       = 16;
ForwardingEntry.LOCAL         = 32;
ForwardingEntry.TAP           = 64;
ForwardingEntry.CAPTURE_OK   = 128;

ForwardingEntry.prototype.from_ndnb = function(
  //XMLDecoder 
  decoder) 
  //throws DecodingException
{
  decoder.readElementStartDTag(this.getElementLabel());
  if (decoder.peekDTag(NDNProtocolDTags.Action))
    this.action = decoder.readUTF8DTagElement(NDNProtocolDTags.Action); 
  if (decoder.peekDTag(NDNProtocolDTags.Name)) {
    this.prefixName = new Name();
    this.prefixName.from_ndnb(decoder) ;
  }
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    this.NdndId = new PublisherPublicKeyDigest();
    this.NdndId.from_ndnb(decoder);
  }
  if (decoder.peekDTag(NDNProtocolDTags.FaceID))
    this.faceID = decoder.readIntegerDTagElement(NDNProtocolDTags.FaceID); 
  if (decoder.peekDTag(NDNProtocolDTags.ForwardingFlags))
    this.flags = decoder.readIntegerDTagElement(NDNProtocolDTags.ForwardingFlags); 
  if (decoder.peekDTag(NDNProtocolDTags.FreshnessSeconds))
    this.lifetime = decoder.readIntegerDTagElement(NDNProtocolDTags.FreshnessSeconds); 

  decoder.readElementClose();
};

ForwardingEntry.prototype.to_ndnb = function(
  //XMLEncoder 
  encoder) 
{
  encoder.writeElementStartDTag(this.getElementLabel());
  if (null != this.action && this.action.length != 0)
    encoder.writeDTagElement(NDNProtocolDTags.Action, this.action);  
  if (null != this.prefixName)
    this.prefixName.to_ndnb(encoder);
  if (null != this.NdndId)
    this.NdndId.to_ndnb(encoder);
  if (null != this.faceID)
    encoder.writeDTagElement(NDNProtocolDTags.FaceID, this.faceID);
  if (null != this.flags)
    encoder.writeDTagElement(NDNProtocolDTags.ForwardingFlags, this.flags);
  if (null != this.lifetime)
    encoder.writeDTagElement(NDNProtocolDTags.FreshnessSeconds, this.lifetime);

  encoder.writeElementClose();         
};

ForwardingEntry.prototype.getElementLabel = function() { return NDNProtocolDTags.ForwardingEntry; }
