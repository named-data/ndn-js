/**
 * This class represents an NDN Data object.
 * Copyright (C) 2013-2018 Regents of the University of California.
 * @author: Meki Cheraoui
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
var Blob = require('./util/blob.js').Blob; /** @ignore */
var SignedBlob = require('./util/signed-blob.js').SignedBlob; /** @ignore */
var ChangeCounter = require('./util/change-counter.js').ChangeCounter; /** @ignore */
var Name = require('./name.js').Name; /** @ignore */
var Sha256WithRsaSignature = require('./sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var MetaInfo = require('./meta-info.js').MetaInfo; /** @ignore */
var IncomingFaceId = require('./lp/incoming-face-id.js').IncomingFaceId; /** @ignore */
var CongestionMark = require('./lp/congestion-mark.js').CongestionMark; /** @ignore */
var WireFormat = require('./encoding/wire-format.js').WireFormat; /** @ignore */
var Crypto = require('./crypto.js');

/**
 * Create a new Data with the optional values.  There are 2 forms of constructor:
 * new Data([name] [, content]);
 * new Data(name, metaInfo [, content]);
 *
 * @constructor
 * @param {Name} name
 * @param {MetaInfo} metaInfo
 * @param {Buffer} content
 */
var Data = function Data(nameOrData, metaInfoOrContent, arg3)
{
  if (nameOrData instanceof Data) {
    // The copy constructor.
    var data = nameOrData;

    // Copy the Data object.
    this.name_ = new ChangeCounter(new Name(data.getName()));
    this.metaInfo_ = new ChangeCounter(new MetaInfo(data.getMetaInfo()));
    this.signature_ = new ChangeCounter(data.getSignature().clone());
    this.content_ = data.content_;
    this.defaultWireEncoding_ = data.getDefaultWireEncoding();
    this.defaultFullName_ = new Name(data.defaultFullName_);
    this.defaultWireEncodingFormat_ = data.defaultWireEncodingFormat_;
  }
  else {
    var name = nameOrData;
    if (typeof name === 'string')
      this.name_ = new ChangeCounter(new Name(name));
    else
      this.name_ = new ChangeCounter(typeof name === 'object' && name instanceof Name ?
         new Name(name) : new Name());

    var metaInfo;
    var content;
    if (typeof metaInfoOrContent === 'object' &&
        metaInfoOrContent instanceof MetaInfo) {
      metaInfo = metaInfoOrContent;
      content = arg3;
    }
    else {
      metaInfo = null;
      content = metaInfoOrContent;
    }

    this.metaInfo_ = new ChangeCounter(typeof metaInfo === 'object' && metaInfo instanceof MetaInfo ?
      new MetaInfo(metaInfo) : new MetaInfo());

    this.content_ = typeof content === 'object' && content instanceof Blob ?
      content : new Blob(content, true);

    this.signature_ = new ChangeCounter(new Sha256WithRsaSignature());
    this.defaultWireEncoding_ = new SignedBlob();
    this.defaultFullName_ = new Name();
    this.defaultWireEncodingFormat_ = null;
  }

  this.getDefaultWireEncodingChangeCount_ = 0;
  this.changeCount_ = 0;
  this.lpPacket_ = null;
};

exports.Data = Data;

/**
 * Get the data packet's name.
 * @return {Name} The name. If not specified, the name size() is 0.
 */
Data.prototype.getName = function()
{
  return this.name_.get();
};

/**
 * Get the data packet's meta info.
 * @return {MetaInfo} The meta info.
 */
Data.prototype.getMetaInfo = function()
{
  return this.metaInfo_.get();
};

/**
 * Get the data packet's signature object.
 * @return {Signature} The signature object.
 */
Data.prototype.getSignature = function()
{
  return this.signature_.get();
};

/**
 * Get the data packet's content.
 * @return {Blob} The content as a Blob, which isNull() if unspecified.
 */
Data.prototype.getContent = function()
{
  return this.content_;
};

/**
 * @deprecated Use getContent. This method returns a Buffer which is the former
 * behavior of getContent, and should only be used while updating your code.
 */
Data.prototype.getContentAsBuffer = function()
{
  return this.content_.buf();
};

/**
 * Return the default wire encoding, which was encoded with
 * getDefaultWireEncodingFormat().
 * @return {SignedBlob} The default wire encoding, whose isNull() may be true
 * if there is no default wire encoding.
 */
Data.prototype.getDefaultWireEncoding = function()
{
  if (this.getDefaultWireEncodingChangeCount_ != this.getChangeCount()) {
    // The values have changed, so the default wire encoding is invalidated.
    this.defaultWireEncoding_ = new SignedBlob();
    this.defaultWireEncodingFormat_ = null;
    this.getDefaultWireEncodingChangeCount_ = this.getChangeCount();
  }

  return this.defaultWireEncoding_;
};

/**
 * Get the WireFormat which is used by getDefaultWireEncoding().
 * @return {WireFormat} The WireFormat, which is only meaningful if the
 * getDefaultWireEncoding() is not isNull().
 */
Data.prototype.getDefaultWireEncodingFormat = function()
{
  return this.defaultWireEncodingFormat_;
};

/**
 * Get the incoming face ID according to the incoming packet header.
 * @return {number} The incoming face ID. If not specified, return null.
 */
Data.prototype.getIncomingFaceId = function()
{
  var field =
    this.lpPacket_ === null ? null : IncomingFaceId.getFirstHeader(this.lpPacket_);
  return field === null ? null : field.getFaceId();
};

/**
 * Get the congestion mark according to the incoming packet header.
 * @return {number} The congestion mark. If not specified, return 0.
 */
Data.prototype.getCongestionMark = function()
{
  var field =
    this.lpPacket_ === null ? null : CongestionMark.getFirstHeader(this.lpPacket_);
  return field === null ? 0 : field.getCongestionMark();
};

/**
 * Get the Data packet's full name, which includes the final
 * ImplicitSha256Digest component based on the wire encoding for a particular
 * wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {Name} The full name. You must not change the Name object - if you
 * need to change it then make a copy.
 */
Data.prototype.getFullName = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  // The default full name depends on the default wire encoding.
  if (!this.getDefaultWireEncoding().isNull() &&
      this.defaultFullName_.size() > 0 &&
      this.getDefaultWireEncodingFormat() == wireFormat)
    // We already have a full name. A non-null default wire encoding means
    // that the Data packet fields have not changed.
    return this.defaultFullName_;

  var fullName = new Name(this.getName());
  var hash = Crypto.createHash('sha256');
  // wireEncode will use the cached encoding if possible.
  hash.update(this.wireEncode(wireFormat).buf());
  fullName.appendImplicitSha256Digest(new Blob(hash.digest(), false));

  if (wireFormat == WireFormat.getDefaultWireFormat())
    // wireEncode has already set defaultWireEncodingFormat_.
    this.defaultFullName_ = fullName;

  return fullName;
};

/**
 * Set name to a copy of the given Name.
 * @param {Name} name The Name which is copied.
 * @return {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setName = function(name)
{
  this.name_.set(typeof name === 'object' && name instanceof Name ?
    new Name(name) : new Name());
  ++this.changeCount_;
  return this;
};

/**
 * Set metaInfo to a copy of the given MetaInfo.
 * @param {MetaInfo} metaInfo The MetaInfo which is copied.
 * @return {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setMetaInfo = function(metaInfo)
{
  this.metaInfo_.set(typeof metaInfo === 'object' && metaInfo instanceof MetaInfo ?
    new MetaInfo(metaInfo) : new MetaInfo());
  ++this.changeCount_;
  return this;
};

/**
 * Set the signature to a copy of the given signature.
 * @param {Signature} signature The signature object which is cloned.
 * @return {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setSignature = function(signature)
{
  this.signature_.set(signature == null ?
    new Sha256WithRsaSignature() : signature.clone());
  ++this.changeCount_;
  return this;
};

/**
 * Set the content to the given value.
 * @param {Blob|Buffer} content The content bytes. If content is not a Blob,
 * then create a new Blob to copy the bytes (otherwise take another pointer to
 * the same Blob).
 * @return {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setContent = function(content)
{
  this.content_ = typeof content === 'object' && content instanceof Blob ?
    content : new Blob(content, true);
  ++this.changeCount_;
  return this;
};

/**
 * Encode this Data for a particular wire format. If wireFormat is the default
 * wire format, also set the defaultWireEncoding field to the encoded result.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {SignedBlob} The encoded buffer in a SignedBlob object.
 */
Data.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (!this.getDefaultWireEncoding().isNull() &&
      this.getDefaultWireEncodingFormat() == wireFormat)
    // We already have an encoding in the desired format.
    return this.getDefaultWireEncoding();

  var result = wireFormat.encodeData(this);
  var wireEncoding = new SignedBlob
    (result.encoding, result.signedPortionBeginOffset,
     result.signedPortionEndOffset);

  if (wireFormat == WireFormat.getDefaultWireFormat())
    // This is the default wire encoding.
    this.setDefaultWireEncoding
      (wireEncoding, WireFormat.getDefaultWireFormat());
  return wireEncoding;
};

/**
 * Decode the input using a particular wire format and update this Data. If
 * wireFormat is the default wire format, also set the defaultWireEncoding to
 * another pointer to the input.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Data.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  var result;
  if (typeof input === 'object' && input instanceof Blob)
    // Input is a blob, so get its buf() and set copy false.
    result = wireFormat.decodeData(this, input.buf(), false);
  else
    result = wireFormat.decodeData(this, input, true);

  if (wireFormat == WireFormat.getDefaultWireFormat())
    // This is the default wire encoding.  In the Blob constructor, set copy
    // true, but if input is already a Blob, it won't copy.
    this.setDefaultWireEncoding(new SignedBlob
      (new Blob(input, true), result.signedPortionBeginOffset,
       result.signedPortionEndOffset),
      WireFormat.getDefaultWireFormat());
  else
    this.setDefaultWireEncoding(new SignedBlob(), null);
};

/**
 * An internal library method to set the LpPacket for an incoming packet. The
 * application should not call this.
 * @param {LpPacket} lpPacket The LpPacket. This does not make a copy.
 * @return {Data} This Data so that you can chain calls to update values.
 * @note This is an experimental feature. This API may change in the future.
 */
Data.prototype.setLpPacket = function(lpPacket)
{
  this.lpPacket_ = lpPacket;
  // Don't update changeCount_ since this doesn't affect the wire encoding.
  return this;
}

/**
 * Get the change count, which is incremented each time this object (or a child
 * object) is changed.
 * @return {number} The change count.
 */
Data.prototype.getChangeCount = function()
{
  // Make sure each of the checkChanged is called.
  var changed = this.name_.checkChanged();
  changed = this.metaInfo_.checkChanged() || changed;
  changed = this.signature_.checkChanged() || changed;
  if (changed)
    // A child object has changed, so update the change count.
    ++this.changeCount_;

  return this.changeCount_;
};

Data.prototype.setDefaultWireEncoding = function
  (defaultWireEncoding, defaultWireEncodingFormat)
{
  this.defaultWireEncoding_ = defaultWireEncoding;
  this.defaultWireEncodingFormat_ = defaultWireEncodingFormat;
  // Set getDefaultWireEncodingChangeCount_ so that the next call to
  // getDefaultWireEncoding() won't clear _defaultWireEncoding.
  this.getDefaultWireEncodingChangeCount_ = this.getChangeCount();
};

// Define properties so we can change member variable types and implement changeCount_.
Object.defineProperty(Data.prototype, "name",
  { get: function() { return this.getName(); },
    set: function(val) { this.setName(val); } });
Object.defineProperty(Data.prototype, "metaInfo",
  { get: function() { return this.getMetaInfo(); },
    set: function(val) { this.setMetaInfo(val); } });
Object.defineProperty(Data.prototype, "signature",
  { get: function() { return this.getSignature(); },
    set: function(val) { this.setSignature(val); } });
/**
 * @deprecated Use getContent and setContent.
 */
Object.defineProperty(Data.prototype, "content",
  { get: function() { return this.getContentAsBuffer(); },
    set: function(val) { this.setContent(val); } });
