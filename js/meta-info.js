/**
 * This class represents an NDN Data MetaInfo object.
 * Copyright (C) 2014-2018 Regents of the University of California.
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
var Name = require('./name.js').Name;

/**
 * A ContentType specifies the content type in a MetaInfo object. If the
 * content type in the packet is not a recognized enum value, then we use
 * ContentType.OTHER_CODE and you can call MetaInfo.getOtherTypeCode(). We do
 * this to keep the recognized content type values independent of packet
 * encoding formats.
 */
var ContentType = {
  BLOB:0,
  LINK:1,
  KEY: 2,
  NACK:3,
  OTHER_CODE: 0x7fff
};

exports.ContentType = ContentType;

/**
 * Create a new MetaInfo with the optional values.
 * @constructor
 */
var MetaInfo = function MetaInfo(publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockId)
{
  if (timestamp)
    throw new Error
      ("MetaInfo constructor: timestamp support has been removed.");
  if (locator)
    throw new Error
      ("MetaInfo constructor: locator support has been removed.");

  if (typeof publisherOrMetaInfo === 'object' &&
      publisherOrMetaInfo instanceof MetaInfo) {
    // Copy values.
    var metaInfo = publisherOrMetaInfo;
    this.publisher_ = metaInfo.publisher_;
    this.type_ = metaInfo.type_;
    this.otherTypeCode_ = metaInfo.otherTypeCode_;
    this.freshnessPeriod_ = metaInfo.freshnessPeriod_;
    this.finalBlockId_ = metaInfo.finalBlockId_;
  }
  else {
    if (publisherOrMetaInfo)
      throw new Error
        ("MetaInfo constructor: publisher support has been removed.");

    this.type = type == null || type < 0 ? ContentType.BLOB : type;
    this.otherTypeCode_ = -1;
    this.freshnessSeconds = freshnessSeconds; // deprecated
    this.finalBlockID = finalBlockId; // byte array // deprecated
  }

  this.changeCount_ = 0;
};

exports.MetaInfo = MetaInfo;

/**
 * Get the content type.
 * @return {number} The content type as an int from ContentType. If this is
 * ContentType.OTHER_CODE, then call getOtherTypeCode() to get the unrecognized
 * content type code.
 */
MetaInfo.prototype.getType = function()
{
  return this.type_;
};

/**
 * Get the content type code from the packet which is other than a recognized
 * ContentType enum value. This is only meaningful if getType() is
 * ContentType.OTHER_CODE.
 * @return {number} The type code.
 */
MetaInfo.prototype.getOtherTypeCode = function()
{
  return this.otherTypeCode_;
};

/**
 * Get the freshness period.
 * @return {number} The freshness period in milliseconds, or null if not
 * specified.
 */
MetaInfo.prototype.getFreshnessPeriod = function()
{
  return this.freshnessPeriod_;
};

/**
 * Get the final block ID.
 * @return {Name.Component} The final block ID as a Name.Component. If the
 * Name.Component getValue().size() is 0, then the final block ID is not specified.
 */
MetaInfo.prototype.getFinalBlockId = function()
{
  return this.finalBlockId_;
};

/**
 * @deprecated Use getFinalBlockId.
 */
MetaInfo.prototype.getFinalBlockID = function()
{
  return this.getFinalBlockId();
};

/**
 * @deprecated Use getFinalBlockId. This method returns a Buffer which is the former
 * behavior of getFinalBlockId, and should only be used while updating your code.
 */
MetaInfo.prototype.getFinalBlockIDAsBuffer = function()
{
  return this.finalBlockId_.getValue().buf();
};

/**
 * Set the content type.
 * @param {number} type The content type as an int from ContentType. If null,
 * this uses ContentType.BLOB. If the packet's content type is not a recognized
 * ContentType enum value, use ContentType.OTHER_CODE and call setOtherTypeCode().
 */
MetaInfo.prototype.setType = function(type)
{
  this.type_ = type == null || type < 0 ? ContentType.BLOB : type;
  ++this.changeCount_;
};

/**
 * Set the packet’s content type code to use when the content type enum is
 * ContentType.OTHER_CODE. If the packet’s content type code is a recognized
 * enum value, just call setType().
 * @param {number} otherTypeCode The packet’s unrecognized content type code,
 * which must be non-negative.
 */
MetaInfo.prototype.setOtherTypeCode = function(otherTypeCode)
{
  if (otherTypeCode < 0)
    throw new Error("MetaInfo other type code must be non-negative");

  this.otherTypeCode_ = otherTypeCode;
  ++this.changeCount_;
};

/**
 * Set the freshness period.
 * @param {number} freshnessPeriod The freshness period in milliseconds, or null
 * for not specified.
 */
MetaInfo.prototype.setFreshnessPeriod = function(freshnessPeriod)
{
  if (freshnessPeriod == null || freshnessPeriod < 0)
    this.freshnessPeriod_ = null;
  else
    this.freshnessPeriod_ = freshnessPeriod;
  ++this.changeCount_;
};

/**
 * Set the final block ID.
 * @param {Name.Component} finalBlockId The final block ID as a Name.Component.
 * If not specified, set to a new default Name.Component(), or to a
 * Name.Component where getValue().size() is 0.
 */
MetaInfo.prototype.setFinalBlockId = function(finalBlockId)
{
  this.finalBlockId_ = typeof finalBlockId === 'object' &&
                       finalBlockId instanceof Name.Component ?
    finalBlockId : new Name.Component(finalBlockId);
  ++this.changeCount_;
};

/**
 * @deprecated Use setFinalBlockId.
 */
MetaInfo.prototype.setFinalBlockID = function(finalBlockId)
{
  this.setFinalBlockId(finalBlockId);
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @return {number} The change count.
 */
MetaInfo.prototype.getChangeCount = function()
{
  return this.changeCount_;
};

// Define properties so we can change member variable types and implement changeCount_.
Object.defineProperty(MetaInfo.prototype, "type",
  { get: function() { return this.getType(); },
    set: function(val) { this.setType(val); } });
/**
 * @deprecated Use getFreshnessPeriod and setFreshnessPeriod.
 */
Object.defineProperty(MetaInfo.prototype, "freshnessSeconds",
  { get: function() {
      if (this.freshnessPeriod_ == null || this.freshnessPeriod_ < 0)
        return null;
      else
        // Convert from milliseconds.
        return this.freshnessPeriod_ / 1000.0;
    },
    set: function(val) {
      if (val == null || val < 0)
        this.freshnessPeriod_ = null;
      else
        // Convert to milliseconds.
        this.freshnessPeriod_ = val * 1000.0;
      ++this.changeCount_;
    } });
/**
 * @deprecated Use getFinalBlockId and setFinalBlockId.
 */
Object.defineProperty(MetaInfo.prototype, "finalBlockID",
  { get: function() { return this.getFinalBlockIDAsBuffer(); },
    set: function(val) { this.setFinalBlockId(val); } });
