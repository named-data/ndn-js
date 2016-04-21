/**
 * This class represents an NDN Data MetaInfo object.
 * Copyright (C) 2014-2016 Regents of the University of California.
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
var Name = require('./name.js').Name; /** @ignore */
var LOG = require('./log.js').Log.LOG;

var ContentType = {
  BLOB:0,
  LINK:1,
  KEY: 2,
  NACK:3
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
    this.freshnessPeriod_ = metaInfo.freshnessPeriod_;
    this.finalBlockId_ = metaInfo.finalBlockId_;
  }
  else {
    if (publisherOrMetaInfo)
      throw new Error
        ("MetaInfo constructor: publisher support has been removed.");

    this.type = type == null || type < 0 ? ContentType.BLOB : type;
    this.freshnessSeconds = freshnessSeconds; // deprecated
    this.finalBlockID = finalBlockId; // byte array // deprecated
  }

  this.changeCount_ = 0;
};

exports.MetaInfo = MetaInfo;

/**
 * Get the content type.
 * @returns {number} The content type as an int from ContentType.
 */
MetaInfo.prototype.getType = function()
{
  return this.type_;
};

/**
 * Get the freshness period.
 * @returns {number} The freshness period in milliseconds, or null if not
 * specified.
 */
MetaInfo.prototype.getFreshnessPeriod = function()
{
  return this.freshnessPeriod_;
};

/**
 * Get the final block ID.
 * @returns {Name.Component} The final block ID as a Name.Component. If the
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
 * @param {number} type The content type as an int from ContentType.  If null,
 * this uses ContentType.BLOB.
 */
MetaInfo.prototype.setType = function(type)
{
  this.type_ = type == null || type < 0 ? ContentType.BLOB : type;
  ++this.changeCount_;
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
    this.freshnessPeriod_ = null;
  else
    this.freshnessPeriod_ = freshnessPeriod;
  ++this.changeCount_;
};

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
 * @returns {number} The change count.
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
