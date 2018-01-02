/**
 * Copyright (C) 2016-2018 Regents of the University of California.
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
var DelegationSet = require('./delegation-set.js').DelegationSet; /** @ignore */
var ContentType = require('./meta-info.js').ContentType; /** @ignore */
var WireFormat = require('./encoding/wire-format.js').WireFormat; /** @ignore */
var Data = require('./data.js').Data;

/**
 * The Link class extends Data and represents a Link instance where the Data
 * content is an encoded delegation set. The format is defined in "link.pdf"
 * attached to Redmine issue http://redmine.named-data.net/issues/2587 .
 *
 * Create a new Link with the optional values. There are 3 forms of the constructor:
 * Link(name);
 * Link(data);
 * Link();
 * @param {Name} name The name for constructing the base Data.
 * @param {Data} data The Data object to copy values from. If the content can be
 * decoded using the default wire encoding, then update the list of delegations.
 * @constructor
 */
var Link = function Link(value)
{
  this.delegations_ = new DelegationSet();

  if (value instanceof Data) {
    // Call the base constructor.
    Data.call(this, value);

    if (!this.getContent().isNull()) {
      try {
        this.delegations_.wireDecode(this.getContent());
        this.getMetaInfo().setType(ContentType.LINK);
      }
      catch (ex) {
        this.delegations_.clear();
      }
    }
  }
  else {
    if (value != undefined)
      // value is a Name.
      Data.call(this, value);
    else
      Data.call(this);

    this.getMetaInfo().setType(ContentType.LINK);
  }
};

Link.prototype = new Data();
Link.prototype.name = "Link";

exports.Link = Link;

/**
 * Override to call the base class wireDecode then populate the list of
 * delegations from the content.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Link.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  Data.prototype.wireDecode.call(this, input, wireFormat);
  if (this.getMetaInfo().getType() != ContentType.LINK)
    throw new Error
      ("Link.wireDecode: MetaInfo ContentType is not LINK.");

  this.delegations_.wireDecode(this.getContent());
};

/**
 * Add a new delegation to the list of delegations, sorted by preference number
 * then by name. Re-encode this object's content using the optional wireFormat.
 * @param {number} preference The preference number.
 * @param {Name} name The delegation name. This makes a copy of the name. If
 * there is already a delegation with the same name, this updates its preference.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the DelegationSet. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {Link} This Link so that you can chain calls to update values.
 */
Link.prototype.addDelegation = function(preference, name, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  this.delegations_.add(preference, name);
  this.encodeContent(wireFormat);

  return this;
};

/**
 * Remove every delegation with the given name. Re-encode this object's content
 * using the optional wireFormat.
 * @param {Name} name Then name to match the name of the delegation(s) to be
 * removed.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the DelegationSet. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {boolean} True if a delegation was removed, otherwise false.
 */
Link.prototype.removeDelegation = function(name, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  var wasRemoved = this.delegations_.remove(name);
  if (wasRemoved)
    this.encodeContent(wireFormat);

  return wasRemoved;
};

/**
 * Get the list of delegation for read only.
 * @return {DelegationSet} The list of delegation, which you should treat as
 * read-only. To modify it, call Link.addDelegation, etc.
 */
Link.prototype.getDelegations = function() { return this.delegations_; };

/**
 * A private method to encode the delegations_ and set this object's content.
 * Also set the meta info content type to LINK.
 * @param {WireFormat} wireFormat A WireFormat object used to encode the
 * DelegationSet.
 */
Link.prototype.encodeContent = function(wireFormat)
{
  this.setContent(this.delegations_.wireEncode(wireFormat));
  this.getMetaInfo().setType(ContentType.LINK);
};
