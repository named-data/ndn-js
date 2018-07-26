/**
 * Copyright (C) 2016-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx packet.hpp https://github.com/named-data/ndn-cxx/blob/master/src/lp/packet.hpp
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
var Blob = require('../util/blob.js').Blob;

/**
 * An LpPacket represents an NDNLPv2 packet including header fields an an
 * optional fragment. This is an internal class which the application normally
 * would not use.
 * http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
 * @constructor
 */
var LpPacket = function LpPacket()
{
  this.headerFields_ = [];
  this.fragmentWireEncoding_ = new Blob();
};

exports.LpPacket = LpPacket;

/**
 * Get the fragment wire encoding.
 * @return {Blob} The wire encoding, or an isNull Blob if not specified.
 */
LpPacket.prototype.getFragmentWireEncoding = function()
{
  return this.fragmentWireEncoding_;
};

/**
 * Get the number of header fields. This does not include the fragment.
 * @return {number} The number of header fields.
 */
LpPacket.prototype.countHeaderFields = function()
{
  return this.headerFields_.length;
};

/**
 * Get the header field at the given index.
 * @param {number} index The index, starting from 0. It is an error if index is
 * greater to or equal to countHeaderFields().
 * @return {object} The header field at the index.
 */
LpPacket.prototype.getHeaderField = function(index)
{
  return this.headerFields_[index];
};

/**
 * Remove all header fields and set the fragment to an isNull Blob.
 */
LpPacket.prototype.clear = function()
{
  this.headerFields_ = [];
  this.fragmentWireEncoding_ = new Blob();
};

/**
 * Set the fragment wire encoding.
 * @param {Blob} fragmentWireEncoding The fragment wire encoding or an isNull
 * Blob if not specified.
 */
LpPacket.prototype.setFragmentWireEncoding = function(fragmentWireEncoding)
{
  this.fragmentWireEncoding_ =
    typeof fragmentWireEncoding === 'object' && fragmentWireEncoding instanceof Blob ?
      fragmentWireEncoding : new Blob(fragmentWireEncoding);
};

/**
 * Add a header field. To add the fragment, use setFragmentWireEncoding().
 * @param {object} headerField The header field to add.
 */
LpPacket.prototype.addHeaderField = function(headerField)
{
  this.headerFields_.push(headerField);
};
