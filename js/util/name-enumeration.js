/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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

var DataUtils = require('../encoding/data-utils.js').DataUtils;
var BinaryXMLDecoder = require('../encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./ndn-protoco-id-tags.js').NDNProtocolDTags;
var Name = require('../name.js').Name;

/**
 * Create a context for getting the response from the name enumeration command, as needed by getComponents.
 * (To do name enumeration, call the static method NameEnumeration.getComponents.)
 * @param {Face} face The Face object for using expressInterest.
 * @param {function} onComponents The onComponents callback given to getComponents.
 */
var NameEnumeration = function NameEnumeration(face, onComponents)
{
  this.face = face;
  this.onComponents = onComponents;
  this.contentParts = [];

  var self = this;
  this.onData = function(interest, data) { self.processData(data); };
  this.onTimeout = function(interest) { self.processTimeout(); };
};

exports.NameEnumeration = NameEnumeration;

/**
 * Use the name enumeration protocol to get the child components of the name prefix.
 * @param {Face} face The Face object for using expressInterest.
 * @param {Name} name The name prefix for finding the child components.
 * @param {function} onComponents On getting the response, this calls onComponents(components) where
 * components is an array of Buffer name components.  If there is no response, this calls onComponents(null).
 */
NameEnumeration.getComponents = function(face, prefix, onComponents)
{
  var command = new Name(prefix);
  // Add %C1.E.be
  command.add([0xc1, 0x2e, 0x45, 0x2e, 0x62, 0x65])

  var enumeration = new NameEnumeration(face, onComponents);
  face.expressInterest(command, enumeration.onData, enumeration.onTimeout);
};

/**
 * Parse the response from the name enumeration command and call this.onComponents.
 * @param {Data} data
 */
NameEnumeration.prototype.processData = function(data)
{
  try {
    if (!NameEnumeration.endsWithSegmentNumber(data.getName()))
      // We don't expect a name without a segment number.  Treat it as a bad packet.
      this.onComponents(null);
    else {
      var segmentNumber = data.getName().get(-1).toSegment();

      // Each time we get a segment, we put it in contentParts, so its length follows the segment numbers.
      var expectedSegmentNumber = this.contentParts.length;
      if (segmentNumber != expectedSegmentNumber)
        // Try again to get the expected segment.  This also includes the case where the first segment is not segment 0.
        this.face.expressInterest
          (data.getName().getPrefix(-1).appendSegment(expectedSegmentNumber), this.onData, this.onTimeout);
      else {
        // Save the content and check if we are finished.
        this.contentParts.push(data.getContent().buf());

        if (data.getMetaInfo() != null && data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
          var finalSegmentNumber = data.getMetaInfo().getFinalBlockId().toSegment();
          if (segmentNumber == finalSegmentNumber) {
            // We are finished.  Parse and return the result.
            this.onComponents(NameEnumeration.parseComponents(Buffer.concat(this.contentParts)));
            return;
          }
        }

        // Fetch the next segment.
        this.face.expressInterest
          (data.getName().getPrefix(-1).appendSegment(expectedSegmentNumber + 1), this.onData, this.onTimeout);
      }
    }
  } catch (ex) {
    console.log("NameEnumeration: ignoring exception: " + ex);
  }
};

/**
 * Just call onComponents(null).
 */
NameEnumeration.prototype.processTimeout = function()
{
  try {
    this.onComponents(null);
  } catch (ex) {
    console.log("NameEnumeration: ignoring exception: " + ex);
  }
};

/**
 * Parse the content as a name enumeration response and return an array of components.  This makes a copy of the component.
 * @param {Buffer} content The content to parse.
 * @returns {Array<Buffer>} The array of components.
 */
NameEnumeration.parseComponents = function(content)
{
  var components = [];
  var decoder = new BinaryXMLDecoder(content);

  decoder.readElementStartDTag(NDNProtocolDTags.Collection);

  while (decoder.peekDTag(NDNProtocolDTags.Link)) {
    decoder.readElementStartDTag(NDNProtocolDTags.Link);
    decoder.readElementStartDTag(NDNProtocolDTags.Name);

    components.push(new Buffer(decoder.readBinaryDTagElement(NDNProtocolDTags.Component)));

    decoder.readElementClose();
    decoder.readElementClose();
  }

  decoder.readElementClose();
  return components;
};

/**
 * Check if the last component in the name is a segment number.
 * TODO: Move to Name class.
 * @param {Name} name
 * @returns {Boolean} True if the name ends with a segment number, otherwise false.
 */
NameEnumeration.endsWithSegmentNumber = function(name) {
  return name.size() >= 1 &&
         name.get(-1).getValue().size() >= 1 &&
         name.get(-1).getValue().buf()[0] == 0;
};
