/**
 * Copyright (C) 2013-2021 Regents of the University of California.
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
var Crypto = require('../crypto.js'); /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var Tlv = require('./tlv/tlv.js').Tlv; /** @ignore */
var TlvEncoder = require('./tlv/tlv-encoder.js').TlvEncoder; /** @ignore */
var TlvDecoder = require('./tlv/tlv-decoder.js').TlvDecoder; /** @ignore */
var Tlv0_3WireFormat = require('./tlv-0_3-wire-format.js').Tlv0_3WireFormat;

/**
 * A Tlv0_2WireFormat implements the WireFormat interface for encoding and
 * decoding with the NDN-TLV wire format, version 0.2.
 * @constructor
 */
var Tlv0_2WireFormat = function Tlv0_2WireFormat()
{
  // Inherit from Tlv0_3WireFormat.
  Tlv0_3WireFormat.call(this);
};

Tlv0_2WireFormat.prototype = new Tlv0_3WireFormat();
Tlv0_2WireFormat.prototype.name = "Tlv0_2WireFormat";

exports.Tlv0_2WireFormat = Tlv0_2WireFormat;

// Default object.
Tlv0_2WireFormat.instance = null;

/**
 * Encode the interest using NDN-TLV and return a Buffer.
 * @param {Interest} interest The Interest object to encode.
 * @return {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the signed
 * portion. The signed portion starts from the first name component and ends
 * just before the final name component (which is assumed to be a signature for
 * a signed interest).
 */
Tlv0_2WireFormat.prototype.encodeInterest = function(interest)
{
  if (!interest.didSetCanBePrefix_ && !Tlv0_3WireFormat.didCanBePrefixWarning_) {
    console.log
      ("WARNING: The default CanBePrefix will change. See Interest.setDefaultCanBePrefix() for details.");
    Tlv0_3WireFormat.didCanBePrefixWarning_ = true;
  }

  if (interest.hasApplicationParameters())
    // The application has specified a format v0.3 field. As we transition to
    // format v0.3, encode as format v0.3 even though the application default is
    // Tlv0_2WireFormat.
    return Tlv0_3WireFormat.encodeInterestV03_
      (interest, signedPortionBeginOffset, signedPortionEndOffset);

  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (interest.getForwardingHint().size() > 0) {
    if (interest.getSelectedDelegationIndex() != null)
      throw new Error
        ("An Interest may not have a selected delegation when encoding a forwarding hint");
    if (interest.hasLink())
      throw new Error
        ("An Interest may not have a link object when encoding a forwarding hint");

    var forwardingHintSaveLength = encoder.getLength();
    Tlv0_3WireFormat.encodeDelegationSet_(interest.getForwardingHint(), encoder);
    encoder.writeTypeAndLength(
      Tlv.ForwardingHint, encoder.getLength() - forwardingHintSaveLength);
  }

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.SelectedDelegation, interest.getSelectedDelegationIndex());
  var linkWireEncoding = interest.getLinkWireEncoding(this);
  if (!linkWireEncoding.isNull())
    // Encode the entire link as is.
    encoder.writeBuffer(linkWireEncoding.buf());

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds());

  // Encode the Nonce as 4 bytes.
  if (interest.getNonce().isNull() || interest.getNonce().size() == 0)
    // This is the most common case. Generate a nonce.
    encoder.writeBlobTlv(Tlv.Nonce, Crypto.randomBytes(4));
  else if (interest.getNonce().size() < 4) {
    var nonce = Buffer(4);
    // Copy existing nonce bytes.
    interest.getNonce().buf().copy(nonce);

    // Generate random bytes for remaining bytes in the nonce.
    for (var i = interest.getNonce().size(); i < 4; ++i)
      nonce[i] = Crypto.randomBytes(1)[0];

    encoder.writeBlobTlv(Tlv.Nonce, nonce);
  }
  else if (interest.getNonce().size() == 4)
    // Use the nonce as-is.
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf());
  else
    // Truncate.
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf().slice(0, 4));

  Tlv0_3WireFormat.encodeSelectors(interest, encoder);
  var tempOffsets = Tlv0_3WireFormat.encodeName(interest.getName(), encoder);
  var signedPortionBeginOffsetFromBack =
    encoder.getLength() - tempOffsets.signedPortionBeginOffset;
  var signedPortionEndOffsetFromBack =
    encoder.getLength() - tempOffsets.signedPortionEndOffset;

  encoder.writeTypeAndLength(Tlv.Interest, encoder.getLength() - saveLength);
  var signedPortionBeginOffset =
    encoder.getLength() - signedPortionBeginOffsetFromBack;
  var signedPortionEndOffset =
    encoder.getLength() - signedPortionEndOffsetFromBack;

  return { encoding: new Blob(encoder.getOutput(), false),
           signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Get a singleton instance of a Tlv0_2WireFormat.  To always use the
 * preferred version NDN-TLV, you should use TlvWireFormat.get().
 * @return {Tlv0_2WireFormat} The singleton instance.
 */
Tlv0_2WireFormat.get = function()
{
  if (Tlv0_2WireFormat.instance === null)
    Tlv0_2WireFormat.instance = new Tlv0_2WireFormat();
  return Tlv0_2WireFormat.instance;
};
