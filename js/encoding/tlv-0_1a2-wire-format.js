/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

var crypto = require('crypto');
var Tlv = require('./tlv/tlv.js').Tlv;
var TlvEncoder = require('./tlv/tlv-encoder.js').TlvEncoder;
var TlvDecoder = require('./tlv/tlv-decoder.js').TlvDecoder;
var WireFormat = require('./wire-format.js').WireFormat;
var Exclude = require('../exclude.js').Exclude;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;
var DecodingException = require('./decoding-exception.js').DecodingException;

/**
 * A Tlv0_1a2WireFormat implements the WireFormat interface for encoding and 
 * decoding with the NDN-TLV wire format, version 0.1a2
 * @constructor
 */
var Tlv0_1a2WireFormat = function Tlv0_1a2WireFormat() 
{
  // Inherit from WireFormat.
  WireFormat.call(this);
};

Tlv0_1a2WireFormat.prototype = new WireFormat();
Tlv0_1a2WireFormat.prototype.name = "Tlv0_1a2WireFormat";

exports.Tlv0_1a2WireFormat = Tlv0_1a2WireFormat;

// Default object.
Tlv0_1a2WireFormat.instance = null;

/**
 * Encode the interest using NDN-TLV and return a Buffer.
 * @param {Interest} interest The Interest object to encode.
 * @returns {Buffer} A buffer containing the encoding.
 */
Tlv0_1a2WireFormat.prototype.encodeInterest = function(interest) 
{
  var encoder = new TlvEncoder();
  var saveLength = encoder.getLength();
  
  // Encode backwards.
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds());
  encoder.writeOptionalNonNegativeIntegerTlv(Tlv.Scope, interest.getScope());
  
  // Encode the Nonce as 4 bytes.
  if (interest.getNonce() == null || interest.getNonce().length == 0)
    // This is the most common case. Generate a nonce.
    encoder.writeBlobTlv(Tlv.Nonce, crypto.randomBytes(4));
  else if (interest.getNonce().length < 4) {
    var nonce = Buffer(4);
    if (interest.getNonce().length > 0)
      // Copy existing nonce bytes.
      interest.getNonce().copy(nonce);

    // Generate random bytes for remainig bytes in the nonce.
    for (var i = interest.getNonce().length; i < 44; ++i)
      nonce[i] = crypto.randomBytes(1)[0];

    encoder.writeBlobTlv(Tlv.Nonce, nonce);
  }
  else if (interest.getNonce().length == 4)
    // Use the nonce as-is.
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce());
  else
    // Truncate.
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().slice(0, 4));
  
  Tlv0_1a2WireFormat.encodeSelectors(interest, encoder);
  Tlv0_1a2WireFormat.encodeName(interest.getName(), encoder);
  
  encoder.writeTypeAndLength(Tlv.Interest, encoder.getLength() - saveLength);
      
  //return Blob(encoder.getOutput());
  return encoder.getOutput();
};

/**
 * Decode input as an NDN-TLV interest and set the fields of the interest 
 * object.  
 * @param {Interest} interest The Interest object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 */
Tlv0_1a2WireFormat.prototype.decodeInterest = function(interest, input) 
{
  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
  Tlv0_1a2WireFormat.decodeName(interest.getName(), decoder);
  if (decoder.peekType(Tlv.Selectors, endOffset))
    Tlv0_1a2WireFormat.decodeSelectors(interest, decoder);
  // Require a Nonce, but don't force it to be 4 bytes.
  var nonce = decoder.readBlobTlv(Tlv.Nonce);
  interest.setScope(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.Scope, endOffset));
  interest.setInterestLifetimeMilliseconds
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.InterestLifetime, endOffset));

  // Set the nonce last because setting other interest fields clears it.
  interest.setNonce(nonce);

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Get a singleton instance of a Tlv1_0a2WireFormat.  To always use the
 * preferred version NDN-TLV, you should use TlvWireFormat.get().
 * @returns {Tlv0_1a2WireFormat} The singleton instance.
 */
Tlv0_1a2WireFormat.get = function()
{
  if (Tlv0_1a2WireFormat.instance === null)
    Tlv0_1a2WireFormat.instance = new Tlv0_1a2WireFormat();
  return Tlv0_1a2WireFormat.instance;
};

Tlv0_1a2WireFormat.encodeName = function(name, encoder)
{
  var saveLength = encoder.getLength();

  // Encode the components backwards.
  for (var i = name.size() - 1; i >= 0; --i)
    encoder.writeBlobTlv(Tlv.NameComponent, name.get(i).getValue());

  encoder.writeTypeAndLength(Tlv.Name, encoder.getLength() - saveLength);
};
        
Tlv0_1a2WireFormat.decodeName = function(name, decoder)
{
  name.clear();
  
  var endOffset = decoder.readNestedTlvsStart(Tlv.Name);      
  while (decoder.getOffset() < endOffset)
      name.append(decoder.readBlobTlv(Tlv.NameComponent));

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode the interest selectors.  If no selectors are written, do not output a 
 * Selectors TLV.
 */
Tlv0_1a2WireFormat.encodeSelectors = function(interest, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (interest.getMustBeFresh())
    encoder.writeTypeAndLength(Tlv.MustBeFresh, 0);
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.ChildSelector, interest.getChildSelector());
  if (interest.getExclude().size() > 0)
    Tlv0_1a2WireFormat.encodeExclude(interest.getExclude(), encoder);
  if (interest.getKeyLocator().getType() != null)
    Tlv0_1a2WireFormat.encodeKeyLocator(interest.getKeyLocator(), encoder);
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents());
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MinSuffixComponents, interest.getMinSuffixComponents());

  // Only output the type and length if values were written.
  if (encoder.getLength() != saveLength)
    encoder.writeTypeAndLength(Tlv.Selectors, encoder.getLength() - saveLength);
};

Tlv0_1a2WireFormat.decodeSelectors = function(interest, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Selectors);

  interest.setMinSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MinSuffixComponents, endOffset));
  interest.setMaxSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MaxSuffixComponents, endOffset));

  if (decoder.peekType(Tlv.KeyLocator, endOffset))
    Tlv0_1a2WireFormat.decodeKeyLocator(interest.getKeyLocator(), decoder);
  else
    interest.getKeyLocator().clear();

  if (decoder.peekType(Tlv.Exclude, endOffset))
    Tlv0_1a2WireFormat.decodeExclude(interest.getExclude(), decoder);
  else
    interest.getExclude().clear();

  interest.setChildSelector(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ChildSelector, endOffset));
  interest.setMustBeFresh(decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset));

  decoder.finishNestedTlvs(endOffset);
};
  
Tlv0_1a2WireFormat.encodeExclude = function(exclude, encoder)
{
  var saveLength = encoder.getLength();

  // TODO: Do we want to order the components (except for ANY)?
  // Encode the entries backwards.
  for (var i = exclude.size() - 1; i >= 0; --i) {
    var entry = exclude.get(i);

    if (entry == Exclude.ANY)
      encoder.writeTypeAndLength(Tlv.Any, 0);
    else
      encoder.writeBlobTlv(Tlv.NameComponent, entry.getValue());
  }
  
  encoder.writeTypeAndLength(Tlv.Exclude, encoder.getLength() - saveLength);
};
  
Tlv0_1a2WireFormat.decodeExclude = function(exclude, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Exclude);

  exclude.clear();
  while (true) {
    if (decoder.peekType(Tlv.NameComponent, endOffset))
      exclude.appendComponent(decoder.readBlobTlv(Tlv.NameComponent));
    else if (decoder.readBooleanTlv(Tlv.Any, endOffset))
      exclude.appendAny();
    else
      // Else no more entries.
      break;
  }
  
  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1a2WireFormat.encodeKeyLocator = function(keyLocator, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (keyLocator.getType() != null) {
    if (keyLocator.getType() == KeyLocatorType.KEYNAME)
      Tlv0_1a2WireFormat.encodeName(keyLocator.getKeyName(), encoder);
    else if (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
             keyLocator.getKeyData().length > 0)
      encoder.writeBlobTlv(Tlv.KeyLocatorDigest, keyLocator.getKeyData());
    else
      throw new Error("Unrecognized KeyLocatorType " + keyLocator.getType());
  }
  
  encoder.writeTypeAndLength(Tlv.KeyLocator, encoder.getLength() - saveLength);
};

Tlv0_1a2WireFormat.decodeKeyLocator = function(keyLocator, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.KeyLocator);

  keyLocator.clear();

  if (decoder.getOffset() == endOffset)
    // The KeyLocator is omitted, so leave the fields as none.
    return;

  if (decoder.peekType(Tlv.Name, endOffset)) {
    // KeyLocator is a Name.
    keyLocator.setType(KeyLocatorType.KEYNAME);
    Tlv0_1a2WireFormat.decodeName(keyLocator.getKeyName(), decoder);
  }
  else if (decoder.peekType(Tlv.KeyLocatorDigest, endOffset)) {
    // KeyLocator is a KeyLocatorDigest.
    keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    keyLocator.setKeyData(decoder.readBlobTlv(Tlv.KeyLocatorDigest));
  }
  else
    throw new DecodingException
      ("decodeKeyLocator: Unrecognized key locator type");

  decoder.finishNestedTlvs(endOffset);
};
