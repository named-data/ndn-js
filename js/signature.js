/**
 * This class represents an NDN Data Signature object.
 * Copyright (C) 2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('./util/blob.js').Blob;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var KeyLocator = require('./key-locator.js').KeyLocator;
var LOG = require('./log.js').Log.LOG;

/**
 * Create a new Signature with the optional values.
 * @constructor
 */
var Signature = function Signature(witnessOrSignatureObject, signature, digestAlgorithm) 
{
  if (typeof witnessOrSignatureObject === 'object' && 
      witnessOrSignatureObject instanceof Signature) {
    // Copy the values.
    this.keyLocator = new KeyLocator(witnessOrSignatureObject.keyLocator);
    this.signature = witnessOrSignatureObject.signature;
    // witness is deprecated.
    this.witness = witnessOrSignatureObject.witness;
    // digestAlgorithm is deprecated.
    this.digestAlgorithm = witnessOrSignatureObject.digestAlgorithm;
  }
  else {
    this.keyLocator = new KeyLocator();
    this.signature = signature;
    // witness is deprecated.
    this.witness = witnessOrSignatureObject;
    // digestAlgorithm is deprecated.
    this.digestAlgorithm = digestAlgorithm;
  }
};

exports.Signature = Signature;

/**
 * Create a new Signature which is a copy of this object.
 * @returns {Signature} A new object which is a copy of this object.
 */
Signature.prototype.clone = function()
{
  return new Signature(this);
};

/**
 * Get the key locator.
 * @returns {KeyLocator} The key locator.
 */
Signature.prototype.getKeyLocator = function()
{
  return this.keyLocator;
};

/**
 * Get the data packet's signature bytes.
 * @returns {Blob} The signature bytes. If not specified, the value isNull().
 */
Signature.prototype.getSignature = function()
{
  // For backwards-compatibility, leave this.signature as a Buffer but return a Blob.                                        
  return new Blob(this.signature, false);
};

/**
 * @deprecated Use getSignature. This method returns a Buffer which is the former
 * behavior of getSignature, and should only be used while updating your code.
 */
Signature.prototype.getSignatureAsBuffer = function() 
{
  return this.signature;
};

/**
 * Set the key locator to a copy of the given keyLocator.
 * @param {KeyLocator} keyLocator The KeyLocator to copy.
 */
Signature.prototype.setKeyLocator = function(keyLocator)
{
  this.keyLocator = typeof keyLocator === 'object' && keyLocator instanceof KeyLocator ?
                    new KeyLocator(keyLocator) : new KeyLocator();
};
  
/**
 * Set the data packet's signature bytes.
 * @param {Blob} signature
 */
Signature.prototype.setSignature = function(signature)
{
  if (signature == null)
    this.signature = null;
  else if (typeof signature === 'object' && signature instanceof Blob)
    this.signature = new Buffer(signature.buf());
  else
    this.signature = new Buffer(signature);
};

Signature.prototype.from_ndnb = function(decoder) 
{
  decoder.readElementStartDTag(this.getElementLabel());
    
  if (LOG > 4) console.log('STARTED DECODING SIGNATURE');
    
  if (decoder.peekDTag(NDNProtocolDTags.DigestAlgorithm)) {
    if (LOG > 4) console.log('DIGIEST ALGORITHM FOUND');
    this.digestAlgorithm = decoder.readUTF8DTagElement(NDNProtocolDTags.DigestAlgorithm); 
  }
  if (decoder.peekDTag(NDNProtocolDTags.Witness)) {
    if (LOG > 4) console.log('WITNESS FOUND');
    this.witness = decoder.readBinaryDTagElement(NDNProtocolDTags.Witness); 
  }
    
  //FORCE TO READ A SIGNATURE

  if (LOG > 4) console.log('SIGNATURE FOUND');
  this.signature = decoder.readBinaryDTagElement(NDNProtocolDTags.SignatureBits);

  decoder.readElementClose();
};

Signature.prototype.to_ndnb = function(encoder) 
{      
  if (!this.validate())
    throw new Error("Cannot encode: field values missing.");
  
  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (null != this.digestAlgorithm && !this.digestAlgorithm.equals(NDNDigestHelper.DEFAULT_DIGEST_ALGORITHM))
    encoder.writeDTagElement(NDNProtocolDTags.DigestAlgorithm, OIDLookup.getDigestOID(this.DigestAlgorithm));
  
  if (null != this.witness)
    // needs to handle null witness
    encoder.writeDTagElement(NDNProtocolDTags.Witness, this.witness);

  encoder.writeDTagElement(NDNProtocolDTags.SignatureBits, this.signature);

  encoder.writeElementClose();       
};

Signature.prototype.getElementLabel = function() { return NDNProtocolDTags.Signature; };

Signature.prototype.validate = function() 
{
  return null != this.signature;
};
