/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * This class represents Interest Objects
 */

var Blob = require('./util/blob.js').Blob;
var Name = require('./name.js').Name;
var Exclude = require('./exclude.js').Exclude;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;
var KeyLocator = require('./key-locator.js').KeyLocator;
var WireFormat = require('./encoding/wire-format.js').WireFormat;

/**
 * Create a new Interest with the optional values.
 * 
 * @constructor
 * @param {Name|Interest} nameOrInterest If this is an Interest, copy values from the interest and ignore the
 * other arguments.  Otherwise this is the optional name for the new Interest.
 * @param {number} minSuffixComponents
 * @param {number} maxSuffixComponents
 * @param {Buffer} publisherPublicKeyDigest
 * @param {Exclude} exclude
 * @param {number} childSelector
 * @param {number} answerOriginKind
 * @param {number} scope
 * @param {number} interestLifetimeMilliseconds in milliseconds
 * @param {Buffer} nonce
 */
var Interest = function Interest
   (nameOrInterest, minSuffixComponents, maxSuffixComponents, publisherPublicKeyDigest, exclude, 
    childSelector, answerOriginKind, scope, interestLifetimeMilliseconds, nonce) 
{
  if (typeof nameOrInterest === 'object' && nameOrInterest instanceof Interest) {
    // Special case: this is a copy constructor.  Ignore all but the first argument.
    var interest = nameOrInterest;
    if (interest.name)
      // Copy the name.
      this.name = new Name(interest.name);
    this.maxSuffixComponents = interest.maxSuffixComponents;
    this.minSuffixComponents = interest.minSuffixComponents;

    this.publisherPublicKeyDigest = interest.publisherPublicKeyDigest;
    this.keyLocator = new KeyLocator(interest.keyLocator);
    this.exclude = new Exclude(interest.exclude);
    this.childSelector = interest.childSelector;
    this.answerOriginKind = interest.answerOriginKind;
    this.scope = interest.scope;
    this.interestLifetime = interest.interestLifetime;
    if (interest.nonce)
      // Copy.
      this.nonce = new Buffer(interest.nonce);    
  }  
  else {
    this.name = typeof nameOrInterest === 'object' && nameOrInterest instanceof Name ?
                new Name(nameOrInterest) : new Name();
    this.maxSuffixComponents = maxSuffixComponents;
    this.minSuffixComponents = minSuffixComponents;

    this.publisherPublicKeyDigest = publisherPublicKeyDigest;
    this.keyLocator = new KeyLocator();
    this.exclude = typeof exclude === 'object' && exclude instanceof Exclude ?
                   new Exclude(exclude) : new Exclude();
    this.childSelector = childSelector;
    this.answerOriginKind = answerOriginKind;
    this.scope = scope;
    this.interestLifetime = interestLifetimeMilliseconds;
    if (nonce)
      // Copy and make sure it is a Buffer.
      this.nonce = new Buffer(nonce);
  }
};

exports.Interest = Interest;

Interest.RECURSIVE_POSTFIX = "*";

Interest.CHILD_SELECTOR_LEFT = 0;
Interest.CHILD_SELECTOR_RIGHT = 1;

Interest.ANSWER_NO_CONTENT_STORE = 0;
Interest.ANSWER_CONTENT_STORE = 1;
Interest.ANSWER_GENERATED = 2;
Interest.ANSWER_STALE = 4;    // Stale answer OK
Interest.MARK_STALE = 16;    // Must have scope 0.  Michael calls this a "hack"

Interest.DEFAULT_ANSWER_ORIGIN_KIND = Interest.ANSWER_CONTENT_STORE | Interest.ANSWER_GENERATED;

/**
 * Return true if this.name.match(name) and the name conforms to the interest selectors.
 * @param {Name} name
 * @returns {boolean}
 */
Interest.prototype.matchesName = function(/*Name*/ name) 
{
  if (!this.name.match(name))
    return false;
    
  if (this.minSuffixComponents != null &&
      // Add 1 for the implicit digest.
      !(name.size() + 1 - this.name.size() >= this.minSuffixComponents))
    return false;
  if (this.maxSuffixComponents != null &&
      // Add 1 for the implicit digest.
      !(name.size() + 1 - this.name.size() <= this.maxSuffixComponents))
    return false;
  if (this.exclude != null && name.size() > this.name.size() &&
      this.exclude.matches(name.components[this.name.size()]))
    return false;
    
  return true;
};

/**
 * @deprecated Use matchesName.
 */
Interest.prototype.matches_name = function(/*Name*/ name) 
{
  return this.matchesName(name);
};

/**
 * Return a new Interest with the same fields as this Interest.  
 */
Interest.prototype.clone = function() 
{
  return new Interest
     (this.name, this.minSuffixComponents, this.maxSuffixComponents, 
      this.publisherPublicKeyDigest, this.exclude, this.childSelector, this.answerOriginKind, 
      this.scope, this.interestLifetime, this.nonce);
};

/**
 * Get the interest Name.
 * @returns {Name} The name.  The name size() may be 0 if not specified.
 */
Interest.prototype.getName = function() { return this.name; };

/**
 * Get the min suffix components.
 * @returns number} The min suffix components, or null if not specified.
 */
Interest.prototype.getMinSuffixComponents = function() 
{ 
  return this.minSuffixComponents; 
};

/**
 * Get the max suffix components.
 * @returns {number} The max suffix components, or null if not specified.
 */
Interest.prototype.getMaxSuffixComponents = function() 
{ 
  return this.maxSuffixComponents; 
};

/**
 * Get the interest key locator.
 * @returns {KeyLocator} The key locator. If its getType() is null, 
 * then the key locator is not specified.
 */
Interest.prototype.getKeyLocator = function() 
{ 
  return this.keyLocator; 
};

/**
 * Get the exclude object.
 * @returns {Exclude} The exclude object. If the exclude size() is zero, then
 * the exclude is not specified.
 */
Interest.prototype.getExclude = function() { return this.exclude; };

/**
 * Get the child selector.
 * @returns {number} The child selector, or null if not specified.
 */
Interest.prototype.getChildSelector = function() 
{ 
  return this.childSelector; 
};

/**
 * @deprecated Use getMustBeFresh.
 */
Interest.prototype.getAnswerOriginKind = function() 
{ 
  return this.answerOriginKind; 
};
  
  /**
   * Return true if the content must be fresh.
   * @return true if must be fresh, otherwise false.
   */
  
/**
 * Get the must be fresh flag. If not specified, the default is true.
 * @returns {boolean} The must be fresh flag.
 */
Interest.prototype.getMustBeFresh = function() 
{
  if (this.answerOriginKind == null || this.answerOriginKind < 0)
    return true;
  else
    return (this.answerOriginKind & Interest.ANSWER_STALE) == 0;
};

/**
 * Return the nonce value from the incoming interest.  If you change any of the 
 * fields in this Interest object, then the nonce value is cleared.
 * @returns {Buffer} The nonce, or null if not specified.
 */
Interest.prototype.getNonce = function() { return this.nonce; };

/**
 * Get the interest scope.
 * @returns {number} The scope, or null if not specified.
 */
Interest.prototype.getScope = function() { return this.scope; };

/**
 * Get the interest lifetime.
 * @returns {number} The interest lifetime in milliseconds, or null if not 
 * specified.
 */
Interest.prototype.getInterestLifetimeMilliseconds = function() 
{ 
  return this.interestLifetime; 
};

Interest.prototype.setName = function(name)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;
  
  this.name = typeof name === 'object' && name instanceof Interest ?
              new Name(name) : new Name();
};
                
Interest.prototype.setMinSuffixComponents = function(minSuffixComponents)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;
  
  this.minSuffixComponents = minSuffixComponents;
};

Interest.prototype.setMaxSuffixComponents = function(maxSuffixComponents)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;
  
  this.maxSuffixComponents = maxSuffixComponents;
};

/**
 * Set this interest to use a copy of the given exclude object. Note: You can 
 * also change this interest's exclude object modifying the object from 
 * getExclude().
 * @param {Exclude} exclude The exlcude object that is copied.
 */
Interest.prototype.setExclude = function(exclude)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;
  
  this.exclude = typeof exclude === 'object' && exclude instanceof Exclude ?
                 new Exclude(exclude) : new Exclude();
};

Interest.prototype.setChildSelector = function(childSelector)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;
  
  this.childSelector = childSelector;
};

/**
 * @deprecated Use setMustBeFresh.
 */
Interest.prototype.setAnswerOriginKind = function(answerOriginKind)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;
  
  this.answerOriginKind = answerOriginKind;
};

/**
 * Set the MustBeFresh flag.
 * @param {boolean} mustBeFresh True if the content must be fresh, otherwise false.
 */
Interest.prototype.setMustBeFresh = function(mustBeFresh)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;
  
  if (this.answerOriginKind == null || this.answerOriginKind < 0) {
    // It is is already the default where MustBeFresh is true. 
    if (!mustBeFresh)
      // Set answerOriginKind_ so that getMustBeFresh returns false.
      this.answerOriginKind = Interest.ANSWER_STALE; 
  }
  else {
    if (mustBeFresh)
      // Clear the stale bit.
      this.answerOriginKind &= ~Interest.ANSWER_STALE;
    else
      // Set the stale bit.
      this.answerOriginKind |= Interest.ANSWER_STALE;
  }
};

Interest.prototype.setScope = function(scope)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;
  
  this.scope = scope;
};

Interest.prototype.setInterestLifetimeMilliseconds = function(interestLifetimeMilliseconds)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;
  
  this.interestLifetime = interestLifetimeMilliseconds;
};

/**
 * @deprecated You should let the wire encoder generate a random nonce 
 * internally before sending the interest.
 */
Interest.prototype.setNonce = function(nonce)
{
  if (nonce)
    // Copy and make sure it is a Buffer.
    this.nonce = new Buffer(nonce);
  else
    this.nonce = null;
};

/**
 * Encode the name according to the "NDN URI Scheme".  If there are interest selectors, append "?" and
 * added the selectors as a query string.  For example "/test/name?ndn.ChildSelector=1".
 * @returns {string} The URI string.
 */
Interest.prototype.toUri = function() 
{  
  var selectors = "";
  
  if (this.minSuffixComponents != null)
    selectors += "&ndn.MinSuffixComponents=" + this.minSuffixComponents;
  if (this.maxSuffixComponents != null)
    selectors += "&ndn.MaxSuffixComponents=" + this.maxSuffixComponents;
  if (this.childSelector != null)
    selectors += "&ndn.ChildSelector=" + this.childSelector;
  if (this.answerOriginKind != null)
    selectors += "&ndn.AnswerOriginKind=" + this.answerOriginKind;
  if (this.scope != null)
    selectors += "&ndn.Scope=" + this.scope;
  if (this.interestLifetime != null)
    selectors += "&ndn.InterestLifetime=" + this.interestLifetime;
  if (this.publisherPublicKeyDigest != null)
    selectors += "&ndn.PublisherPublicKeyDigest=" + Name.toEscapedString(this.publisherPublicKeyDigest.publisherPublicKeyDigest);
  if (this.nonce != null)
    selectors += "&ndn.Nonce=" + Name.toEscapedString(this.nonce);
  if (this.exclude != null && this.exclude.size() > 0)
    selectors += "&ndn.Exclude=" + this.exclude.toUri();

  var result = this.name.toUri();
  if (selectors != "")
    // Replace the first & with ?.
    result += "?" + selectors.substr(1);
  
  return result;
};

/**
 * Encode this Interest for a particular wire format.
 * @param {a subclass of WireFormat} wireFormat (optional) A WireFormat object 
 * used to encode this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @returns {Blob} The encoded buffer in a Blob object.
 */
Interest.prototype.wireEncode = function(wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return wireFormat.encodeInterest(this);
};

/**
 * Decode the input using a particular wire format and update this Interest.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {a subclass of WireFormat} wireFormat (optional) A WireFormat object 
 * used to decode this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Interest.prototype.wireDecode = function(input, wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ? 
                     input.buf() : input;
  wireFormat.decodeInterest(this, decodeBuffer);
};

// Since binary-xml-wire-format.js includes this file, put these at the bottom 
// to avoid problems with cycles of require.
var BinaryXmlWireFormat = require('./encoding/binary-xml-wire-format.js').BinaryXmlWireFormat;

/**
 * @deprecated Use wireDecode(input, BinaryXmlWireFormat.get()).
 */
Interest.prototype.from_ndnb = function(/*XMLDecoder*/ decoder) 
{
  BinaryXmlWireFormat.decodeInterest(this, decoder);
};

/**
 * @deprecated Use wireEncode(BinaryXmlWireFormat.get()).
 */
Interest.prototype.to_ndnb = function(/*XMLEncoder*/ encoder) 
{
  BinaryXmlWireFormat.encodeInterest(this, encoder);
};

/**
 * @deprecated Use wireEncode.  If you need binary XML, use
 * wireEncode(BinaryXmlWireFormat.get()).
 */
Interest.prototype.encode = function(wireFormat) 
{
  return this.wireEncode(BinaryXmlWireFormat.get()).buf();
};

/**
 * @deprecated Use wireDecode.  If you need binary XML, use
 * wireDecode(input, BinaryXmlWireFormat.get()).
 */
Interest.prototype.decode = function(input, wireFormat) 
{
  this.wireDecode(input, BinaryXmlWireFormat.get())
};
