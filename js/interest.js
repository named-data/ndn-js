/**
 * This class represents Interest Objects
 * Copyright (C) 2013-2015 Regents of the University of California.
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

var Blob = require('./util/blob.js').Blob;
var SignedBlob = require('./util/signed-blob.js').SignedBlob;
var ChangeCounter = require('./util/change-counter.js').ChangeCounter;
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
 */
var Interest = function Interest
   (nameOrInterest, minSuffixComponents, maxSuffixComponents, publisherPublicKeyDigest, exclude,
    childSelector, answerOriginKind, scope, interestLifetimeMilliseconds, nonce)
{
  if (typeof nameOrInterest === 'object' && nameOrInterest instanceof Interest) {
    // Special case: this is a copy constructor.  Ignore all but the first argument.
    var interest = nameOrInterest;
    // Copy the name.
    this.name_ = new ChangeCounter(new Name(interest.getName()));
    this.maxSuffixComponents_ = interest.maxSuffixComponents_;
    this.minSuffixComponents_ = interest.minSuffixComponents_;

    this.publisherPublicKeyDigest_ = interest.publisherPublicKeyDigest_;
    this.keyLocator_ = new ChangeCounter(new KeyLocator(interest.getKeyLocator()));
    this.exclude_ = new ChangeCounter(new Exclude(interest.getExclude()));
    this.childSelector_ = interest.childSelector_;
    this.answerOriginKind_ = interest.answerOriginKind_;
    this.scope_ = interest.scope_;
    this.interestLifetimeMilliseconds_ = interest.interestLifetimeMilliseconds_;
    this.nonce_ = interest.nonce_;
    this.defaultWireEncoding_ = interest.getDefaultWireEncoding();
    this.defaultWireEncodingFormat_ = interest.defaultWireEncodingFormat_;
  }
  else {
    this.name_ = new ChangeCounter(typeof nameOrInterest === 'object' &&
                                   nameOrInterest instanceof Name ?
      new Name(nameOrInterest) : new Name());
    this.maxSuffixComponents_ = maxSuffixComponents;
    this.minSuffixComponents_ = minSuffixComponents;

    this.publisherPublicKeyDigest_ = publisherPublicKeyDigest;
    this.keyLocator_ = new ChangeCounter(new KeyLocator());
    this.exclude_ = new ChangeCounter(typeof exclude === 'object' && exclude instanceof Exclude ?
      new Exclude(exclude) : new Exclude());
    this.childSelector_ = childSelector;
    this.answerOriginKind_ = answerOriginKind;
    this.scope_ = scope;
    this.interestLifetimeMilliseconds_ = interestLifetimeMilliseconds;
    this.nonce_ = typeof nonce === 'object' && nonce instanceof Blob ?
      nonce : new Blob(nonce, true);
    this.defaultWireEncoding_ = new SignedBlob();
    this.defaultWireEncodingFormat_ = null;
  }

  this.getNonceChangeCount_ = 0;
  this.getDefaultWireEncodingChangeCount_ = 0;
  this.changeCount_ = 0;
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
 * Check if this interest's name matches the given name (using Name.match) and
 * the given name also conforms to the interest selectors.
 * @param {Name} name The name to check.
 * @returns {boolean} True if the name and interest selectors match, False otherwise.
 */
Interest.prototype.matchesName = function(/*Name*/ name)
{
  if (!this.getName().match(name))
    return false;

  if (this.minSuffixComponents_ != null &&
      // Add 1 for the implicit digest.
      !(name.size() + 1 - this.getName().size() >= this.minSuffixComponents_))
    return false;
  if (this.maxSuffixComponents_ != null &&
      // Add 1 for the implicit digest.
      !(name.size() + 1 - this.getName().size() <= this.maxSuffixComponents_))
    return false;
  if (this.getExclude() != null && name.size() > this.getName().size() &&
      this.getExclude().matches(name.get(this.getName().size())))
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
  return new Interest(this);
};

/**
 * Get the interest Name.
 * @returns {Name} The name.  The name size() may be 0 if not specified.
 */
Interest.prototype.getName = function() { return this.name_.get(); };

/**
 * Get the min suffix components.
 * @returns number} The min suffix components, or null if not specified.
 */
Interest.prototype.getMinSuffixComponents = function()
{
  return this.minSuffixComponents_;
};

/**
 * Get the max suffix components.
 * @returns {number} The max suffix components, or null if not specified.
 */
Interest.prototype.getMaxSuffixComponents = function()
{
  return this.maxSuffixComponents_;
};

/**
 * Get the interest key locator.
 * @returns {KeyLocator} The key locator. If its getType() is null,
 * then the key locator is not specified.
 */
Interest.prototype.getKeyLocator = function()
{
  return this.keyLocator_.get();
};

/**
 * Get the exclude object.
 * @returns {Exclude} The exclude object. If the exclude size() is zero, then
 * the exclude is not specified.
 */
Interest.prototype.getExclude = function() { return this.exclude_.get(); };

/**
 * Get the child selector.
 * @returns {number} The child selector, or null if not specified.
 */
Interest.prototype.getChildSelector = function()
{
  return this.childSelector_;
};

/**
 * @deprecated Use getMustBeFresh.
 */
Interest.prototype.getAnswerOriginKind = function()
{
  if (!WireFormat.ENABLE_NDNX)
    throw new Error
      ("getAnswerOriginKind is for NDNx and is deprecated. To enable while you upgrade your code to use NFD's getMustBeFresh(), set WireFormat.ENABLE_NDNX = true");

  return this.answerOriginKind_;
};

/**
 * Get the must be fresh flag. If not specified, the default is true.
 * @returns {boolean} The must be fresh flag.
 */
Interest.prototype.getMustBeFresh = function()
{
  if (this.answerOriginKind_ == null || this.answerOriginKind_ < 0)
    return true;
  else
    return (this.answerOriginKind_ & Interest.ANSWER_STALE) == 0;
};

/**
 * Return the nonce value from the incoming interest.  If you change any of the
 * fields in this Interest object, then the nonce value is cleared.
 * @returns {Blob} The nonce. If not specified, the value isNull().
 */
Interest.prototype.getNonce = function()
{
  if (this.getNonceChangeCount_ != this.getChangeCount()) {
    // The values have changed, so the existing nonce is invalidated.
    this.nonce_ = new Blob();
    this.getNonceChangeCount_ = this.getChangeCount();
  }

  return this.nonce_;
};

/**
 * @deprecated Use getNonce. This method returns a Buffer which is the former
 * behavior of getNonce, and should only be used while updating your code.
 */
Interest.prototype.getNonceAsBuffer = function()
{
  return this.getNonce().buf();
};

/**
 * Get the interest scope.
 * @returns {number} The scope, or null if not specified.
 */
Interest.prototype.getScope = function() { return this.scope_; };

/**
 * Get the interest lifetime.
 * @returns {number} The interest lifetime in milliseconds, or null if not
 * specified.
 */
Interest.prototype.getInterestLifetimeMilliseconds = function()
{
  return this.interestLifetimeMilliseconds_;
};

/**
 * Return the default wire encoding, which was encoded with
 * getDefaultWireEncodingFormat().
 * @returns {SignedBlob} The default wire encoding, whose isNull() may be true
 * if there is no default wire encoding.
 */
Interest.prototype.getDefaultWireEncoding = function()
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
 * @returns {WireFormat} The WireFormat, which is only meaningful if the
 * getDefaultWireEncoding() is not isNull().
 */
Interest.prototype.getDefaultWireEncodingFormat = function()
{
  return this.defaultWireEncodingFormat_;
};

/**
 * Set the interest name.
 * Note: You can also call getName and change the name values directly.
 * @param {Name} name The interest name. This makes a copy of the name.
 * @returns {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setName = function(name)
{
  this.name_.set(typeof name === 'object' && name instanceof Name ?
    new Name(name) : new Name());
  ++this.changeCount_;
  return this;
};

/**
 * Set the min suffix components count.
 * @param {number} minSuffixComponents The min suffix components count. If not
 * specified, set to undefined.
 * @returns {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setMinSuffixComponents = function(minSuffixComponents)
{
  this.minSuffixComponents_ = minSuffixComponents;
  ++this.changeCount_;
  return this;
};

/**
 * Set the max suffix components count.
 * @param {number} maxSuffixComponents The max suffix components count. If not
 * specified, set to undefined.
 * @returns {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setMaxSuffixComponents = function(maxSuffixComponents)
{
  this.maxSuffixComponents_ = maxSuffixComponents;
  ++this.changeCount_;
  return this;
};

/**
 * Set this interest to use a copy of the given exclude object. Note: You can
 * also call getExclude and change the exclude entries directly.
 * @param {Exclude} exclude The Exclude object. This makes a copy of the object.
 * If no exclude is specified, set to a new default Exclude(), or to an Exclude
 * with size() 0.
 * @returns {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setExclude = function(exclude)
{
  this.exclude_.set(typeof exclude === 'object' && exclude instanceof Exclude ?
    new Exclude(exclude) : new Exclude());
  ++this.changeCount_;
  return this;
};

/**
 * Set the child selector.
 * @param {number} childSelector The child selector. If not specified, set to
 * undefined.
 * @returns {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setChildSelector = function(childSelector)
{
  this.childSelector_ = childSelector;
  ++this.changeCount_;
  return this;
};

/**
 * @deprecated Use setMustBeFresh.
 */
Interest.prototype.setAnswerOriginKind = function(answerOriginKind)
{
  if (!WireFormat.ENABLE_NDNX)
    throw new Error
      ("setAnswerOriginKind is for NDNx and is deprecated. To enable while you upgrade your code to use NFD's setMustBeFresh(), set WireFormat.ENABLE_NDNX = true");

  this.answerOriginKind_ = answerOriginKind;
  ++this.changeCount_;
  return this;
};

/**
 * Set the MustBeFresh flag.
 * @param {boolean} mustBeFresh True if the content must be fresh, otherwise
 * false. If you do not set this flag, the default value is true.
 * @returns {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setMustBeFresh = function(mustBeFresh)
{
  if (this.answerOriginKind_ == null || this.answerOriginKind_ < 0) {
    // It is is already the default where MustBeFresh is true.
    if (!mustBeFresh)
      // Set answerOriginKind_ so that getMustBeFresh returns false.
      this.answerOriginKind_ = Interest.ANSWER_STALE;
  }
  else {
    if (mustBeFresh)
      // Clear the stale bit.
      this.answerOriginKind_ &= ~Interest.ANSWER_STALE;
    else
      // Set the stale bit.
      this.answerOriginKind_ |= Interest.ANSWER_STALE;
  }
  ++this.changeCount_;
  return this;
};

/**
 * Set the interest scope.
 * @param {number} scope The interest scope. If not specified, set to undefined.
 * @returns {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setScope = function(scope)
{
  this.scope_ = scope;
  ++this.changeCount_;
  return this;
};

/**
 * Set the interest lifetime.
 * @param {number} interestLifetimeMilliseconds The interest lifetime in
 * milliseconds. If not specified, set to -1.
 * @returns {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setInterestLifetimeMilliseconds = function(interestLifetimeMilliseconds)
{
  this.interestLifetimeMilliseconds_ = interestLifetimeMilliseconds;
  ++this.changeCount_;
  return this;
};

/**
 * @deprecated You should let the wire encoder generate a random nonce
 * internally before sending the interest.
 */
Interest.prototype.setNonce = function(nonce)
{
  this.nonce_ = typeof nonce === 'object' && nonce instanceof Blob ?
    nonce : new Blob(nonce, true);
  // Set _getNonceChangeCount so that the next call to getNonce() won't clear
  // this.nonce_.
  ++this.changeCount_;
  this.getNonceChangeCount_ = this.getChangeCount();
  return this;
};

/**
 * Encode the name according to the "NDN URI Scheme".  If there are interest selectors, append "?" and
 * added the selectors as a query string.  For example "/test/name?ndn.ChildSelector=1".
 * Note: This is an experimental feature.  See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/interest.html#interest-touri-method .
 * @returns {string} The URI string.
 */
Interest.prototype.toUri = function()
{
  var selectors = "";

  if (this.minSuffixComponents_ != null)
    selectors += "&ndn.MinSuffixComponents=" + this.minSuffixComponents_;
  if (this.maxSuffixComponents_ != null)
    selectors += "&ndn.MaxSuffixComponents=" + this.maxSuffixComponents_;
  if (this.childSelector_ != null)
    selectors += "&ndn.ChildSelector=" + this.childSelector_;
  if (this.answerOriginKind_ != null)
    selectors += "&ndn.AnswerOriginKind=" + this.answerOriginKind_;
  if (this.scope_ != null)
    selectors += "&ndn.Scope=" + this.scope_;
  if (this.interestLifetimeMilliseconds_ != null)
    selectors += "&ndn.InterestLifetime=" + this.interestLifetimeMilliseconds_;
  if (this.publisherPublicKeyDigest_ != null)
    selectors += "&ndn.PublisherPublicKeyDigest=" + Name.toEscapedString(this.publisherPublicKeyDigest_.publisherPublicKeyDigest_);
  if (this.getNonce().size() > 0)
    selectors += "&ndn.Nonce=" + Name.toEscapedString(this.getNonce().buf());
  if (this.getExclude() != null && this.getExclude().size() > 0)
    selectors += "&ndn.Exclude=" + this.getExclude().toUri();

  var result = this.getName().toUri();
  if (selectors != "")
    // Replace the first & with ?.
    result += "?" + selectors.substr(1);

  return result;
};

/**
 * Encode this Interest for a particular wire format. If wireFormat is the
 * default wire format, also set the defaultWireEncoding field to the encoded
 * result.
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @returns {SignedBlob} The encoded buffer in a SignedBlob object.
 */
Interest.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (!this.getDefaultWireEncoding().isNull() &&
      this.getDefaultWireEncodingFormat() == wireFormat)
    // We already have an encoding in the desired format.
    return this.getDefaultWireEncoding();

  var result = wireFormat.encodeInterest(this);
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
 * Decode the input using a particular wire format and update this Interest. If
 * wireFormat is the default wire format, also set the defaultWireEncoding to
 * another pointer to the input.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Interest.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ?
    input.buf() : input;
  var result = wireFormat.decodeInterest(this, decodeBuffer);

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
 * Get the change count, which is incremented each time this object (or a child
 * object) is changed.
 * @returns {number} The change count.
 */
Interest.prototype.getChangeCount = function()
{
  // Make sure each of the checkChanged is called.
  var changed = this.name_.checkChanged();
  changed = this.keyLocator_.checkChanged() || changed;
  changed = this.exclude_.checkChanged() || changed;
  if (changed)
    // A child object has changed, so update the change count.
    ++this.changeCount_;

  return this.changeCount_;
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

Interest.prototype.setDefaultWireEncoding = function
  (defaultWireEncoding, defaultWireEncodingFormat)
{
  this.defaultWireEncoding_ = defaultWireEncoding;
  this.defaultWireEncodingFormat_ = defaultWireEncodingFormat;
  // Set getDefaultWireEncodingChangeCount_ so that the next call to
  // getDefaultWireEncoding() won't clear _defaultWireEncoding.
  this.getDefaultWireEncodingChangeCount_ = this.getChangeCount();
};

// Define properties so we can change member variable types and implement changeCount_.
Object.defineProperty(Interest.prototype, "name",
  { get: function() { return this.getName(); },
    set: function(val) { this.setName(val); } });
Object.defineProperty(Interest.prototype, "minSuffixComponents",
  { get: function() { return this.getMinSuffixComponents(); },
    set: function(val) { this.setMinSuffixComponents(val); } });
Object.defineProperty(Interest.prototype, "maxSuffixComponents",
  { get: function() { return this.getMaxSuffixComponents(); },
    set: function(val) { this.setMaxSuffixComponents(val); } });
Object.defineProperty(Interest.prototype, "keyLocator",
  { get: function() { return this.getKeyLocator(); },
    set: function(val) { this.setKeyLocator(val); } });
Object.defineProperty(Interest.prototype, "exclude",
  { get: function() { return this.getExclude(); },
    set: function(val) { this.setExclude(val); } });
Object.defineProperty(Interest.prototype, "childSelector",
  { get: function() { return this.getChildSelector(); },
    set: function(val) { this.setChildSelector(val); } });
Object.defineProperty(Interest.prototype, "scope",
  { get: function() { return this.getScope(); },
    set: function(val) { this.setScope(val); } });
/**
 * @deprecated Use getInterestLifetimeMilliseconds and setInterestLifetimeMilliseconds.
 */
Object.defineProperty(Interest.prototype, "interestLifetime",
  { get: function() { return this.getInterestLifetimeMilliseconds(); },
    set: function(val) { this.setInterestLifetimeMilliseconds(val); } });
/**
 * @deprecated Use getMustBeFresh and setMustBeFresh.
 */
Object.defineProperty(Interest.prototype, "answerOriginKind",
  { get: function() { return this.getAnswerOriginKind(); },
    set: function(val) { this.setAnswerOriginKind(val); } });
/**
 * @deprecated Use getNonce and setNonce.
 */
Object.defineProperty(Interest.prototype, "nonce",
  { get: function() { return this.getNonceAsBuffer(); },
    set: function(val) { this.setNonce(val); } });
/**
 * @deprecated Use KeyLocator where keyLocatorType is KEY_LOCATOR_DIGEST.
 */
Object.defineProperty(Interest.prototype, "publisherPublicKeyDigest",
  { get: function() { return this.publisherPublicKeyDigest_; },
    set: function(val) { this.publisherPublicKeyDigest_ = val; ++this.changeCount_; } });
