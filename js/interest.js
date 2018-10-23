/**
 * This class represents Interest Objects
 * Copyright (C) 2013-2018 Regents of the University of California.
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
var Crypto = require('./crypto.js'); /** @ignore */
var Blob = require('./util/blob.js').Blob; /** @ignore */
var SignedBlob = require('./util/signed-blob.js').SignedBlob; /** @ignore */
var ChangeCounter = require('./util/change-counter.js').ChangeCounter; /** @ignore */
var Name = require('./name.js').Name; /** @ignore */
var Exclude = require('./exclude.js').Exclude; /** @ignore */
var Link = require('./link.js').Link; /** @ignore */
var KeyLocator = require('./key-locator.js').KeyLocator; /** @ignore */
var DelegationSet = require('./delegation-set.js').DelegationSet; /** @ignore */
var IncomingFaceId = require('./lp/incoming-face-id.js').IncomingFaceId; /** @ignore */
var WireFormat = require('./encoding/wire-format.js').WireFormat;

/**
 * Create a new Interest with the optional values.
 *
 * @constructor
 * @param {Name|Interest|string} nameOrInterest (optional) If this is an
 * Interest, copy values from the Interest. If this is a Name, create an
 * Interest with a copy of the Name. If this is a create a Name from the URI.
 */
var Interest = function Interest
   (nameOrInterest, minSuffixComponents, maxSuffixComponents,
    publisherPublicKeyDigest, exclude, childSelector, answerOriginKind, scope,
    interestLifetimeMilliseconds, nonce)
{
  if (publisherPublicKeyDigest != null)
    throw new Error
      ("Interest constructor: PublisherPublicKeyDigest support has been removed.");
  if (answerOriginKind != null)
    throw new Error
      ("Interest constructor: answerOriginKind support has been removed. Use setMustBeFresh().");
  if (scope != null)
    throw new Error("Interest constructor: scope support has been removed.");
  if (nonce != null)
    throw new Error("Interest constructor: nonce support in the constructor has been removed.");

  if (minSuffixComponents != null)
    console.log("Interest constructor: The minSuffixComponents param is deprecated. Use setMinSuffixComponents().")
  if (maxSuffixComponents != null)
    console.log("Interest constructor: The maxSuffixComponents param is deprecated. Use setMaxSuffixComponents().")
  if (exclude != null)
    console.log("Interest constructor: The exclude param is deprecated. Use setExclude().")
  if (childSelector != null)
    console.log("Interest constructor: The childSelector param is deprecated. Use setChildSelector().")
  if (interestLifetimeMilliseconds != null)
    console.log("Interest constructor: The interestLifetimeMilliseconds param is deprecated. Use setInterestLifetimeMilliseconds().")

  if (typeof nameOrInterest === 'object' && nameOrInterest instanceof Interest) {
    // Special case: this is a copy constructor.  Ignore all but the first argument.
    var interest = nameOrInterest;
    // Copy the name.
    this.name_ = new ChangeCounter(new Name(interest.getName()));
    this.maxSuffixComponents_ = interest.maxSuffixComponents_;
    this.minSuffixComponents_ = interest.minSuffixComponents_;

    this.keyLocator_ = new ChangeCounter(new KeyLocator(interest.getKeyLocator()));
    this.exclude_ = new ChangeCounter(new Exclude(interest.getExclude()));
    this.childSelector_ = interest.childSelector_;
    this.mustBeFresh_ = interest.mustBeFresh_;
    this.interestLifetimeMilliseconds_ = interest.interestLifetimeMilliseconds_;
    this.forwardingHint_ = new ChangeCounter
      (new DelegationSet(interest.getForwardingHint()));
    this.nonce_ = interest.nonce_;
    this.linkWireEncoding_ = interest.linkWireEncoding_;
    this.linkWireEncodingFormat_ = interest.linkWireEncodingFormat_;
    this.link_ = new ChangeCounter(null);
    if (interest.link_.get() != null)
      this.link_.set(new Link(interest.link_.get()));
    this.selectedDelegationIndex_ = interest.selectedDelegationIndex_;
    this.defaultWireEncoding_ = interest.getDefaultWireEncoding();
    this.defaultWireEncodingFormat_ = interest.defaultWireEncodingFormat_;
  }
  else {
    this.name_ = new ChangeCounter(new Name(nameOrInterest));
    this.maxSuffixComponents_ = maxSuffixComponents;
    this.minSuffixComponents_ = minSuffixComponents;

    this.keyLocator_ = new ChangeCounter(new KeyLocator());
    this.exclude_ = new ChangeCounter(typeof exclude === 'object' && exclude instanceof Exclude ?
      new Exclude(exclude) : new Exclude());
    this.childSelector_ = childSelector;
    this.mustBeFresh_ = true;
    this.interestLifetimeMilliseconds_ = interestLifetimeMilliseconds;
    this.forwardingHint_ = new ChangeCounter(new DelegationSet());
    this.nonce_ = new Blob();
    this.linkWireEncoding_ = new Blob();
    this.linkWireEncodingFormat_ = null;
    this.link_ = new ChangeCounter(null);
    this.selectedDelegationIndex_ = null;
    this.defaultWireEncoding_ = new SignedBlob();
    this.defaultWireEncodingFormat_ = null;
  }

  this.getNonceChangeCount_ = 0;
  this.getDefaultWireEncodingChangeCount_ = 0;
  this.changeCount_ = 0;
  this.lpPacket_ = null;
};

exports.Interest = Interest;

Interest.RECURSIVE_POSTFIX = "*";

Interest.CHILD_SELECTOR_LEFT = 0;
Interest.CHILD_SELECTOR_RIGHT = 1;

/**
 * Check if this interest's name matches the given name (using Name.match) and
 * the given name also conforms to the interest selectors.
 * @param {Name} name The name to check.
 * @return {boolean} True if the name and interest selectors match, False otherwise.
 */
Interest.prototype.matchesName = function(name)
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
 * Check if the given Data packet can satisfy this Interest. This method
 * considers the Name, MinSuffixComponents, MaxSuffixComponents,
 * PublisherPublicKeyLocator, and Exclude. It does not consider the
 * ChildSelector or MustBeFresh. This uses the given wireFormat to get the
 * Data packet encoding for the full Name.
 * @param {Data} data The Data packet to check.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the Data packet to get its full Name. If omitted, use
 * WireFormat.getDefaultWireFormat().
 * @return {boolean} True if the given Data packet can satisfy this Interest.
 */
Interest.prototype.matchesData = function(data, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  // Imitate ndn-cxx Interest::matchesData.
  var interestNameLength = this.getName().size();
  var dataName = data.getName();
  var fullNameLength = dataName.size() + 1;

  // Check MinSuffixComponents.
  var hasMinSuffixComponents = (this.getMinSuffixComponents() != null);
  var minSuffixComponents =
    hasMinSuffixComponents ? this.getMinSuffixComponents() : 0;
  if (!(interestNameLength + minSuffixComponents <= fullNameLength))
    return false;

  // Check MaxSuffixComponents.
  var hasMaxSuffixComponents = (this.getMaxSuffixComponents() != null);
  if (hasMaxSuffixComponents &&
      !(interestNameLength + this.getMaxSuffixComponents() >= fullNameLength))
    return false;

  // Check the prefix.
  if (interestNameLength === fullNameLength) {
    if (this.getName().get(-1).isImplicitSha256Digest()) {
      if (!this.getName().equals(data.getFullName(wireFormat)))
        return false;
    }
    else
      // The Interest Name is the same length as the Data full Name, but the
      //   last component isn't a digest so there's no possibility of matching.
      return false;
  }
  else {
    // The Interest Name should be a strict prefix of the Data full Name.
    if (!this.getName().isPrefixOf(dataName))
      return false;
  }

  // Check the Exclude.
  // The Exclude won't be violated if the Interest Name is the same as the
  //   Data full Name.
  if (this.getExclude().size() > 0 && fullNameLength > interestNameLength) {
    if (interestNameLength == fullNameLength - 1) {
      // The component to exclude is the digest.
      if (this.getExclude().matches
          (data.getFullName(wireFormat).get(interestNameLength)))
        return false;
    }
    else {
      // The component to exclude is not the digest.
      if (this.getExclude().matches(dataName.get(interestNameLength)))
        return false;
    }
  }

  // Check the KeyLocator.
  var publisherPublicKeyLocator = this.getKeyLocator();
  if (publisherPublicKeyLocator.getType()) {
    var signature = data.getSignature();
    if (!KeyLocator.canGetFromSignature(signature))
      // No KeyLocator in the Data packet.
      return false;
    if (!publisherPublicKeyLocator.equals
        (KeyLocator.getFromSignature(signature)))
      return false;
  }

  return true;
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
 * @return {Name} The name.  The name size() may be 0 if not specified.
 */
Interest.prototype.getName = function() { return this.name_.get(); };

/**
 * Get the min suffix components.
 * @return {number} The min suffix components, or null if not specified.
 */
Interest.prototype.getMinSuffixComponents = function()
{
  return this.minSuffixComponents_;
};

/**
 * Get the max suffix components.
 * @return {number} The max suffix components, or null if not specified.
 */
Interest.prototype.getMaxSuffixComponents = function()
{
  return this.maxSuffixComponents_;
};

/**
 * Get the CanBePrefix flag. If not specified, the default is true.
 * @returns {boolean} The CanBePrefix flag.
 */
Interest.prototype.getCanBePrefix = function()
{
  // Use the closest v0.2 semantics. CanBePrefix is the opposite of exact
  // match where MaxSuffixComponents is 1 (for the implicit digest).
  return this.maxSuffixComponents_ != 1;
};

/**
 * Get the interest key locator.
 * @return {KeyLocator} The key locator. If its getType() is null,
 * then the key locator is not specified.
 */
Interest.prototype.getKeyLocator = function()
{
  return this.keyLocator_.get();
};

/**
 * Get the exclude object.
 * @return {Exclude} The exclude object. If the exclude size() is zero, then
 * the exclude is not specified.
 */
Interest.prototype.getExclude = function() { return this.exclude_.get(); };

/**
 * Get the child selector.
 * @return {number} The child selector, or null if not specified.
 */
Interest.prototype.getChildSelector = function()
{
  return this.childSelector_;
};

/**
 * Get the must be fresh flag. If not specified, the default is true.
 * @return {boolean} The must be fresh flag.
 */
Interest.prototype.getMustBeFresh = function()
{
  return this.mustBeFresh_;
};

/**
 * Return the nonce value from the incoming interest.  If you change any of the
 * fields in this Interest object, then the nonce value is cleared.
 * @return {Blob} The nonce. If not specified, the value isNull().
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
 * Get the forwarding hint object which you can modify to add or remove
 * forwarding hints.
 * @return {DelegationSet} The forwarding hint as a DelegationSet.
 */
Interest.prototype.getForwardingHint = function()
{
  return this.forwardingHint_.get();
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
 * Check if this interest has a link object (or a link wire encoding which
 * can be decoded to make the link object).
 * @return {boolean} True if this interest has a link object, false if not.
 * @deprecated Use getForwardingHint.
 */
Interest.prototype.hasLink = function()
{
  return this.link_.get() != null || !this.linkWireEncoding_.isNull();
};

/**
 * Get the link object. If necessary, decode it from the link wire encoding.
 * @return {Link} The link object, or null if not specified.
 * @throws DecodingException For error decoding the link wire encoding (if
 * necessary).
 * @deprecated Use getForwardingHint.
 */
Interest.prototype.getLink = function()
{
  if (this.link_.get() != null)
    return this.link_.get();
  else if (!this.linkWireEncoding_.isNull()) {
    // Decode the link object from linkWireEncoding_.
    var link = new Link();
    link.wireDecode(this.linkWireEncoding_, this.linkWireEncodingFormat_);
    this.link_.set(link);

    // Clear linkWireEncoding_ since it is now managed by the link object.
    this.linkWireEncoding_ = new Blob();
    this.linkWireEncodingFormat_ = null;

    return link;
  }
  else
    return null;
};

/**
 * Get the wire encoding of the link object. If there is already a wire
 * encoding then return it. Otherwise encode from the link object (if
 * available).
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * the Link. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {Blob} The wire encoding, or an isNull Blob if the link is not
 * specified.
 * @deprecated Use getForwardingHint.
 */
Interest.prototype.getLinkWireEncoding = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (!this.linkWireEncoding_.isNull() && this.linkWireEncodingFormat_ == wireFormat)
    return this.linkWireEncoding_;

  var link = this.getLink();
  if (link != null)
    return link.wireEncode(wireFormat);
  else
    return new Blob();
};

/**
 * Get the selected delegation index.
 * @return {number} The selected delegation index. If not specified, return null.
 * @deprecated Use getForwardingHint.
 */
Interest.prototype.getSelectedDelegationIndex = function()
{
  return this.selectedDelegationIndex_;
};

/**
 * Get the interest lifetime.
 * @return {number} The interest lifetime in milliseconds, or null if not
 * specified.
 */
Interest.prototype.getInterestLifetimeMilliseconds = function()
{
  return this.interestLifetimeMilliseconds_;
};

/**
 * Return the default wire encoding, which was encoded with
 * getDefaultWireEncodingFormat().
 * @return {SignedBlob} The default wire encoding, whose isNull() may be true
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
 * @return {WireFormat} The WireFormat, which is only meaningful if the
 * getDefaultWireEncoding() is not isNull().
 */
Interest.prototype.getDefaultWireEncodingFormat = function()
{
  return this.defaultWireEncodingFormat_;
};

/**
 * Get the incoming face ID according to the incoming packet header.
 * @return {number} The incoming face ID. If not specified, return null.
 */
Interest.prototype.getIncomingFaceId = function()
{
  var field =
    this.lpPacket_ === null ? null : IncomingFaceId.getFirstHeader(this.lpPacket_);
  return field === null ? null : field.getFaceId();
};

/**
 * Set the interest name.
 * Note: You can also call getName and change the name values directly.
 * @param {Name} name The interest name. This makes a copy of the name.
 * @return {Interest} This Interest so that you can chain calls to update values.
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
 * @return {Interest} This Interest so that you can chain calls to update values.
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
 * @return {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setMaxSuffixComponents = function(maxSuffixComponents)
{
  this.maxSuffixComponents_ = maxSuffixComponents;
  ++this.changeCount_;
  return this;
};

/**
 * Set the CanBePrefix flag.
 * @param {boolean} canBePrefix True if the Interest name can be a prefix. If
 * you do not set this flag, the default value is true.
 * @return {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setCanBePrefix = function(canBePrefix)
{
  // Use the closest v0.2 semantics. CanBePrefix is the opposite of exact
  // match where MaxSuffixComponents is 1 (for the implicit digest).
  this.maxSuffixComponents_ = (canBePrefix ? null : 1);
  ++this.changeCount_;
  return this;
};

/**
 * Set this interest to use a copy of the given KeyLocator object.
 * Note: You can also call getKeyLocator and change the key locator directly.
 * @param {KeyLocator} keyLocator The KeyLocator object. This makes a copy of the object.
 * If no key locator is specified, set to a new default KeyLocator(), or to a
 * KeyLocator with an unspecified type.
 * @return {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setKeyLocator = function(keyLocator)
{
  this.keyLocator_.set
    (typeof keyLocator === 'object' && keyLocator instanceof KeyLocator ?
     new KeyLocator(keyLocator) : new KeyLocator());
  ++this.changeCount_;
  return this;
};

/**
 * Set this interest to use a copy of the given exclude object. Note: You can
 * also call getExclude and change the exclude entries directly.
 * @param {Exclude} exclude The Exclude object. This makes a copy of the object.
 * If no exclude is specified, set to a new default Exclude(), or to an Exclude
 * with size() 0.
 * @return {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setExclude = function(exclude)
{
  this.exclude_.set(typeof exclude === 'object' && exclude instanceof Exclude ?
    new Exclude(exclude) : new Exclude());
  ++this.changeCount_;
  return this;
};

/**
 * Set this interest to use a copy of the given DelegationSet object as the
 * forwarding hint.
 * Note: You can also call getForwardingHint and change the forwarding hint
 * directly.
 * @param {DelegationSet} forwardingHint The DelegationSet object to use as the
 * forwarding  hint. This makes a copy of the object. If no forwarding hint is
 * specified, set to a new default DelegationSet() with no entries.
 * @return {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setForwardingHint = function(forwardingHint)
{
  this.forwardingHint_.set
    (typeof forwardingHint === 'object' && forwardingHint instanceof DelegationSet ?
     new DelegationSet(forwardingHint) : new DelegationSet());
  ++this.changeCount_;
  return this;
};

/**
 * Set the link wire encoding bytes, without decoding them. If there is
 * a link object, set it to null. If you later call getLink(), it will
 * decode the wireEncoding to create the link object.
 * @param {Blob} encoding The Blob with the bytes of the link wire encoding.
 * If no link is specified, set to an empty Blob() or call unsetLink().
 * @param {WireFormat} wireFormat The wire format of the encoding, to be used
 * later if necessary to decode. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {Interest} This Interest so that you can chain calls to update values.
 * @deprecated Use setForwardingHint.
 */
Interest.prototype.setLinkWireEncoding = function(encoding, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  this.linkWireEncoding_ = encoding;
  this.linkWireEncodingFormat_ = wireFormat;

  // Clear the link object, assuming that it has a different encoding.
  this.link_.set(null);

  ++this.changeCount_;
  return this;
};

/**
 * Clear the link wire encoding and link object so that getLink() returns null.
 * @return {Interest} This Interest so that you can chain calls to update values.
 * @deprecated Use setForwardingHint.
 */
Interest.prototype.unsetLink = function()
{
  return this.setLinkWireEncoding(new Blob(), null);
};

/**
 * Set the selected delegation index.
 * @param {number} selectedDelegationIndex The selected delegation index. If not
 * specified, set to null.
 * @return {Interest} This Interest so that you can chain calls to update values.
 * @deprecated Use setForwardingHint.
 */
Interest.prototype.setSelectedDelegationIndex = function(selectedDelegationIndex)
{
  this.selectedDelegationIndex_ = selectedDelegationIndex;
  ++this.changeCount_;
  return this;
};

/**
 * Set the child selector.
 * @param {number} childSelector The child selector. If not specified, set to
 * undefined.
 * @return {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setChildSelector = function(childSelector)
{
  this.childSelector_ = childSelector;
  ++this.changeCount_;
  return this;
};

/**
 * Set the MustBeFresh flag.
 * @param {boolean} mustBeFresh True if the content must be fresh, otherwise
 * false. If you do not set this flag, the default value is true.
 * @return {Interest} This Interest so that you can chain calls to update values.
 */
Interest.prototype.setMustBeFresh = function(mustBeFresh)
{
  this.mustBeFresh_ = (mustBeFresh ? true : false);
  ++this.changeCount_;
  return this;
};

/**
 * Set the interest lifetime.
 * @param {number} interestLifetimeMilliseconds The interest lifetime in
 * milliseconds. If not specified, set to undefined.
 * @return {Interest} This Interest so that you can chain calls to update values.
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
  // Set getNonceChangeCount_ so that the next call to getNonce() won't clear
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
 * @return {string} The URI string.
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
  selectors += "&ndn.MustBeFresh=" + (this.mustBeFresh_ ? 1 : 0);
  if (this.interestLifetimeMilliseconds_ != null)
    selectors += "&ndn.InterestLifetime=" + this.interestLifetimeMilliseconds_;
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
 * @return {SignedBlob} The encoded buffer in a SignedBlob object.
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

  var result;
  if (typeof input === 'object' && input instanceof Blob)
    // Input is a blob, so get its buf() and set copy false.
    result = wireFormat.decodeInterest(this, input.buf(), false);
  else
    result = wireFormat.decodeInterest(this, input, true);

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
 * Update the bytes of the nonce with new random values. This ensures that the
 * new nonce value is different than the current one. If the current nonce is
 * not specified, this does nothing.
 */
Interest.prototype.refreshNonce = function()
{
  var currentNonce = this.getNonce();
  if (currentNonce.size() === 0)
    return;

  var newNonce;
  while (true) {
    newNonce = new Blob(Crypto.randomBytes(currentNonce.size()), false);
    if (!newNonce.equals(currentNonce))
      break;
  }

  this.nonce_ = newNonce;
  // Set getNonceChangeCount_ so that the next call to getNonce() won't clear
  // this.nonce_.
  ++this.changeCount_;
  this.getNonceChangeCount_ = this.getChangeCount();
};

/**
 * An internal library method to set the LpPacket for an incoming packet. The
 * application should not call this.
 * @param {LpPacket} lpPacket The LpPacket. This does not make a copy.
 * @return {Interest} This Interest so that you can chain calls to update values.
 * @note This is an experimental feature. This API may change in the future.
 */
Interest.prototype.setLpPacket = function(lpPacket)
{
  this.lpPacket_ = lpPacket;
  // Don't update changeCount_ since this doesn't affect the wire encoding.
  return this;
}

/**
 * Get the change count, which is incremented each time this object (or a child
 * object) is changed.
 * @return {number} The change count.
 */
Interest.prototype.getChangeCount = function()
{
  // Make sure each of the checkChanged is called.
  var changed = this.name_.checkChanged();
  changed = this.keyLocator_.checkChanged() || changed;
  changed = this.exclude_.checkChanged() || changed;
  changed = this.forwardingHint_.checkChanged() || changed;
  if (changed)
    // A child object has changed, so update the change count.
    ++this.changeCount_;

  return this.changeCount_;
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
/**
 * @deprecated Use getInterestLifetimeMilliseconds and setInterestLifetimeMilliseconds.
 */
Object.defineProperty(Interest.prototype, "interestLifetime",
  { get: function() { return this.getInterestLifetimeMilliseconds(); },
    set: function(val) { this.setInterestLifetimeMilliseconds(val); } });
/**
 * @deprecated Use getNonce and setNonce.
 */
Object.defineProperty(Interest.prototype, "nonce",
  { get: function() { return this.getNonceAsBuffer(); },
    set: function(val) { this.setNonce(val); } });
