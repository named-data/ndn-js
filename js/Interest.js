/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Interest Objects
 */

/**
 * Create a new Interest with the optional values.
 * 
 * @constructor
 * @param {Name} name
 * @param {FaceInstance} faceInstance
 * @param {number} minSuffixComponents
 * @param {number} maxSuffixComponents
 * @param {Uint8Array} publisherPublicKeyDigest
 * @param {Exclude} exclude
 * @param {number} childSelector
 * @param {number} answerOriginKind
 * @param {number} scope
 * @param {number} interestLifetime in milliseconds
 * @param {Uint8Array} nonce
 */
var Interest = function Interest
   (name, faceInstance, minSuffixComponents, maxSuffixComponents, publisherPublicKeyDigest, exclude, 
    childSelector, answerOriginKind, scope, interestLifetimeMilliseconds, nonce) {
		
	this.name = name;
	this.faceInstance = faceInstance;
	this.maxSuffixComponents = maxSuffixComponents;
	this.minSuffixComponents = minSuffixComponents;
	
	this.publisherPublicKeyDigest = publisherPublicKeyDigest;
	this.exclude = exclude;
	this.childSelector = childSelector;
	this.answerOriginKind = answerOriginKind;
	this.scope = scope;
	this.interestLifetime = interestLifetimeMilliseconds;
	this.nonce = nonce;	
};

Interest.RECURSIVE_POSTFIX = "*";

Interest.CHILD_SELECTOR_LEFT = 0;
Interest.CHILD_SELECTOR_RIGHT = 1;
Interest.ANSWER_CONTENT_STORE = 1;
Interest.ANSWER_GENERATED = 2;
Interest.ANSWER_STALE = 4;		// Stale answer OK
Interest.MARK_STALE = 16;		// Must have scope 0.  Michael calls this a "hack"

Interest.DEFAULT_ANSWER_ORIGIN_KIND = Interest.ANSWER_CONTENT_STORE | Interest.ANSWER_GENERATED;

/**
 * @deprecated Use BinaryXmlWireFormat.decodeInterest.
 */
Interest.prototype.from_ccnb = function(/*XMLDecoder*/ decoder) {
  BinaryXmlWireFormat.decodeInterest(this, decoder);
};

/**
 * @deprecated Use BinaryXmlWireFormat.encodeInterest.
 */
Interest.prototype.to_ccnb = function(/*XMLEncoder*/ encoder){
  BinaryXmlWireFormat.encodeInterest(this, encoder);
};

/**
 * Encode this Interest for a particular wire format.
 * @param {WireFormat} wireFormat if null, use BinaryXmlWireFormat.
 * @returns {Uint8Array}
 */
Interest.prototype.encode = function(wireFormat) {
  wireFormat = (wireFormat || BinaryXmlWireFormat.instance);
  return wireFormat.encodeInterest(this);
};

/**
 * Decode the input using a particular wire format and update this Interest.
 * @param {Uint8Array} input
 * @param {WireFormat} wireFormat if null, use BinaryXmlWireFormat.
 */
Interest.prototype.decode = function(input, wireFormat) {
  wireFormat = (wireFormat || BinaryXmlWireFormat.instance);
  wireFormat.decodeInterest(this, input);
};

/**
 * Return true if this.name.match(name) and the name conforms to the interest selectors.
 */
Interest.prototype.matches_name = function(/*Name*/ name) {
    if (!this.name.match(name))
        return false;
    
    if (this.minSuffixComponents != null &&
        // Add 1 for the implicit digest.
        !(name.components.length + 1 - this.name.components.length >= this.minSuffixComponents))
        return false;
    if (this.maxSuffixComponents != null &&
        // Add 1 for the implicit digest.
        !(name.components.length + 1 - this.name.components.length <= this.maxSuffixComponents))
        return false;
    if (this.exclude != null && name.components.length > this.name.components.length &&
        this.exclude.matches(name.components[this.name.components.length]))
        return false;
    
    return true;
};

/**
 * Return a new Interest with the same fields as this Interest.  
 * Note: This does NOT make a deep clone of the name, exclue or other objects.
 */
Interest.prototype.clone = function() {
    return new Interest
       (this.name, this.faceInstance, this.minSuffixComponents, this.maxSuffixComponents, 
        this.publisherPublicKeyDigest, this.exclude, this.childSelector, this.answerOriginKind, 
        this.scope, this.interestLifetime, this.nonce);
};

/*
 * Handle the interest Exclude element.
 * values is 
 */

/**
 * 
 * @constructor
 * @param {Array<Uint8Array|Exclude.ANY>} values an array where each element is either Uint8Array component or Exclude.ANY.
 */
var Exclude = function Exclude(values) { 
	this.values = (values || []);
}

Exclude.ANY = "*";

Exclude.prototype.from_ccnb = function(/*XMLDecoder*/ decoder) {
	decoder.readStartElement(CCNProtocolDTags.Exclude);

	while (true) {
        if (decoder.peekStartElement(CCNProtocolDTags.Component))
            this.values.push(decoder.readBinaryElement(CCNProtocolDTags.Component));
        else if (decoder.peekStartElement(CCNProtocolDTags.Any)) {
            decoder.readStartElement(CCNProtocolDTags.Any);
            decoder.readEndElement();
            this.values.push(Exclude.ANY);
        }
        else if (decoder.peekStartElement(CCNProtocolDTags.Bloom)) {
            // Skip the Bloom and treat it as Any.
            decoder.readBinaryElement(CCNProtocolDTags.Bloom);
            this.values.push(Exclude.ANY);
        }
        else
            break;
	}
    
    decoder.readEndElement();
};

Exclude.prototype.to_ccnb = function(/*XMLEncoder*/ encoder)  {
	if (this.values == null || this.values.length == 0)
		return;

	encoder.writeStartElement(CCNProtocolDTags.Exclude);
    
    // TODO: Do we want to order the components (except for ANY)?
    for (var i = 0; i < this.values.length; ++i) {
        if (this.values[i] == Exclude.ANY) {
            encoder.writeStartElement(CCNProtocolDTags.Any);
            encoder.writeEndElement();
        }
        else
            encoder.writeElement(CCNProtocolDTags.Component, this.values[i]);
    }

	encoder.writeEndElement();
};

/**
 * Return a string with elements separated by "," and Exclude.ANY shown as "*". 
 */
Exclude.prototype.to_uri = function() {
	if (this.values == null || this.values.length == 0)
		return "";

    var result = "";
    for (var i = 0; i < this.values.length; ++i) {
        if (i > 0)
            result += ",";
        
        if (this.values[i] == Exclude.ANY)
            result += "*";
        else
            result += Name.toEscapedString(this.values[i]);
    }
    return result;
};

/**
 * Return true if the component matches any of the exclude criteria.
 */
Exclude.prototype.matches = function(/*Uint8Array*/ component) {
    for (var i = 0; i < this.values.length; ++i) {
        if (this.values[i] == Exclude.ANY) {
            var lowerBound = null;
            if (i > 0)
                lowerBound = this.values[i - 1];
            
            // Find the upper bound, possibly skipping over multiple ANY in a row.
            var iUpperBound;
            var upperBound = null;
            for (iUpperBound = i + 1; iUpperBound < this.values.length; ++iUpperBound) {
                if (this.values[iUpperBound] != Exclude.ANY) {
                    upperBound = this.values[iUpperBound];
                    break;
                }
            }
            
            // If lowerBound != null, we already checked component equals lowerBound on the last pass.
            // If upperBound != null, we will check component equals upperBound on the next pass.
            if (upperBound != null) {
                if (lowerBound != null) {
                    if (Exclude.compareComponents(component, lowerBound) > 0 &&
                        Exclude.compareComponents(component, upperBound) < 0)
                        return true;
                }
                else {
                    if (Exclude.compareComponents(component, upperBound) < 0)
                        return true;
                }
                
                // Make i equal iUpperBound on the next pass.
                i = iUpperBound - 1;
            }
            else {
                if (lowerBound != null) {
                    if (Exclude.compareComponents(component, lowerBound) > 0)
                        return true;
                }
                else
                    // this.values has only ANY.
                    return true;
            }
        }
        else {
            if (DataUtils.arraysEqual(component, this.values[i]))
                return true;
        }
    }
    
    return false;
};

/**
 * Return -1 if component1 is less than component2, 1 if greater or 0 if equal.
 * A component is less if it is shorter, otherwise if equal length do a byte comparison.
 */
Exclude.compareComponents = function(/*Uint8Array*/ component1, /*Uint8Array*/ component2) {
    if (component1.length < component2.length)
        return -1;
    if (component1.length > component2.length)
        return 1;
    
    for (var i = 0; i < component1.length; ++i) {
        if (component1[i] < component2[i])
            return -1;
        if (component1[i] > component2[i])
            return 1;
    }

    return 0;
};
