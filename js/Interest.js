/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Interest Objects
 */

// _interestLifetime is in milliseconds.
var Interest = function Interest
   (_name, _faceInstance, _minSuffixComponents, _maxSuffixComponents, _publisherPublicKeyDigest, _exclude, 
    _childSelector, _answerOriginKind, _scope, _interestLifetime, _nonce) {
		
	this.name = _name;
	this.faceInstance = _faceInstance;
	this.maxSuffixComponents = _maxSuffixComponents;
	this.minSuffixComponents = _minSuffixComponents;
	
	this.publisherPublicKeyDigest = _publisherPublicKeyDigest;
	this.exclude = _exclude;
	this.childSelector = _childSelector;
	this.answerOriginKind = _answerOriginKind;
	this.scope = _scope;
	this.interestLifetime = _interestLifetime;  // milli seconds
	this.nonce = _nonce;	
};

Interest.RECURSIVE_POSTFIX = "*";

Interest.CHILD_SELECTOR_LEFT = 0;
Interest.CHILD_SELECTOR_RIGHT = 1;
Interest.ANSWER_CONTENT_STORE = 1;
Interest.ANSWER_GENERATED = 2;
Interest.ANSWER_STALE = 4;		// Stale answer OK
Interest.MARK_STALE = 16;		// Must have scope 0.  Michael calls this a "hack"

Interest.DEFAULT_ANSWER_ORIGIN_KIND = Interest.ANSWER_CONTENT_STORE | Interest.ANSWER_GENERATED;


Interest.prototype.from_ccnb = function(/*XMLDecoder*/ decoder) {

		decoder.readStartElement(CCNProtocolDTags.Interest);

		this.name = new Name();
		this.name.from_ccnb(decoder);

		if (decoder.peekStartElement(CCNProtocolDTags.MinSuffixComponents))
			this.minSuffixComponents = decoder.readIntegerElement(CCNProtocolDTags.MinSuffixComponents);

		if (decoder.peekStartElement(CCNProtocolDTags.MaxSuffixComponents)) 
			this.maxSuffixComponents = decoder.readIntegerElement(CCNProtocolDTags.MaxSuffixComponents);
			
		if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
			this.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
			this.publisherPublicKeyDigest.from_ccnb(decoder);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.Exclude)) {
			this.exclude = new Exclude();
			this.exclude.from_ccnb(decoder);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.ChildSelector))
			this.childSelector = decoder.readIntegerElement(CCNProtocolDTags.ChildSelector);
		
		if (decoder.peekStartElement(CCNProtocolDTags.AnswerOriginKind))
			this.answerOriginKind = decoder.readIntegerElement(CCNProtocolDTags.AnswerOriginKind);
		
		if (decoder.peekStartElement(CCNProtocolDTags.Scope))
			this.scope = decoder.readIntegerElement(CCNProtocolDTags.Scope);

		if (decoder.peekStartElement(CCNProtocolDTags.InterestLifetime))
			this.interestLifetime = 1000.0 * DataUtils.bigEndianToUnsignedInt
                (decoder.readBinaryElement(CCNProtocolDTags.InterestLifetime)) / 4096;
		
		if (decoder.peekStartElement(CCNProtocolDTags.Nonce))
			this.nonce = decoder.readBinaryElement(CCNProtocolDTags.Nonce);
		
		decoder.readEndElement();
};

Interest.prototype.to_ccnb = function(/*XMLEncoder*/ encoder){
		//Could check if name is present
		
		encoder.writeStartElement(CCNProtocolDTags.Interest);
		
		this.name.to_ccnb(encoder);
	
		if (null != this.minSuffixComponents) 
			encoder.writeElement(CCNProtocolDTags.MinSuffixComponents, this.minSuffixComponents);	

		if (null != this.maxSuffixComponents) 
			encoder.writeElement(CCNProtocolDTags.MaxSuffixComponents, this.maxSuffixComponents);

		if (null != this.publisherPublicKeyDigest)
			this.publisherPublicKeyDigest.to_ccnb(encoder);
		
		if (null != this.exclude)
			this.exclude.to_ccnb(encoder);
		
		if (null != this.childSelector) 
			encoder.writeElement(CCNProtocolDTags.ChildSelector, this.childSelector);

		if (this.DEFAULT_ANSWER_ORIGIN_KIND != this.answerOriginKind && this.answerOriginKind!=null) 
			encoder.writeElement(CCNProtocolDTags.AnswerOriginKind, this.answerOriginKind);
		
		if (null != this.scope) 
			encoder.writeElement(CCNProtocolDTags.Scope, this.scope);
		
		if (null != this.interestLifetime) 
			encoder.writeElement(CCNProtocolDTags.InterestLifetime, 
                DataUtils.nonNegativeIntToBigEndian((this.interestLifetime / 1000.0) * 4096));
		
		if (null != this.nonce)
			encoder.writeElement(CCNProtocolDTags.Nonce, this.nonce);
		
		encoder.writeEndElement();

};

/*
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

/*
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
 * _values is an array where each element is either Uint8Array component or Exclude.ANY.
 */
var Exclude = function Exclude(_values) { 
	this.values = (_values || []);
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

/*
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

/*
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

/*
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
