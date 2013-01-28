/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Interest Objects
 */

// _interestLifetime is in milliseconds.
var Interest = function Interest(_name,_faceInstance,_minSuffixComponents,_maxSuffixComponents,_publisherPublicKeyDigest, _exclude, _childSelector,_answerOriginKind,_scope,_interestLifetime,_nonce){
		
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

Interest.prototype.matches_name = function(/*Name*/ name) {
    return this.name.match(name);
}

/**
 * Exclude
 */
var Exclude = function Exclude(_values){ 
	this.OPTIMUM_FILTER_SIZE = 100;
	this.values = _values; //array of elements
}

Exclude.prototype.from_ccnb = function(/*XMLDecoder*/ decoder) {
		decoder.readStartElement(this.getElementLabel());

		//TODO APPLY FILTERS/EXCLUDE.  For now, just skip the element.
        var structureDecoder = new BinaryXMLStructureDecoder();
        structureDecoder.seek(decoder.offset);
        if (!structureDecoder.findElementEnd(decoder.istream))
            throw new ContentDecodingException(new Error("Cannot find the end of interest Exclude element"));
        decoder.seek(structureDecoder.offset);
        
		//TODO 
		/*var component;
		var any = false;
		while ((component = decoder.peekStartElement(CCNProtocolDTags.Component)) || 
				(any = decoder.peekStartElement(CCNProtocolDTags.Any)) ||
					decoder.peekStartElement(CCNProtocolDTags.Bloom)) {
			var ee = component?new ExcludeComponent(): any ? new ExcludeAny() : new BloomFilter();
			ee.decode(decoder);
			_values.add(ee);
		}*/
};

Exclude.prototype.to_ccnb=function(/*XMLEncoder*/ encoder)  {
		if (!validate()) {
			throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
		}

		if (empty())
			return;

		encoder.writeStartElement(getElementLabel());

		encoder.writeEndElement();
		
	};

Exclude.prototype.getElementLabel = function() { return CCNProtocolDTags.Exclude; };


/**
 * ExcludeAny
 */
var ExcludeAny = function ExcludeAny() {

};

ExcludeAny.prototype.from_ccnb = function(decoder) {
		decoder.readStartElement(this.getElementLabel());
		decoder.readEndElement();
};


ExcludeAny.prototype.to_ccnb = function( encoder) {
		encoder.writeStartElement(this.getElementLabel());
		encoder.writeEndElement();
};

ExcludeAny.prototype.getElementLabel=function() { return CCNProtocolDTags.Any; };


/**
 * ExcludeComponent
 */
var ExcludeComponent = function ExcludeComponent(_body) {

	//TODO Check BODY is an Array of componenets.
	
	this.body = _body
};

ExcludeComponent.prototype.from_ccnb = function( decoder)  {
		this.body = decoder.readBinaryElement(this.getElementLabel());
};

ExcludeComponent.prototype.to_ccnb = function(encoder) {
		encoder.writeElement(this.getElementLabel(), this.body);
};

ExcludeComponent.prototype.getElementLabel = function() { return CCNProtocolDTags.Component; };
