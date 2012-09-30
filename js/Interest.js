 /*
 * @author: ucla-cs
 * This class represents Interest Objects
 */

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
	this.interestLifetime = null;		// For now we don't have the ability to set an interest lifetime
	this.nonce = _nonce;
	

	this.RECURSIVE_POSTFIX = "*";

	this.CHILD_SELECTOR_LEFT = 0;
	this.CHILD_SELECTOR_RIGHT = 1;
	this.ANSWER_CONTENT_STORE = 1;
	this.ANSWER_GENERATED = 2;
	this.ANSWER_STALE = 4;		// Stale answer OK
	this.MARK_STALE = 16;		// Must have scope 0.  Michael calls this a "hack"

	this.DEFAULT_ANSWER_ORIGIN_KIND = this.ANSWER_CONTENT_STORE | this.ANSWER_GENERATED;

};

Interest.prototype.from_ccnb = function(/*XMLDecoder*/ decoder) {

		decoder.readStartElement(CCNProtocolDTags.Interest);

		this.name = new Name();
		this.name.from_ccnb(decoder);

		if (decoder.peekStartElement(CCNProtocolDTags.MinSuffixComponents)) {
			this.minSuffixComponents = decoder.readIntegerElement(CCNProtocolDTags.MinSuffixComponents);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.MaxSuffixComponents)) {
			this.maxSuffixComponents = decoder.readIntegerElement(CCNProtocolDTags.MaxSuffixComponents);
		}
			
		if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
			this.publisherPublicKeyDigest = new publisherPublicKeyDigest();
			this.publisherPublicKeyDigest.from_ccnb(decoder);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.Exclude)) {
			this.exclude = new Exclude();
			this.exclude.from_ccnb(decoder);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.ChildSelector)) {
			this.childSelector = decoder.readIntegerElement(CCNProtocolDTags.ChildSelector);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.AnswerOriginKind)) {
			// call setter to handle defaulting
			this.answerOriginKind = decoder.readIntegerElement(CCNProtocolDTags.AnswerOriginKind);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.Scope)) {
			this.scope = decoder.readIntegerElement(CCNProtocolDTags.Scope);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.InterestLifetime)) {
			this.interestLifetime = decoder.readBinaryElement(CCNProtocolDTags.InterestLifetime);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.Nonce)) {
			this.nonce = decoder.readBinaryElement(CCNProtocolDTags.Nonce);
		}
		
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

		//TODO Encode OriginKind
		if (this.DEFAULT_ANSWER_ORIGIN_KIND != this.answerOriginKind && this.answerOriginKind!=null) 
			encoder.writeElement(CCNProtocolDTags.AnswerOriginKind, this.answerOriginKind);
		
		if (null != this.scope) 
			encoder.writeElement(CCNProtocolDTags.Scope, this.scope);
		
		if (null != this.nonce)
			encoder.writeElement(CCNProtocolDTags.Nonce, this.nonce);
		
		encoder.writeEndElement();

};

Interest.prototype.matches_name = function(/*Name*/ name){
	var i_name = this.name.components;
	var o_name = name.components;

	// The intrest name is longer than the name we are checking it against.
	if (i_name.length > o_name.length)
            return false;

	// Check if at least one of given components doesn't match.
        for (var i = 0; i < i_name.length; ++i) {
            if (!DataUtils.arraysEqual(i_name[i], o_name[i]))
                return false;
        }

	return true;
}

