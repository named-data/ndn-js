/*
 * @author: ucla-cs
 * This class represents Interest Objects
 */

var Interest = function Interest(_Name,_MinSuffixComponents,_MaxSuffixComponents,_PublisherPublicKeyDigest, _Exclude, _ChildSelector,_AnswerOriginKind,_Scope,_InterestLifetime,_Nonce){
		
	this.Name = _Name;
	this.MaxSuffixComponents = _MaxSuffixComponents;
	this.MinSuffixComponents = _MinSuffixComponents;
	
	this.PublisherKeyDigest = _PublisherPublicKeyDigest;
	this.Exclude = _Exclude;
	this.ChildSelector = _ChildSelector;
	this.AnswerOriginKind = _AnswerOriginKind;
	this.Scope = _Scope;
	this.InterestLifetime = null;		// For now we don't have the ability to set an interest lifetime
	this.Nonce = _Nonce;
	

	this.RECURSIVE_POSTFIX = "*";

	this.CHILD_SELECTOR_LEFT = 0;
	this.CHILD_SELECTOR_RIGHT = 1;
	this.ANSWER_CONTENT_STORE = 1;
	this.ANSWER_GENERATED = 2;
	this.ANSWER_STALE = 4;		// Stale answer OK
	this.MARK_STALE = 16;		// Must have Scope 0.  Michael calls this a "hack"

	this.DEFAULT_ANSWER_ORIGIN_KIND = this.ANSWER_CONTENT_STORE | this.ANSWER_GENERATED;

};

Interest.prototype.decode = function(/*XMLDecoder*/ decoder) {

		decoder.readStartElement(CCNProtocolDTags.Interest);

		this.Name = new ContentName();
		this.Name.decode(decoder);

		if (decoder.peekStartElement(CCNProtocolDTags.MinSuffixComponents)) {
			this.MinSuffixComponents = decoder.readIntegerElement(CCNProtocolDTags.MinSuffixComponents);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.MaxSuffixComponents)) {
			this.MaxSuffixComponents = decoder.readIntegerElement(CCNProtocolDTags.MaxSuffixComponents);
		}
			
		//TODO decode PublisherID
		/*if (PublisherID.peek(decoder)) {
			this.Publisher = new PublisherID();
			this.Publisher.decode(decoder);
		}*/

		if (decoder.peekStartElement(CCNProtocolDTags.Exclude)) {
			this.Exclude = new Exclude();
			this.Exclude.decode(decoder);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.ChildSelector)) {
			this.ChildSelector = decoder.readIntegerElement(CCNProtocolDTags.ChildSelector);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.AnswerOriginKind)) {
			// call setter to handle defaulting
			this.AnswerOriginKind = decoder.readIntegerElement(CCNProtocolDTags.AnswerOriginKind);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.Scope)) {
			this.Scope = decoder.readIntegerElement(CCNProtocolDTags.Scope);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.InterestLifetime)) {
			this.InterestLifetime = decoder.readBinaryElement(CCNProtocolDTags.InterestLifetime);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.Nonce)) {
			this.Nonce = decoder.readBinaryElement(CCNProtocolDTags.Nonce);
		}
		
		decoder.readEndElement();
};

Interest.prototype.encode = function(/*XMLEncoder*/ encoder){
		/*if (!validate()) {
			throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
		}*/
		
		encoder.writeStartElement(CCNProtocolDTags.Interest);
		
		this.Name.encode(encoder);
	
		if (null != this.MinSuffixComponents) 
			encoder.writeElement(CCNProtocolDTags.MinSuffixComponents, this.MinSuffixComponents);	

		if (null != this.MaxSuffixComponents) 
			encoder.writeElement(CCNProtocolDTags.MaxSuffixComponents, this.MaxSuffixComponents);

		//TODO Encode PublisherID
		
		/*if (null != this.PublisherID)
			publisherID().encode(encoder);*/
		
		//TODO Encode Exclude
		
		//if (null != this.Exclude)
			//exclude().encode(encoder);
		
		if (null != this.ChildSelector) 
			encoder.writeElement(CCNProtocolDTags.ChildSelector, this.ChildSelector);

		//TODO Encode OriginKind
		if (this.DEFAULT_ANSWER_ORIGIN_KIND != this.AnswerOriginKind && this.AnswerOriginKind!=null) 
			//encoder.writeElement(CCNProtocolDTags.AnswerOriginKind, this.AnswerOriginKind);
		
		if (null != this.Scope) 
			encoder.writeElement(CCNProtocolDTags.Scope, this.Scope);
		
		if (null != this.Nonce)
			encoder.writeElement(CCNProtocolDTags.Nonce, this.Nonce);
		
		encoder.writeEndElement();

};

