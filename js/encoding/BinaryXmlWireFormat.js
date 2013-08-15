/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * This class represents Interest Objects
 */

/**
 * A BinaryXmlWireFormat implements the WireFormat interface for encoding and decoding in binary XML.
 * @constructor
 */
var BinaryXmlWireFormat = function BinaryXmlWireFormat() {
  // Inherit from WireFormat.
  WireFormat.call(this);
};

/**
 * Encode the interest and return a Uint8Array.
 * @param {Interest} interest
 * @returns {UInt8Array}
 */
BinaryXmlWireFormat.prototype.encodeInterest = function(interest) {
	var encoder = new BinaryXMLEncoder();
	BinaryXmlWireFormat.encodeInterest(interest, encoder);	
	return encoder.getReducedOstream();  
};

/**
 * Decode the input and put the result in interest.
 * @param {Interest} interest
 * @param {Uint8Array} input
 */
BinaryXmlWireFormat.prototype.decodeInterest = function(interest, input) {
	var decoder = new BinaryXMLDecoder(input);
  BinaryXmlWireFormat.decodeInterest(interest, decoder);
};

/**
 * Encode the contentObject and return a Uint8Array. 
 * @param {ContentObject} contentObject
 * @returns {Uint8Array}
 */
BinaryXmlWireFormat.prototype.encodeContentObject = function(contentObject) {
	var encoder = new BinaryXMLEncoder();
	BinaryXmlWireFormat.encodeContentObject(contentObject, encoder);	
	return encoder.getReducedOstream();  
};

/**
 * Decode the input and put the result in contentObject.
 * @param {ContentObject} contentObject
 * @param {Uint8Array} input
 */
BinaryXmlWireFormat.prototype.decodeContentObject = function(contentObject, input) {
	var decoder = new BinaryXMLDecoder(input);
  BinaryXmlWireFormat.decodeContentObject(contentObject, decoder);
};

// Default object.
BinaryXmlWireFormat.instance = new BinaryXmlWireFormat();

/**
 * Encode the interest by calling the operations on the encoder.
 * @param {Interest} interest
 * @param {BinaryXMLEncoder} encoder
 */
BinaryXmlWireFormat.encodeInterest = function(interest, encoder) {
	encoder.writeStartElement(NDNProtocolDTags.Interest);
		
	interest.name.to_ndnb(encoder);
	
	if (null != interest.minSuffixComponents) 
		encoder.writeElement(NDNProtocolDTags.MinSuffixComponents, interest.minSuffixComponents);	

	if (null != interest.maxSuffixComponents) 
		encoder.writeElement(NDNProtocolDTags.MaxSuffixComponents, interest.maxSuffixComponents);

	if (null != interest.publisherPublicKeyDigest)
		interest.publisherPublicKeyDigest.to_ndnb(encoder);
		
	if (null != interest.exclude)
		interest.exclude.to_ndnb(encoder);
		
	if (null != interest.childSelector) 
		encoder.writeElement(NDNProtocolDTags.ChildSelector, interest.childSelector);

	if (interest.DEFAULT_ANSWER_ORIGIN_KIND != interest.answerOriginKind && interest.answerOriginKind!=null) 
		encoder.writeElement(NDNProtocolDTags.AnswerOriginKind, interest.answerOriginKind);
		
	if (null != interest.scope) 
		encoder.writeElement(NDNProtocolDTags.Scope, interest.scope);
		
	if (null != interest.interestLifetime) 
		encoder.writeElement(NDNProtocolDTags.InterestLifetime, 
                DataUtils.nonNegativeIntToBigEndian((interest.interestLifetime / 1000.0) * 4096));
		
	if (null != interest.nonce)
		encoder.writeElement(NDNProtocolDTags.Nonce, interest.nonce);
		
	encoder.writeEndElement();
};

/**
 * Use the decoder to place the result in interest.
 * @param {Interest} interest
 * @param {BinaryXMLDecoder} decoder
 */
BinaryXmlWireFormat.decodeInterest = function(interest, decoder) {
	decoder.readStartElement(NDNProtocolDTags.Interest);

	interest.name = new Name();
	interest.name.from_ndnb(decoder);

	if (decoder.peekStartElement(NDNProtocolDTags.MinSuffixComponents))
		interest.minSuffixComponents = decoder.readIntegerElement(NDNProtocolDTags.MinSuffixComponents);
  else
    interest.minSuffixComponents = null;

	if (decoder.peekStartElement(NDNProtocolDTags.MaxSuffixComponents)) 
		interest.maxSuffixComponents = decoder.readIntegerElement(NDNProtocolDTags.MaxSuffixComponents);
  else
    interest.maxSuffixComponents = null;
			
	if (decoder.peekStartElement(NDNProtocolDTags.PublisherPublicKeyDigest)) {
		interest.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
		interest.publisherPublicKeyDigest.from_ndnb(decoder);
	}
  else
    interest.publisherPublicKeyDigest = null;

	if (decoder.peekStartElement(NDNProtocolDTags.Exclude)) {
		interest.exclude = new Exclude();
		interest.exclude.from_ndnb(decoder);
	}
  else
    interest.exclude = null;
		
	if (decoder.peekStartElement(NDNProtocolDTags.ChildSelector))
		interest.childSelector = decoder.readIntegerElement(NDNProtocolDTags.ChildSelector);
  else
    interest.childSelector = null;
		
	if (decoder.peekStartElement(NDNProtocolDTags.AnswerOriginKind))
		interest.answerOriginKind = decoder.readIntegerElement(NDNProtocolDTags.AnswerOriginKind);
  else
    interest.answerOriginKind = null;
		
	if (decoder.peekStartElement(NDNProtocolDTags.Scope))
		interest.scope = decoder.readIntegerElement(NDNProtocolDTags.Scope);
  else
    interest.scope = null;

	if (decoder.peekStartElement(NDNProtocolDTags.InterestLifetime))
		interest.interestLifetime = 1000.0 * DataUtils.bigEndianToUnsignedInt
               (decoder.readBinaryElement(NDNProtocolDTags.InterestLifetime)) / 4096;
  else
    interest.interestLifetime = null;              
		
	if (decoder.peekStartElement(NDNProtocolDTags.Nonce))
		interest.nonce = decoder.readBinaryElement(NDNProtocolDTags.Nonce);
  else
    interest.nonce = null;
		
	decoder.readEndElement();
};

/**
 * Encode the contentObject by calling the operations on the encoder.
 * @param {ContentObject} contentObject
 * @param {BinaryXMLEncoder} encoder
 */
BinaryXmlWireFormat.encodeContentObject = function(contentObject, encoder)  {
	//TODO verify name, SignedInfo and Signature is present
	encoder.writeStartElement(contentObject.getElementLabel());

	if (null != contentObject.signature) 
    contentObject.signature.to_ndnb(encoder);
		
	contentObject.startSIG = encoder.offset;

	if (null != contentObject.name) 
    contentObject.name.to_ndnb(encoder);
	
	if (null != contentObject.signedInfo) 
    contentObject.signedInfo.to_ndnb(encoder);

	encoder.writeElement(NDNProtocolDTags.Content, contentObject.content);
	
	contentObject.endSIG = encoder.offset;
	
	encoder.writeEndElement();
	
	contentObject.saveRawData(encoder.ostream);	
};

/**
 * Use the decoder to place the result in contentObject.
 * @param {ContentObject} contentObject
 * @param {BinaryXMLDecoder} decoder
 */
BinaryXmlWireFormat.decodeContentObject = function(contentObject, decoder) {
	// TODO VALIDATE THAT ALL FIELDS EXCEPT SIGNATURE ARE PRESENT
  decoder.readStartElement(contentObject.getElementLabel());

	if( decoder.peekStartElement(NDNProtocolDTags.Signature) ){
		contentObject.signature = new Signature();
		contentObject.signature.from_ndnb(decoder);
	}
  else
    contentObject.signature = null;
		
	contentObject.startSIG = decoder.offset;

	contentObject.name = new Name();
	contentObject.name.from_ndnb(decoder);
		
	if( decoder.peekStartElement(NDNProtocolDTags.SignedInfo) ){
		contentObject.signedInfo = new SignedInfo();
		contentObject.signedInfo.from_ndnb(decoder);
	}
  else
    contentObject.signedInfo = null;

  contentObject.content = decoder.readBinaryElement(NDNProtocolDTags.Content, null, true);
		
	contentObject.endSIG = decoder.offset;
		
	decoder.readEndElement();
		
	contentObject.saveRawData(decoder.input);
};
