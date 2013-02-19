/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents ContentObject Objects
 */
var ContentObject = function ContentObject(_name,_signedInfo,_content,_signature){
	
	
	if (typeof _name == 'string') {
		this.name = new Name(_name);
	}
	else{
		//TODO Check the class of _name
		this.name = _name;
	}
	this.signedInfo = _signedInfo;
	
	if (typeof _content == 'string') {
		this.content = DataUtils.toNumbersFromString(_content);
	} else {
		this.content = _content;
	}
	
	this.signature = _signature;

	
	this.startSIG = null;
	this.endSIG = null;
	
	//this.startSignedInfo = null;
	this.endContent = null;
	
	this.rawSignatureData = null;
};

ContentObject.prototype.sign = function(){

	var n1 = this.encodeObject(this.name);
	var n2 = this.encodeObject(this.signedInfo);
	var n3 = this.encodeContent();
	/*console.log('sign: ');
	console.log(n1);
	console.log(n2);
	console.log(n3);*/
	
	//var n = n1.concat(n2,n3);
	var tempBuf = new ArrayBuffer(n1.length + n2.length + n3.length);
	var n = new Uint8Array(tempBuf);
	//console.log(n);
	n.set(n1, 0);
	//console.log(n);
	n.set(n2, n1.length);
	//console.log(n);
	n.set(n3, n1.length + n2.length);
	//console.log(n);
	
	if(LOG>4)console.log('Signature Data is (binary) '+n);
	
	if(LOG>4)console.log('Signature Data is (RawString)');
	
	if(LOG>4)console.log( DataUtils.toString(n) );
	
	//var sig = DataUtils.toString(n);

	
	var rsa = new RSAKey();
			
	rsa.readPrivateKeyFromPEMString(globalKeyManager.privateKey);
	
	//var hSig = rsa.signString(sig, "sha256");

	var hSig = rsa.signByteArrayWithSHA256(n);

	
	if(LOG>4)console.log('SIGNATURE SAVED IS');
	
	if(LOG>4)console.log(hSig);
	
	if(LOG>4)console.log(  DataUtils.toNumbers(hSig.trim()));

	this.signature.signature = DataUtils.toNumbers(hSig.trim());
	

};

ContentObject.prototype.encodeObject = function encodeObject(obj){
	var enc = new BinaryXMLEncoder();
 
	obj.to_ccnb(enc);
	
	var num = enc.getReducedOstream();

	return num;

	
};

ContentObject.prototype.encodeContent = function encodeContent(obj){
	var enc = new BinaryXMLEncoder();
	 
	enc.writeElement(CCNProtocolDTags.Content, this.content);

	var num = enc.getReducedOstream();

	return num;

	
};

ContentObject.prototype.saveRawData = function(bytes){
	
	var sigBits = bytes.subarray(this.startSIG, this.endSIG);

	this.rawSignatureData = sigBits;
};

ContentObject.prototype.from_ccnb = function(/*XMLDecoder*/ decoder) {

	// TODO VALIDATE THAT ALL FIELDS EXCEPT SIGNATURE ARE PRESENT

		decoder.readStartElement(this.getElementLabel());


		if( decoder.peekStartElement(CCNProtocolDTags.Signature) ){
			this.signature = new Signature();
			this.signature.from_ccnb(decoder);
		}
		
		//this.endSIG = decoder.offset;

		this.startSIG = decoder.offset;

		this.name = new Name();
		this.name.from_ccnb(decoder);
		
		//this.startSignedInfo = decoder.offset;
	
		
		if( decoder.peekStartElement(CCNProtocolDTags.SignedInfo) ){
			this.signedInfo = new SignedInfo();
			this.signedInfo.from_ccnb(decoder);
		}
		
		this.content = decoder.readBinaryElement(CCNProtocolDTags.Content);

		
		//this.endContent = decoder.offset;
		this.endSIG = decoder.offset;

		
		decoder.readEndElement();
		
		this.saveRawData(decoder.istream);
};

ContentObject.prototype.to_ccnb = function(/*XMLEncoder*/ encoder)  {

	//TODO verify name, SignedInfo and Signature is present


	encoder.writeStartElement(this.getElementLabel());

	


	if(null!=this.signature) this.signature.to_ccnb(encoder);
	
	
	this.startSIG = encoder.offset;
	

	if(null!=this.name) this.name.to_ccnb(encoder);
	
	//this.endSIG = encoder.offset;
	//this.startSignedInfo = encoder.offset;
	
	
	if(null!=this.signedInfo) this.signedInfo.to_ccnb(encoder);

	encoder.writeElement(CCNProtocolDTags.Content, this.content);

	
	this.endSIG = encoder.offset;
	
	//this.endContent = encoder.offset;
	

	encoder.writeEndElement();
	
	this.saveRawData(encoder.ostream);
	
};

ContentObject.prototype.getElementLabel= function(){return CCNProtocolDTags.ContentObject;};

/**
 * Signature
 */
var Signature = function Signature(_witness,_signature,_digestAlgorithm) {
	
    this.Witness = _witness;//byte [] _witness;
	this.signature = _signature;//byte [] _signature;
	this.digestAlgorithm = _digestAlgorithm//String _digestAlgorithm;
};

Signature.prototype.from_ccnb =function( decoder) {
		decoder.readStartElement(this.getElementLabel());
		
		if(LOG>4)console.log('STARTED DECODING SIGNATURE');
		
		if (decoder.peekStartElement(CCNProtocolDTags.DigestAlgorithm)) {
			if(LOG>4)console.log('DIGIEST ALGORITHM FOUND');
			this.digestAlgorithm = decoder.readUTF8Element(CCNProtocolDTags.DigestAlgorithm); 
		}
		if (decoder.peekStartElement(CCNProtocolDTags.Witness)) {
			if(LOG>4)console.log('WITNESS FOUND');
			this.Witness = decoder.readBinaryElement(CCNProtocolDTags.Witness); 
		}
		
		//FORCE TO READ A SIGNATURE

			if(LOG>4)console.log('SIGNATURE FOUND');
			this.signature = decoder.readBinaryElement(CCNProtocolDTags.SignatureBits);

		decoder.readEndElement();
	
};


Signature.prototype.to_ccnb= function( encoder){
    	
	if (!this.validate()) {
		throw new Error("Cannot encode: field values missing.");
	}
	
	encoder.writeStartElement(this.getElementLabel());
	
	if ((null != this.digestAlgorithm) && (!this.digestAlgorithm.equals(CCNDigestHelper.DEFAULT_DIGEST_ALGORITHM))) {
		encoder.writeElement(CCNProtocolDTags.DigestAlgorithm, OIDLookup.getDigestOID(this.DigestAlgorithm));
	}
	
	if (null != this.Witness) {
		// needs to handle null witness
		encoder.writeElement(CCNProtocolDTags.Witness, this.Witness);
	}

	encoder.writeElement(CCNProtocolDTags.SignatureBits, this.signature);

	encoder.writeEndElement();   		
};

Signature.prototype.getElementLabel = function() { return CCNProtocolDTags.Signature; };


Signature.prototype.validate = function() {
		return null != this.signature;
};


/**
 * SignedInfo
 */
var ContentType = {DATA:0, ENCR:1, GONE:2, KEY:3, LINK:4, NACK:5};
var ContentTypeValue = {0:0x0C04C0, 1:0x10D091,2:0x18E344,3:0x28463F,4:0x2C834A,5:0x34008A};
var ContentTypeValueReverse = {0x0C04C0:0, 0x10D091:1,0x18E344:2,0x28463F:3,0x2C834A:4,0x34008A:5};

var SignedInfo = function SignedInfo(_publisher,_timestamp,_type,_locator,_freshnessSeconds,_finalBlockID){

	//TODO, Check types

    this.publisher = _publisher; //publisherPublicKeyDigest
    this.timestamp=_timestamp; // CCN Time
    this.type=_type; // ContentType
    this.locator =_locator;//KeyLocator
    this.freshnessSeconds =_freshnessSeconds; // Integer
    this.finalBlockID=_finalBlockID; //byte array
    
    // SWT: merge setFields() method into constructor
    this.setFields();

};

SignedInfo.prototype.setFields = function(){
	//BASE64 -> RAW STRING
	
	//this.locator = new KeyLocator(  DataUtils.toNumbersFromString(stringCertificate)  ,KeyLocatorType.CERTIFICATE );
	
	var publicKeyHex = globalKeyManager.publicKey;

	if(LOG>4)console.log('PUBLIC KEY TO WRITE TO CONTENT OBJECT IS ');
	if(LOG>4)console.log(publicKeyHex);
	
	var publicKeyBytes = DataUtils.toNumbers(globalKeyManager.publicKey) ; 

	

	//var stringCertificate = DataUtils.base64toString(globalKeyManager.certificate);
	
	//if(LOG>3)console.log('string Certificate is '+stringCertificate);

	//HEX -> BYTE ARRAY
	//var publisherkey = DataUtils.toNumbers(hex_sha256(stringCertificate));
	
	//if(LOG>3)console.log('publisher key is ');
	//if(LOG>3)console.log(publisherkey);
	
	var publisherKeyDigest = hex_sha256_from_bytes(publicKeyBytes);

	this.publisher = new PublisherPublicKeyDigest(  DataUtils.toNumbers(  publisherKeyDigest )  );
	
	//this.publisher = new PublisherPublicKeyDigest(publisherkey);

	var d = new Date();
	
	var time = d.getTime();
	

    this.timestamp = new CCNTime( time );
    
    if(LOG>4)console.log('TIME msec is');

    if(LOG>4)console.log(this.timestamp.msec);

    //DATA
	this.type = 0;//0x0C04C0;//ContentTypeValue[ContentType.DATA];
	
	//if(LOG>4)console.log('toNumbersFromString(stringCertificate) '+DataUtils.toNumbersFromString(stringCertificate));
	
	if(LOG>4)console.log('PUBLIC KEY TO WRITE TO CONTENT OBJECT IS ');
	if(LOG>4)console.log(publicKeyBytes);

	this.locator = new KeyLocator(  publicKeyBytes  ,KeyLocatorType.KEY );

	//this.locator = new KeyLocator(  DataUtils.toNumbersFromString(stringCertificate)  ,KeyLocatorType.CERTIFICATE );

};

SignedInfo.prototype.from_ccnb = function( decoder){

		decoder.readStartElement( this.getElementLabel() );
		
		if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
			if(LOG>4)console.log('DECODING PUBLISHER KEY');
			this.publisher = new PublisherPublicKeyDigest();
			this.publisher.from_ccnb(decoder);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.Timestamp)) {
			if(LOG>4)console.log('DECODING TIMESTAMP');
			this.timestamp = decoder.readDateTime(CCNProtocolDTags.Timestamp);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.Type)) {
			var binType = decoder.readBinaryElement(CCNProtocolDTags.Type);//byte [] 
		
			
			//TODO Implement type of Key Reading
			
			if(LOG>4)console.log('Binary Type of of Signed Info is '+binType);

			this.type = binType;
			
			
			//TODO Implement type of Key Reading
			
			
			if (null == this.type) {
				throw new Error("Cannot parse signedInfo type: bytes.");
			}
			
		} else {
			this.type = ContentType.DATA; // default
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
			this.freshnessSeconds = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds);
			if(LOG>4)console.log('FRESHNESS IN SECONDS IS '+ this.freshnessSeconds);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.FinalBlockID)) {
			if(LOG>4)console.log('DECODING FINAL BLOCKID');
			this.finalBlockID = decoder.readBinaryElement(CCNProtocolDTags.FinalBlockID);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.KeyLocator)) {
			if(LOG>4)console.log('DECODING KEY LOCATOR');
			this.locator = new KeyLocator();
			this.locator.from_ccnb(decoder);
		}
				
		decoder.readEndElement();
};

SignedInfo.prototype.to_ccnb = function( encoder)  {
		if (!this.validate()) {
			throw new Error("Cannot encode : field values missing.");
		}
		encoder.writeStartElement(this.getElementLabel());
		
		if (null!=this.publisher) {
			if(LOG>3) console.log('ENCODING PUBLISHER KEY' + this.publisher.publisherPublicKeyDigest);

			this.publisher.to_ccnb(encoder);
		}

		if (null!=this.timestamp) {
			encoder.writeDateTime(CCNProtocolDTags.Timestamp, this.timestamp );
		}
		
		if (null!=this.type && this.type !=0) {
			
			encoder.writeElement(CCNProtocolDTags.type, this.type);
		}
		
		if (null!=this.freshnessSeconds) {
			encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);
		}

		if (null!=this.finalBlockID) {
			encoder.writeElement(CCNProtocolDTags.FinalBlockID, this.finalBlockID);
		}

		if (null!=this.locator) {
			this.locator.to_ccnb(encoder);
		}

		encoder.writeEndElement();   		
};
	
SignedInfo.prototype.valueToType = function(){
	//for (Entry<byte [], ContentType> entry : ContentValueTypes.entrySet()) {
		//if (Arrays.equals(value, entry.getKey()))
			//return entry.getValue();
		//}
	return null;
	
};

SignedInfo.prototype.getElementLabel = function() { 
	return CCNProtocolDTags.SignedInfo;
};

SignedInfo.prototype.validate = function() {
		// We don't do partial matches any more, even though encoder/decoder
		// is still pretty generous.
		if (null ==this.publisher || null==this.timestamp ||null== this.locator)
			return false;
		return true;
};
