/*
 * @author: ucla-cs
 * This class represents ContentObject Objects
 */
var ContentObject = function ContentObject(_name,_signedInfo,_content,_signature){
	
	
	if (typeof _name === 'string'){
		this.name = new ContentName(_name);
	}
	else{
		//TODO Check the class of _name
		this.name = _name;
	}
	this.SignedInfo = _signedInfo;
	this.content=_content;
	this.Signature = _signature;

	
	this.startSIG = null;
	this.endSIG = null;
	
	this.startSignedInfo = null;
	this.endContent = null;
	
	this.rawSignatureData = null;
};

ContentObject.prototype.sign = function(){

	var n1 = this.encodeObject(this.name);
	var n2 = this.encodeObject(this.SignedInfo);
	var n3 = this.encodeContent();
	
	var n = n1.concat(n2,n3);
	
	if(LOG>2)console.log('Signature Data is (binary) '+n);
	
	if(LOG>2)console.log('Signature Data is (RawString)');
	
	if(LOG>2)console.log( DataUtils.toString(n) );
	
	var sig = DataUtils.toString(n);

	
	var rsa = new RSAKey();
			
	rsa.readPrivateKeyFromPEMString(globalKeyManager.privateKey);
	
	//var hSig = rsa.signString(sig, "sha256");

	var hSig = rsa.signByteArrayWithSHA256(n);

	
	if(LOG>2)console.log('SIGNATURE SAVED IS');
	
	if(LOG>2)console.log(hSig);
	
	if(LOG>2)console.log(  DataUtils.toNumbers(hSig.trim()));

	this.Signature.Signature = DataUtils.toNumbers(hSig.trim());
	

};

ContentObject.prototype.encodeObject = function encodeObject(obj){
	var enc = new BinaryXMLEncoder();
 
	obj.encode(enc);
	
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
	
	var sigBits = bytes.slice(this.startSIG, this.endSIG );

	this.rawSignatureData = sigBits;
};

ContentObject.prototype.from_ccnb = function(/*XMLDecoder*/ decoder) {

	// TODO VALIDATE THAT ALL FIELDS EXCEPT SIGNATURE ARE PRESENT

		decoder.readStartElement(this.getElementLabel());


		if( decoder.peekStartElement(CCNProtocolDTags.Signature) ){
			this.Signature = new Signature();
			this.Signature.decode(decoder);
		}
		
		//this.endSIG = decoder.offset;

		this.startSIG = decoder.offset;

		this.name = new ContentName();
		this.name.decode(decoder);
		
		//this.startSignedInfo = decoder.offset;
	
		
		if( decoder.peekStartElement(CCNProtocolDTags.SignedInfo) ){
			this.SignedInfo = new SignedInfo();
			this.SignedInfo.decode(decoder);
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

	


	if(null!=this.Signature) this.Signature.encode(encoder);
	
	
	this.startSIG = encoder.offset;
	

	if(null!=this.name) this.name.encode(encoder);
	
	//this.endSIG = encoder.offset;
	//this.startSignedInfo = encoder.offset;
	
	
	if(null!=this.SignedInfo) this.SignedInfo.encode(encoder);

	encoder.writeElement(CCNProtocolDTags.Content, this.content);

	
	this.endSIG = encoder.offset;
	
	//this.endContent = encoder.offset;
	

	encoder.writeEndElement();
	
	this.saveRawData(encoder.ostream);
	
};

ContentObject.prototype.getElementLabel= function(){return CCNProtocolDTags.ContentObject;};
