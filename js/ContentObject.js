/*
 * @author: ucla-cs
 * This class represents ContentObject Objects
 */
var ContentObject = function ContentObject(_Name,_SignedInfo,_Content,_Signature){
	
	
	if (typeof _Name === 'string'){
		this.Name = new ContentName(_Name);
	}
	else{
		//TODO Check the class of _Name
		this.Name = _Name;
	}
	this.SignedInfo = _SignedInfo;
	this.Content=_Content;
	this.Signature = _Signature;

	
	this.StartSIG = null;
	this.EndSIG = null;
	
	this.StartSignedInfo = null;
	this.EndContent = null;
	
	this.rawSignatureData = null;
};

ContentObject.prototype.sign = function(){

	var n1 = this.encodeObject(this.Name);
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
	 
	enc.writeElement(CCNProtocolDTags.Content, this.Content);

	var num = enc.getReducedOstream();

	return num;

	
};

ContentObject.prototype.saveRawData = function(bytes){
	
	var sigBits = bytes.slice(this.StartSIG, this.EndSIG );

	this.rawSignatureData = sigBits;
};

ContentObject.prototype.decode = function(/*XMLDecoder*/ decoder) {

	// TODO VALIDATE THAT ALL FIELDS EXCEPT SIGNATURE ARE PRESENT

		decoder.readStartElement(this.getElementLabel());


		if( decoder.peekStartElement(CCNProtocolDTags.Signature) ){
			this.Signature = new Signature();
			this.Signature.decode(decoder);
		}
		
		//this.EndSIG = decoder.offset;

		this.StartSIG = decoder.offset;

		this.Name = new ContentName();
		this.Name.decode(decoder);
		
		//this.StartSignedInfo = decoder.offset;
	
		
		if( decoder.peekStartElement(CCNProtocolDTags.SignedInfo) ){
			this.SignedInfo = new SignedInfo();
			this.SignedInfo.decode(decoder);
		}
		
		this.Content = decoder.readBinaryElement(CCNProtocolDTags.Content);

		
		//this.EndContent = decoder.offset;
		this.EndSIG = decoder.offset;

		
		decoder.readEndElement();
		
		this.saveRawData(decoder.istream);
};

ContentObject.prototype.encode = function(/*XMLEncoder*/ encoder)  {

	//TODO verify Name, SignedInfo and Signature is present


	encoder.writeStartElement(this.getElementLabel());

	


	if(null!=this.Signature) this.Signature.encode(encoder);
	
	
	this.StartSIG = encoder.offset;
	

	if(null!=this.Name) this.Name.encode(encoder);
	
	//this.EndSIG = encoder.offset;
	//this.StartSignedInfo = encoder.offset;
	
	
	if(null!=this.SignedInfo) this.SignedInfo.encode(encoder);

	encoder.writeElement(CCNProtocolDTags.Content, this.Content);

	
	this.EndSIG = encoder.offset;
	
	//this.EndContent = encoder.offset;
	

	encoder.writeEndElement();
	
	this.saveRawData(encoder.ostream);
	
};

ContentObject.prototype.getElementLabel= function(){return CCNProtocolDTags.ContentObject;};
