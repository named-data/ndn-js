/* This file is created by running make-ndn-js.jsm.sh in this directory.
 * It concatenates ndn-js-header.txt with all the ndn-js source files to
 *   make ndn-js.jsm .
 * author: ucla-cs
 * See COPYING for copyright and distribution information.
 */

var EXPORTED_SYMBOLS = ["NDN", "Closure", "Name", "Interest", "ContentObject", "DataUtils"];

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("resource://gre/modules/NetUtil.jsm");

// LOG is used by some of the NDN code.
var LOG = 0;

// jsbn.js needs the navigator object which isn't defined in XPCOM, so make a local hack.
var navigator = {
    appName: "Netscape"
};

// Some code calls console.log without checking LOG>0.  Until this is cleaned up, make a local hack console.
var console = {
    log: function(message) {
        dump(message + "\n");
    }
};

/* 
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * Provide the callback closure for the async communication methods in the NDN class.
 * This is a port of Closure.py from PyCCN, written by: 
 * Derek Kulinski <takeda@takeda.tk>
 * Jeff Burke <jburke@ucla.edu>
 */

/*
 * Create a subclass of Closure and pass an object to async calls.
 */
var Closure = function Closure() {
	// I don't think storing NDN's closure is needed
	// and it creates a reference loop, as of now both
	// of those variables are never set -- Derek
	//
	// Use instance variables to return data to callback
	this.ndn_data = null;  // this holds the ndn_closure
    this.ndn_data_dirty = false;
};

// Upcall result
Closure.RESULT_ERR               = -1; // upcall detected an error
Closure.RESULT_OK                =  0; // normal upcall return
Closure.RESULT_REEXPRESS         =  1; // reexpress the same interest again
Closure.RESULT_INTEREST_CONSUMED =  2; // upcall claims to consume interest
Closure.RESULT_VERIFY            =  3; // force an unverified result to be verified

// Upcall kind
Closure.UPCALL_FINAL              = 0; // handler is about to be deregistered
Closure.UPCALL_INTEREST           = 1; // incoming interest
Closure.UPCALL_CONSUMED_INTEREST  = 2; // incoming interest, someone has answered
Closure.UPCALL_CONTENT            = 3; // incoming verified content
Closure.UPCALL_INTEREST_TIMED_OUT = 4; // interest timed out
Closure.UPCALL_CONTENT_UNVERIFIED = 5; // content that has not been verified
Closure.UPCALL_CONTENT_BAD        = 6; // verification failed

/*
 * Override this in your subclass.
 * If you're getting strange errors in upcall()
 * check your code whether you're returning a value.
 */
Closure.prototype.upcall = function(kind, upcallInfo) {
	//dump('upcall ' + this + " " + kind + " " + upcallInfo + "\n");
	return Closure.RESULT_OK;
};

var UpcallInfo = function UpcallInfo(ndn, interest, matchedComps, contentObject) {
	this.ndn = ndn;  // NDN object (not used)
	this.interest = interest;  // Interest object
	this.matchedComps = matchedComps;  // int
	this.contentObject = contentObject;  // Content object
};

UpcallInfo.prototype.toString = function() {
	var ret = "ndn = " + this.ndn;
	ret += "\nInterest = " + this.interest;
	ret += "\nmatchedComps = " + this.matchedComps;
	ret += "\nContentObject: " + this.contentObject;
	return ret;
}

/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents the top-level object for communicating with an NDN host.
 */

/**
 * host is default '127.0.0.1'.
 * port is default 9695.
 */
var NDN = function NDN(host, port){
	this.host = (host || '127.0.0.1');
	this.port = (port || 9695);
};

NDN.prototype.createRoute = function(host,port){
	this.host=host;
	this.port=port;
}

NDN.prototype.get = function(message){
	if(this.host!=null && this.port!=null){
		var output ='';
		message = message.trim();
		if(message==null || message =="" ){
			console.log('INVALID INPUT TO GET');
			return null;
		}
		
		
		//var array = Name.createNameArray(message);

		int = new Interest(new Name(message));

		int.InterestLifetime = 4200;
		
		var hex = encodeToHexInterest(int);
		
		//var result = get_java_socket_bridge().connectAndStart(ndnurl,ndnport,hex);
		
		var result = get(this.host,this.port, hex);


		if(LOG>0)console.log('BINARY RESPONSE IS ' +result);
		
		if(result==null || result==undefined || result =="" ){
			/*if(result[0] != '0'||result[1]!='4') {
				if(LOG>2)console.log('INVALID ANSWER');
			}*/
			return null;
		}
		
		else{
			
			co = decodeHexContentObject(result);

			if(LOG>2) {
				console.log('DECODED CONTENT OBJECT');
				console.log(co);
			}
			return co;
		}
	}
	else{

		console.log('ERROR URL OR PORT NOT SET');

		return null;

	}
	

}

NDN.prototype.put = function(name,content){
	if(this.host!=null && this.port!=null){
		
		var co = this.get("/%C1.M.S.localhost/%C1.M.SRV/ccnd");
		
		if(!co || !co.signedInfo || !co.signedInfo.publisher || !co.signedInfo.publisher.publisherPublicKeyDigest){
			alert("Cannot contact router");
			
			return null;
		}
		
		var ccnxnodename = co.signedInfo.publisher.publisherPublicKeyDigest;
		
		name = name.trim();
		
		var fe = new ForwardingEntry('selfreg',new Name(name),null, null, 3,2147483647);
		
		var bytes = encodeForwardingEntry(fe);
		
		
		var si = new SignedInfo();
		si.setFields();
		
		var co = new ContentObject(new Name(),si,bytes,new Signature()); 
		co.sign();
		
		var coBinary = encodeToBinaryContentObject(co);
		
		//var ccnxnodename = unescape('%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F');
		
		var interestName = new Name(['ccnx',ccnxnodename,'selfreg',coBinary]);

		int = new Interest(interestName);
		int.scope = 1;
		
		var hex = encodeToHexInterest(int);

		console.log('GOING TO PUT INTEREST OBJECT');
		
		console.log(hex);
		
		//var result = put(this.host,this.port, hex,name);

		
	//if(LOG>3)console.log('received interest'); //from host'+ host +':'+port+' with name '+name);
	
	//if(LOG>3)console.log('DATA ');
	
	//if(LOG>3)console.log(result);
	
	//interest = decodeHexInterest(result);
	
	//console.log('SUCCESSFULLY PARSED INTEREST');
	
	console.log('CREATING ANSWER');
	var si = new SignedInfo();
	si.setFields();
	
	var answer = DataUtils.toNumbersFromString(content);

	var co = new ContentObject(new Name(name),si,answer,new Signature()); 
	co.sign();
	
	
	var outputHex = encodeToHexContentObject(co);
	
	//console.log('SENDING ANSWER');

	//return get_java_socket_bridge().putAnswer(outputHex,name);

	var result = put(this.host,this.port, hex,name,outputHex);


	return result;
	}
	else{
		console.log('ERROR URL OR PORT NOT SET');

		return null;
	}
}

/** Encode name as an Interest. If template is not null, use its attributes.
 *  Send the interest to host:port, read the entire response and call
 *  closure.upcall(Closure.UPCALL_CONTENT (or Closure.UPCALL_CONTENT_UNVERIFIED),
 *                 new UpcallInfo(this, interest, 0, contentObject)).
 */
NDN.prototype.expressInterest = function(
        // Name
        name,
        // Closure
        closure,
        // Interest
        template) {
	if (this.host == null || this.port == null) {
		dump('ERROR host OR port NOT SET\n');
        return;
    }
    
	interest = new Interest(name);
    if (template != null) {
        // TODO: Exactly what do we copy from template?
        interest.interestLifetime = template.interestLifetime;
    }
    else
        interest.interestLifetime = 4200;
	var outputHex = encodeToHexInterest(interest);
		
	var dataListener = {
		onReceivedData : function(result) {
			if (result == null || result == undefined || result.length == 0)
				listener.onReceivedContentObject(null);
			else {
                var decoder = new BinaryXMLDecoder(result);	
                var co = new ContentObject();
                co.from_ccnb(decoder);
                   					
				if(LOG>2) {
					dump('DECODED CONTENT OBJECT\n');
					dump(co);
					dump('\n');
				}
					
                // TODO: verify the content object and set kind to UPCALL_CONTENT.
				var result = closure.upcall(Closure.UPCALL_CONTENT_UNVERIFIED,
                               new UpcallInfo(this, interest, 0, co));
                // TODO: Check result for Closure.RESULT_OK, etc.          
			}
		}
	}
        
	return getAsync(this.host, this.port, outputHex, dataListener);
};


/* 
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * Implement getAsync and putAsync used by NDN using nsISocketTransportService.
 * This is used inside Firefox XPCOM modules.
 */

// Assume already imported the following:
// Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
// Components.utils.import("resource://gre/modules/NetUtil.jsm");

/** Convert outputHex to binary, send to host:port and call listener.onReceivedData(data)
 *    where data is a byte array.
 */
function getAsync(host, port, outputHex, listener) {
    readAllFromSocket(host, port, DataUtils.hexToRawString(outputHex), listener);
}

/** Send outputData to host:port, read the entire response and call listener.onReceivedData(data)
 *    where data is a byte array.
 *  Code derived from http://stackoverflow.com/questions/7816386/why-nsiscriptableinputstream-is-not-working .
 */
function readAllFromSocket(host, port, outputData, listener) {
	var transportService = Components.classes["@mozilla.org/network/socket-transport-service;1"].getService
	(Components.interfaces.nsISocketTransportService);
	var pump = Components.classes["@mozilla.org/network/input-stream-pump;1"].createInstance
	(Components.interfaces.nsIInputStreamPump);
	var transport = transportService.createTransport(null, 0, host, port, null);
	var outStream = transport.openOutputStream(1, 0, 0);
	outStream.write(outputData, outputData.length);
	outStream.flush();
	var inStream = transport.openInputStream(0, 0, 0);
	var dataListener = {
		data: [],
        structureDecoder: new BinaryXMLStructureDecoder(),
		calledOnReceivedData: false,
        debugNOnDataAvailable: 0,
		
		onStartRequest: function (request, context) {
		},
		onStopRequest: function (request, context, status) {
			inStream.close();
			outStream.close();
			if (!this.calledOnReceivedData) {
				this.calledOnReceivedData = true;
				listener.onReceivedData(this.data);
			}
		},
		onDataAvailable: function (request, context, _inputStream, offset, count) {
            if (this.calledOnReceivedData)
                // Already finished.  Ignore extra data.
                return;
            
			try {
                this.debugNOnDataAvailable += 1;
				// Ignore _inputStream and use inStream.
				// Use readInputStreamToString to handle binary data.
				var rawData = NetUtil.readInputStreamToString(inStream, count);
                this.data = this.data.concat(DataUtils.toNumbersFromString(rawData));
				
				// Scan the input to check if a whole ccnb object has been read.
                if (this.structureDecoder.findElementEnd(this.data))
                    // Finish.
                    this.onStopRequest();
			} catch (ex) {
				dump("readAllFromSocket.onDataAvailable exception: " + ex + "\n");
			}
		}
    };
	
	pump.init(inStream, -1, -1, 0, 0, true);
    pump.asyncRead(dataListener, null);
}

/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class contains all CCNx tags
 */


var CCNProtocolDTags = {

	/**
	 * Note if you add one of these, add it to the reverse string map as well.
	 * Emphasize getting the work done at compile time over trying to make something
	 * flexible and developer error-proof.
	 */

	 Any : 13,
	 Name : 14,
	 Component : 15,
	 Certificate : 16,
	 Collection : 17,
	 CompleteName : 18,
	 Content : 19,
	 SignedInfo : 20,
	 ContentDigest : 21,
	 ContentHash : 22,
	 Count : 24,
	 Header : 25,
	 Interest : 26,	/* 20090915 */
	 Key : 27,
	 KeyLocator : 28,
	 KeyName : 29,
	 Length : 30,
	 Link : 31,
	 LinkAuthenticator : 32,
	 NameComponentCount : 33,	/* DeprecatedInInterest */
	 RootDigest : 36,
	 Signature : 37,
	 Start : 38,
	 Timestamp : 39,
	 Type : 40,
	 Nonce : 41,
	 Scope : 42,
	 Exclude : 43,
	 Bloom : 44,
	 BloomSeed : 45,
	 AnswerOriginKind : 47,
	 InterestLifetime : 48,
	 Witness : 53,
	 SignatureBits : 54,
	 DigestAlgorithm : 55,
	 BlockSize : 56,
	 FreshnessSeconds : 58,
	 FinalBlockID : 59,
	 PublisherPublicKeyDigest : 60,
	 PublisherCertificateDigest : 61,
	 PublisherIssuerKeyDigest : 62,
	 PublisherIssuerCertificateDigest : 63,
	 ContentObject : 64,	/* 20090915 */
	 WrappedKey : 65,
	 WrappingKeyIdentifier : 66,
	 WrapAlgorithm : 67,
	 KeyAlgorithm : 68,
	 Label : 69,
	 EncryptedKey : 70,
	 EncryptedNonceKey : 71,
	 WrappingKeyName : 72,
	 Action : 73,
	 FaceID : 74,
	 IPProto : 75,
	 Host : 76,
	 Port : 77,
	 MulticastInterface : 78,
	 ForwardingFlags : 79,
	 FaceInstance : 80,
	 ForwardingEntry : 81,
	 MulticastTTL : 82,
	 MinSuffixComponents : 83,
	 MaxSuffixComponents : 84,
	 ChildSelector : 85,
	 RepositoryInfo : 86,
	 Version : 87,
	 RepositoryVersion : 88,
	 GlobalPrefix : 89,
	 LocalName : 90,
	 Policy : 91,
	 Namespace : 92,
	 GlobalPrefixName : 93,
	 PolicyVersion : 94,
	 KeyValueSet : 95,
	 KeyValuePair : 96,
	 IntegerValue : 97,
	 DecimalValue : 98,
	 StringValue : 99,
	 BinaryValue : 100,
	 NameValue : 101,
	 Entry : 102,
	 ACL : 103,
	 ParameterizedName : 104,
	 Prefix : 105,
	 Suffix : 106,
	 Root : 107,
	 ProfileName : 108,
	 Parameters : 109,
	 InfoString : 110,
	// 111 unallocated
	 StatusResponse : 112,
	 StatusCode : 113,
	 StatusText : 114,

	// Sync protocol
	 SyncNode : 115,
	 SyncNodeKind : 116,
	 SyncNodeElement : 117,
	 SyncVersion : 118,
	 SyncNodeElements : 119,
	 SyncContentHash : 120,
	 SyncLeafCount : 121,
	 SyncTreeDepth : 122,
	 SyncByteCount : 123,
	 ConfigSlice : 124,
	 ConfigSliceList : 125,
	 ConfigSliceOp : 126,

	// Remember to keep in sync with schema/tagnames.csvsdict
	 CCNProtocolDataUnit : 17702112,
	 CCNPROTOCOL_DATA_UNIT : "CCNProtocolDataUnit"
};

var CCNProtocolDTagsStrings = [
	null, null, null, null, null, null, null, null, null, null, null,
	null, null,
	"Any", "Name", "Component", "Certificate", "Collection", "CompleteName",
	"Content", "SignedInfo", "ContentDigest", "ContentHash", null, "Count", "Header",
	"Interest", "Key", "KeyLocator", "KeyName", "Length", "Link", "LinkAuthenticator",
	"NameComponentCount", null, null, "RootDigest", "Signature", "Start", "Timestamp", "Type",
	"Nonce", "Scope", "Exclude", "Bloom", "BloomSeed", null, "AnswerOriginKind",
	"InterestLifetime", null, null, null, null, "Witness", "SignatureBits", "DigestAlgorithm", "BlockSize",
	null, "FreshnessSeconds", "FinalBlockID", "PublisherPublicKeyDigest", "PublisherCertificateDigest",
	"PublisherIssuerKeyDigest", "PublisherIssuerCertificateDigest", "ContentObject",
	"WrappedKey", "WrappingKeyIdentifier", "WrapAlgorithm", "KeyAlgorithm", "Label",
	"EncryptedKey", "EncryptedNonceKey", "WrappingKeyName", "Action", "FaceID", "IPProto",
	"Host", "Port", "MulticastInterface", "ForwardingFlags", "FaceInstance",
	"ForwardingEntry", "MulticastTTL", "MinSuffixComponents", "MaxSuffixComponents", "ChildSelector",
	"RepositoryInfo", "Version", "RepositoryVersion", "GlobalPrefix", "LocalName",
	"Policy", "Namespace", "GlobalPrefixName", "PolicyVersion", "KeyValueSet", "KeyValuePair",
	"IntegerValue", "DecimalValue", "StringValue", "BinaryValue", "NameValue", "Entry",
	"ACL", "ParameterizedName", "Prefix", "Suffix", "Root", "ProfileName", "Parameters",
	"InfoString", null,
    "StatusResponse", "StatusCode", "StatusText", "SyncNode", "SyncNodeKind", "SyncNodeElement",
    "SyncVersion", "SyncNodeElements", "SyncContentHash", "SyncLeafCount", "SyncTreeDepth", "SyncByteCount",
    "ConfigSlice", "ConfigSliceList", "ConfigSliceOp" ];


//TESTING
//console.log(exports.CCNProtocolDTagsStrings[17]);


/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents CCNTime Objects
 */

var CCNTime = function CCNTime(
                               
		input) {




	this.NANOS_MAX = 999877929;
	
	/*if(typeof input =='object'){
		this.longDate = DataUtils.byteArrayToUnsignedLong(input);
		this.binaryDate = input;
	}*/
	if(typeof input =='number'){
		this.msec = input;
		//this.binaryDate = DataUtils.unsignedLongToByteArray(input);

	}
	else{
		if(LOG>1) console.log('UNRECOGNIZED TYPE FOR TIME');
	}
};


CCNTime.prototype.getJavascriptDate = function(){
	var d = new Date();
	d.setTime( this.msec );
	return d
};

	/**
	 * Create a CCNTime
	 * @param timestamp source timestamp to initialize from, some precision will be lost
	 */


	/**
	 * Create a CCNTime from its binary encoding
	 * @param binaryTime12 the binary representation of a CCNTime
	 */
/*CCNTime.prototype.setDateBinary = function(
	//byte [] 
		binaryTime12) {


	if ((null == binaryTime12) || (binaryTime12.length == 0)) {
		throw new IllegalArgumentException("Invalid binary time!");
	}
	

	value = 0;
	for(i = 0; i < binaryTime12.length; i++) {
		value = value << 8;
		b = (binaryTime12[i]) & 0xFF;
		value |= b;
	}

	//this.date = new Date(value);

};

//byte[]
CCNTime.prototype.toBinaryTime = function() {

	return this.msec; //unsignedLongToByteArray(this.date.getTime());

}*/
/*
unsignedLongToByteArray= function( value) {
	if( 0 == value )
		return [0];

	if( 0 <= value && value <= 0x00FF ) {
		//byte [] 
		bb = new Array[1];
		bb[0] = (value & 0x00FF);
		return bb;
	}

	
	//byte [] 
	out = null;
	//int
	offset = -1;
	for(var i = 7; i >=0; --i) {
		//byte
		b = ((value >> (i * 8)) & 0xFF);
		if( out == null && b != 0 ) {
			out = new Array(i+1);//byte[i+1];
			offset = i;
		}
		if( out != null )
			out[ offset - i ] = b;
	}
	return out;
}*/
	

/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents a Name
 */
 

var Name = function Name(_components){

	if( typeof _components == 'string') {
		
		if(LOG>3)console.log('Content Name String '+_components);
		this.components = Name.makeBlob(Name.createNameArray(_components));
	}
	else if(typeof _components === 'object' && _components instanceof Array ){
		
		if(LOG>4)console.log('Content Name Array '+_components);
		this.components = Name.makeBlob(_components);

	}
	else if(_components==null){
		this.components =[];
	}
	else{

		if(LOG>1)console.log("NO CONTENT NAME GIVEN");

	}
};

Name.prototype.getName=function(){
	
	var output = "";
	
	for(var i=0;i<this.components.length;i++){
		output+= "/"+ DataUtils.toString(this.components[i]);
	}
	
	return output;
	
};

Name.makeBlob=function(name){
	
	var blobArrays = new Array(name.length);

	for(var i=0;i<name.length;i++){
		if(typeof name[i] == 'string')
			blobArrays[i]= DataUtils.toNumbersFromString( name[i] );
		else if(typeof name[i] == 'object')
			blobArrays[i]= name[i] ;
		else 
			if(LOG>4)console.log('NAME COMPONENT INVALID');
	}
	
	return blobArrays;
};

Name.createNameArray=function(name){


	name = unescape(name);
	
	var array = name.split('/');

	
	if(name[0]=="/")
		array=array.slice(1,array.length);
		
	if(name[name.length-1]=="/")
		array=array.slice(0,array.length-1);
	
	return array;
}


Name.prototype.from_ccnb = function(/*XMLDecoder*/ decoder)  {
		decoder.readStartElement(this.getElementLabel());

		
		this.components = new Array(); //new ArrayList<byte []>();

		while (decoder.peekStartElement(CCNProtocolDTags.Component)) {
			this.add(decoder.readBinaryElement(CCNProtocolDTags.Component));
		}
		
		decoder.readEndElement();
};

Name.prototype.to_ccnb = function(/*XMLEncoder*/ encoder)  {
		
		if( this.components ==null ) 
			throw new Error("CANNOT ENCODE EMPTY CONTENT NAME");

		encoder.writeStartElement(this.getElementLabel());
		var count = this.components.length;
		for (var i=0; i < count; i++) {
			encoder.writeElement(CCNProtocolDTags.Component, this.components[i]);
		}
		encoder.writeEndElement();
};

Name.prototype.getElementLabel = function(){
	return CCNProtocolDTags.Name;
};

Name.prototype.add = function(param){
	return this.components.push(param);
};


/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents ContentObject Objects
 */
var ContentObject = function ContentObject(_name,_signedInfo,_content,_signature){
	
	
	if (typeof _name === 'string'){
		this.name = new Name(_name);
	}
	else{
		//TODO Check the class of _name
		this.name = _name;
	}
	this.signedInfo = _signedInfo;
	this.content=_content;
	this.signature = _signature;

	
	this.startSIG = null;
	this.endSIG = null;
	
	this.startSignedInfo = null;
	this.endContent = null;
	
	this.rawSignatureData = null;
};

ContentObject.prototype.sign = function(){

	var n1 = this.encodeObject(this.name);
	var n2 = this.encodeObject(this.signedInfo);
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
	
	var sigBits = bytes.slice(this.startSIG, this.endSIG );

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

var generateSignature = function(contentName,content,signedinfo){
	
	var enc = new BinaryXMLEncoder();
	contentName.to_ccnb(enc);
	var hex1 = toHex(enc.getReducedOstream());

	var enc = new BinaryXMLEncoder();
	content.to_ccnb(enc);
	var hex2 = toHex(enc.getReducedOstream());

	var enc = new BinaryXMLEncoder();
	signedinfo.to_ccnb(enc);
	var hex3 = toHex(enc.getReducedOstream());

	var hex = hex1+hex2+hex3;

	//globalKeyManager.sig

};

Signature.prototype.from_ccnb =function( decoder) {
		decoder.readStartElement(this.getElementLabel());
		
		if(LOG>4)console.log('STARTED DECODING SIGNATURE ');
		
		if (decoder.peekStartElement(CCNProtocolDTags.DigestAlgorithm)) {
			
			if(LOG>4)console.log('DIGIEST ALGORITHM FOUND');
			this.digestAlgorithm = decoder.readUTF8Element(CCNProtocolDTags.DigestAlgorithm); 
		}
		if (decoder.peekStartElement(CCNProtocolDTags.Witness)) {
			if(LOG>4)console.log('WITNESS FOUND FOUND');
			this.Witness = decoder.readBinaryElement(CCNProtocolDTags.Witness); 
		}
		
		//FORCE TO READ A SIGNATURE

			//if(LOG>4)console.log('SIGNATURE FOUND ');
			this.signature = decoder.readBinaryElement(CCNProtocolDTags.SignatureBits);	
			if(LOG>4)console.log('READ SIGNATURE ');

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

};

SignedInfo.prototype.setFields = function(){
	//BASE64 -> RAW STRING
	
	//this.locator = new KeyLocator(  DataUtils.toNumbersFromString(stringCertificate)  ,KeyLocatorType.CERTIFICATE );
	
	var publicKeyHex = globalKeyManager.publicKey;

	console.log('PUBLIC KEY TO WRITE TO CONTENT OBJECT IS ');
	console.log(publicKeyHex);
	
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
	
	console.log('PUBLIC KEY TO WRITE TO CONTENT OBJECT IS ');
	console.log(publicKeyBytes);

	this.locator = new KeyLocator(  publicKeyBytes  ,KeyLocatorType.KEY );

	//this.locator = new KeyLocator(  DataUtils.toNumbersFromString(stringCertificate)  ,KeyLocatorType.CERTIFICATE );

};

SignedInfo.prototype.from_ccnb = function( decoder){

		decoder.readStartElement( this.getElementLabel() );
		
		if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
			if(LOG>3) console.log('DECODING PUBLISHER KEY');
			this.publisher = new PublisherPublicKeyDigest();
			this.publisher.from_ccnb(decoder);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.Timestamp)) {
			this.timestamp = decoder.readDateTime(CCNProtocolDTags.Timestamp);
			if(LOG>4)console.log('TIMESTAMP FOUND IS  '+this.timestamp);

		}

		if (decoder.peekStartElement(CCNProtocolDTags.Type)) {
			binType = decoder.readBinaryElement(CCNProtocolDTags.Type);//byte [] 
		
			
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
			if(LOG>4) console.log('FRESHNESS IN SECONDS IS '+ this.freshnessSeconds);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.FinalBlockID)) {
			this.finalBlockID = decoder.readBinaryElement(CCNProtocolDTags.FinalBlockID);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.KeyLocator)) {
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

/*
 * Date Format 1.2.3
 * (c) 2007-2009 Steven Levithan <stevenlevithan.com>
 * MIT license
 *
 * Includes enhancements by Scott Trenda <scott.trenda.net>
 * and Kris Kowal <cixar.com/~kris.kowal/>
 *
 * Accepts a date, a mask, or a date and a mask.
 * Returns a formatted version of the given date.
 * The date defaults to the current date/time.
 * The mask defaults to dateFormat.masks.default.
 */

var DateFormat = function () {
	var	token = /d{1,4}|m{1,4}|yy(?:yy)?|([HhMsTt])\1?|[LloSZ]|"[^"]*"|'[^']*'/g,
		timezone = /\b(?:[PMCEA][SDP]T|(?:Pacific|Mountain|Central|Eastern|Atlantic) (?:Standard|Daylight|Prevailing) Time|(?:GMT|UTC)(?:[-+]\d{4})?)\b/g,
		timezoneClip = /[^-+\dA-Z]/g,
		pad = function (val, len) {
			val = String(val);
			len = len || 2;
			while (val.length < len) val = "0" + val;
			return val;
		};

	// Regexes and supporting functions are cached through closure
	return function (date, mask, utc) {
		var dF = dateFormat;

		// You can't provide utc if you skip other args (use the "UTC:" mask prefix)
		if (arguments.length == 1 && Object.prototype.toString.call(date) == "[object String]" && !/\d/.test(date)) {
			mask = date;
			date = undefined;
		}

		// Passing date through Date applies Date.parse, if necessary
		date = date ? new Date(date) : new Date;
		if (isNaN(date)) throw SyntaxError("invalid date");

		mask = String(dF.masks[mask] || mask || dF.masks["default"]);

		// Allow setting the utc argument via the mask
		if (mask.slice(0, 4) == "UTC:") {
			mask = mask.slice(4);
			utc = true;
		}

		var	_ = utc ? "getUTC" : "get",
			d = date[_ + "Date"](),
			D = date[_ + "Day"](),
			m = date[_ + "Month"](),
			y = date[_ + "FullYear"](),
			H = date[_ + "Hours"](),
			M = date[_ + "Minutes"](),
			s = date[_ + "Seconds"](),
			L = date[_ + "Milliseconds"](),
			o = utc ? 0 : date.getTimezoneOffset(),
			flags = {
				d:    d,
				dd:   pad(d),
				ddd:  dF.i18n.dayNames[D],
				dddd: dF.i18n.dayNames[D + 7],
				m:    m + 1,
				mm:   pad(m + 1),
				mmm:  dF.i18n.monthNames[m],
				mmmm: dF.i18n.monthNames[m + 12],
				yy:   String(y).slice(2),
				yyyy: y,
				h:    H % 12 || 12,
				hh:   pad(H % 12 || 12),
				H:    H,
				HH:   pad(H),
				M:    M,
				MM:   pad(M),
				s:    s,
				ss:   pad(s),
				l:    pad(L, 3),
				L:    pad(L > 99 ? Math.round(L / 10) : L),
				t:    H < 12 ? "a"  : "p",
				tt:   H < 12 ? "am" : "pm",
				T:    H < 12 ? "A"  : "P",
				TT:   H < 12 ? "AM" : "PM",
				Z:    utc ? "UTC" : (String(date).match(timezone) || [""]).pop().replace(timezoneClip, ""),
				o:    (o > 0 ? "-" : "+") + pad(Math.floor(Math.abs(o) / 60) * 100 + Math.abs(o) % 60, 4),
				S:    ["th", "st", "nd", "rd"][d % 10 > 3 ? 0 : (d % 100 - d % 10 != 10) * d % 10]
			};

		return mask.replace(token, function ($0) {
			return $0 in flags ? flags[$0] : $0.slice(1, $0.length - 1);
		});
	};
}();

// Some common format strings
DateFormat.masks = {
	"default":      "ddd mmm dd yyyy HH:MM:ss",
	shortDate:      "m/d/yy",
	mediumDate:     "mmm d, yyyy",
	longDate:       "mmmm d, yyyy",
	fullDate:       "dddd, mmmm d, yyyy",
	shortTime:      "h:MM TT",
	mediumTime:     "h:MM:ss TT",
	longTime:       "h:MM:ss TT Z",
	isoDate:        "yyyy-mm-dd",
	isoTime:        "HH:MM:ss",
	isoDateTime:    "yyyy-mm-dd'T'HH:MM:ss",
	isoUtcDateTime: "UTC:yyyy-mm-dd'T'HH:MM:ss'Z'"
};

// Internationalization strings
DateFormat.i18n = {
	dayNames: [
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
		"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
	],
	monthNames: [
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
		"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"
	]
};

// For convenience...
Date.prototype.format = function (mask, utc) {
	return dateFormat(this, mask, utc);
};

 /*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
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

/**
 * Exclude
 */
var Exclude = function Exclude(_values){ 
	
	this.OPTIMUM_FILTER_SIZE = 100;
	

	this.values = _values; //array of elements
	
}

Exclude.prototype.from_ccnb = function(/*XMLDecoder*/ decoder) {


		
		decoder.readStartElement(this.getElementLabel());

		//TODO APPLY FILTERS/EXCLUDE
		
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

		decoder.readEndElement();

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

/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents Key Objects
 */

var Key = function Key(){
    /* TODO: Port from PyCCN:
	generateRSA()
	privateToDER()
	publicToDER()
	privateToPEM()
	publicToPEM()
	fromDER()
	fromPEM()
     */
}

/**
 * KeyLocator
 */
var KeyLocatorType = {
	  NAME:1,
	  KEY:2,
	  CERTIFICATE:3
};

var KeyLocator = function KeyLocator(_input,_type){ 

    this.type=_type;
    
    if (_type==KeyLocatorType.NAME){
    	this.keyName = _input;
    }
    else if(_type==KeyLocatorType.KEY){
    	console.log('SET KEY');
    	this.publicKey = _input;
    }
    else if(_type==KeyLocatorType.CERTIFICATE){
    	this.certificate = _input;
    }

};

KeyLocator.prototype.from_ccnb = function(decoder) {

		decoder.readStartElement(this.getElementLabel());

		if (decoder.peekStartElement(CCNProtocolDTags.Key)) {
			try {
				encodedKey = decoder.readBinaryElement(CCNProtocolDTags.Key);
				// This is a DER-encoded SubjectPublicKeyInfo.
				
				//TODO FIX THIS, This should create a Key Object instead of keeping bytes

				this.publicKey =   encodedKey;//CryptoUtil.getPublicKey(encodedKey);
				this.type = 2;
				

				if(LOG>4) console.log('PUBLIC KEY FOUND: '+ this.publicKey);
				//this.publicKey = encodedKey;
				
				
			} catch (e) {
				throw new Error("Cannot parse key: ", e);
			} 

			if (null == this.publicKey) {
				throw new Error("Cannot parse key: ");
			}

		} else if ( decoder.peekStartElement(CCNProtocolDTags.Certificate)) {
			try {
				encodedCert = decoder.readBinaryElement(CCNProtocolDTags.Certificate);
				
				/*
				 * Certificates not yet working
				 */
				
				//CertificateFactory factory = CertificateFactory.getInstance("X.509");
				//this.certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encodedCert));
				

				this.certificate = encodedCert;
				this.type = 3;

				if(LOG>4) console.log('CERTIFICATE FOUND: '+ this.certificate);
				
			} catch ( e) {
				throw new Error("Cannot decode certificate: " +  e);
			}
			if (null == this.certificate) {
				throw new Error("Cannot parse certificate! ");
			}
		} else  {
			this.type = 1;


			this.keyName = new KeyName();
			this.keyName.from_ccnb(decoder);
		}
		decoder.readEndElement();
	}
	

	KeyLocator.prototype.to_ccnb = function( encoder) {
		
		if(LOG>2) console.log('type is is ' + this.type);
		//TODO Check if Name is missing
		if (!this.validate()) {
			throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
		}

		
		//TODO FIX THIS TOO
		encoder.writeStartElement(this.getElementLabel());
		
		if (this.type == KeyLocatorType.KEY) {
			if(LOG>5)console.log('About to encode a public key' +this.publicKey);
			encoder.writeElement(CCNProtocolDTags.Key, this.publicKey);
			
		} else if (this.type == KeyLocatorType.CERTIFICATE) {
			
			try {
				encoder.writeElement(CCNProtocolDTags.Certificate, this.certificate);
			} catch ( e) {
				throw new Error("CertificateEncodingException attempting to write key locator: " + e);
			}
			
		} else if (this.type == KeyLocatorType.NAME) {
			
			this.keyName.to_ccnb(encoder);
		}
		encoder.writeEndElement();
		
};

KeyLocator.prototype.getElementLabel = function() {
	return CCNProtocolDTags.KeyLocator; 
};

KeyLocator.prototype.validate = function() {
	return (  (null != this.keyName) || (null != this.publicKey) || (null != this.certificate)   );
};

/**
 * KeyName is only used by KeyLocator.
 */
var KeyName = function KeyName() {
	

	this.contentName = this.contentName;//contentName
	this.publisherID =this.publisherID;//publisherID

};

KeyName.prototype.from_ccnb=function( decoder){
	

	decoder.readStartElement(this.getElementLabel());

	this.contentName = new Name();
	this.contentName.from_ccnb(decoder);
	
	if(LOG>4) console.log('KEY NAME FOUND: ');
	
	if ( PublisherID.peek(decoder) ) {
		this.publisherID = new PublisherID();
		this.publisherID.from_ccnb(decoder);
	}
	
	decoder.readEndElement();
};

KeyName.prototype.to_ccnb = function( encoder) {
	if (!this.validate()) {
		throw new Error("Cannot encode : field values missing.");
	}
	
	encoder.writeStartElement(this.getElementLabel());
	
	this.contentName.to_ccnb(encoder);
	if (null != this.publisherID)
		this.publisherID.to_ccnb(encoder);

	encoder.writeEndElement();   		
};
	
KeyName.prototype.getElementLabel = function() { return CCNProtocolDTags.KeyName; };

KeyName.prototype.validate = function() {
		// DKS -- do we do recursive validation?
		// null signedInfo ok
		return (null != this.contentName);
};

/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents Publisher and PublisherType Objects
 */


var PublisherType = function PublisherType(_tag){
    	this.KEY =(CCNProtocolDTags.PublisherPublicKeyDigest);
    	this.CERTIFICATE= (CCNProtocolDTags.PublisherCertificateDigest);
    	this.ISSUER_KEY=	(CCNProtocolDTags.PublisherIssuerKeyDigest);
    	this.ISSUER_CERTIFICATE	=(CCNProtocolDTags.PublisherIssuerCertificateDigest);

    	this.Tag = _tag;
}; 

var isTypeTagVal = function(tagVal) {
		if ((tagVal == CCNProtocolDTags.PublisherPublicKeyDigest) ||
			(tagVal == CCNProtocolDTags.PublisherCertificateDigest) ||
			(tagVal == CCNProtocolDTags.PublisherIssuerKeyDigest) ||
			(tagVal == CCNProtocolDTags.PublisherIssuerCertificateDigest)) {
			return true;
		}
		return false;
};




var PublisherID = function PublisherID() {

	this.PUBLISHER_ID_DIGEST_ALGORITHM = "SHA-256";
	this.PUBLISHER_ID_LEN = 256/8;
    
	//TODO, implement publisherID creation and key creation

    //TODO implement generatePublicKeyDigest
    this.publisherID =null;//= generatePublicKeyDigest(key);//ByteArray
    
    //TODO implement generate key
    //CryptoUtil.generateKeyID(PUBLISHER_ID_DIGEST_ALGORITHM, key);
    this.publisherType = null;//isIssuer ? PublisherType.ISSUER_KEY : PublisherType.KEY;//publisher Type
    
};


PublisherID.prototype.from_ccnb = function(decoder) {
		
		// We have a choice here of one of 4 binary element types.
		var nextTag = decoder.peekStartElementAsLong();
		
		if (null == nextTag) {
			throw new Error("Cannot parse publisher ID.");
		} 
		
		this.publisherType = new PublisherType(nextTag); 
		
		if (!isTypeTagVal(nextTag)) {
			throw new Error("Invalid publisher ID, got unexpected type: " + nextTag);
		}
		this.publisherID = decoder.readBinaryElement(nextTag);
		if (null == this.publisherID) {
			throw new ContentDecodingException("Cannot parse publisher ID of type : " + nextTag + ".");
		}
};

PublisherID.prototype.to_ccnb = function(encoder) {
	if (!this.validate()) {
		throw new Error("Cannot encode " + this.getClass().getName() + ": field values missing.");
	}

	encoder.writeElement(this.getElementLabel(), this.publisherID);
};
	
PublisherID.peek = function(/* XMLDecoder */ decoder) {

		//Long
		nextTag = decoder.peekStartElementAsLong();
		
		if (null == nextTag) {
			// on end element
			return false;
		}
		return (isTypeTagVal(nextTag));
	};

PublisherID.prototype.getElementLabel = function() { 
	return this.publisherType.Tag;
};

PublisherID.prototype.validate = function(){
	return ((null != id() && (null != type())));
};




/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents PublisherPublicKeyDigest Objects
 */
var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(_pkd){ 
	
 	 //this.PUBLISHER_ID_LEN = 256/8;
	 this.PUBLISHER_ID_LEN = 512/8;
 	 

	 this.publisherPublicKeyDigest = _pkd;
 	 //if( typeof _pkd == "object") this.publisherPublicKeyDigest = _pkd; // Byte Array
 	 //else if( typeof _pkd == "PublicKey") ;//TODO...
    
};

PublisherPublicKeyDigest.prototype.from_ccnb = function( decoder) {		

		this.publisherPublicKeyDigest = decoder.readBinaryElement(this.getElementLabel());
		
		if(LOG>4)console.log('Publisher public key digest is ' + this.publisherPublicKeyDigest);

		if (null == this.publisherPublicKeyDigest) {
			throw new Error("Cannot parse publisher key digest.");
		}
		
		//TODO check if the length of the PublisherPublicKeyDigest is correct ( Security reason)

		if (this.publisherPublicKeyDigest.length != this.PUBLISHER_ID_LEN) {
			
			console.log('LENGTH OF PUBLISHER ID IS WRONG! Expected ' + this.PUBLISHER_ID_LEN + ", got " + this.publisherPublicKeyDigest.length);
			
			//this.publisherPublicKeyDigest = new PublisherPublicKeyDigest(this.PublisherPublicKeyDigest).PublisherKeyDigest;
		
		}
	};

PublisherPublicKeyDigest.prototype.to_ccnb= function( encoder) {
		//TODO Check that the ByteArray for the key is present
		if (!this.validate()) {
			throw new Error("Cannot encode : field values missing.");
		}
		if(LOG>3) console.log('PUBLISHER KEY DIGEST IS'+this.publisherPublicKeyDigest);
		encoder.writeElement(this.getElementLabel(), this.publisherPublicKeyDigest);
};
	
PublisherPublicKeyDigest.prototype.getElementLabel = function() { return CCNProtocolDTags.PublisherPublicKeyDigest; };

PublisherPublicKeyDigest.prototype.validate =function() {
		return (null != this.publisherPublicKeyDigest);
};

/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents Face Instances
 */

var NetworkProtocol = { TCP:6, UDP:17};

var FaceInstance  = function FaceInstance(
	    _action,
		_publisherPublicKeyDigest,
		_faceID,
		_ipProto,
		_host,
		_port,
		_multicastInterface,
		_multicastTTL,
		_freshnessSeconds){
	

	this.action = _action;
	this.publisherPublicKeyDigest = _publisherPublicKeyDigest;
	this.faceID = _faceID;
	this.ipProto = _ipProto;
	this.host = _host;
	this.Port = _port;
	this.multicastInterface =_multicastInterface;
	this.multicastTTL =_multicastTTL;
	this.freshnessSeconds = _freshnessSeconds;
	
	//action           ::= ("newface" | "destroyface" | "queryface")
	//publisherPublicKeyDigest ::= SHA-256 digest
	//faceID           ::= nonNegativeInteger
	//ipProto          ::= nonNegativeInteger [IANA protocol number, 6=TCP, 17=UDP]
	//Host             ::= textual representation of numeric IPv4 or IPv6 address
	//Port             ::= nonNegativeInteger [1..65535]
	//MulticastInterface ::= textual representation of numeric IPv4 or IPv6 address
	//MulticastTTL     ::= nonNegativeInteger [1..255]
	//freshnessSeconds ::= nonNegativeInteger

};

/**
 * Used by NetworkObject to decode the object from a network stream.
 * @see org.ccnx.ccn.impl.encoding.XMLEncodable
 */
FaceInstance.prototype.from_ccnb = function(//XMLDecoder 
	decoder) {

	decoder.readStartElement(this.getElementLabel());
	
	if (decoder.peekStartElement(CCNProtocolDTags.Action)) {
		
		this.action = decoder.readUTF8Element(CCNProtocolDTags.Action);
		
	}
	if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
		
		this.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
		this.publisherPublicKeyDigest.from_ccnb(decoder);
		
	}
	if (decoder.peekStartElement(CCNProtocolDTags.FaceID)) {
		
		this.faceID = decoder.readIntegerElement(CCNProtocolDTags.FaceID);
		
	}
	if (decoder.peekStartElement(CCNProtocolDTags.IPProto)) {
		
		//int
		var pI = decoder.readIntegerElement(CCNProtocolDTags.IPProto);
		
		this.ipProto = null;
		
		if (NetworkProtocol.TCP == pI) {
			
			this.ipProto = NetworkProtocol.TCP;
			
		} else if (NetworkProtocol.UDP == pI) {
			
			this.ipProto = NetworkProtocol.UDP;
			
		} else {
			
			throw new Error("FaceInstance.decoder.  Invalid " + 
					CCNProtocolDTags.tagToString(CCNProtocolDTags.IPProto) + " field: " + pI);
			
		}
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.Host)) {
		
		this.host = decoder.readUTF8Element(CCNProtocolDTags.Host);
		
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.Port)) {
		this.Port = decoder.readIntegerElement(CCNProtocolDTags.Port); 
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.MulticastInterface)) {
		this.multicastInterface = decoder.readUTF8Element(CCNProtocolDTags.MulticastInterface); 
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.MulticastTTL)) {
		this.multicastTTL = decoder.readIntegerElement(CCNProtocolDTags.MulticastTTL); 
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
		this.freshnessSeconds = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds); 
	}
	decoder.readEndElement();
}

/**
 * Used by NetworkObject to encode the object to a network stream.
 * @see org.ccnx.ccn.impl.encoding.XMLEncodable
 */
FaceInstance.prototype.to_ccnb = function(//XMLEncoder
	encoder){

	//if (!this.validate()) {
		//throw new Error("Cannot encode : field values missing.");
		//throw new Error("")
	//}
	encoder.writeStartElement(this.getElementLabel());
	
	if (null != this.action && this.action.length != 0)
		encoder.writeElement(CCNProtocolDTags.Action, this.action);	
	
	if (null != this.publisherPublicKeyDigest) {
		this.publisherPublicKeyDigest.to_ccnb(encoder);
	}
	if (null != this.faceID) {
		encoder.writeElement(CCNProtocolDTags.FaceID, this.faceID);
	}
	if (null != this.ipProto) {
		//encoder.writeElement(CCNProtocolDTags.IPProto, this.IpProto.value());
		encoder.writeElement(CCNProtocolDTags.IPProto, this.ipProto);
	}
	if (null != this.host && this.host.length != 0) {
		encoder.writeElement(CCNProtocolDTags.Host, this.host);	
	}
	if (null != this.Port) {
		encoder.writeElement(CCNProtocolDTags.Port, this.Port);
	}
	if (null != this.multicastInterface && this.multicastInterface.length != 0) {
		encoder.writeElement(CCNProtocolDTags.MulticastInterface, this.multicastInterface);
	}
	if (null !=  this.multicastTTL) {
		encoder.writeElement(CCNProtocolDTags.MulticastTTL, this.multicastTTL);
	}
	if (null != this.freshnessSeconds) {
		encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);
	}
	encoder.writeEndElement();   			
}


FaceInstance.prototype.getElementLabel= function(){return CCNProtocolDTags.FaceInstance;};


/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents Forwarding Entries
 */

var ForwardingEntry = function ForwardingEntry(
                                               //ActionType 
		_action, 
		//Name 
		_prefixName, 
		//PublisherPublicKeyDigest
		_ccndId, 
		//Integer 
		_faceID, 
		//Integer 
		_flags, 
		//Integer 
		_lifetime){
		
		
	
		//String
	this.action = _action;
		//Name\
	this.prefixName = _prefixName;
		//PublisherPublicKeyDigest 
	this.ccndID = _ccndId;
		//Integer		
	this.faceID = _faceID;
		//Integer		
	this.flags = _flags;
		//Integer 		
	this.lifetime = _lifetime;  // in seconds

};

ForwardingEntry.prototype.from_ccnb =function(
	//XMLDecoder 
	decoder) 
	//throws ContentDecodingException
	{
			decoder.readStartElement(this.getElementLabel());
			if (decoder.peekStartElement(CCNProtocolDTags.Action)) {
				this.action = decoder.readUTF8Element(CCNProtocolDTags.Action); 
			}
			if (decoder.peekStartElement(CCNProtocolDTags.Name)) {
				this.prefixName = new Name();
				this.prefixName.from_ccnb(decoder) ;
			}
			if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
				this.CcndId = new PublisherPublicKeyDigest();
				this.CcndId.from_ccnb(decoder);
			}
			if (decoder.peekStartElement(CCNProtocolDTags.FaceID)) {
				this.faceID = decoder.readIntegerElement(CCNProtocolDTags.FaceID); 
			}
			if (decoder.peekStartElement(CCNProtocolDTags.ForwardingFlags)) {
				this.flags = decoder.readIntegerElement(CCNProtocolDTags.ForwardingFlags); 
			}
			if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
				this.lifetime = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds); 
			}
			decoder.readEndElement();
		};

		/**
		 * Used by NetworkObject to encode the object to a network stream.
		 * @see org.ccnx.ccn.impl.encoding.XMLEncodable
		 */
ForwardingEntry.prototype.to_ccnb =function(
	//XMLEncoder 
encoder) 
{


			//if (!validate()) {
				//throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
			//}
			encoder.writeStartElement(this.getElementLabel());
			if (null != this.action && this.action.length != 0)
				encoder.writeElement(CCNProtocolDTags.Action, this.action);	
			if (null != this.prefixName) {
				this.prefixName.to_ccnb(encoder);
			}
			if (null != this.CcndId) {
				this.CcndId.to_ccnb(encoder);
			}
			if (null != this.faceID) {
				encoder.writeElement(CCNProtocolDTags.FaceID, this.faceID);
			}
			if (null != this.flags) {
				encoder.writeElement(CCNProtocolDTags.ForwardingFlags, this.flags);
			}
			if (null != this.lifetime) {
				encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, this.lifetime);
			}
			encoder.writeEndElement();   			
		};

ForwardingEntry.prototype.getElementLabel = function() { return CCNProtocolDTags.ForwardingEntry; }

/*
 * This class is used to encode ccnb binary elements (blob, type/value pairs).
 * 
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 */

var XML_EXT = 0x00; 
	
var XML_TAG = 0x01; 
	
var XML_DTAG = 0x02; 
	
var XML_ATTR = 0x03; 
 
var XML_DATTR = 0x04; 
	
var XML_BLOB = 0x05; 
	
var XML_UDATA = 0x06; 
	
var XML_CLOSE = 0x0;

var XML_SUBTYPE_PROCESSING_INSTRUCTIONS = 16; 


var XML_TT_BITS = 3;
var XML_TT_MASK = ((1 << XML_TT_BITS) - 1);
var XML_TT_VAL_BITS = XML_TT_BITS + 1;
var XML_TT_VAL_MASK = ((1 << (XML_TT_VAL_BITS)) - 1);
var XML_REG_VAL_BITS = 7;
var XML_REG_VAL_MASK = ((1 << XML_REG_VAL_BITS) - 1);
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); // 0x80
var BYTE_MASK = 0xFF;
var LONG_BYTES = 8;
var LONG_BITS = 64;
	
var bits_11 = 0x0000007FF;
var bits_18 = 0x00003FFFF;
var bits_32 = 0x0FFFFFFFF;


var BinaryXMLEncoder = function BinaryXMLEncoder(){

	this.ostream = new Array(10000);
	
	
	this.offset =0;
	
	this.CODEC_NAME = "Binary";
	
};

BinaryXMLEncoder.prototype.writeUString = function(/*String*/ utf8Content){
	this.encodeUString(this.ostream, utf8Content, XML_UDATA);
};

BinaryXMLEncoder.prototype.writeBlob = function(/*byte []*/ binaryContent
		//, /*int*/ offset, /*int*/ length
		)  {
	
	if(LOG >3) console.log(binaryContent);
	
	this.encodeBlob(this.ostream, binaryContent, this.offset, binaryContent.length);
};

BinaryXMLEncoder.prototype.writeStartElement = function(/*String*/ tag, /*TreeMap<String,String>*/ attributes){

	/*Long*/ dictionaryVal = tag;//stringToTag(tag);
	
	if (null == dictionaryVal) {

		this.encodeUString(this.ostream, tag, XML_TAG);
		
	} else {
		this.encodeTypeAndVal(XML_DTAG, dictionaryVal, this.ostream);
	}
	
	if (null != attributes) {
		this.writeAttributes(attributes); 
	}
};


BinaryXMLEncoder.prototype.writeEndElement = function(){

	this.ostream[this.offset] = XML_CLOSE;
	this.offset+= 1;
}

BinaryXMLEncoder.prototype.writeAttributes = function(/*TreeMap<String,String>*/ attributes) {
	
	if (null == attributes) {
		return;
	}

	// the keySet of a TreeMap is sorted.

	for(var i=0; i<attributes.length;i++){
		var strAttr = attributes[i].k;
		var strValue = attributes[i].v;

		var dictionaryAttr = stringToTag(strAttr);
		if (null == dictionaryAttr) {
			// not in dictionary, encode as attr
			// compressed format wants length of tag represented as length-1
			// to save that extra bit, as tag cannot be 0 length.
			// encodeUString knows to do that.
			this.encodeUString(this.ostream, strAttr, XML_ATTR);
		} else {
			this.encodeTypeAndVal(XML_DATTR, dictionaryAttr, this.ostream);
		}
		// Write value
		this.encodeUString(this.ostream, strValue);
		
	}

	
}

//returns a string
stringToTag = function(/*long*/ tagVal) {
	if ((tagVal >= 0) && (tagVal < CCNProtocolDTagsStrings.length)) {
		return CCNProtocolDTagsStrings[tagVal];
	} else if (tagVal == CCNProtocolDTags.CCNProtocolDataUnit) {
		return CCNProtocolDTags.CCNPROTOCOL_DATA_UNIT;
	}
	return null;
};

//returns a Long
tagToString =  function(/*String*/ tagName) {
	// the slow way, but right now we don't care.... want a static lookup for the forward direction
	for (var i=0; i < CCNProtocolDTagsStrings.length; ++i) {
		if ((null != CCNProtocolDTagsStrings[i]) && (CCNProtocolDTagsStrings[i] == tagName)) {
			return i;
		}
	}
	if (CCNProtocolDTags.CCNPROTOCOL_DATA_UNIT == tagName) {
		return CCNProtocolDTags.CCNProtocolDataUnit;
	}
	return null;
};


BinaryXMLEncoder.prototype.writeElement = function(
		//long 
		tag, 
		//byte[] 
		Content,
		//TreeMap<String, String> 
		attributes) {
	
	this.writeStartElement(tag, attributes);
	// Will omit if 0-length
	
	if(typeof Content === 'number') {
		if(LOG>4) console.log('GOING TO WRITE THE NUMBER .charCodeAt(0) ' +Content.toString().charCodeAt(0) );
		if(LOG>4) console.log('GOING TO WRITE THE NUMBER ' +Content.toString() );
		if(LOG>4) console.log('type of number is ' +typeof Content.toString() );
		

		
		this.writeUString(Content.toString());
		//whatever
		
	}
	
	else if(typeof Content === 'string'){
		if(LOG>4) console.log('GOING TO WRITE THE STRING  ' +Content );
		if(LOG>4) console.log('type of STRING is ' +typeof Content );
		
		this.writeUString(Content);
	}
	
	else{
	//else if(typeof Content === 'string'){
		 //console.log('went here');
		//this.writeBlob(Content);
	//}
	if(LOG>4) console.log('GOING TO WRITE A BLOB  ' +Content );
	//else if(typeof Content === 'object'){
		this.writeBlob(Content);
	//}
	}
	
	this.writeEndElement();
}

//TODO

var TypeAndVal = function TypeAndVal(_type,_val) {
	this.type = _type;
	this.val = _val;
	
};

BinaryXMLEncoder.prototype.encodeTypeAndVal = function(
		//int
		type, 
		//long 
		val, 
		//byte [] 
		buf) {
	
	if(LOG>4)console.log('Encoding type '+ type+ ' and value '+ val);
	
	if(LOG>4) console.log('OFFSET IS ' + this.offset );
	
	if ((type > XML_UDATA) || (type < 0) || (val < 0)) {
		throw new Error("Tag and value must be positive, and tag valid.");
	}
	
	// Encode backwards. Calculate how many bytes we need:
	var numEncodingBytes = this.numEncodingBytes(val);
	
	if ((this.offset + numEncodingBytes) > buf.length) {
		throw new Error("Buffer space of " + (buf.length-this.offset) + 
											" bytes insufficient to hold " + 
											numEncodingBytes + " of encoded type and value.");
	}

	// Bottom 4 bits of val go in last byte with tag.
	buf[this.offset + numEncodingBytes - 1] = 
		//(byte)
			(BYTE_MASK &
					(((XML_TT_MASK & type) | 
					 ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
					 XML_TT_NO_MORE); // set top bit for last byte
	val = val >>> XML_TT_VAL_BITS;;
	
	// Rest of val goes into preceding bytes, 7 bits per byte, top bit
	// is "more" flag.
	var i = this.offset + numEncodingBytes - 2;
	while ((0 != val) && (i >= this.offset)) {
		buf[i] = //(byte)
				(BYTE_MASK &
						    (val & XML_REG_VAL_MASK)); // leave top bit unset
		val = val >>> XML_REG_VAL_BITS;
		--i;
	}
	if (val != 0) {
		throw new Error( "This should not happen: miscalculated encoding");
		//Log.warning(Log.FAC_ENCODING, "This should not happen: miscalculated encoding length, have " + val + " left.");
	}
	this.offset+= numEncodingBytes;
	
	return numEncodingBytes;
};

BinaryXMLEncoder.prototype.encodeUString = function(
		//OutputStream 
		ostream, 
		//String 
		ustring, 
		//byte 
		type) {
	
	if ((null == ustring) || (ustring.length == 0)) {
		return;
	}
	
	
	//byte [] data utils
	/*custom*/
	//byte[]
	
	if(LOG>3) console.log("The string to write is ");
	
	if(LOG>3) console.log(ustring);

	//COPY THE STRING TO AVOID PROBLEMS
	strBytes = new Array(ustring.length);
	
	var i = 0;	

	for( ; i<ustring.length; i++) //in InStr.ToCharArray())
	{
		if(LOG>3)console.log("ustring[" + i + '] = ' + ustring[i]);
		strBytes[i] = ustring.charCodeAt(i);
	}
	
	//strBytes = DataUtils.getBytesFromUTF8String(ustring);
	
	this.encodeTypeAndVal(type, 
						(((type == XML_TAG) || (type == XML_ATTR)) ?
								(strBytes.length-1) :
								strBytes.length), ostream);
	
	if(LOG>3) console.log("THE string to write is ");
	
	if(LOG>3) console.log(strBytes);
	
	this.writeString(strBytes,this.offset);
	
	this.offset+= strBytes.length;

};



BinaryXMLEncoder.prototype.encodeBlob = function(
		//OutputStream 
		ostream, 
		//byte [] 
		blob, 
		//int 
		offset, 
		//int 
		length) {


	if ((null == blob) || (length == 0)) {

		return;
	}
	
	if(LOG>4) console.log('LENGTH OF XML_BLOB IS '+length);
	
	
	blobCopy = new Array(blob.Length);
	var i = 0;
	for( ;i<blob.length;i++) //in InStr.ToCharArray())
	{
		blobCopy[i] = blob[i];
	}

	this.encodeTypeAndVal(XML_BLOB, length, ostream,offset);
	
	if (null != blob) {

		this.writeBlobArray(blobCopy,this.offset);
		this.offset += length;
	}
};

var ENCODING_LIMIT_1_BYTE = ((1 << (XML_TT_VAL_BITS)) - 1);
var ENCODING_LIMIT_2_BYTES = ((1 << (XML_TT_VAL_BITS + XML_REG_VAL_BITS)) - 1);
var ENCODING_LIMIT_3_BYTES = ((1 << (XML_TT_VAL_BITS + 2 * XML_REG_VAL_BITS)) - 1);

BinaryXMLEncoder.prototype.numEncodingBytes = function(
		//long
		x) {
	if (x <= ENCODING_LIMIT_1_BYTE) return (1);
	if (x <= ENCODING_LIMIT_2_BYTES) return (2);
	if (x <= ENCODING_LIMIT_3_BYTES) return (3);
	
	var numbytes = 1;
	
	// Last byte gives you XML_TT_VAL_BITS
	// Remainder each give you XML_REG_VAL_BITS
	x = x >>> XML_TT_VAL_BITS;
	while (x != 0) {
        numbytes++;
		x = x >>> XML_REG_VAL_BITS;
	}
	return (numbytes);
};

BinaryXMLEncoder.prototype.writeDateTime = function(
		//String 
		tag, 
		//CCNTime 
		dateTime) {
	
	if(LOG>4)console.log('ENCODING DATE with LONG VALUE');
	if(LOG>4)console.log(dateTime.msec);
	
	//var binarydate = DataUtils.unsignedLongToByteArray( Math.round((dateTime.msec/1000) * 4096)  );
	

	//parse to hex
	var binarydate =  Math.round((dateTime.msec/1000) * 4096).toString(16)  ;

	//HACK
	var binarydate =  DataUtils.toNumbers( '0'.concat(binarydate,'0')) ;

	
	if(LOG>4)console.log('ENCODING DATE with BINARY VALUE');
	if(LOG>4)console.log(binarydate);
	
	if(LOG>4)console.log('ENCODING DATE with BINARY VALUE(HEX)');
	if(LOG>4)console.log(DataUtils.toHex(binarydate));
	

	this.writeElement(tag, binarydate);

};

BinaryXMLEncoder.prototype.writeString = function(
		//String 
		input,
		//CCNTime 
		offset) {
	
    if(typeof input === 'string'){
		//console.log('went here');
    	if(LOG>4) console.log('GOING TO WRITE A STRING');
    	if(LOG>4) console.log(input);
        
		for (var i = 0; i < input.length; i++) {
			if(LOG>4) console.log('input.charCodeAt(i)=' + input.charCodeAt(i));
		    this.ostream[this.offset+i] = (input.charCodeAt(i));
		}
	}
    
    else{
    	
    	if(LOG>4) console.log('GOING TO WRITE A STRING IN BINARY FORM');
    	if(LOG>4) console.log(input);
    	
    	this.writeBlobArray(input);
    	
    }
    /*
	else if(typeof input === 'object'){
		
	}	
	*/
};

BinaryXMLEncoder.prototype.writeBlobArray = function(
		//String 
		Blob,
		//CCNTime 
		offset) {
	
	if(LOG>4) console.log('GOING TO WRITE A BLOB');
    
	for (var i = 0; i < Blob.length; i++) {
	    this.ostream[this.offset+i] = Blob[i];
	}
	
};



BinaryXMLEncoder.prototype.getReducedOstream = function() {
	
	return this.ostream.slice(0,this.offset);
	
};


/*
 * This class is used to decode ccnb binary elements (blob, type/value pairs).
 * 
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 */

var XML_EXT = 0x00; 
	
var XML_TAG = 0x01; 
	
var XML_DTAG = 0x02; 
	
var XML_ATTR = 0x03; 
 
var XML_DATTR = 0x04; 
	
var XML_BLOB = 0x05; 
	
var XML_UDATA = 0x06; 
	
var XML_CLOSE = 0x0;

var XML_SUBTYPE_PROCESSING_INSTRUCTIONS = 16; 
	

var XML_TT_BITS = 3;
var XML_TT_MASK = ((1 << XML_TT_BITS) - 1);
var XML_TT_VAL_BITS = XML_TT_BITS + 1;
var XML_TT_VAL_MASK = ((1 << (XML_TT_VAL_BITS)) - 1);
var XML_REG_VAL_BITS = 7;
var XML_REG_VAL_MASK = ((1 << XML_REG_VAL_BITS) - 1);
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); // 0x80
var BYTE_MASK = 0xFF;
var LONG_BYTES = 8;
var LONG_BITS = 64;
	
var bits_11 = 0x0000007FF;
var bits_18 = 0x00003FFFF;
var bits_32 = 0x0FFFFFFFF;



//returns a string
tagToString = function(/*long*/ tagVal) {
	if ((tagVal >= 0) && (tagVal < CCNProtocolDTagsStrings.length)) {
		return CCNProtocolDTagsStrings[tagVal];
	} else if (tagVal == CCNProtocolDTags.CCNProtocolDataUnit) {
		return CCNProtocolDTags.CCNPROTOCOL_DATA_UNIT;
	}
	return null;
};

//returns a Long
stringToTag =  function(/*String*/ tagName) {
	// the slow way, but right now we don't care.... want a static lookup for the forward direction
	for (var i=0; i < CCNProtocolDTagsStrings.length; ++i) {
		if ((null != CCNProtocolDTagsStrings[i]) && (CCNProtocolDTagsStrings[i] == tagName)) {
			return i;
		}
	}
	if (CCNProtocolDTags.CCNPROTOCOL_DATA_UNIT == tagName) {
		return CCNProtocolDTags.CCNProtocolDataUnit;
	}
	return null;
};

//console.log(stringToTag(64));
var BinaryXMLDecoder = function BinaryXMLDecoder(istream){
	var MARK_LEN=512;
	var DEBUG_MAX_LEN =  32768;
	
	this.istream = istream;
	this.offset = 0;
};

BinaryXMLDecoder.prototype.readAttributes = function(
	//TreeMap<String,String> 
	attributes){
	
	if (null == attributes) {
		return;
	}

	try {

		//this.TypeAndVal 
		nextTV = this.peekTypeAndVal();

		while ((null != nextTV) && ((XML_ATTR == nextTV.type()) ||
				(XML_DATTR == nextTV.type()))) {

			//this.TypeAndVal 
			thisTV = this.decodeTypeAndVal();

			var attributeName = null;
			if (XML_ATTR == thisTV.type()) {
				
				attributeName = this.decodeUString(thisTV.val()+1);

			} else if (XML_DATTR == thisTV.type()) {
				// DKS TODO are attributes same or different dictionary?
				attributeName = tagToString(thisTV.val());
				if (null == attributeName) {
					throw new ContentDecodingException("Unknown DATTR value" + thisTV.val());
				}
			}
			
			var attributeValue = this.decodeUString();

			attributes.put(attributeName, attributeValue);

			nextTV = this.peekTypeAndVal();
		}

	} catch ( e) {

		throw new ContentDecodingException("readStartElement", e);
	}
};


BinaryXMLDecoder.prototype.initializeDecoding = function() {
		//if (!this.istream.markSupported()) {
			//throw new IllegalArgumentException(this.getClass().getName() + ": input stream must support marking!");
		//}
}

BinaryXMLDecoder.prototype.readStartDocument = function(){
		// Currently no start document in binary encoding.
	}

BinaryXMLDecoder.prototype.readEndDocument = function() {
		// Currently no end document in binary encoding.
	};

BinaryXMLDecoder.prototype.readStartElement = function(
		//String 
		startTag,
		//TreeMap<String, String> 
		attributes) {
	
		
		//NOT SURE
		//if(typeof startTag == 'number')
			//startTag = tagToString(startTag);
		
		//try {
			//TypeAndVal 
			tv = this.decodeTypeAndVal();
			
			if (null == tv) {
				throw new Error("Expected start element: " + startTag + " got something not a tag.");
			}
			
			//String 
			decodedTag = null;
			//console.log(tv);
			//console.log(typeof tv);
			
			//console.log(XML_TAG);
			if (tv.type() == XML_TAG) {
				//console.log('got here');
				//Log.info(Log.FAC_ENCODING, "Unexpected: got tag in readStartElement; looking for tag " + startTag + " got length: " + (int)tv.val()+1);
				// Tag value represents length-1 as tags can never be empty.
				var valval ;
				if(typeof tv.val() == 'string'){
					valval = (parseInt(tv.val())) + 1;
				}
				else
					valval = (tv.val())+ 1;
				
				//console.log('valval is ' +valval);
				
				decodedTag = this.decodeUString(valval);
				
			} else if (tv.type() == XML_DTAG) {
				//console.log('gothere');
				//console.log(tv.val());
				//decodedTag = tagToString(tv.val());
				//console.log()
				decodedTag = tv.val();
			}
			
			//console.log(decodedTag);
			//console.log('startTag is '+startTag);
			
			
			if ((null ==  decodedTag) || decodedTag != startTag ) {
				console.log('expecting '+ startag + ' but got '+ decodedTag);
				throw new Error("Expected start element: " + startTag + " got: " + decodedTag + "(" + tv.val() + ")");
			}
			
			// DKS: does not read attributes out of stream if caller doesn't
			// ask for them. Should possibly peek and skip over them regardless.
			// TODO: fix this
			if (null != attributes) {
				readAttributes(attributes); 
			}
			
		//} catch ( e) {
			//console.log(e);
			//throw new Error("readStartElement", e);
		//}
	}
	

BinaryXMLDecoder.prototype.readAttributes = function(
	//TreeMap<String,String> 
	attributes) {
	
	if (null == attributes) {
		return;
	}

	try {
		// Now need to get attributes.
		//TypeAndVal 
		nextTV = this.peekTypeAndVal();

		while ((null != nextTV) && ((XML_ATTR == nextTV.type()) ||
				(XML_DATTR == nextTV.type()))) {

			// Decode this attribute. First, really read the type and value.
			//this.TypeAndVal 
			thisTV = this.decodeTypeAndVal();

			//String 
			attributeName = null;
			if (XML_ATTR == thisTV.type()) {
				// Tag value represents length-1 as attribute names cannot be empty.
				var valval ;
				if(typeof tv.val() == 'string'){
					valval = (parseInt(tv.val())) + 1;
				}
				else
					valval = (tv.val())+ 1;
				
				attributeName = this.decodeUString(valval);

			} else if (XML_DATTR == thisTV.type()) {
				// DKS TODO are attributes same or different dictionary?
				attributeName = tagToString(thisTV.val());
				if (null == attributeName) {
					throw new Error("Unknown DATTR value" + thisTV.val());
				}
			}
			// Attribute values are always UDATA
			//String
			attributeValue = this.decodeUString();

			//
			attributes.push([attributeName, attributeValue]);

			nextTV = this.peekTypeAndVal();
		}

	} catch ( e) {
		Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
		throw new Error("readStartElement", e);
	}
};

//returns a string
BinaryXMLDecoder.prototype.peekStartElementAsString = function() {
	//this.istream.mark(MARK_LEN);

	//String 
	decodedTag = null;
	var previousOffset = this.offset;
	try {
		// Have to distinguish genuine errors from wrong tags. Could either use
		// a special exception subtype, or redo the work here.
		//this.TypeAndVal 
		tv = this.decodeTypeAndVal();

		if (null != tv) {

			if (tv.type() == XML_TAG) {
				/*if (tv.val()+1 > DEBUG_MAX_LEN) {
					throw new ContentDecodingException("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!");
				}*/

				// Tag value represents length-1 as tags can never be empty.
				var valval ;
				if(typeof tv.val() == 'string'){
					valval = (parseInt(tv.val())) + 1;
				}
				else
					valval = (tv.val())+ 1;
				
				decodedTag = this.decodeUString(valval);
				
				//Log.info(Log.FAC_ENCODING, "Unexpected: got text tag in peekStartElement; length: " + valval + " decoded tag = " + decodedTag);

			} else if (tv.type() == XML_DTAG) {
				decodedTag = tagToString(tv.val());					
			}

		} // else, not a type and val, probably an end element. rewind and return false.

	} catch ( e) {

	} finally {
		try {
			this.offset = previousOffset;
		} catch ( e) {
			Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
			throw new ContentDecodingException("Cannot reset stream! " + e.getMessage(), e);
		}
	}
	return decodedTag;
};

BinaryXMLDecoder.prototype.peekStartElement = function(
		//String 
		startTag) {
	//String 
	if(typeof startTag == 'string'){
		decodedTag = this.peekStartElementAsString();
		
		if ((null !=  decodedTag) && decodedTag == startTag) {
			return true;
		}
		return false;
	}
	else if(typeof startTag == 'number'){
		decodedTag = this.peekStartElementAsLong();
		if ((null !=  decodedTag) && decodedTag == startTag) {
			return true;
		}
		return false;
	}
	else{
		throw new Error("SHOULD BE STRING OR NUMBER");
	}
}
//returns Long
BinaryXMLDecoder.prototype.peekStartElementAsLong = function() {
		//this.istream.mark(MARK_LEN);

		//Long
		decodedTag = null;
		
		var previousOffset = this.offset;
		
		try {
			// Have to distinguish genuine errors from wrong tags. Could either use
			// a special exception subtype, or redo the work here.
			//this.TypeAndVal
			tv = this.decodeTypeAndVal();

			if (null != tv) {

				if (tv.type() == XML_TAG) {
					if (tv.val()+1 > DEBUG_MAX_LEN) {
						throw new ContentDecodingException("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!");
					}

					var valval ;
					if(typeof tv.val() == 'string'){
						valval = (parseInt(tv.val())) + 1;
					}
					else
						valval = (tv.val())+ 1;
					
					// Tag value represents length-1 as tags can never be empty.
					//String 
					strTag = this.decodeUString(valval);
					
					decodedTag = stringToTag(strTag);
					
					//Log.info(Log.FAC_ENCODING, "Unexpected: got text tag in peekStartElement; length: " + valval + " decoded tag = " + decodedTag);
					
				} else if (tv.type() == XML_DTAG) {
					decodedTag = tv.val();					
				}

			} // else, not a type and val, probably an end element. rewind and return false.

		} catch ( e) {
			
		} finally {
			try {
				//this.istream.reset();
				this.offset = previousOffset;
			} catch ( e) {
				Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
				throw new Error("Cannot reset stream! " + e.getMessage(), e);
			}
		}
		return decodedTag;
	};


// returns a byte[]
BinaryXMLDecoder.prototype.readBinaryElement = function(
		//long 
		startTag,
		//TreeMap<String, String> 
		attributes){
	//byte [] 
	blob = null;
	
		this.readStartElement(startTag, attributes);
		blob = this.readBlob();
	

	return blob;

};
	
	
BinaryXMLDecoder.prototype.readEndElement = function(){
		//try {
			if(LOG>4)console.log('this.offset is '+this.offset);
			
			var next = this.istream[this.offset]; 
			
			this.offset++;
			//read();
			
			if(LOG>4)console.log('XML_CLOSE IS '+XML_CLOSE);
			if(LOG>4)console.log('next is '+next);
			
			if (next != XML_CLOSE) {
				console.log("Expected end element, got: " + next);
				throw new ContentDecodingException("Expected end element, got: " + next);
			}
		//} catch ( e) {
			//throw new ContentDecodingException(e);
		//}
	};


//String	
BinaryXMLDecoder.prototype.readUString = function(){
			//String 
			ustring = this.decodeUString();	
			this.readEndElement();
			return ustring;

	};
	

//returns a byte[]
BinaryXMLDecoder.prototype.readBlob = function() {
			//byte []
			
			blob = this.decodeBlob();	
			this.readEndElement();
			return blob;

	};


//CCNTime
BinaryXMLDecoder.prototype.readDateTime = function(
	//long 
	startTag)  {
	//byte [] 
	
	var byteTimestamp = this.readBinaryElement(startTag);

	//var lontimestamp = DataUtils.byteArrayToUnsignedLong(byteTimestamp);

	var byteTimestamp = DataUtils.toHex(byteTimestamp);
	
	
	var byteTimestamp = parseInt(byteTimestamp, 16);

	lontimestamp = (byteTimestamp/ 4096) * 1000;

	//if(lontimestamp<0) lontimestamp =  - lontimestamp;

	if(LOG>3) console.log('DECODED DATE WITH VALUE');
	if(LOG>3) console.log(lontimestamp);
	

	//CCNTime 
	timestamp = new CCNTime(lontimestamp);
	//timestamp.setDateBinary(byteTimestamp);
	
	if (null == timestamp) {
		throw new ContentDecodingException("Cannot parse timestamp: " + DataUtils.printHexBytes(byteTimestamp));
	}		
	return timestamp;
};

BinaryXMLDecoder.prototype.decodeTypeAndVal = function() {
	
	/*int*/next;
	/*int*/type = -1;
	/*long*/val = 0;
	/*boolean*/more = true;

	
	//var savedOffset = this.offset;
	var count = 0;
	
	do {
		
		var next = this.istream[this.offset ];
		
		
		if (next < 0) {
			return null; 
		}

		if ((0 == next) && (0 == val)) {
			return null;
		}
		
		more = (0 == (next & XML_TT_NO_MORE));
		
		if  (more) {
			val = val << XML_REG_VAL_BITS;
			val |= (next & XML_REG_VAL_MASK);
		} else {

			type = next & XML_TT_MASK;
			val = val << XML_TT_VAL_BITS;
			val |= ((next >>> XML_TT_BITS) & XML_TT_VAL_MASK);
		}
		
		this.offset++;
		
	} while (more);
	
	if(LOG>3)console.log('TYPE is '+ type + ' VAL is '+ val);

	return new TypeAndVal(type, val);
};



//TypeAndVal
BinaryXMLDecoder.peekTypeAndVal = function() {
	//TypeAndVal 
	tv = null;
	
	//this.istream.mark(LONG_BYTES*2);		
	
	var previousOffset = this.offset;
	
	try {
		tv = this.decodeTypeAndVal();
	} finally {
		//this.istream.reset();
		this.offset = previousOffset;
	}
	
	return tv;
};


//byte[]
BinaryXMLDecoder.prototype.decodeBlob = function(
		//int 
		blobLength) {
	
	
	if(null == blobLength){
		//TypeAndVal
		tv = this.decodeTypeAndVal();

		var valval ;
		
		if(typeof tv.val() == 'string'){
			valval = (parseInt(tv.val()));
		}
		else
			valval = (tv.val());
		
		//console.log('valval here is ' + valval);
		return  this.decodeBlob(valval);
	}
	
	//
	//byte [] 

	bytes = this.istream.slice(this.offset, this.offset+ blobLength);
	this.offset += blobLength;
	
	//int 
	return bytes;
	
	count = 0;

};

var count =0;

//String
BinaryXMLDecoder.prototype.decodeUString = function(
		//int 
		byteLength) {
	
	/*
	console.log('COUNT IS '+count);
	console.log('INPUT BYTELENGTH IS '+byteLength);
	count++;
	if(null == byteLength||  undefined == byteLength){
		console.log("!!!!");
		tv = this.decodeTypeAndVal();
		var valval ;
		if(typeof tv.val() == 'string'){
			valval = (parseInt(tv.val()));
		}
		else
			valval = (tv.val());
		
		if(LOG>4) console.log('valval  is ' + valval);
		byteLength= this.decodeUString(valval);
		
		//if(LOG>4) console.log('byte Length found in type val is '+ byteLength.charCodeAt(0));
		byteLength = parseInt(byteLength);
		
		
		//byteLength = byteLength.charCodeAt(0);
		//if(LOG>4) console.log('byte Length found in type val is '+ byteLength);
	}
	if(LOG>4)console.log('byteLength is '+byteLength);
	if(LOG>4)console.log('type of byteLength is '+typeof byteLength);
	
	stringBytes = this.decodeBlob(byteLength);
	
	//console.log('String bytes are '+ stringBytes);
	//console.log('stringBytes);
	
	if(LOG>4)console.log('byteLength is '+byteLength);
	if(LOG>4)console.log('this.offset is '+this.offset);

	tempBuffer = this.istream.slice(this.offset, this.offset+byteLength);
	if(LOG>4)console.log('TEMPBUFFER IS' + tempBuffer);
	if(LOG>4)console.log( tempBuffer);

	if(LOG>4)console.log('ADDING to offset value' + byteLength);
	this.offset+= byteLength;
	//if(LOG>3)console.log('read the String' + tempBuffer.toString('ascii'));
	//return tempBuffer.toString('ascii');//
	
	
	//if(LOG>3)console.log( 'STRING READ IS '+ DataUtils.getUTF8StringFromBytes(stringBytes) ) ;
	//if(LOG>3)console.log( 'STRING READ IS '+ DataUtils.getUTF8StringFromBytes(tempBuffer) ) ;
	//if(LOG>3)console.log(DataUtils.getUTF8StringFromBytes(tempBuffer) ) ;
	//return DataUtils.getUTF8StringFromBytes(tempBuffer);
	
	if(LOG>3)console.log( 'STRING READ IS '+ DataUtils.toString(stringBytes) ) ;
	if(LOG>3)console.log( 'TYPE OF STRING READ IS '+ typeof DataUtils.toString(stringBytes) ) ;

	return  DataUtils.toString(stringBytes);*/

	if(null == byteLength ){
		var tempStreamPosition = this.offset;
			
		//TypeAndVal 
		tv = this.decodeTypeAndVal();
		
		if(LOG>3)console.log('TV is '+tv);
		if(LOG>3)console.log(tv);
		
		if(LOG>3)console.log('Type of TV is '+typeof tv);
	
		if ((null == tv) || (XML_UDATA != tv.type())) { // if we just have closers left, will get back null
			//if (Log.isLoggable(Log.FAC_ENCODING, Level.FINEST))
				//Log.finest(Log.FAC_ENCODING, "Expected UDATA, got " + ((null == tv) ? " not a tag " : tv.type()) + ", assuming elided 0-length blob.");
			
			this.offset = tempStreamPosition;
			
			return "";
		}
			
		return this.decodeUString(tv.val());
	}
	else{
		//byte [] 
		stringBytes = this.decodeBlob(byteLength);
		
		//return DataUtils.getUTF8StringFromBytes(stringBytes);
		return  DataUtils.toString(stringBytes);
		
	}
};




//OBject containg a pair of type and value
var TypeAndVal = function TypeAndVal(_type,_val) {
	this.t = _type;
	this.v = _val;
};

TypeAndVal.prototype.type = function(){
	return this.t;
};

TypeAndVal.prototype.val = function(){
	return this.v;
};
//TODO






BinaryXMLDecoder.prototype.readIntegerElement =function(
	//String 
	startTag) {

	//String 
	if(LOG>4) console.log('READING INTEGER '+ startTag);
	if(LOG>4) console.log('TYPE OF '+ typeof startTag);
	
	//try {
		
	strVal = this.readUTF8Element(startTag);

	//}
	//catch (e) {
		//throw new Error("Cannot parse " + startTag + ": " + strVal);
	//}
	
	return parseInt(strVal);
};


BinaryXMLDecoder.prototype.readUTF8Element =function(
			//String 
			startTag,
			//TreeMap<String, String> 
			attributes) {
			//throws ContentDecodingException 

		this.readStartElement(startTag, attributes); // can't use getElementText, can't get attributes
		//String 
		strElementText = this.readUString();
		return strElementText;
};

/* 
 * Set the offset into the input, used for the next read.
 */
BinaryXMLDecoder.prototype.seek = function(
        //int
        offset) {
    this.offset = offset;        
}

/*
 * This class uses BinaryXMLDecoder to follow the structure of a ccnb binary element to 
 * determine its end.
 * 
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 */

var BinaryXMLStructureDecoder = function BinaryXMLDecoder() {
    this.gotElementEnd = false;
	this.offset = 0;
    this.level = 0;
    this.state = BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE;
    this.headerStartOffset = 0;
    this.readBytesEndOffset = 0;
};

BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE = 0;
BinaryXMLStructureDecoder.READ_BYTES = 1;

/*
 * Continue scanning input starting from this.offset.  If found the end of the element
 *   which started at offset 0 then return true, else false.
 * If this returns false, you should read more into input and call again.
 * You have to pass in input each time because the array could be reallocated.
 * This throws an exception for badly formed ccnb.
 */
BinaryXMLStructureDecoder.prototype.findElementEnd = function(
    // byte array
    input)
{
    if (this.gotElementEnd)
        // Someone is calling when we already got the end.
        return true;
    
    var decoder = new BinaryXMLDecoder(input);
    
    while (true) {
        if (this.offset >= input.length)
            // All the cases assume we have some input.
            return false;
                
        switch (this.state) {
            case BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE:               
                // First check for XML_CLOSE.
                if (this.offset == this.headerStartOffset && input[this.offset] == XML_CLOSE) {
                    ++this.offset;
                    // Close the level.
                    --this.level;
                    if (this.level == 0)
                        // Finished.
                        return true;
                    if (this.level < 0)
                        throw new Error("BinaryXMLStructureDecoder: Unexepected close tag at offset " +
                            (this.offset - 1));
                    
                    // Get ready for the next header.
                    this.headerStartOffset = this.offset;
                    break;
                }

                while (true) {
                    if (this.offset >= input.length)                    
                        return false;
                    if (input[this.offset++] & XML_TT_NO_MORE)
                        // Break and read the header.
                        break;
                }
            
                decoder.seek(this.headerStartOffset);
                var typeAndVal = decoder.decodeTypeAndVal();
                if (typeAndVal == null)
                    throw new Error("BinaryXMLStructureDecoder: Can't read header starting at offset " +
                        this.headerStartOffset);
                
                // Set the next state based on the type.
                var type = typeAndVal.t;
                if (type == XML_DATTR)
                    // We already consumed the item. READ_HEADER_OR_CLOSE again.
                    // ccnb has rules about what must follow an attribute, but we are just scanning.
                    this.headerStartOffset = this.offset;
                else if (type == XML_DTAG || type == XML_EXT) {
                    // Start a new level and READ_HEADER_OR_CLOSE again.
                    ++this.level;
                    this.headerStartOffset = this.offset;
                }
                else if (type == XML_TAG || type == XML_ATTR) {
                    if (type == XML_TAG)
                        // Start a new level and read the tag.
                        ++this.level;
                    // Minimum tag or attribute length is 1.
                    this.readBytesEndOffset = this.offset + typeAndVal.v + 1;
                    this.state = BinaryXMLStructureDecoder.READ_BYTES;
                    // ccnb has rules about what must follow an attribute, but we are just scanning.
                }
                else if (type == XML_BLOB || type == XML_UDATA) {
                    this.readBytesEndOffset = this.offset + typeAndVal.v;
                    this.state = BinaryXMLStructureDecoder.READ_BYTES;
                }
                else
                    throw new Error("BinaryXMLStructureDecoder: Unrecognized header type " + type);
                break;
            
            case BinaryXMLStructureDecoder.READ_BYTES:
                if (input.length < this.readBytesEndOffset) {
                    // Need more.
                    this.offset = input.length;
                    return false;
                }
                // Got the bytes.  Read a new header or close.
                this.offset = this.readBytesEndOffset;
                this.headerStartOffset = this.offset;
                this.state = BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE;
                break;
            
            default:
                // We don't expect this to happen.
                throw new Error("BinaryXMLStructureDecoder: Unrecognized state " + this.state);
        }
    }
};

/*
 * This class contains utilities to help parse the data
 * author: ucla-cs
 * See COPYING for copyright and distribution information.
 */
 
var DataUtils = function DataUtils(){
	
	
};


/*
 * NOTE THIS IS CURRENTLY NOT BEHING USED
 * 
 */

DataUtils.keyStr = "ABCDEFGHIJKLMNOP" +
               "QRSTUVWXYZabcdef" +
               "ghijklmnopqrstuv" +
               "wxyz0123456789+/" +
               "=";

               
/**
 * Raw String to Base 64
 */
DataUtils.stringtoBase64=function stringtoBase64(input) {
     input = escape(input);
     var output = "";
     var chr1, chr2, chr3 = "";
     var enc1, enc2, enc3, enc4 = "";
     var i = 0;

     do {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);

        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (isNaN(chr2)) {
           enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
           enc4 = 64;
        }

        output = output +
           DataUtils.keyStr.charAt(enc1) +
           DataUtils.keyStr.charAt(enc2) +
           DataUtils.keyStr.charAt(enc3) +
           DataUtils.keyStr.charAt(enc4);
        chr1 = chr2 = chr3 = "";
        enc1 = enc2 = enc3 = enc4 = "";
     } while (i < input.length);

     return output;
  }

/**
 * Base 64 to Raw String 
 */
DataUtils.base64toString = function base64toString(input) {
     var output = "";
     var chr1, chr2, chr3 = "";
     var enc1, enc2, enc3, enc4 = "";
     var i = 0;

     // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
     var base64test = /[^A-Za-z0-9\+\/\=]/g;
     /* Test for invalid characters. */
     if (base64test.exec(input)) {
        alert("There were invalid base64 characters in the input text.\n" +
              "Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='\n" +
              "Expect errors in decoding.");
     }
     
     input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

     do {
        enc1 = DataUtils.keyStr.indexOf(input.charAt(i++));
        enc2 = DataUtils.keyStr.indexOf(input.charAt(i++));
        enc3 = DataUtils.keyStr.indexOf(input.charAt(i++));
        enc4 = DataUtils.keyStr.indexOf(input.charAt(i++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        output = output + String.fromCharCode(chr1);

        if (enc3 != 64) {
           output = output + String.fromCharCode(chr2);
        }
        if (enc4 != 64) {
           output = output + String.fromCharCode(chr3);
        }

        chr1 = chr2 = chr3 = "";
        enc1 = enc2 = enc3 = enc4 = "";

     } while (i < input.length);

     return unescape(output);
  };

//byte [] 

/**
 * NOT WORKING!!!!!
 * 
 * Unsiged Long Number to Byte Array
 */
	
 /*
DataUtils.unsignedLongToByteArray= function( value) {
	
	if(LOG>4)console.log('INPUT IS '+value);
	
	if( 0 == value )
		return [0];

	if( 0 <= value && value <= 0x00FF ) {
		//byte [] 
		var bb = new Array(1);
		bb[0] = (value & 0x00FF);
		return bb;
	}

	if(LOG>4) console.log('type of value is '+typeof value);
	if(LOG>4) console.log('value is '+value);
	//byte [] 
	var out = null;
	//int
	var offset = -1;
	for(var i = 7; i >=0; --i) {
		//byte
		console.log(i);
		console.log('value is '+value);
		console.log('(value >> (i * 8)) '+ (value >> (i * 8))  );
		console.log(' ((value >> (i * 8)) & 0xFF) '+ ((value >> (i * 8)) & 0xFF)  );

		var b = ((value >> (i * 8)) & 0xFF)  ;
		
		if(LOG>4) console.log('b is '+b);
		
		if( out == null && b != 0 ) {
			//out = new byte[i+1];
			out = new Array(i+1);
			offset = i;
		}
		
		if( out != null )
			out[ offset - i ] = b;
	}
	if(LOG>4)console.log('OUTPUT IS ');
	if(LOG>4)console.log(out);
	return out;
}
*/
	
/**
 * NOT WORKING!!!!!
 * 
 * Unsiged Long Number to Byte Array
 *//*
DataUtils.byteArrayToUnsignedLong = function(//final byte [] 
	src) {
		if(LOG>4) console.log('INPUT IS ');
		if(LOG>4) console.log(src);
		
		var value = 0;
		for(var i = 0; i < src.length; i++) {
			value = value << 8;
			// Java will assume the byte is signed, so extend it and trim it.
			
			
			var b = ((src[i]) & 0xFF );
			value |= b;
		}
		
		if(LOG>4) console.log('OUTPUT IS ');
		
		if(LOG>4) console.log(value);

		return value;
	}*/


/**
 * Hex String to Byte Array
 */
	//THIS IS NOT WORKING
/*
DataUtils.HexStringtoByteArray = function(str) {
    var byteArray = [];
    for (var i = 0; i < str.length; i++)
        if (str.charCodeAt(i) <= 0x7F)
            byteArray.push(str.charCodeAt(i));
        else {
            var h = encodeURIComponent(str.charAt(i)).substr(1).split('%');
            for (var j = 0; j < h.length; j++)
                byteArray.push(parseInt(h[j], 16));
        }
    return byteArray;
};
*/
	
/**
 * Byte Array to Hex String
 */
DataUtils.byteArrayToHexString = function(byteArray) {
    var str = '';
    for (var i = 0; i < byteArray.length; i++)
        str +=  byteArray[i] <= 0x7F?
                byteArray[i] === 0x25 ? "%25" : // %
                String.fromCharCode(byteArray[i]) :
                "%" + byteArray[i].toString(16).toUpperCase();
    return decodeURIComponent(str);
};


/**
 * Byte array to Hex String
 */
//http://ejohn.org/blog/numbers-hex-and-colors/
DataUtils.toHex = function(arguments){
	if(LOG>4) console.log('ABOUT TO CONVERT '+ arguments);
  //console.log(arguments);
  var ret = "";
  for ( var i = 0; i < arguments.length; i++ )
    ret += (arguments[i] < 16 ? "0" : "") + arguments[i].toString(16);
  return ret; //.toUpperCase();
}

/**
 * Raw string to hex string.
 */
DataUtils.stringToHex = function(arguments){
	var ret = "";
	for (var i = 0; i < arguments.length; ++i) {
		var value = arguments.charCodeAt(i);
		ret += (value < 16 ? "0" : "") + value.toString(16);
	}
	return ret;
}

/**
 * Byte array to raw string
 */
//DOES NOT SEEM TO WORK
DataUtils.toString = function(arguments){
  //console.log(arguments);
  var ret = "";
  for ( var i = 0; i < arguments.length; i++ )
    ret += String.fromCharCode(arguments[i]);
  return ret;
}

/**
 * Hex String to byte array
 */
DataUtils.toNumbers=function( str ){
	if(typeof str =='string'){
		  var ret = [];
		   str.replace(/(..)/g, function(str){
		    ret.push( parseInt( str, 16 ) );
		  });
		   return ret;
    }
}

/**
 * Hex String to raw string.
 */
DataUtils.hexToRawString = function(str) {
    if(typeof str =='string') {
		var ret = "";
		str.replace(/(..)/g, function(s) {
			ret += String.fromCharCode(parseInt(s, 16));
		});
		return ret;
    }
}

/**
 * Raw String to Byte Array
 */
DataUtils.toNumbersFromString = function( str ){
	var bytes = new Array(str.length);
	for(var i=0;i<str.length;i++)
		bytes[i] = str.charCodeAt(i);
	return bytes;
}

DataUtils.encodeUtf8 = function (string) {
		string = string.replace(/\r\n/g,"\n");
		var utftext = "";
 
		for (var n = 0; n < string.length; n++) {
 
			var c = string.charCodeAt(n);
 
			if (c < 128) {
				utftext += String.fromCharCode(c);
			}
			else if((c > 127) && (c < 2048)) {
				utftext += String.fromCharCode((c >> 6) | 192);
				utftext += String.fromCharCode((c & 63) | 128);
			}
			else {
				utftext += String.fromCharCode((c >> 12) | 224);
				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
				utftext += String.fromCharCode((c & 63) | 128);
			}
 
		}
 
		return utftext;
	};
 
	// public method for url decoding
DataUtils.decodeUtf8 = function (utftext) {
		var string = "";
		var i = 0;
		var c = c1 = c2 = 0;
 
		while ( i < utftext.length ) {
 
			c = utftext.charCodeAt(i);
 
			if (c < 128) {
				string += String.fromCharCode(c);
				i++;
			}
			else if((c > 191) && (c < 224)) {
				c2 = utftext.charCodeAt(i+1);
				string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
				i += 2;
			}
			else {
				c2 = utftext.charCodeAt(i+1);
				c3 = utftext.charCodeAt(i+2);
				string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
				i += 3;
			}
 
		}
 
		return string;
	};

	test = function(){
		console.log(DataUtils.decodeUtf8("HELLO.~"));
		return DataUtils.decodeUtf8("HELLO.~");
	}

//NOT WORKING
/*
DataUtils.getUTF8StringFromBytes = function(bytes) {
	
	bytes = toString(bytes);

    var ix = 0;
 
    if( bytes.slice(0,3) == "\xEF\xBB\xBF") {
        ix = 3;
    }
 
    var string = "";
    for( ; ix < bytes.length; ix++ ) {
        var byte1 = bytes[ix].charCodeAt(0);
        if( byte1 < 0x80 ) {
            string += String.fromCharCode(byte1);
        } else if( byte1 >= 0xC2 && byte1 < 0xE0 ) {
            var byte2 = bytes[++ix].charCodeAt(0);
            string += String.fromCharCode(((byte1&0x1F)<<6) + (byte2&0x3F));
        } else if( byte1 >= 0xE0 && byte1 < 0xF0 ) {
            var byte2 = bytes[++ix].charCodeAt(0);
            var byte3 = bytes[++ix].charCodeAt(0);
            string += String.fromCharCode(((byte1&0xFF)<<12) + ((byte2&0x3F)<<6) + (byte3&0x3F));
        } else if( byte1 >= 0xF0 && byte1 < 0xF5) {
            var byte2 = bytes[++ix].charCodeAt(0);
            var byte3 = bytes[++ix].charCodeAt(0);
            var byte4 = bytes[++ix].charCodeAt(0);
            var codepoint = ((byte1&0x07)<<18) + ((byte2&0x3F)<<12)+ ((byte3&0x3F)<<6) + (byte4&0x3F);
            codepoint -= 0x10000;
            string += String.fromCharCode(
                (codepoint>>10) + 0xD800,
                (codepoint&0x3FF) + 0xDC00
            );
        }
    }
 
    return string;
}*/

/**
 * Return true if a1 and a2 are the same length with equal elements.
 */
DataUtils.arraysEqual = function(a1, a2){
    if (a1.length != a2.length)
        return false;
    
    for (var i = 0; i < a1.length; ++i) {
        if (a1[i] != a2[i])
            return false;
    }

    return true;
}
/*
 * This file contains utilities to help encode and decode NDN objects.
 * author: ucla-cs
 * See COPYING for copyright and distribution information.
 */

function encodeToHexInterest(interest){
	
	var enc = new BinaryXMLEncoder();
 
	interest.to_ccnb(enc);
	
	var hex = DataUtils.toHex(enc.getReducedOstream());

	return hex;

	
}


function encodeToHexContentObject(co){
	var enc = new BinaryXMLEncoder();
 
	co.to_ccnb(enc);
	
	var hex = DataUtils.toHex(enc.getReducedOstream());

	return hex;

	
}

function encodeToBinaryContentObject(co){
	var enc = new BinaryXMLEncoder();
 
	co.to_ccnb(enc);
	
	var hex = enc.getReducedOstream();

	return hex;

	
}

function encodeForwardingEntry(co){
	var enc = new BinaryXMLEncoder();
 
	co.to_ccnb(enc);
	
	var bytes = enc.getReducedOstream();

	return bytes;

	
}



function decodeHexFaceInstance(result){
	
	var numbers = DataUtils.toNumbers(result);
			
	
	decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODING HEX FACE INSTANCE  \n'+numbers);

	var faceInstance = new FaceInstance();

	faceInstance.from_ccnb(decoder);

	return faceInstance;
	
}

function decodeHexInterest(result){
	var numbers = DataUtils.toNumbers(result);
			
	
	decoder = new BinaryXMLDecoder(numbers);
	if(LOG>3)console.log('DECODING HEX INTERST  \n'+numbers);

	var interest = new Interest();

	interest.from_ccnb(decoder);

	return interest;
	
}



function decodeHexContentObject(result){
	var numbers = DataUtils.toNumbers(result);

	decoder = new BinaryXMLDecoder(numbers);
	if(LOG>3)console.log('DECODED HEX CONTENT OBJECT \n'+numbers);
	
	co = new ContentObject();

	co.from_ccnb(decoder);

	return co;
	
}



function decodeHexForwardingEntry(result){
	var numbers = DataUtils.toNumbers(result);

	decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODED HEX FORWARDING ENTRY \n'+numbers);
	
	forwardingEntry = new ForwardingEntry();

	forwardingEntry.from_ccnb(decoder);

	return forwardingEntry;
	
}

/* Return a user friendly HTML string with the contents of co.
   This also outputs to console.log.
 */
function contentObjectToHtml(/* ContentObject */ co) {
    var output ="";
			
    if(co==-1)
	output+= "NO CONTENT FOUND"
    else if (co==-2)
	output+= "CONTENT NAME IS EMPTY"
    else{
	if(co.name!=null && co.name.components!=null){
	    output+= "NAME: ";
	    
	    for(var i=0;i<co.name.components.length;i++){
		output+= "/"+ DataUtils.toString(co.name.components[i]);
	    }
	    output+= "<br />";
	    output+= "<br />";
	}
	
	if(co.content !=null){
	    output += "CONTENT(ASCII): "+ DataUtils.toString(co.content);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.content !=null){
	    output += "CONTENT(hex): "+ DataUtils.toHex(co.content);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signature !=null && co.signature.signature!=null){
	    output += "SIGNATURE(hex): "+ DataUtils.toHex(co.signature.signature);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signedInfo !=null && co.signedInfo.publisher!=null && co.signedInfo.publisher.publisherPublicKeyDigest!=null){
	    output += "Publisher Public Key Digest(hex): "+ DataUtils.toHex(co.signedInfo.publisher.publisherPublicKeyDigest);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signedInfo !=null && co.signedInfo.timestamp!=null){
	    var d = new Date();
	    d.setTime( co.signedInfo.timestamp.msec );
	    
	    var bytes = [217, 185, 12, 225, 217, 185, 12, 225];
	    
	    output += "TimeStamp: "+d;
	    output+= "<br />";
	    output += "TimeStamp(number): "+ co.signedInfo.timestamp.msec;
	    
	    output+= "<br />";
	}
	if(co.signedInfo !=null && co.signedInfo.finalBlockID!=null){
	    output += "FinalBlockID: "+ DataUtils.toHex(co.signedInfo.finalBlockID);
	    output+= "<br />";
	}
	if(co.signedInfo!=null && co.signedInfo.locator!=null && co.signedInfo.locator.certificate!=null){
	    var tmp = DataUtils.toString(co.signedInfo.locator.certificate);
	    var publickey = rstr2b64(tmp);
	    var publickeyHex = DataUtils.toHex(co.signedInfo.locator.certificate).toLowerCase();
	    var publickeyString = DataUtils.toString(co.signedInfo.locator.certificate);
	    var signature = DataUtils.toHex(co.signature.signature).toLowerCase();
	    var input = DataUtils.toString(co.rawSignatureData);
	    
	    output += "DER Certificate: "+publickey ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    if(LOG>2) console.log(" ContentName + SignedInfo + Content = "+input);
	    
	    if(LOG>2) console.log("HEX OF ContentName + SignedInfo + Content = ");
	    if(LOG>2) console.log(DataUtils.stringtoBase64(input));
	    
	    if(LOG>2) console.log(" PublicKey = "+publickey );
	    if(LOG>2) console.log(" PublicKeyHex = "+publickeyHex );
	    if(LOG>2) console.log(" PublicKeyString = "+publickeyString );
	    
	    if(LOG>2) console.log(" Signature is");
	    if(LOG>2) console.log( signature );
	    //if(LOG>2) console.log(" Signature NOW IS" );
	    //if(LOG>2) console.log(co.signature.signature);

	    var x509 = new X509();
	    x509.readCertPEM(publickey);
	    
	    //x509.readCertPEMWithoutRSAInit(publickey);

	    var result = x509.subjectPublicKeyRSA.verifyByteArray(co.rawSignatureData, signature);
	    if(LOG>2) console.log('result is '+result);
	    
	    var n = x509.subjectPublicKeyRSA.n;
	    var e =  x509.subjectPublicKeyRSA.e;
	    
	    if(LOG>2) console.log('PUBLIC KEY n after is ');
	    if(LOG>2) console.log(n);

	    if(LOG>2) console.log('EXPONENT e after is ');
	    if(LOG>2) console.log(e);
	    
	    /*var rsakey = new RSAKey();
	      
	      var kp = publickeyHex.slice(56,314);
	      
	      output += "PUBLISHER KEY(hex): "+kp ;
	      
	      output+= "<br />";
	      output+= "<br />";
	      
	      console.log('kp is '+kp);
	      
	      var exp = publickeyHex.slice(318,324);
	      
	      console.log('kp size is '+kp.length );
	      output += "exponent: "+exp ;
	      
	      output+= "<br />";
	      output+= "<br />";
	      
	      console.log('exp is '+exp);
	      
	      rsakey.setPublic(kp,exp);

	      var result = rsakey.verifyString(input, signature);*/
	    
	    if(result)
		output += 'SIGNATURE VALID';
	    else
		output += 'SIGNATURE INVALID';
	    
	    //output += "VALID: "+ toHex(co.signedInfo.locator.publicKey);
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    //if(LOG>4) console.log('str'[1]);
	}
	if(co.signedInfo!=null && co.signedInfo.locator!=null && co.signedInfo.locator.publicKey!=null){
	    var publickey = rstr2b64(DataUtils.toString(co.signedInfo.locator.publicKey));
	    var publickeyHex = DataUtils.toHex(co.signedInfo.locator.publicKey).toLowerCase();
	    var publickeyString = DataUtils.toString(co.signedInfo.locator.publicKey);
	    var signature = DataUtils.toHex(co.signature.signature).toLowerCase();
	    var input = DataUtils.toString(co.rawSignatureData);
	    
	    output += "DER Certificate: "+publickey ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    if(LOG>2) console.log(" ContentName + SignedInfo + Content = "+input);
	    if(LOG>2) console.log(" PublicKey = "+publickey );
	    if(LOG>2) console.log(" PublicKeyHex = "+publickeyHex );
	    if(LOG>2) console.log(" PublicKeyString = "+publickeyString );
	    
	    if(LOG>2) console.log(" Signature "+signature );
	    
	    if(LOG>2) console.log(" Signature NOW IS" );
	    
	    if(LOG>2) console.log(co.signature.signature);
	    
	    /*var x509 = new X509();
	      
	      x509.readCertPEM(publickey);
	      
	      
	      //x509.readCertPEMWithoutRSAInit(publickey);

	      var result = x509.subjectPublicKeyRSA.verifyString(input, signature);*/
	    //console.log('result is '+result);
	    
	    var kp = publickeyHex.slice(56,314);
	    
	    output += "PUBLISHER KEY(hex): "+kp ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    console.log('PUBLIC KEY IN HEX is ');
	    console.log(kp);

	    var exp = publickeyHex.slice(318,324);
	    
	    console.log('kp size is '+kp.length );
	    output += "exponent: "+exp ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    console.log('EXPONENT is ');
	    console.log(exp);
	    
	    /*var c1 = hex_sha256(input);
	      var c2 = signature;
	      
	      if(LOG>4)console.log('input is ');
	      if(LOG>4)console.log(input);
	      if(LOG>4)console.log('C1 is ');
	      if(LOG>4)console.log(c1);
	      if(LOG>4)console.log('C2 is ');
	      if(LOG>4)console.log(c2);
	      var result = c1 == c2;*/
	    
	    var rsakey = new RSAKey();
	    
	    rsakey.setPublic(kp,exp);
	    
	    var result = rsakey.verifyByteArray(co.rawSignatureData,signature);
	    // var result = rsakey.verifyString(input, signature);
	    
	    console.log('PUBLIC KEY n after is ');
	    console.log(rsakey.n);

	    console.log('EXPONENT e after is ');
	    console.log(rsakey.e);
	    
	    if(result)
		output += 'SIGNATURE VALID';
	    else
		output += 'SIGNATURE INVALID';
	    
	    //output += "VALID: "+ toHex(co.signedInfo.locator.publicKey);
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    //if(LOG>4) console.log('str'[1]);
	}
    }

    return output;
}

/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 */

var KeyManager = function KeyManager(){

	
//Certificate from CCNx

this.certificate = 'MIIBmzCCAQQCCQC32FyQa61S7jANBgkqhkiG9w0BAQUFADASMRAwDgYDVQQDEwd'+

'heGVsY2R2MB4XDTEyMDQyODIzNDQzN1oXDTEyMDUyODIzNDQzN1owEjEQMA4GA1'+

'UEAxMHYXhlbGNkdjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4X0wp9goq'+

'xuECxdULcr2IHr9Ih4Iaypg0Wy39URIup8/CLzQmdsh3RYqd55hqonu5VTTpH3i'+

'MLx6xZDVJAZ8OJi7pvXcQ2C4Re2kjL2c8SanI0RfDhlS1zJadfr1VhRPmpivcYa'+

'wJ4aFuOLAi+qHFxtN7lhcGCgpW1OV60oXd58CAwEAATANBgkqhkiG9w0BAQUFAA'+

'OBgQDLOrA1fXzSrpftUB5Ro6DigX1Bjkf7F5Bkd69hSVp+jYeJFBBlsILQAfSxU'+

'ZPQtD+2Yc3iCmSYNyxqu9PcufDRJlnvB7PG29+L3y9lR37tetzUV9eTscJ7rdp8'+

'Wt6AzpW32IJ/54yKNfP7S6ZIoIG+LP6EIxq6s8K1MXRt8uBJKw==';


//this.publicKey = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhfTCn2CirG4QLF1QtyvYgev0iHghrKmDRbLf1REi6nz8IvNCZ2yHdFip3nmGqie7lVNOkfeIwvHrFkNUkBnw4mLum9dxDYLhF7aSMvZzxJqcjRF8OGVLXMlp1+vVWFE+amK9xhrAnhoW44sCL6ocXG03uWFwYKClbU5XrShd3nwIDAQAB';
this.publicKey ='30819F300D06092A864886F70D010101050003818D0030818902818100E17D30A7D828AB1B840B17542DCAF6207AFD221E086B2A60D16CB7F54448BA9F3F08BCD099DB21DD162A779E61AA89EEE554D3A47DE230BC7AC590D524067C3898BBA6F5DC4360B845EDA48CBD9CF126A723445F0E1952D7325A75FAF556144F9A98AF7186B0278685B8E2C08BEA87171B4DEE585C1828295B5395EB4A17779F0203010001';
//Private Key from CCNx

this.privateKey ='MIICXQIBAAKBgQDhfTCn2CirG4QLF1QtyvYgev0iHghrKmDRbLf1REi6nz8IvNCZ2yHdFip3nmGqie7lVNOkfeIwvHrFkNUkBnw4mLum9dxDYLhF7aSMvZzxJqcjRF8OGVLXMlp1+vVWFE+amK9xhrAnhoW44sCL6ocXG03uWFwYKClbU5XrShd3nwIDAQABAoGAGkv6T6jC3WmhFZYL6CdCWvlc6gysmKrhjarrLTxgavtFY6R5g2ft5BXAsCCVbUkWxkIFSKqxpVNl0gKZCNGEzPDN6mHJOQI/h0rlxNIHAuGfoAbCzALnqmyZivhJAPGijAyKuU9tczsst5+Kpn+bn7ehzHQuj7iwJonS5WbojqECQQD851K8TpW2GrRizNgG4dx6orZxAaon/Jnl8lS7soXhllQty7qG+oDfzznmdMsiznCqEABzHUUKOVGE9RWPN3aRAkEA5D/w9N55d0ibnChFJlc8cUAoaqH+w+U3oQP2Lb6AZHJpLptN4y4b/uf5d4wYU5/i/gC7SSBH3wFhh9bjRLUDLwJAVOx8vN0Kqt7myfKNbCo19jxjVSlA8TKCn1Oznl/BU1I+rC4oUaEW25DjmX6IpAR8kq7S59ThVSCQPjxqY/A08QJBAIRaF2zGPITQk3r/VumemCvLWiRK/yG0noc9dtibqHOWbCtcXtOm/xDWjq+lis2i3ssOvYrvrv0/HcDY+Dv1An0CQQCLJtMsfSg4kvG/FRY5UMhtMuwo8ovYcMXt4Xv/LWaMhndD67b2UGawQCRqr5ghRTABWdDD/HuuMBjrkPsX0861';


/*
	this.certificate = 
			'MIIBvTCCASYCCQD55fNzc0WF7TANBgkqhkiG9w0BAQUFADAjMQswCQYDVQQGEwJK'+
			'UDEUMBIGA1UEChMLMDAtVEVTVC1SU0EwHhcNMTAwNTI4MDIwODUxWhcNMjAwNTI1'+
			'MDIwODUxWjAjMQswCQYDVQQGEwJKUDEUMBIGA1UEChMLMDAtVEVTVC1SU0EwgZ8w'+
			'DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANGEYXtfgDRlWUSDn3haY4NVVQiKI9Cz'+
			'Thoua9+DxJuiseyzmBBe7Roh1RPqdvmtOHmEPbJ+kXZYhbozzPRbFGHCJyBfCLzQ'+
			'fVos9/qUQ88u83b0SFA2MGmQWQAlRtLy66EkR4rDRwTj2DzR4EEXgEKpIvo8VBs/'+
			'3+sHLF3ESgAhAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAEZ6mXFFq3AzfaqWHmCy1'+
			'ARjlauYAa8ZmUFnLm0emg9dkVBJ63aEqARhtok6bDQDzSJxiLpCEF6G4b/Nv/M/M'+
			'LyhP+OoOTmETMegAVQMq71choVJyOFE5BtQa6M/lCHEOya5QUfoRF2HF9EjRF44K'+
			'3OK+u3ivTSj3zwjtpudY5Xo=';
	
	this.privateKey =
			'MIICWwIBAAKBgQDRhGF7X4A0ZVlEg594WmODVVUIiiPQs04aLmvfg8SborHss5gQ'+
			'Xu0aIdUT6nb5rTh5hD2yfpF2WIW6M8z0WxRhwicgXwi80H1aLPf6lEPPLvN29EhQ'+
			'NjBpkFkAJUbS8uuhJEeKw0cE49g80eBBF4BCqSL6PFQbP9/rByxdxEoAIQIDAQAB'+
			'AoGAA9/q3Zk6ib2GFRpKDLO/O2KMnAfR+b4XJ6zMGeoZ7Lbpi3MW0Nawk9ckVaX0'+
			'ZVGqxbSIX5Cvp/yjHHpww+QbUFrw/gCjLiiYjM9E8C3uAF5AKJ0r4GBPl4u8K4bp'+
			'bXeSxSB60/wPQFiQAJVcA5xhZVzqNuF3EjuKdHsw+dk+dPECQQDubX/lVGFgD/xY'+
			'uchz56Yc7VHX+58BUkNSewSzwJRbcueqknXRWwj97SXqpnYfKqZq78dnEF10SWsr'+
			'/NMKi+7XAkEA4PVqDv/OZAbWr4syXZNv/Mpl4r5suzYMMUD9U8B2JIRnrhmGZPzL'+
			'x23N9J4hEJ+Xh8tSKVc80jOkrvGlSv+BxwJAaTOtjA3YTV+gU7Hdza53sCnSw/8F'+
			'YLrgc6NOJtYhX9xqdevbyn1lkU0zPr8mPYg/F84m6MXixm2iuSz8HZoyzwJARi2p'+
			'aYZ5/5B2lwroqnKdZBJMGKFpUDn7Mb5hiSgocxnvMkv6NjT66Xsi3iYakJII9q8C'+
			'Ma1qZvT/cigmdbAh7wJAQNXyoizuGEltiSaBXx4H29EdXNYWDJ9SS5f070BRbAIl'+
			'dqRh3rcNvpY6BKJqFapda1DjdcncZECMizT/GMrc1w==';
			
			*/
};


KeyManager.prototype.verify = function verify(message,signature){
	
	var input = message;

	var  _PEM_X509CERT_STRING_ = this.certificate;
	
	var x509 = new X509();
	
	x509.readCertPEM(_PEM_X509CERT_STRING_);
	
	var result = x509.subjectPublicKeyRSA.verifyString(input, signature);
	
	return result;
};

KeyManager.prototype.sign= function sign(message){
	
	var input = message;
		
	var  _PEM_PRIVATE_KEY_STRING_ = this.privateKey;
	
	var rsa = new RSAKey();
	
	rsa.readPrivateKeyFromPEMString(_PEM_PRIVATE_KEY_STRING_);
	
	var hSig = rsa.signString(input, "sha256");
	
	return hSig;

};



var globalKeyManager = new KeyManager();
//var KeyPair = { "public" : "PUBLIC KEY" , "private" : "PRIVATE KEY" };



/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS 180-1
 * Version 2.2 Copyright Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */

/**
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_sha1(s)    { return rstr2hex(rstr_sha1(str2rstr_utf8(s))); }
function b64_sha1(s)    { return rstr2b64(rstr_sha1(str2rstr_utf8(s))); }
function any_sha1(s, e) { return rstr2any(rstr_sha1(str2rstr_utf8(s)), e); }
function hex_hmac_sha1(k, d)
  { return rstr2hex(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_sha1(k, d)
  { return rstr2b64(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_sha1(k, d, e)
  { return rstr2any(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d)), e); }

/**
 * Perform a simple self-test to see if the VM is working
 */
function sha1_vm_test()
{
  return hex_sha1("abc").toLowerCase() == "a9993e364706816aba3e25717850c26c9cd0d89d";
}

/**
 * Calculate the SHA1 of a raw string
 */
function rstr_sha1(s)
{
  return binb2rstr(binb_sha1(rstr2binb(s), s.length * 8));
}

/**
 * Calculate the HMAC-SHA1 of a key and some data (raw strings)
 */
function rstr_hmac_sha1(key, data)
{
  var bkey = rstr2binb(key);
  if(bkey.length > 16) bkey = binb_sha1(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binb_sha1(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
  return binb2rstr(binb_sha1(opad.concat(hash), 512 + 160));
}

/**
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/**
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/**
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var remainders = Array();
  var i, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  /*
   * Repeatedly perform a long division. The binary array forms the dividend,
   * the length of the encoding is the divisor. Once computed, the quotient
   * forms the dividend for the next step. We stop when the dividend is zero.
   * All remainders are stored for later use.
   */
  while(dividend.length > 0)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[remainders.length] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  /* Append leading zero equivalents */
  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)));
  for(i = output.length; i < full_length; i++)
    output = encoding[0] + output;

  return output;
}

/**
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/**
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/**
 * Convert a raw string to an array of big-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binb(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
  return output;
}

/**
 * Convert an array of big-endian words to a string
 */
function binb2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (24 - i % 32)) & 0xFF);
  return output;
}

/**
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function binb_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = bit_rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(bit_rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = bit_rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

/**
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/**
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/**
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/**
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-256, as defined
 * in FIPS 180-2
 * Version 2.2 Copyright Angel Marin, Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 * Also http://anmar.eu.org/projects/jssha2/
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */

//@author axelcdv
/**
 * Computes the Sha-256 hash of the given byte array
 * @param {byte[]} 
 * @return the hex string corresponding to the Sha-256 hash of the byte array
 */
function hex_sha256_from_bytes(byteArray){
	return rstr2hex(binb2rstr(binb_sha256( byteArray2binb(byteArray), byteArray.length * 8)));
}

function hex_sha256(s)    { return rstr2hex(rstr_sha256(str2rstr_utf8(s))); }
function b64_sha256(s)    { return rstr2b64(rstr_sha256(str2rstr_utf8(s))); }
function any_sha256(s, e) { return rstr2any(rstr_sha256(str2rstr_utf8(s)), e); }
function hex_hmac_sha256(k, d)
  { return rstr2hex(rstr_hmac_sha256(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_sha256(k, d)
  { return rstr2b64(rstr_hmac_sha256(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_sha256(k, d, e)
  { return rstr2any(rstr_hmac_sha256(str2rstr_utf8(k), str2rstr_utf8(d)), e); }

	
/*
	function hex_sha256(s)    { return rstr2hex(rstr_sha256(s)); }
function b64_sha256(s)    { return rstr2b64(rstr_sha256(s)); }
function any_sha256(s, e) { return rstr2any(rstr_sha256(s), e); }
function hex_hmac_sha256(k, d)
  { return rstr2hex(rstr_hmac_sha256(str2rstr_utf8(k), d)); }
function b64_hmac_sha256(k, d)
  { return rstr2b64(rstr_hmac_sha256(str2rstr_utf8(k), d)); }
function any_hmac_sha256(k, d, e)
  { return rstr2any(rstr_hmac_sha256(str2rstr_utf8(k), d), e); }
*/
	
/*
 * Perform a simple self-test to see if the VM is working
 */
function sha256_vm_test()
{
  return hex_sha256("abc").toLowerCase() ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
}

/**
 * Calculate the sha256 of a raw string
 * @param s: the raw string
 */
function rstr_sha256(s)
{
  return binb2rstr(binb_sha256(rstr2binb(s), s.length * 8));
}

/**
 * Calculate the HMAC-sha256 of a key and some data (raw strings)
 */
function rstr_hmac_sha256(key, data)
{
  var bkey = rstr2binb(key);
  if(bkey.length > 16) bkey = binb_sha256(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binb_sha256(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
  return binb2rstr(binb_sha256(opad.concat(hash), 512 + 256));
}

/**
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var remainders = Array();
  var i, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  /*
   * Repeatedly perform a long division. The binary array forms the dividend,
   * the length of the encoding is the divisor. Once computed, the quotient
   * forms the dividend for the next step. We stop when the dividend is zero.
   * All remainders are stored for later use.
   */
  while(dividend.length > 0)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[remainders.length] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  /* Append leading zero equivalents */
  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)))
  for(i = output.length; i < full_length; i++)
    output = encoding[0] + output;

  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/**
 * Convert a raw string to an array of big-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binb(input)
{
  console.log('Raw string comming is '+input);
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
  return output;
}

/**
 * @author axelcdv
 * Convert a byte array to an array of big-endian words
 * @param {byte[]} input
 * @return the array of big-endian words
 */
function byteArray2binb(input){
	console.log("Byte array coming is " + input);
	var output = Array(input.length >> 2);
	  for(var i = 0; i < output.length; i++)
	    output[i] = 0;
	  for(var i = 0; i < input.length * 8; i += 8)
	    output[i>>5] |= (input[i / 8] & 0xFF) << (24 - i % 32);
	  return output;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (24 - i % 32)) & 0xFF);
  return output;
}

/*
 * Main sha256 function, with its support functions
 */
function sha256_S (X, n) {return ( X >>> n ) | (X << (32 - n));}
function sha256_R (X, n) {return ( X >>> n );}
function sha256_Ch(x, y, z) {return ((x & y) ^ ((~x) & z));}
function sha256_Maj(x, y, z) {return ((x & y) ^ (x & z) ^ (y & z));}
function sha256_Sigma0256(x) {return (sha256_S(x, 2) ^ sha256_S(x, 13) ^ sha256_S(x, 22));}
function sha256_Sigma1256(x) {return (sha256_S(x, 6) ^ sha256_S(x, 11) ^ sha256_S(x, 25));}
function sha256_Gamma0256(x) {return (sha256_S(x, 7) ^ sha256_S(x, 18) ^ sha256_R(x, 3));}
function sha256_Gamma1256(x) {return (sha256_S(x, 17) ^ sha256_S(x, 19) ^ sha256_R(x, 10));}
function sha256_Sigma0512(x) {return (sha256_S(x, 28) ^ sha256_S(x, 34) ^ sha256_S(x, 39));}
function sha256_Sigma1512(x) {return (sha256_S(x, 14) ^ sha256_S(x, 18) ^ sha256_S(x, 41));}
function sha256_Gamma0512(x) {return (sha256_S(x, 1)  ^ sha256_S(x, 8) ^ sha256_R(x, 7));}
function sha256_Gamma1512(x) {return (sha256_S(x, 19) ^ sha256_S(x, 61) ^ sha256_R(x, 6));}

var sha256_K = new Array
(
  1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993,
  -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
  1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
  264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
  -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
  113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
  1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885,
  -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
  430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
  1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872,
  -1866530822, -1538233109, -1090935817, -965641998
);

function binb_sha256(m, l)
{
  var HASH = new Array(1779033703, -1150833019, 1013904242, -1521486534,
                       1359893119, -1694144372, 528734635, 1541459225);
  var W = new Array(64);
  var a, b, c, d, e, f, g, h;
  var i, j, T1, T2;

  /* append padding */
  m[l >> 5] |= 0x80 << (24 - l % 32);
  m[((l + 64 >> 9) << 4) + 15] = l;

  for(i = 0; i < m.length; i += 16)
  {
    a = HASH[0];
    b = HASH[1];
    c = HASH[2];
    d = HASH[3];
    e = HASH[4];
    f = HASH[5];
    g = HASH[6];
    h = HASH[7];

    for(j = 0; j < 64; j++)
    {
      if (j < 16) W[j] = m[j + i];
      else W[j] = safe_add(safe_add(safe_add(sha256_Gamma1256(W[j - 2]), W[j - 7]),
                                            sha256_Gamma0256(W[j - 15])), W[j - 16]);

      T1 = safe_add(safe_add(safe_add(safe_add(h, sha256_Sigma1256(e)), sha256_Ch(e, f, g)),
                                                          sha256_K[j]), W[j]);
      T2 = safe_add(sha256_Sigma0256(a), sha256_Maj(a, b, c));
      h = g;
      g = f;
      f = e;
      e = safe_add(d, T1);
      d = c;
      c = b;
      b = a;
      a = safe_add(T1, T2);
    }

    HASH[0] = safe_add(a, HASH[0]);
    HASH[1] = safe_add(b, HASH[1]);
    HASH[2] = safe_add(c, HASH[2]);
    HASH[3] = safe_add(d, HASH[3]);
    HASH[4] = safe_add(e, HASH[4]);
    HASH[5] = safe_add(f, HASH[5]);
    HASH[6] = safe_add(g, HASH[6]);
    HASH[7] = safe_add(h, HASH[7]);
  }
  return HASH;
}

function safe_add (x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-512, as defined
 * in FIPS 180-2
 * Version 2.2 Copyright Anonymous Contributor, Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_sha512(s)    { return rstr2hex(rstr_sha512(str2rstr_utf8(s))); }
function b64_sha512(s)    { return rstr2b64(rstr_sha512(str2rstr_utf8(s))); }
function any_sha512(s, e) { return rstr2any(rstr_sha512(str2rstr_utf8(s)), e);}
function hex_hmac_sha512(k, d)
  { return rstr2hex(rstr_hmac_sha512(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_sha512(k, d)
  { return rstr2b64(rstr_hmac_sha512(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_sha512(k, d, e)
  { return rstr2any(rstr_hmac_sha512(str2rstr_utf8(k), str2rstr_utf8(d)), e);}

/*
 * Perform a simple self-test to see if the VM is working
 */
function sha512_vm_test()
{
  return hex_sha512("abc").toLowerCase() ==
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
}

/*
 * Calculate the SHA-512 of a raw string
 */
function rstr_sha512(s)
{
  return binb2rstr(binb_sha512(rstr2binb(s), s.length * 8));
}

/*
 * Calculate the HMAC-SHA-512 of a key and some data (raw strings)
 */
function rstr_hmac_sha512(key, data)
{
  var bkey = rstr2binb(key);
  if(bkey.length > 32) bkey = binb_sha512(bkey, key.length * 8);

  var ipad = Array(32), opad = Array(32);
  for(var i = 0; i < 32; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binb_sha512(ipad.concat(rstr2binb(data)), 1024 + data.length * 8);
  return binb2rstr(binb_sha512(opad.concat(hash), 1024 + 512));
}

/*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var i, j, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  /*
   * Repeatedly perform a long division. The binary array forms the dividend,
   * the length of the encoding is the divisor. Once computed, the quotient
   * forms the dividend for the next step. All remainders are stored for later
   * use.
   */
  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)));
  var remainders = Array(full_length);
  for(j = 0; j < full_length; j++)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[j] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/*
 * Convert a raw string to an array of big-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binb(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
  return output;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (24 - i % 32)) & 0xFF);
  return output;
}

/*
 * Calculate the SHA-512 of an array of big-endian dwords, and a bit length
 */
var sha512_k;
function binb_sha512(x, len)
{
  if(sha512_k == undefined)
  {
    //SHA512 constants
    sha512_k = new Array(
new int64(0x428a2f98, -685199838), new int64(0x71374491, 0x23ef65cd),
new int64(-1245643825, -330482897), new int64(-373957723, -2121671748),
new int64(0x3956c25b, -213338824), new int64(0x59f111f1, -1241133031),
new int64(-1841331548, -1357295717), new int64(-1424204075, -630357736),
new int64(-670586216, -1560083902), new int64(0x12835b01, 0x45706fbe),
new int64(0x243185be, 0x4ee4b28c), new int64(0x550c7dc3, -704662302),
new int64(0x72be5d74, -226784913), new int64(-2132889090, 0x3b1696b1),
new int64(-1680079193, 0x25c71235), new int64(-1046744716, -815192428),
new int64(-459576895, -1628353838), new int64(-272742522, 0x384f25e3),
new int64(0xfc19dc6, -1953704523), new int64(0x240ca1cc, 0x77ac9c65),
new int64(0x2de92c6f, 0x592b0275), new int64(0x4a7484aa, 0x6ea6e483),
new int64(0x5cb0a9dc, -1119749164), new int64(0x76f988da, -2096016459),
new int64(-1740746414, -295247957), new int64(-1473132947, 0x2db43210),
new int64(-1341970488, -1728372417), new int64(-1084653625, -1091629340),
new int64(-958395405, 0x3da88fc2), new int64(-710438585, -1828018395),
new int64(0x6ca6351, -536640913), new int64(0x14292967, 0xa0e6e70),
new int64(0x27b70a85, 0x46d22ffc), new int64(0x2e1b2138, 0x5c26c926),
new int64(0x4d2c6dfc, 0x5ac42aed), new int64(0x53380d13, -1651133473),
new int64(0x650a7354, -1951439906), new int64(0x766a0abb, 0x3c77b2a8),
new int64(-2117940946, 0x47edaee6), new int64(-1838011259, 0x1482353b),
new int64(-1564481375, 0x4cf10364), new int64(-1474664885, -1136513023),
new int64(-1035236496, -789014639), new int64(-949202525, 0x654be30),
new int64(-778901479, -688958952), new int64(-694614492, 0x5565a910),
new int64(-200395387, 0x5771202a), new int64(0x106aa070, 0x32bbd1b8),
new int64(0x19a4c116, -1194143544), new int64(0x1e376c08, 0x5141ab53),
new int64(0x2748774c, -544281703), new int64(0x34b0bcb5, -509917016),
new int64(0x391c0cb3, -976659869), new int64(0x4ed8aa4a, -482243893),
new int64(0x5b9cca4f, 0x7763e373), new int64(0x682e6ff3, -692930397),
new int64(0x748f82ee, 0x5defb2fc), new int64(0x78a5636f, 0x43172f60),
new int64(-2067236844, -1578062990), new int64(-1933114872, 0x1a6439ec),
new int64(-1866530822, 0x23631e28), new int64(-1538233109, -561857047),
new int64(-1090935817, -1295615723), new int64(-965641998, -479046869),
new int64(-903397682, -366583396), new int64(-779700025, 0x21c0c207),
new int64(-354779690, -840897762), new int64(-176337025, -294727304),
new int64(0x6f067aa, 0x72176fba), new int64(0xa637dc5, -1563912026),
new int64(0x113f9804, -1090974290), new int64(0x1b710b35, 0x131c471b),
new int64(0x28db77f5, 0x23047d84), new int64(0x32caab7b, 0x40c72493),
new int64(0x3c9ebe0a, 0x15c9bebc), new int64(0x431d67c4, -1676669620),
new int64(0x4cc5d4be, -885112138), new int64(0x597f299c, -60457430),
new int64(0x5fcb6fab, 0x3ad6faec), new int64(0x6c44198c, 0x4a475817));
  }

  //Initial hash values
  var H = new Array(
new int64(0x6a09e667, -205731576),
new int64(-1150833019, -2067093701),
new int64(0x3c6ef372, -23791573),
new int64(-1521486534, 0x5f1d36f1),
new int64(0x510e527f, -1377402159),
new int64(-1694144372, 0x2b3e6c1f),
new int64(0x1f83d9ab, -79577749),
new int64(0x5be0cd19, 0x137e2179));

  var T1 = new int64(0, 0),
    T2 = new int64(0, 0),
    a = new int64(0,0),
    b = new int64(0,0),
    c = new int64(0,0),
    d = new int64(0,0),
    e = new int64(0,0),
    f = new int64(0,0),
    g = new int64(0,0),
    h = new int64(0,0),
    //Temporary variables not specified by the document
    s0 = new int64(0, 0),
    s1 = new int64(0, 0),
    Ch = new int64(0, 0),
    Maj = new int64(0, 0),
    r1 = new int64(0, 0),
    r2 = new int64(0, 0),
    r3 = new int64(0, 0);
  var j, i;
  var W = new Array(80);
  for(i=0; i<80; i++)
    W[i] = new int64(0, 0);

  // append padding to the source string. The format is described in the FIPS.
  x[len >> 5] |= 0x80 << (24 - (len & 0x1f));
  x[((len + 128 >> 10)<< 5) + 31] = len;

  for(i = 0; i<x.length; i+=32) //32 dwords is the block size
  {
    int64copy(a, H[0]);
    int64copy(b, H[1]);
    int64copy(c, H[2]);
    int64copy(d, H[3]);
    int64copy(e, H[4]);
    int64copy(f, H[5]);
    int64copy(g, H[6]);
    int64copy(h, H[7]);

    for(j=0; j<16; j++)
    {
        W[j].h = x[i + 2*j];
        W[j].l = x[i + 2*j + 1];
    }

    for(j=16; j<80; j++)
    {
      //sigma1
      int64rrot(r1, W[j-2], 19);
      int64revrrot(r2, W[j-2], 29);
      int64shr(r3, W[j-2], 6);
      s1.l = r1.l ^ r2.l ^ r3.l;
      s1.h = r1.h ^ r2.h ^ r3.h;
      //sigma0
      int64rrot(r1, W[j-15], 1);
      int64rrot(r2, W[j-15], 8);
      int64shr(r3, W[j-15], 7);
      s0.l = r1.l ^ r2.l ^ r3.l;
      s0.h = r1.h ^ r2.h ^ r3.h;

      int64add4(W[j], s1, W[j-7], s0, W[j-16]);
    }

    for(j = 0; j < 80; j++)
    {
      //Ch
      Ch.l = (e.l & f.l) ^ (~e.l & g.l);
      Ch.h = (e.h & f.h) ^ (~e.h & g.h);

      //Sigma1
      int64rrot(r1, e, 14);
      int64rrot(r2, e, 18);
      int64revrrot(r3, e, 9);
      s1.l = r1.l ^ r2.l ^ r3.l;
      s1.h = r1.h ^ r2.h ^ r3.h;

      //Sigma0
      int64rrot(r1, a, 28);
      int64revrrot(r2, a, 2);
      int64revrrot(r3, a, 7);
      s0.l = r1.l ^ r2.l ^ r3.l;
      s0.h = r1.h ^ r2.h ^ r3.h;

      //Maj
      Maj.l = (a.l & b.l) ^ (a.l & c.l) ^ (b.l & c.l);
      Maj.h = (a.h & b.h) ^ (a.h & c.h) ^ (b.h & c.h);

      int64add5(T1, h, s1, Ch, sha512_k[j], W[j]);
      int64add(T2, s0, Maj);

      int64copy(h, g);
      int64copy(g, f);
      int64copy(f, e);
      int64add(e, d, T1);
      int64copy(d, c);
      int64copy(c, b);
      int64copy(b, a);
      int64add(a, T1, T2);
    }
    int64add(H[0], H[0], a);
    int64add(H[1], H[1], b);
    int64add(H[2], H[2], c);
    int64add(H[3], H[3], d);
    int64add(H[4], H[4], e);
    int64add(H[5], H[5], f);
    int64add(H[6], H[6], g);
    int64add(H[7], H[7], h);
  }

  //represent the hash as an array of 32-bit dwords
  var hash = new Array(16);
  for(i=0; i<8; i++)
  {
    hash[2*i] = H[i].h;
    hash[2*i + 1] = H[i].l;
  }
  return hash;
}

//A constructor for 64-bit numbers
function int64(h, l)
{
  this.h = h;
  this.l = l;
  //this.toString = int64toString;
}

//Copies src into dst, assuming both are 64-bit numbers
function int64copy(dst, src)
{
  dst.h = src.h;
  dst.l = src.l;
}

//Right-rotates a 64-bit number by shift
//Won't handle cases of shift>=32
//The function revrrot() is for that
function int64rrot(dst, x, shift)
{
    dst.l = (x.l >>> shift) | (x.h << (32-shift));
    dst.h = (x.h >>> shift) | (x.l << (32-shift));
}

//Reverses the dwords of the source and then rotates right by shift.
//This is equivalent to rotation by 32+shift
function int64revrrot(dst, x, shift)
{
    dst.l = (x.h >>> shift) | (x.l << (32-shift));
    dst.h = (x.l >>> shift) | (x.h << (32-shift));
}

//Bitwise-shifts right a 64-bit number by shift
//Won't handle shift>=32, but it's never needed in SHA512
function int64shr(dst, x, shift)
{
    dst.l = (x.l >>> shift) | (x.h << (32-shift));
    dst.h = (x.h >>> shift);
}

//Adds two 64-bit numbers
//Like the original implementation, does not rely on 32-bit operations
function int64add(dst, x, y)
{
   var w0 = (x.l & 0xffff) + (y.l & 0xffff);
   var w1 = (x.l >>> 16) + (y.l >>> 16) + (w0 >>> 16);
   var w2 = (x.h & 0xffff) + (y.h & 0xffff) + (w1 >>> 16);
   var w3 = (x.h >>> 16) + (y.h >>> 16) + (w2 >>> 16);
   dst.l = (w0 & 0xffff) | (w1 << 16);
   dst.h = (w2 & 0xffff) | (w3 << 16);
}

//Same, except with 4 addends. Works faster than adding them one by one.
function int64add4(dst, a, b, c, d)
{
   var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff);
   var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (w0 >>> 16);
   var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (w1 >>> 16);
   var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (w2 >>> 16);
   dst.l = (w0 & 0xffff) | (w1 << 16);
   dst.h = (w2 & 0xffff) | (w3 << 16);
}

//Same, except with 5 addends
function int64add5(dst, a, b, c, d, e)
{
   var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff) + (e.l & 0xffff);
   var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (w0 >>> 16);
   var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (e.h & 0xffff) + (w1 >>> 16);
   var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (w2 >>> 16);
   dst.l = (w0 & 0xffff) | (w1 << 16);
   dst.h = (w2 & 0xffff) | (w3 << 16);
}

/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;   /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = "";  /* base-64 pad character. "=" for strict RFC compliance   */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_md5(s)    { return rstr2hex(rstr_md5(str2rstr_utf8(s))); }
function b64_md5(s)    { return rstr2b64(rstr_md5(str2rstr_utf8(s))); }
function any_md5(s, e) { return rstr2any(rstr_md5(str2rstr_utf8(s)), e); }
function hex_hmac_md5(k, d)
  { return rstr2hex(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_md5(k, d)
  { return rstr2b64(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_md5(k, d, e)
  { return rstr2any(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d)), e); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
  return hex_md5("abc").toLowerCase() == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of a raw string
 */
function rstr_md5(s)
{
  return binl2rstr(binl_md5(rstr2binl(s), s.length * 8));
}

/*
 * Calculate the HMAC-MD5, of a key and some data (raw strings)
 */
function rstr_hmac_md5(key, data)
{
  var bkey = rstr2binl(key);
  if(bkey.length > 16) bkey = binl_md5(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binl_md5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
  return binl2rstr(binl_md5(opad.concat(hash), 512 + 128));
}

/*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var i, j, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  /*
   * Repeatedly perform a long division. The binary array forms the dividend,
   * the length of the encoding is the divisor. Once computed, the quotient
   * forms the dividend for the next step. All remainders are stored for later
   * use.
   */
  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)));
  var remainders = Array(full_length);
  for(j = 0; j < full_length; j++)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[j] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/*
 * Convert a raw string to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binl(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (i%32);
  return output;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (i % 32)) & 0xFF);
  return output;
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length.
 */
function binl_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return Array(a, b, c, d);
}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * A JavaScript implementation of the RIPEMD-160 Algorithm
 * Version 2.2 Copyright Jeremy Lin, Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 * Also http://www.ocf.berkeley.edu/~jjlin/jsotp/
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_rmd160(s)    { return rstr2hex(rstr_rmd160(str2rstr_utf8(s))); }
function b64_rmd160(s)    { return rstr2b64(rstr_rmd160(str2rstr_utf8(s))); }
function any_rmd160(s, e) { return rstr2any(rstr_rmd160(str2rstr_utf8(s)), e); }
function hex_hmac_rmd160(k, d)
  { return rstr2hex(rstr_hmac_rmd160(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_rmd160(k, d)
  { return rstr2b64(rstr_hmac_rmd160(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_rmd160(k, d, e)
  { return rstr2any(rstr_hmac_rmd160(str2rstr_utf8(k), str2rstr_utf8(d)), e); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function rmd160_vm_test()
{
  return hex_rmd160("abc").toLowerCase() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";
}

/*
 * Calculate the rmd160 of a raw string
 */
function rstr_rmd160(s)
{
  return binl2rstr(binl_rmd160(rstr2binl(s), s.length * 8));
}

/*
 * Calculate the HMAC-rmd160 of a key and some data (raw strings)
 */
function rstr_hmac_rmd160(key, data)
{
  var bkey = rstr2binl(key);
  if(bkey.length > 16) bkey = binl_rmd160(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binl_rmd160(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
  return binl2rstr(binl_rmd160(opad.concat(hash), 512 + 160));
}

/*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var remainders = Array();
  var i, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  /*
   * Repeatedly perform a long division. The binary array forms the dividend,
   * the length of the encoding is the divisor. Once computed, the quotient
   * forms the dividend for the next step. We stop when the dividend is zero.
   * All remainders are stored for later use.
   */
  while(dividend.length > 0)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[remainders.length] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  /* Append leading zero equivalents */
  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)))
  for(i = output.length; i < full_length; i++)
    output = encoding[0] + output;

  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/*
 * Convert a raw string to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binl(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (i%32);
  return output;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (i % 32)) & 0xFF);
  return output;
}

/*
 * Calculate the RIPE-MD160 of an array of little-endian words, and a bit length.
 */
function binl_rmd160(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (len % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var h0 = 0x67452301;
  var h1 = 0xefcdab89;
  var h2 = 0x98badcfe;
  var h3 = 0x10325476;
  var h4 = 0xc3d2e1f0;

  for (var i = 0; i < x.length; i += 16) {
    var T;
    var A1 = h0, B1 = h1, C1 = h2, D1 = h3, E1 = h4;
    var A2 = h0, B2 = h1, C2 = h2, D2 = h3, E2 = h4;
    for (var j = 0; j <= 79; ++j) {
      T = safe_add(A1, rmd160_f(j, B1, C1, D1));
      T = safe_add(T, x[i + rmd160_r1[j]]);
      T = safe_add(T, rmd160_K1(j));
      T = safe_add(bit_rol(T, rmd160_s1[j]), E1);
      A1 = E1; E1 = D1; D1 = bit_rol(C1, 10); C1 = B1; B1 = T;
      T = safe_add(A2, rmd160_f(79-j, B2, C2, D2));
      T = safe_add(T, x[i + rmd160_r2[j]]);
      T = safe_add(T, rmd160_K2(j));
      T = safe_add(bit_rol(T, rmd160_s2[j]), E2);
      A2 = E2; E2 = D2; D2 = bit_rol(C2, 10); C2 = B2; B2 = T;
    }
    T = safe_add(h1, safe_add(C1, D2));
    h1 = safe_add(h2, safe_add(D1, E2));
    h2 = safe_add(h3, safe_add(E1, A2));
    h3 = safe_add(h4, safe_add(A1, B2));
    h4 = safe_add(h0, safe_add(B1, C2));
    h0 = T;
  }
  return [h0, h1, h2, h3, h4];
}

function rmd160_f(j, x, y, z)
{
  return ( 0 <= j && j <= 15) ? (x ^ y ^ z) :
         (16 <= j && j <= 31) ? (x & y) | (~x & z) :
         (32 <= j && j <= 47) ? (x | ~y) ^ z :
         (48 <= j && j <= 63) ? (x & z) | (y & ~z) :
         (64 <= j && j <= 79) ? x ^ (y | ~z) :
         "rmd160_f: j out of range";
}
function rmd160_K1(j)
{
  return ( 0 <= j && j <= 15) ? 0x00000000 :
         (16 <= j && j <= 31) ? 0x5a827999 :
         (32 <= j && j <= 47) ? 0x6ed9eba1 :
         (48 <= j && j <= 63) ? 0x8f1bbcdc :
         (64 <= j && j <= 79) ? 0xa953fd4e :
         "rmd160_K1: j out of range";
}
function rmd160_K2(j)
{
  return ( 0 <= j && j <= 15) ? 0x50a28be6 :
         (16 <= j && j <= 31) ? 0x5c4dd124 :
         (32 <= j && j <= 47) ? 0x6d703ef3 :
         (48 <= j && j <= 63) ? 0x7a6d76e9 :
         (64 <= j && j <= 79) ? 0x00000000 :
         "rmd160_K2: j out of range";
}
var rmd160_r1 = [
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
   7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
   3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
   1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
   4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
];
var rmd160_r2 = [
   5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
   6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
  15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
   8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
  12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
];
var rmd160_s1 = [
  11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
   7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
  11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
  11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
   9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
];
var rmd160_s2 = [
   8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
   9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
   9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
  15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
   8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
];

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64pad="=";

function hex2b64(h) {
  var i;
  var c;
  var ret = "";
  for(i = 0; i+3 <= h.length; i+=3) {
    c = parseInt(h.substring(i,i+3),16);
    ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
  }
  if(i+1 == h.length) {
    c = parseInt(h.substring(i,i+1),16);
    ret += b64map.charAt(c << 2);
  }
  else if(i+2 == h.length) {
    c = parseInt(h.substring(i,i+2),16);
    ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
  }
  while((ret.length & 3) > 0) ret += b64pad;
  return ret;
}

// convert a base64 string to hex
function b64tohex(s) {
  var ret = ""
  var i;
  var k = 0; // b64 state, 0-3
  var slop;
  for(i = 0; i < s.length; ++i) {
    if(s.charAt(i) == b64pad) break;
    v = b64map.indexOf(s.charAt(i));
    if(v < 0) continue;
    if(k == 0) {
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 1;
    }
    else if(k == 1) {
      ret += int2char((slop << 2) | (v >> 4));
      slop = v & 0xf;
      k = 2;
    }
    else if(k == 2) {
      ret += int2char(slop);
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 3;
    }
    else {
      ret += int2char((slop << 2) | (v >> 4));
      ret += int2char(v & 0xf);
      k = 0;
    }
  }
  if(k == 1)
    ret += int2char(slop << 2);
  return ret;
}

// convert a base64 string to a byte/number array
function b64toBA(s) {
  //piggyback on b64tohex for now, optimize later
  var h = b64tohex(s);
  var i;
  var a = new Array();
  for(i = 0; 2*i < h.length; ++i) {
    a[i] = parseInt(h.substring(2*i,2*i+2),16);
  }
  return a;
}

// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
function parseBigInt(str,r) {
  return new BigInteger(str,r);
}

function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}

/**
 * PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
 * @param s: the string to encode
 * @param n: the size in byte
 */ 
function pkcs1pad2(s,n) {
  if(n < s.length + 11) { // TODO: fix for utf-8
    alert("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
      ba[--n] = c;
    }
    else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    }
    else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var rng = new SecureRandom();
  var x = new Array();
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

/** 
 * "empty" RSA key constructor
 * @returns {RSAKey}
 */
function RSAKey() {
  this.n = null;
  this.e = 0;
  this.d = null;
  this.p = null;
  this.q = null;
  this.dmp1 = null;
  this.dmq1 = null;
  this.coeff = null;
}

/** 
 * Set the public key fields N and e from hex strings
 * @param N
 * @param E
 * @returns {RSASetPublic}
 */
function RSASetPublic(N,E) {
  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
  }
  else
    alert("Invalid RSA public key");
}

/** 
 * Perform raw public operation on "x": return x^e (mod n)
 * @param x
 * @returns x^e (mod n)
 */
function RSADoPublic(x) {
  return x.modPowInt(this.e, this.n);
}

/**
 * Return the PKCS#1 RSA encryption of "text" as an even-length hex string
 */ 
function RSAEncrypt(text) {
  var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;

// Depends on rsa.js and jsbn2.js

// Version 1.1: support utf-8 decoding in pkcs1unpad2

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
function pkcs1unpad2(d,n) {
  var b = d.toByteArray();
  var i = 0;
  while(i < b.length && b[i] == 0) ++i;
  if(b.length-i != n-1 || b[i] != 2)
    return null;
  ++i;
  while(b[i] != 0)
    if(++i >= b.length) return null;
  var ret = "";
  while(++i < b.length) {
    var c = b[i] & 255;
    if(c < 128) { // utf-8 decode
      ret += String.fromCharCode(c);
    }
    else if((c > 191) && (c < 224)) {
      ret += String.fromCharCode(((c & 31) << 6) | (b[i+1] & 63));
      ++i;
    }
    else {
      ret += String.fromCharCode(((c & 15) << 12) | ((b[i+1] & 63) << 6) | (b[i+2] & 63));
      i += 2;
    }
  }
  return ret;
}

// Set the private key fields N, e, and d from hex strings
function RSASetPrivate(N,E,D) {
  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
    this.d = parseBigInt(D,16);
  }
  else
    alert("Invalid RSA private key");
}

// Set the private key fields N, e, d and CRT params from hex strings
function RSASetPrivateEx(N,E,D,P,Q,DP,DQ,C) {
  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
    this.d = parseBigInt(D,16);
    this.p = parseBigInt(P,16);
    this.q = parseBigInt(Q,16);
    this.dmp1 = parseBigInt(DP,16);
    this.dmq1 = parseBigInt(DQ,16);
    this.coeff = parseBigInt(C,16);
  }
  else
    alert("Invalid RSA private key");
}

/**
 * Generate a new random private key B bits long, using public expt E
 */
function RSAGenerate(B,E) {
  var rng = new SecureRandom();
  var qs = B>>1;
  this.e = parseInt(E,16);
  var ee = new BigInteger(E,16);
  for(;;) {
    for(;;) {
      this.p = new BigInteger(B-qs,1,rng);
      if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
    }
    for(;;) {
      this.q = new BigInteger(qs,1,rng);
      if(this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
    }
    if(this.p.compareTo(this.q) <= 0) {
      var t = this.p;
      this.p = this.q;
      this.q = t;
    }
    var p1 = this.p.subtract(BigInteger.ONE);	// p1 = p - 1
    var q1 = this.q.subtract(BigInteger.ONE);	// q1 = q - 1
    var phi = p1.multiply(q1);
    if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
      this.n = this.p.multiply(this.q);	// this.n = p * q
      this.d = ee.modInverse(phi);	// this.d = 
      this.dmp1 = this.d.mod(p1);	// this.dmp1 = d mod (p - 1)
      this.dmq1 = this.d.mod(q1);	// this.dmq1 = d mod (q - 1)
      this.coeff = this.q.modInverse(this.p);	// this.coeff = (q ^ -1) mod p
      break;
    }
  }
}

/**
 * Perform raw private operation on "x": return x^d (mod n)
 * @return x^d (mod n)
 */ 
function RSADoPrivate(x) {
  if(this.p == null || this.q == null)
    return x.modPow(this.d, this.n);

  // TODO: re-calculate any missing CRT params
  var xp = x.mod(this.p).modPow(this.dmp1, this.p); // xp=cp?
  var xq = x.mod(this.q).modPow(this.dmq1, this.q); // xq=cq?

  while(xp.compareTo(xq) < 0)
    xp = xp.add(this.p);
  // NOTE:
  // xp.subtract(xq) => cp -cq
  // xp.subtract(xq).multiply(this.coeff).mod(this.p) => (cp - cq) * u mod p = h
  // xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq) => cq + (h * q) = M
  return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
function RSADecrypt(ctext) {
  var c = parseBigInt(ctext, 16);
  var m = this.doPrivate(c);
  if(m == null) return null;
  return pkcs1unpad2(m, (this.n.bitLength()+7)>>3);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is a Base64-encoded string and the output is a plain string.
//function RSAB64Decrypt(ctext) {
//  var h = b64tohex(ctext);
//  if(h) return this.decrypt(h); else return null;
//}

// protected
RSAKey.prototype.doPrivate = RSADoPrivate;

// public
RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.decrypt = RSADecrypt;
//RSAKey.prototype.b64_decrypt = RSAB64Decrypt;

/*! rsapem-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// rsa-pem.js - adding function for reading/writing PKCS#1 PEM private key
//              to RSAKey class.
//
// version: 1.1 (2012-May-10)
//
// Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license/
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.
// 
//
// Depends on:
//
//
//
// _RSApem_pemToBase64(sPEM)
//
//   removing PEM header, PEM footer and space characters including
//   new lines from PEM formatted RSA private key string.
//

function _rsapem_pemToBase64(sPEMPrivateKey) {
  var s = sPEMPrivateKey;
  s = s.replace("-----BEGIN RSA PRIVATE KEY-----", "");
  s = s.replace("-----END RSA PRIVATE KEY-----", "");
  s = s.replace(/[ \n]+/g, "");
  return s;
}

function _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey) {
  var a = new Array();
  var v1 = ASN1HEX.getStartPosOfV_AtObj(hPrivateKey, 0);
  var n1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, v1);
  var e1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, n1);
  var d1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, e1);
  var p1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, d1);
  var q1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, p1);
  var dp1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, q1);
  var dq1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, dp1);
  var co1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, dq1);
  a.push(v1, n1, e1, d1, p1, q1, dp1, dq1, co1);
  return a;
}

function _rsapem_getHexValueArrayOfChildrenFromHex(hPrivateKey) {
  var posArray = _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey);
  var v =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[0]);
  var n =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[1]);
  var e =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[2]);
  var d =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[3]);
  var p =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[4]);
  var q =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[5]);
  var dp = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[6]);
  var dq = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[7]);
  var co = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[8]);
  var a = new Array();
  a.push(v, n, e, d, p, q, dp, dq, co);
  return a;
}

/**
 * read PKCS#1 private key from a string
 * @name readPrivateKeyFromPEMString
 * @memberOf RSAKey#
 * @function
 * @param {String} keyPEM string of PKCS#1 private key.
 */
function _rsapem_readPrivateKeyFromPEMString(keyPEM) {
  var keyB64 = _rsapem_pemToBase64(keyPEM);
  var keyHex = b64tohex(keyB64) // depends base64.js
  var a = _rsapem_getHexValueArrayOfChildrenFromHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
}

RSAKey.prototype.readPrivateKeyFromPEMString = _rsapem_readPrivateKeyFromPEMString;

/*! rsasign-1.2.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// rsa-sign.js - adding signing functions to RSAKey class.
//
//
// version: 1.2.1 (08 May 2012)
//
// Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license/
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.

//
// Depends on:
//   function sha1.hex(s) of sha1.js
//   jsbn.js
//   jsbn2.js
//   rsa.js
//   rsa2.js
//

// keysize / pmstrlen
//  512 /  128
// 1024 /  256
// 2048 /  512
// 4096 / 1024

/**
 * @property {Dictionary} _RSASIGN_DIHEAD
 * @description Array of head part of hexadecimal DigestInfo value for hash algorithms.
 * You can add any DigestInfo hash algorith for signing.
 * See PKCS#1 v2.1 spec (p38).
 */
var _RSASIGN_DIHEAD = [];
_RSASIGN_DIHEAD['sha1'] =      "3021300906052b0e03021a05000414";
_RSASIGN_DIHEAD['sha256'] =    "3031300d060960864801650304020105000420";
_RSASIGN_DIHEAD['sha384'] =    "3041300d060960864801650304020205000430";
_RSASIGN_DIHEAD['sha512'] =    "3051300d060960864801650304020305000440";
_RSASIGN_DIHEAD['md2'] =       "3020300c06082a864886f70d020205000410";
_RSASIGN_DIHEAD['md5'] =       "3020300c06082a864886f70d020505000410";
_RSASIGN_DIHEAD['ripemd160'] = "3021300906052b2403020105000414";

/**
 * @property {Dictionary} _RSASIGN_HASHHEXFUNC
 * @description Array of functions which calculate hash and returns it as hexadecimal.
 * You can add any hash algorithm implementations.
 */
var _RSASIGN_HASHHEXFUNC = [];
_RSASIGN_HASHHEXFUNC['sha1'] =      function(s){return hex_sha1(s);};  // http://pajhome.org.uk/crypt/md5/md5.html
_RSASIGN_HASHHEXFUNC['sha256'] =    function(s){return hex_sha256(s);} // http://pajhome.org.uk/crypt/md5/md5.html
_RSASIGN_HASHHEXFUNC['sha512'] =    function(s){return hex_sha512(s);} // http://pajhome.org.uk/crypt/md5/md5.html
_RSASIGN_HASHHEXFUNC['md5'] =       function(s){return hex_md5(s);};   // http://pajhome.org.uk/crypt/md5/md5.html
_RSASIGN_HASHHEXFUNC['ripemd160'] = function(s){return hex_rmd160(s);};   // http://pajhome.org.uk/crypt/md5/md5.html

//@author axelcdv
var _RSASIGN_HASHBYTEFUNC = [];
_RSASIGN_HASHBYTEFUNC['sha256'] = 	function(byteArray){return hex_sha256_from_bytes(byteArray);};

//_RSASIGN_HASHHEXFUNC['sha1'] =   function(s){return sha1.hex(s);}   // http://user1.matsumoto.ne.jp/~goma/js/hash.html
//_RSASIGN_HASHHEXFUNC['sha256'] = function(s){return sha256.hex;}    // http://user1.matsumoto.ne.jp/~goma/js/hash.html

var _RE_HEXDECONLY = new RegExp("");
_RE_HEXDECONLY.compile("[^0-9a-f]", "gi");

// ========================================================================
// Signature Generation
// ========================================================================

function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg) {
  var pmStrLen = keySize / 4;
  var hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
  var sHashHex = hashFunc(s);

  var sHead = "0001";
  var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
  var sMid = "";
  var fLen = pmStrLen - sHead.length - sTail.length;
  for (var i = 0; i < fLen; i += 2) {
    sMid += "ff";
  }
  sPaddedMessageHex = sHead + sMid + sTail;
  return sPaddedMessageHex;
}


//@author: ucla-cs
function _rsasign_getHexPaddedDigestInfoForStringHEX(s, keySize, hashAlg) {
  var pmStrLen = keySize / 4;
  var hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
  var sHashHex = hashFunc(s);

  var sHead = "0001";
  var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
  var sMid = "";
  var fLen = pmStrLen - sHead.length - sTail.length;
  for (var i = 0; i < fLen; i += 2) {
    sMid += "ff";
  }
  sPaddedMessageHex = sHead + sMid + sTail;
  return sPaddedMessageHex;
}

/**
 * Apply padding, then computes the hash of the given byte array, according to the key size and with the hash algorithm
 * @param byteArray (byte[])
 * @param keySize (int)
 * @param hashAlg the hash algorithm to apply (string)
 * @return the hash of byteArray
 */
function _rsasign_getHexPaddedDigestInfoForByteArray(byteArray, keySize, hashAlg){
	var pmStrLen = keySize / 4;
	var hashFunc = _RSASIGN_HASHBYTEFUNC[hashAlg];
	var sHashHex = hashFunc(byteArray); //returns hex hash
	
	var sHead = "0001";
	  var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
	  var sMid = "";
	  var fLen = pmStrLen - sHead.length - sTail.length;
	  for (var i = 0; i < fLen; i += 2) {
	    sMid += "ff";
	  }
	  sPaddedMessageHex = sHead + sMid + sTail;
	  return sPaddedMessageHex;
}

function _zeroPaddingOfSignature(hex, bitLength) {
  var s = "";
  var nZero = bitLength / 4 - hex.length;
  for (var i = 0; i < nZero; i++) {
    s = s + "0";
  }
  return s + hex;
}

/**
 * sign for a message string with RSA private key.<br/>
 * @name signString
 * @memberOf RSAKey#
 * @function
 * @param {String} s message string to be signed.
 * @param {String} hashAlg hash algorithm name for signing.<br/>
 * @return returns hexadecimal string of signature value.
 */
function _rsasign_signString(s, hashAlg) {
  //alert("this.n.bitLength() = " + this.n.bitLength());
  var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
  var biPaddedMessage = parseBigInt(hPM, 16);
  var biSign = this.doPrivate(biPaddedMessage);
  var hexSign = biSign.toString(16);
  return _zeroPaddingOfSignature(hexSign, this.n.bitLength());
}

//@author: ucla-cs
function _rsasign_signStringHEX(s, hashAlg) {
  //alert("this.n.bitLength() = " + this.n.bitLength());
  var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
  var biPaddedMessage = parseBigInt(hPM, 16);
  var biSign = this.doPrivate(biPaddedMessage);
  var hexSign = biSign.toString(16);
  return _zeroPaddingOfSignature(hexSign, this.n.bitLength());
}


/**
 * Sign a message byteArray with an RSA private key
 * @name signByteArray
 * @memberOf RSAKey#
 * @function
 * @param {byte[]} byteArray
 * @param {Sring} hashAlg the hash algorithm to apply
 * @param {RSAKey} rsa key to sign with: hack because the context is lost here
 * @return hexadecimal string of signature value
 */
function _rsasign_signByteArray(byteArray, hashAlg, rsaKey) {
	var hPM = _rsasign_getHexPaddedDigestInfoForByteArray(byteArray, rsaKey.n.bitLength(), hashAlg); ///hack because the context is lost here
	var biPaddedMessage = parseBigInt(hPM, 16);
	var biSign = rsaKey.doPrivate(biPaddedMessage); //hack because the context is lost here
	var hexSign = biSign.toString(16);
	return _zeroPaddingOfSignature(hexSign, rsaKey.n.bitLength()); //hack because the context is lost here
}

/**
 * Sign a byte array with the Sha-256 algorithm
 * @param {byte[]} byteArray
 * @return hexadecimal string of signature value
 */
function _rsasign_signByteArrayWithSHA256(byteArray){
	return _rsasign_signByteArray(byteArray, 'sha256', this); //Hack because the context is lost in the next function
}


function _rsasign_signStringWithSHA1(s) {
  return _rsasign_signString(s, 'sha1');
}

function _rsasign_signStringWithSHA256(s) {
  return _rsasign_signString(s, 'sha256');
}

// ========================================================================
// Signature Verification
// ========================================================================

function _rsasign_getDecryptSignatureBI(biSig, hN, hE) {
  var rsa = new RSAKey();
  rsa.setPublic(hN, hE);
  var biDecryptedSig = rsa.doPublic(biSig);
  return biDecryptedSig;
}

function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE) {
  var biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
  var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
  return hDigestInfo;
}

function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo) {
  for (var algName in _RSASIGN_DIHEAD) {
    var head = _RSASIGN_DIHEAD[algName];
    var len = head.length;
    if (hDigestInfo.substring(0, len) == head) {
      var a = [algName, hDigestInfo.substring(len)];
      return a;
    }
  }
  return [];
}

function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE) {
  var hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
  var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  if (digestInfoAry.length == 0) return false;
  var algName = digestInfoAry[0];
  var diHashValue = digestInfoAry[1];
  var ff = _RSASIGN_HASHHEXFUNC[algName];
  var msgHashValue = ff(sMsg);
  return (diHashValue == msgHashValue);
}

function _rsasign_verifyHexSignatureForMessage(hSig, sMsg) {
  var biSig = parseBigInt(hSig, 16);
  var result = _rsasign_verifySignatureWithArgs(sMsg, biSig,
						this.n.toString(16),
						this.e.toString(16));
  return result;
}

/**
 * verifies a sigature for a message string with RSA public key.<br/>
 * @name verifyString
 * @memberOf RSAKey#
 * @function
 * @param {String} sMsg message string to be verified.
 * @param {String} hSig hexadecimal string of siganture.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0
 */
function _rsasign_verifyString(sMsg, hSig) {
  hSig = hSig.replace(_RE_HEXDECONLY, '');
  
  if(LOG>3)console.log('n is '+this.n);
  if(LOG>3)console.log('e is '+this.e);
  
  if (hSig.length != this.n.bitLength() / 4) return 0;
  hSig = hSig.replace(/[ \n]+/g, "");
  var biSig = parseBigInt(hSig, 16);
  var biDecryptedSig = this.doPublic(biSig);
  var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
  var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  
  if (digestInfoAry.length == 0) return false;
  var algName = digestInfoAry[0];
  var diHashValue = digestInfoAry[1];
  var ff = _RSASIGN_HASHHEXFUNC[algName];
  var msgHashValue = ff(sMsg);
  return (diHashValue == msgHashValue);
}

/**
 * verifies a sigature for a message byte array with RSA public key.<br/>
 * @name verifyByteArray
 * @memberOf RSAKey#
 * @function
 * @param {byte[]} byteArray message byte array to be verified.
 * @param {String} hSig hexadecimal string of signature.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0 
 */
function _rsasign_verifyByteArray(byteArray, hSig) {
	hSig = hSig.replace(_RE_HEXDECONLY, '');
	  
	  if(LOG>3)console.log('n is '+this.n);
	  if(LOG>3)console.log('e is '+this.e);
	  
	  if (hSig.length != this.n.bitLength() / 4) return 0;
	  hSig = hSig.replace(/[ \n]+/g, "");
	  var biSig = parseBigInt(hSig, 16);
	  var biDecryptedSig = this.doPublic(biSig);
	  var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
	  var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
	  
	  if (digestInfoAry.length == 0) return false;
	  var algName = digestInfoAry[0];
	  var diHashValue = digestInfoAry[1];
	  var ff = _RSASIGN_HASHBYTEFUNC[algName];
	  var msgHashValue = ff(byteArray);
	  return (diHashValue == msgHashValue);
}

RSAKey.prototype.signString = _rsasign_signString;

RSAKey.prototype.signByteArray = _rsasign_signByteArray; //@author axelcdv
RSAKey.prototype.signByteArrayWithSHA256 = _rsasign_signByteArrayWithSHA256; //@author axelcdv

RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;
RSAKey.prototype.sign = _rsasign_signString;
RSAKey.prototype.signWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signWithSHA256 = _rsasign_signStringWithSHA256;


/*RSAKey.prototype.signStringHEX = _rsasign_signStringHEX;
RSAKey.prototype.signStringWithSHA1HEX = _rsasign_signStringWithSHA1HEX;
RSAKey.prototype.signStringWithSHA256HEX = _rsasign_signStringWithSHA256HEX;
RSAKey.prototype.signHEX = _rsasign_signStringHEX;
RSAKey.prototype.signWithSHA1HEX = _rsasign_signStringWithSHA1HEX;
RSAKey.prototype.signWithSHA256HEX = _rsasign_signStringWithSHA256HEX;
*/

RSAKey.prototype.verifyByteArray = _rsasign_verifyByteArray;
RSAKey.prototype.verifyString = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;
RSAKey.prototype.verify = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForByteArrayMessage = _rsasign_verifyHexSignatureForMessage;

/*
RSAKey.prototype.verifyStringHEX = _rsasign_verifyStringHEX;
RSAKey.prototype.verifyHexSignatureForMessageHEX = _rsasign_verifyHexSignatureForMessageHEX;
RSAKey.prototype.verifyHEX = _rsasign_verifyStringHEX;
RSAKey.prototype.verifyHexSignatureForByteArrayMessageHEX = _rsasign_verifyHexSignatureForMessageHEX;
*/
	
	
/**
 * @name RSAKey
 * @class
 * @description Tom Wu's RSA Key class and extension
 */

/*! asn1hex-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// asn1hex.js - Hexadecimal represented ASN.1 string library
//
// version: 1.1 (09-May-2012)
//
// Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license/
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.
//
// Depends on:
//

// MEMO:
//   f('3082025b02...', 2) ... 82025b ... 3bytes
//   f('020100', 2) ... 01 ... 1byte
//   f('0203001...', 2) ... 03 ... 1byte
//   f('02818003...', 2) ... 8180 ... 2bytes
//   f('3080....0000', 2) ... 80 ... -1
//
//   Requirements:
//   - ASN.1 type octet length MUST be 1. 
//     (i.e. ASN.1 primitives like SET, SEQUENCE, INTEGER, OCTETSTRING ...)
//   - 
/**
 * get byte length for ASN.1 L(length) bytes
 * @name getByteLengthOfL_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return byte length for ASN.1 L(length) bytes
 */
function _asnhex_getByteLengthOfL_AtObj(s, pos) {
  if (s.substring(pos + 2, pos + 3) != '8') return 1;
  var i = parseInt(s.substring(pos + 3, pos + 4));
  if (i == 0) return -1; 		// length octet '80' indefinite length
  if (0 < i && i < 10) return i + 1;	// including '8?' octet;
  return -2;				// malformed format
}


/**
 * get hexadecimal string for ASN.1 L(length) bytes
 * @name getHexOfL_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return {String} hexadecimal string for ASN.1 L(length) bytes
 */
function _asnhex_getHexOfL_AtObj(s, pos) {
  var len = _asnhex_getByteLengthOfL_AtObj(s, pos);
  if (len < 1) return '';
  return s.substring(pos + 2, pos + 2 + len * 2);
}

//
//   getting ASN.1 length value at the position 'idx' of
//   hexa decimal string 's'.
//
//   f('3082025b02...', 0) ... 82025b ... ???
//   f('020100', 0) ... 01 ... 1
//   f('0203001...', 0) ... 03 ... 3
//   f('02818003...', 0) ... 8180 ... 128
/**
 * get integer value of ASN.1 length for ASN.1 data
 * @name getIntOfL_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return ASN.1 L(length) integer value
 */
function _asnhex_getIntOfL_AtObj(s, pos) {
  var hLength = _asnhex_getHexOfL_AtObj(s, pos);
  if (hLength == '') return -1;
  var bi;
  if (parseInt(hLength.substring(0, 1)) < 8) {
     bi = parseBigInt(hLength, 16);
  } else {
     bi = parseBigInt(hLength.substring(2), 16);
  }
  return bi.intValue();
}

/**
 * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
 * @name getStartPosOfV_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 */
function _asnhex_getStartPosOfV_AtObj(s, pos) {
  var l_len = _asnhex_getByteLengthOfL_AtObj(s, pos);
  if (l_len < 0) return l_len;
  return pos + (l_len + 1) * 2;
}

/**
 * get hexadecimal string of ASN.1 V(value)
 * @name getHexOfV_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return {String} hexadecimal string of ASN.1 value.
 */
function _asnhex_getHexOfV_AtObj(s, pos) {
  var pos1 = _asnhex_getStartPosOfV_AtObj(s, pos);
  var len = _asnhex_getIntOfL_AtObj(s, pos);
  return s.substring(pos1, pos1 + len * 2);
}

/**
 * get hexadecimal string of ASN.1 TLV at
 * @name getHexOfTLV_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return {String} hexadecimal string of ASN.1 TLV.
 * @since 1.1
 */
function _asnhex_getHexOfTLV_AtObj(s, pos) {
  var hT = s.substr(pos, 2);
  var hL = _asnhex_getHexOfL_AtObj(s, pos);
  var hV = _asnhex_getHexOfV_AtObj(s, pos);
  return hT + hL + hV;
}

/**
 * get next sibling starting index for ASN.1 object string
 * @name getPosOfNextSibling_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return next sibling starting index for ASN.1 object string
 */
function _asnhex_getPosOfNextSibling_AtObj(s, pos) {
  var pos1 = _asnhex_getStartPosOfV_AtObj(s, pos);
  var len = _asnhex_getIntOfL_AtObj(s, pos);
  return pos1 + len * 2;
}

/**
 * get array of indexes of child ASN.1 objects
 * @name getPosArrayOfChildren_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} start string index of ASN.1 object
 * @return {Array of Number} array of indexes for childen of ASN.1 objects
 */
function _asnhex_getPosArrayOfChildren_AtObj(h, pos) {
  var a = new Array();
  var p0 = _asnhex_getStartPosOfV_AtObj(h, pos);
  a.push(p0);

  var len = _asnhex_getIntOfL_AtObj(h, pos);
  var p = p0;
  var k = 0;
  while (1) {
    var pNext = _asnhex_getPosOfNextSibling_AtObj(h, p);
    if (pNext == null || (pNext - p0  >= (len * 2))) break;
    if (k >= 200) break;

    a.push(pNext);
    p = pNext;

    k++;
  }

  return a;
}

/**
 * get string index of nth child object of ASN.1 object refered by h, idx
 * @name getNthChildIndex_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} h hexadecimal string of ASN.1 DER encoded data
 * @param {Number} idx start string index of ASN.1 object
 * @param {Number} nth for child
 * @return {Number} string index of nth child.
 * @since 1.1
 */
function _asnhex_getNthChildIndex_AtObj(h, idx, nth) {
  var a = _asnhex_getPosArrayOfChildren_AtObj(h, idx);
  return a[nth];
}

// ========== decendant methods ==============================

/**
 * get string index of nth child object of ASN.1 object refered by h, idx
 * @name getDecendantIndexByNthList
 * @memberOf ASN1HEX
 * @function
 * @param {String} h hexadecimal string of ASN.1 DER encoded data
 * @param {Number} currentIndex start string index of ASN.1 object
 * @param {Array of Number} nthList array list of nth
 * @return {Number} string index refered by nthList
 * @since 1.1
 */
function _asnhex_getDecendantIndexByNthList(h, currentIndex, nthList) {
  if (nthList.length == 0) {
    return currentIndex;
  }
  var firstNth = nthList.shift();
  var a = _asnhex_getPosArrayOfChildren_AtObj(h, currentIndex);
  return _asnhex_getDecendantIndexByNthList(h, a[firstNth], nthList);
}

/**
 * get hexadecimal string of ASN.1 TLV refered by current index and nth index list.
 * @name getDecendantHexTLVByNthList
 * @memberOf ASN1HEX
 * @function
 * @param {String} h hexadecimal string of ASN.1 DER encoded data
 * @param {Number} currentIndex start string index of ASN.1 object
 * @param {Array of Number} nthList array list of nth
 * @return {Number} hexadecimal string of ASN.1 TLV refered by nthList
 * @since 1.1
 */
function _asnhex_getDecendantHexTLVByNthList(h, currentIndex, nthList) {
  var idx = _asnhex_getDecendantIndexByNthList(h, currentIndex, nthList);
  return _asnhex_getHexOfTLV_AtObj(h, idx);
}

/**
 * get hexadecimal string of ASN.1 V refered by current index and nth index list.
 * @name getDecendantHexVByNthList
 * @memberOf ASN1HEX
 * @function
 * @param {String} h hexadecimal string of ASN.1 DER encoded data
 * @param {Number} currentIndex start string index of ASN.1 object
 * @param {Array of Number} nthList array list of nth
 * @return {Number} hexadecimal string of ASN.1 V refered by nthList
 * @since 1.1
 */
function _asnhex_getDecendantHexVByNthList(h, currentIndex, nthList) {
  var idx = _asnhex_getDecendantIndexByNthList(h, currentIndex, nthList);
  return _asnhex_getHexOfV_AtObj(h, idx);
}

// ========== class definition ==============================

/**
 * ASN.1 DER encoded hexadecimal string utility class
 * @class ASN.1 DER encoded hexadecimal string utility class
 * @author Kenji Urushima
 * @version 1.1 (09 May 2012)
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 * @since 1.1
 */
function ASN1HEX() {
  return ASN1HEX;
}

ASN1HEX.getByteLengthOfL_AtObj = _asnhex_getByteLengthOfL_AtObj;
ASN1HEX.getHexOfL_AtObj = _asnhex_getHexOfL_AtObj;
ASN1HEX.getIntOfL_AtObj = _asnhex_getIntOfL_AtObj;
ASN1HEX.getStartPosOfV_AtObj = _asnhex_getStartPosOfV_AtObj;
ASN1HEX.getHexOfV_AtObj = _asnhex_getHexOfV_AtObj;
ASN1HEX.getHexOfTLV_AtObj = _asnhex_getHexOfTLV_AtObj;
ASN1HEX.getPosOfNextSibling_AtObj = _asnhex_getPosOfNextSibling_AtObj;
ASN1HEX.getPosArrayOfChildren_AtObj = _asnhex_getPosArrayOfChildren_AtObj;
ASN1HEX.getNthChildIndex_AtObj = _asnhex_getNthChildIndex_AtObj;
ASN1HEX.getDecendantIndexByNthList = _asnhex_getDecendantIndexByNthList;
ASN1HEX.getDecendantHexVByNthList = _asnhex_getDecendantHexVByNthList;
ASN1HEX.getDecendantHexTLVByNthList = _asnhex_getDecendantHexTLVByNthList;

/*! x509-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
// 
// x509.js - X509 class to read subject public key from certificate.
//
// version: 1.1 (10-May-2012)
//
// Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.
// 

// Depends:
//   base64.js
//   rsa.js
//   asn1hex.js

function _x509_pemToBase64(sCertPEM) {
  var s = sCertPEM;
  s = s.replace("-----BEGIN CERTIFICATE-----", "");
  s = s.replace("-----END CERTIFICATE-----", "");
  s = s.replace(/[ \n]+/g, "");
  return s;
}

function _x509_pemToHex(sCertPEM) {
  var b64Cert = _x509_pemToBase64(sCertPEM);
  var hCert = b64tohex(b64Cert);
  return hCert;
}

function _x509_getHexTbsCertificateFromCert(hCert) {
  var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
  return pTbsCert;
}

// NOTE: privateKeyUsagePeriod field of X509v2 not supported.
// NOTE: v1 and v3 supported
function _x509_getSubjectPublicKeyInfoPosFromCertHex(hCert) {
  var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pTbsCert); 
  if (a.length < 1) return -1;
  if (hCert.substring(a[0], a[0] + 10) == "a003020102") { // v3
    if (a.length < 6) return -1;
    return a[6];
  } else {
    if (a.length < 5) return -1;
    return a[5];
  }
}

// NOTE: Without BITSTRING encapsulation.
function _x509_getSubjectPublicKeyPosFromCertHex(hCert) {
  var pInfo = _x509_getSubjectPublicKeyInfoPosFromCertHex(hCert);
  if (pInfo == -1) return -1;    
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pInfo); 
  
  if (a.length != 2) return -1;
  var pBitString = a[1];
  if (hCert.substring(pBitString, pBitString + 2) != '03') return -1;
  var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hCert, pBitString);

  if (hCert.substring(pBitStringV, pBitStringV + 2) != '00') return -1;
  return pBitStringV + 2;
}

function _x509_getPublicKeyHexArrayFromCertHex(hCert) {
  var p = _x509_getSubjectPublicKeyPosFromCertHex(hCert);
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p); 
  //var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a[3]); 
  if(LOG>4){
	  console.log('a is now');
	  console.log(a);
  }
  
  //if (a.length != 2) return [];
  if (a.length < 2) return [];

  var hN = ASN1HEX.getHexOfV_AtObj(hCert, a[0]);
  var hE = ASN1HEX.getHexOfV_AtObj(hCert, a[1]);
  if (hN != null && hE != null) {
    return [hN, hE];
  } else {
    return [];
  }
}

function _x509_getPublicKeyHexArrayFromCertPEM(sCertPEM) {
  var hCert = _x509_pemToHex(sCertPEM);
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
  return a;
}

// ===== get basic fields from hex =====================================
/**
 * get hexadecimal string of serialNumber field of certificate.<br/>
 * @name getSerialNumberHex
 * @memberOf X509#
 * @function
 */
function _x509_getSerialNumberHex() {
  return ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 1]);
}

/**
 * get hexadecimal string of issuer field of certificate.<br/>
 * @name getIssuerHex
 * @memberOf X509#
 * @function
 */
function _x509_getIssuerHex() {
  return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]);
}

/**
 * get string of issuer field of certificate.<br/>
 * @name getIssuerString
 * @memberOf X509#
 * @function
 */
function _x509_getIssuerString() {
  return _x509_hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]));
}

/**
 * get hexadecimal string of subject field of certificate.<br/>
 * @name getSubjectHex
 * @memberOf X509#
 * @function
 */
function _x509_getSubjectHex() {
  return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]);
}

/**
 * get string of subject field of certificate.<br/>
 * @name getSubjectString
 * @memberOf X509#
 * @function
 */
function _x509_getSubjectString() {
  return _x509_hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]));
}

/**
 * get notBefore field string of certificate.<br/>
 * @name getNotBefore
 * @memberOf X509#
 * @function
 */
function _x509_getNotBefore() {
  var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 0]);
  s = s.replace(/(..)/g, "%$1");
  s = decodeURIComponent(s);
  return s;
}

/**
 * get notAfter field string of certificate.<br/>
 * @name getNotAfter
 * @memberOf X509#
 * @function
 */
function _x509_getNotAfter() {
  var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 1]);
  s = s.replace(/(..)/g, "%$1");
  s = decodeURIComponent(s);
  return s;
}

// ===== read certificate =====================================

_x509_DN_ATTRHEX = {
    "0603550406": "C",
    "060355040a": "O",
    "060355040b": "OU",
    "0603550403": "CN",
    "0603550405": "SN",
    "0603550408": "ST",
    "0603550407": "L" };

function _x509_hex2dn(hDN) {
  var s = "";
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hDN, 0);
  for (var i = 0; i < a.length; i++) {
    var hRDN = ASN1HEX.getHexOfTLV_AtObj(hDN, a[i]);
    s = s + "/" + _x509_hex2rdn(hRDN);
  }
  return s;
}

function _x509_hex2rdn(hRDN) {
    var hType = ASN1HEX.getDecendantHexTLVByNthList(hRDN, 0, [0, 0]);
    var hValue = ASN1HEX.getDecendantHexVByNthList(hRDN, 0, [0, 1]);
    var type = "";
    try { type = _x509_DN_ATTRHEX[hType]; } catch (ex) { type = hType; }
    hValue = hValue.replace(/(..)/g, "%$1");
    var value = decodeURIComponent(hValue);
    return type + "=" + value;
}

// ===== read certificate =====================================


/**
 * read PEM formatted X.509 certificate from string.<br/>
 * @name readCertPEM
 * @memberOf X509#
 * @function
 * @param {String} sCertPEM string for PEM formatted X.509 certificate
 */
function _x509_readCertPEM(sCertPEM) {
  var hCert = _x509_pemToHex(sCertPEM);
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
  if(LOG>4){
	  console.log('HEX VALUE IS ' + hCert);
	  console.log('type of a' + typeof a);
	  console.log('a VALUE IS ');
	  console.log(a);
	  console.log('a[0] VALUE IS ' + a[0]);
	  console.log('a[1] VALUE IS ' + a[1]);
  }
  var rsa = new RSAKey();
  rsa.setPublic(a[0], a[1]);
  this.subjectPublicKeyRSA = rsa;
  this.subjectPublicKeyRSA_hN = a[0];
  this.subjectPublicKeyRSA_hE = a[1];
  this.hex = hCert;
}

function _x509_readCertPEMWithoutRSAInit(sCertPEM) {
  var hCert = _x509_pemToHex(sCertPEM);
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
  this.subjectPublicKeyRSA.setPublic(a[0], a[1]);
  this.subjectPublicKeyRSA_hN = a[0];
  this.subjectPublicKeyRSA_hE = a[1];
  this.hex = hCert;
}

/**
 * X.509 certificate class.<br/>
 * @class X.509 certificate class
 * @property {RSAKey} subjectPublicKeyRSA Tom Wu's RSAKey object
 * @property {String} subjectPublicKeyRSA_hN hexadecimal string for modulus of RSA public key
 * @property {String} subjectPublicKeyRSA_hE hexadecimal string for public exponent of RSA public key
 * @property {String} hex hexacedimal string for X.509 certificate.
 * @author Kenji Urushima
 * @version 1.0.1 (08 May 2012)
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 */
function X509() {
  this.subjectPublicKeyRSA = null;
  this.subjectPublicKeyRSA_hN = null;
  this.subjectPublicKeyRSA_hE = null;
  this.hex = null;
}

X509.prototype.readCertPEM = _x509_readCertPEM;
X509.prototype.readCertPEMWithoutRSAInit = _x509_readCertPEMWithoutRSAInit;
X509.prototype.getSerialNumberHex = _x509_getSerialNumberHex;
X509.prototype.getIssuerHex = _x509_getIssuerHex;
X509.prototype.getSubjectHex = _x509_getSubjectHex;
X509.prototype.getIssuerString = _x509_getIssuerString;
X509.prototype.getSubjectString = _x509_getSubjectString;
X509.prototype.getNotBefore = _x509_getNotBefore;
X509.prototype.getNotAfter = _x509_getNotAfter;


// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    a.fromInt(lowprimes[i]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)

