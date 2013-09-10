/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * Provide the callback closure for the async communication methods in the NDN class.
 * This is a port of Closure.py from PyNDN, written by: 
 * Derek Kulinski <takeda@takeda.tk>
 * Jeff Burke <jburke@ucla.edu>
 */

/**
 * You should create a subclass of Closure and pass an object to async calls.
 * @constructor
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
Closure.RESULT_FETCHKEY          =  4; // get the key in the key locator and re-call the interest
                                       //   with the key available in the local storage

// Upcall kind
Closure.UPCALL_FINAL              = 0; // handler is about to be deregistered
Closure.UPCALL_INTEREST           = 1; // incoming interest
Closure.UPCALL_CONSUMED_INTEREST  = 2; // incoming interest, someone has answered
Closure.UPCALL_CONTENT            = 3; // incoming verified content
Closure.UPCALL_INTEREST_TIMED_OUT = 4; // interest timed out
Closure.UPCALL_CONTENT_UNVERIFIED = 5; // content that has not been verified
Closure.UPCALL_CONTENT_BAD        = 6; // verification failed

/**
 * Override this in your subclass.
 * If you're getting strange errors in upcall()
 * check your code whether you're returning a value.
 */
Closure.prototype.upcall = function(kind, upcallInfo) {
	//dump('upcall ' + this + " " + kind + " " + upcallInfo + "\n");
	return Closure.RESULT_OK;
};

/**
 * An UpcallInfo is passed to Closure.upcall.
 * @constructor
 */
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
/** 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

/**
 * @constructor
 */
var WebSocketTransport = function WebSocketTransport() {    
    if (!WebSocket)
        throw new Error("WebSocket support is not available on this platform.");
    
	this.ws = null;
    this.connectedHost = null; // Read by NDN.
    this.connectedPort = null; // Read by NDN.
    this.elementReader = null;
    this.defaultGetHostAndPort = NDN.makeShuffledGetHostAndPort
        (["A.ws.ndn.ucla.edu", "B.ws.ndn.ucla.edu", "C.ws.ndn.ucla.edu", "D.ws.ndn.ucla.edu", 
          "E.ws.ndn.ucla.edu"],
         9696);
};

/**
 * Connect to the host and port in ndn.  This replaces a previous connection and sets connectedHost
 *   and connectedPort.  Once connected, call onopenCallback().
 * Listen on the port to read an entire binary XML encoded element and call
 *    ndn.onReceivedElement(element).
 */
WebSocketTransport.prototype.connect = function(ndn, onopenCallback) {
	if (this.ws != null)
		delete this.ws;
	
	this.ws = new WebSocket('ws://' + ndn.host + ':' + ndn.port);
	if (LOG > 0) console.log('ws connection created.');
    this.connectedHost = ndn.host;
    this.connectedPort = ndn.port;
	
	this.ws.binaryType = "arraybuffer";
	
    this.elementReader = new BinaryXmlElementReader(ndn);
	var self = this;
	this.ws.onmessage = function(ev) {
		var result = ev.data;
		//console.log('RecvHandle called.');
			
		if(result == null || result == undefined || result == "" ) {
			console.log('INVALID ANSWER');
		} else if (result instanceof ArrayBuffer) {
	        var bytearray = new Uint8Array(result);
	        
			if (LOG>3) console.log('BINARY RESPONSE IS ' + DataUtils.toHex(bytearray));
			
			try {
                // Find the end of the binary XML element and call ndn.onReceivedElement.
                self.elementReader.onReceivedData(bytearray);
			} catch (ex) {
				console.log("NDN.ws.onmessage exception: " + ex);
				return;
			}
		}
	}
	
	this.ws.onopen = function(ev) {
		if (LOG > 3) console.log(ev);
		if (LOG > 3) console.log('ws.onopen: WebSocket connection opened.');
		if (LOG > 3) console.log('ws.onopen: ReadyState: ' + this.readyState);
        // NDN.registerPrefix will fetch the ndndid when needed.
        
        onopenCallback();
	}
	
	this.ws.onerror = function(ev) {
		console.log('ws.onerror: ReadyState: ' + this.readyState);
		console.log(ev);
		console.log('ws.onerror: WebSocket error: ' + ev.data);
	}
	
	this.ws.onclose = function(ev) {
		console.log('ws.onclose: WebSocket connection closed.');
		self.ws = null;
		
		// Close NDN when WebSocket is closed
		ndn.readyStatus = NDN.CLOSED;
		ndn.onclose();
		//console.log("NDN.onclose event fired.");
	}
};

/**
 * Send the Uint8Array data.
 */
WebSocketTransport.prototype.send = function(data) {
	if (this.ws != null) {
        // If we directly use data.buffer to feed ws.send(), 
        // WebSocket may end up sending a packet with 10000 bytes of data.
        // That is, WebSocket will flush the entire buffer
        // regardless of the offset of the Uint8Array. So we have to create
        // a new Uint8Array buffer with just the right size and copy the 
        // content from binaryInterest to the new buffer.
        //    ---Wentao
        var bytearray = new Uint8Array(data.length);
        bytearray.set(data);
        this.ws.send(bytearray.buffer);
		if (LOG > 3) console.log('ws.send() returned.');
	}
	else
		console.log('WebSocket connection is not established.');
}
/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

// Create a namespace.
var NameEnumeration = new Object();

/**
 * Use the name enumeration protocol to get the child components of the name prefix.
 * @param {NDN} ndn The NDN object for using expressInterest.
 * @param {Name} name The name prefix for finding the child components.
 * @param {function} onComponents On getting the response, this calls onComponents(components) where
 * components is an array of Uint8Array name components.  If there is no response, this calls onComponents(null). 
 */
NameEnumeration.getComponents = function(ndn, prefix, onComponents)
{
  var command = new Name(prefix);
  // Add %C1.E.be
  command.add([0xc1, 0x2e, 0x45, 0x2e, 0x62, 0x65])
  
  ndn.expressInterest(command, new NameEnumeration.Closure(onComponents));
};

/**
 * Create a closure for getting the response from the name enumeration command.
 * @param {function} onComponents The onComponents callback given to getComponents.
 */
NameEnumeration.Closure = function NameEnumerationClosure(onComponents) 
{
  // Inherit from Closure.
  Closure.call(this);
  
  this.onComponents = onComponents;
  this.components = [];
};

/**
 * Parse the response from the name enumeration command and call this.onComponents.
 * @param {type} kind
 * @param {type} upcallInfo
 * @returns {Closure.RESULT_OK}
 */
NameEnumeration.Closure.prototype.upcall = function(kind, upcallInfo) 
{
  try {
    if (kind == Closure.UPCALL_CONTENT || kind == Closure.UPCALL_CONTENT_UNVERIFIED) {
      var data = upcallInfo.contentObject;
    
      NameEnumeration.addComponents(data.content, this.components);
    }
    else
      // Treat anything else as a timeout.
      this.components = null;
  
    this.onComponents(this.components);
  } catch (ex) {
    console.log("NameEnumeration: ignoring exception: " + ex);
  }

  return Closure.RESULT_OK;
};

/**
 * Parse the content as a name enumeration response and add to components.  This makes a copy of the component.
 * @param {Uint8Array} content The content to parse.
 * @param {Array<Uint8Array>} components 
 * @returns {undefined}
 */
NameEnumeration.addComponents = function(content, components)
{
  var decoder = new BinaryXMLDecoder(content);
  
  decoder.readStartElement(NDNProtocolDTags.Collection);
 
  while (decoder.peekStartElement(NDNProtocolDTags.Link)) {
    decoder.readStartElement(NDNProtocolDTags.Link);    
    decoder.readStartElement(NDNProtocolDTags.Name);
    
    components.push(new Uint8Array(decoder.readBinaryElement(NDNProtocolDTags.Component)));
    
    decoder.readEndElement();  
    decoder.readEndElement();  
  }

  decoder.readEndElement();  
};/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class contains all NDNx tags
 */


var NDNProtocolDTags = {

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
	 NDNProtocolDataUnit : 17702112,
	 NDNPROTOCOL_DATA_UNIT : "NDNProtocolDataUnit"
};

var NDNProtocolDTagsStrings = [
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
//console.log(exports.NDNProtocolDTagsStrings[17]);

/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents NDNTime Objects
 */

/**
 * @constructor
 */
var NDNTime = function NDNTime(input) {
	this.NANOS_MAX = 999877929;
	
	if(typeof input =='number')
		this.msec = input;
	else{
		if(LOG>1) console.log('UNRECOGNIZED TYPE FOR TIME');
	}
};


NDNTime.prototype.getJavascriptDate = function(){
	var d = new Date();
	d.setTime( this.msec );
	return d
};

	/**
	 * Create a NDNTime
	 * @param timestamp source timestamp to initialize from, some precision will be lost
	 */


	/**
	 * Create a NDNTime from its binary encoding
	 * @param binaryTime12 the binary representation of a NDNTime
	 */
/*NDNTime.prototype.setDateBinary = function(
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
NDNTime.prototype.toBinaryTime = function() {

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
	
/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * This is the closure class for use in expressInterest to re express with exponential falloff.
 */

/**
 * Create a new ExponentialReExpressClosure where upcall responds to UPCALL_INTEREST_TIMED_OUT
 *   by expressing the interest again with double the interestLifetime. If the interesLifetime goes
 *   over maxInterestLifetime, then call callerClosure.upcall with UPCALL_INTEREST_TIMED_OUT.
 * When upcall is not UPCALL_INTEREST_TIMED_OUT, just call callerClosure.upcall.
 * @constructor
 * @param {Closure} callerClosure
 * @param {Object} settings if not null, an associative array with the following defaults:
 * {
 *   maxInterestLifetime: 16000 // milliseconds
 * }
 */
var ExponentialReExpressClosure = function ExponentialReExpressClosure
        (callerClosure, settings) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.callerClosure = callerClosure;
    settings = (settings || {});
	this.maxInterestLifetime = (settings.maxInterestLifetime || 16000);
};

/**
 * Wrap this.callerClosure to responds to UPCALL_INTEREST_TIMED_OUT
 *   by expressing the interest again as described in the constructor.
 */
ExponentialReExpressClosure.prototype.upcall = function(kind, upcallInfo) {
    try {
        if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
            var interestLifetime = upcallInfo.interest.interestLifetime;
            if (interestLifetime == null)
                return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);
            
            var nextInterestLifetime = interestLifetime * 2;
            if (nextInterestLifetime > this.maxInterestLifetime)
                return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);
            
            var nextInterest = upcallInfo.interest.clone();
            nextInterest.interestLifetime = nextInterestLifetime;
            upcallInfo.ndn.expressInterest(nextInterest.name, this, nextInterest);
            return Closure.RESULT_OK;
        }  
        else
            return this.callerClosure.upcall(kind, upcallInfo);
    } catch (ex) {
        console.log("ExponentialReExpressClosure.upcall exception: " + ex);
        return Closure.RESULT_ERR;
    }
};
/**
 * @author: Meki Cheraoui, Jeff Thompson
 * See COPYING for copyright and distribution information.
 * This class represents a Name as an array of components where each is a byte array.
 */
 
/**
 * Create a new Name from components.
 * 
 * @constructor
 * @param {String|Name|Array<String|Array<number>|ArrayBuffer|Uint8Array|Name>} components if a string, parse it as a URI.  If a Name, add a deep copy of its components.  
 * Otherwise it is an array of components where each is a string, byte array, ArrayBuffer, Uint8Array or Name.
 * Convert each and store as an array of Uint8Array.  If a component is a string, encode as utf8.
 */
var Name = function Name(components) {
	if( typeof components == 'string') {		
		if(LOG>3)console.log('Content Name String '+components);
		this.components = Name.createNameArray(components);
	}
	else if(typeof components === 'object'){		
		this.components = [];
    if (components instanceof Name)
      this.add(components);
    else {
      for (var i = 0; i < components.length; ++i)
        this.add(components[i]);
    }
	}
	else if(components==null)
		this.components =[];
	else
		if(LOG>1)console.log("NO CONTENT NAME GIVEN");
};

Name.prototype.getName = function() {
    return this.to_uri();
};

/** Parse uri as a URI and return an array of Uint8Array components.
 */
Name.createNameArray = function(uri) {
    uri = uri.trim();
    if (uri.length <= 0)
        return [];

    var iColon = uri.indexOf(':');
    if (iColon >= 0) {
        // Make sure the colon came before a '/'.
        var iFirstSlash = uri.indexOf('/');
        if (iFirstSlash < 0 || iColon < iFirstSlash)
            // Omit the leading protocol such as ndn:
            uri = uri.substr(iColon + 1, uri.length - iColon - 1).trim();
    }
    
  	if (uri[0] == '/') {
        if (uri.length >= 2 && uri[1] == '/') {
            // Strip the authority following "//".
            var iAfterAuthority = uri.indexOf('/', 2);
            if (iAfterAuthority < 0)
                // Unusual case: there was only an authority.
                return [];
            else
                uri = uri.substr(iAfterAuthority + 1, uri.length - iAfterAuthority - 1).trim();
        }
        else
            uri = uri.substr(1, uri.length - 1).trim();
    }

	var array = uri.split('/');
    
    // Unescape the components.
    for (var i = 0; i < array.length; ++i) {
        var component = Name.fromEscapedString(array[i]);
        
        if (component == null) {
            // Ignore the illegal componenent.  This also gets rid of a trailing '/'.
            array.splice(i, 1);
            --i;  
            continue;
        }
        else
            array[i] = component;
    }

	return array;
}


Name.prototype.from_ndnb = function(/*XMLDecoder*/ decoder)  {
		decoder.readStartElement(this.getElementLabel());

		
		this.components = new Array(); //new ArrayList<byte []>();

		while (decoder.peekStartElement(NDNProtocolDTags.Component)) {
			this.add(decoder.readBinaryElement(NDNProtocolDTags.Component));
		}
		
		decoder.readEndElement();
};

Name.prototype.to_ndnb = function(/*XMLEncoder*/ encoder)  {
		
		if( this.components ==null ) 
			throw new Error("CANNOT ENCODE EMPTY CONTENT NAME");

		encoder.writeStartElement(this.getElementLabel());
		var count = this.components.length;
		for (var i=0; i < count; i++) {
			encoder.writeElement(NDNProtocolDTags.Component, this.components[i]);
		}
		encoder.writeEndElement();
};

Name.prototype.getElementLabel = function(){
	return NDNProtocolDTags.Name;
};

/**
 * Convert the component to a Uint8Array and add to this Name.
 * Return this Name object to allow chaining calls to add.
 * @param {String|Array<number>|ArrayBuffer|Uint8Array|Name} component If a component is a string, encode as utf8.
 * @returns {Name}
 */
Name.prototype.add = function(component){
    var result;
    if(typeof component == 'string')
        result = DataUtils.stringToUtf8Array(component);
	else if(typeof component == 'object' && component instanceof Uint8Array)
        result = new Uint8Array(component);
	else if(typeof component == 'object' && component instanceof ArrayBuffer) {
        // Make a copy.  Don't use ArrayBuffer.slice since it isn't always supported.
        result = new Uint8Array(new ArrayBuffer(component.byteLength));
        result.set(new Uint8Array(component));
    }
    else if (typeof component == 'object' && component instanceof Name) {
        var components;
        if (component == this)
            // special case, when we need to create a copy
            components = this.components.slice(0, this.components.length);
        else
            components = component.components;
        
        for (var i = 0; i < components.length; ++i)
            this.components.push(new Uint8Array(components[i]));
        return this;
    }
	else if(typeof component == 'object')
        // Assume component is a byte array.  We can't check instanceof Array because
        //   this doesn't work in JavaScript if the array comes from a different module.
        result = new Uint8Array(component);
	else 
		throw new Error("Cannot add Name element at index " + this.components.length + 
            ": Invalid type");
    
    this.components.push(result);
	return this;
};

/**
 * Return the escaped name string according to "NDNx URI Scheme".
 * @returns {String}
 */
Name.prototype.to_uri = function() {	
    if (this.components.length == 0)
        return "/";
    
	var result = "";
	
	for(var i = 0; i < this.components.length; ++i)
		result += "/"+ Name.toEscapedString(this.components[i]);
	
	return result;	
};

/**
 * Add a component that represents a segment number
 *
 * This component has a special format handling:
 * - if number is zero, then %00 is added
 * - if number is between 1 and 255, %00%01 .. %00%FF is added
 * - ...
 * @param {number} number the segment number (integer is expected)
 * @returns {Name}
 */
Name.prototype.addSegment = function(number) {
    var segmentNumberBigEndian = DataUtils.nonNegativeIntToBigEndian(number);
    // Put a 0 byte in front.
    var segmentNumberComponent = new Uint8Array(segmentNumberBigEndian.length + 1);
    segmentNumberComponent.set(segmentNumberBigEndian, 1);

    this.components.push(segmentNumberComponent);
    return this;
};

/**
 * Return a new Name with the first nComponents components of this Name.
 */
Name.prototype.getPrefix = function(nComponents) {
    return new Name(this.components.slice(0, nComponents));
}

/**
 * @brief Get prefix of the name, containing less minusComponents right components
 * @param minusComponents number of components to cut from the back
 */
Name.prototype.cut = function (minusComponents) {
    return new Name(this.components.slice(0, this.components.length-1));
}

/**
 * Return a new ArrayBuffer of the component at i.
 */
Name.prototype.getComponent = function(i) {
    var result = new ArrayBuffer(this.components[i].length);
    new Uint8Array(result).set(this.components[i]);
    return result;
}

/**
 * The "file name" in a name is the last component that isn't blank and doesn't start with one of the
 *   special marker octets (for version, etc.).  Return the index in this.components of
 *   the file name, or -1 if not found.
 */
Name.prototype.indexOfFileName = function() {
    for (var i = this.components.length - 1; i >= 0; --i) {
        var component = this.components[i];
        if (component.length <= 0)
            continue;
        
        if (component[0] == 0 || component[0] == 0xC0 || component[0] == 0xC1 || 
            (component[0] >= 0xF5 && component[0] <= 0xFF))
            continue;
        
        return i;
    }
    
    return -1;
}

/**
 * Return true if this Name has the same components as name.
 */
Name.prototype.equalsName = function(name) {
    if (this.components.length != name.components.length)
        return false;
    
    // Start from the last component because they are more likely to differ.
    for (var i = this.components.length - 1; i >= 0; --i) {
        if (!DataUtils.arraysEqual(this.components[i], name.components[i]))
            return false;
    }
    
    return true;
}

/**
 * Find the last component in name that has a ContentDigest and return the digest value as Uint8Array, 
 *   or null if not found.  See Name.getComponentContentDigestValue.
 */
Name.prototype.getContentDigestValue = function() {
    for (var i = this.components.length - 1; i >= 0; --i) {
        var digestValue = Name.getComponentContentDigestValue(this.components[i]);
        if (digestValue != null)
           return digestValue;
    }
    
    return null;
}

/**
 * If component is a ContentDigest, return the digest value as a Uint8Array subarray (don't modify!).
 * If not a ContentDigest, return null.
 * A ContentDigest component is Name.ContentDigestPrefix + 32 bytes + Name.ContentDigestSuffix.
 */
Name.getComponentContentDigestValue = function(component) {
    var digestComponentLength = Name.ContentDigestPrefix.length + 32 + Name.ContentDigestSuffix.length; 
    // Check for the correct length and equal ContentDigestPrefix and ContentDigestSuffix.
    if (component.length == digestComponentLength &&
        DataUtils.arraysEqual(component.subarray(0, Name.ContentDigestPrefix.length), 
                              Name.ContentDigestPrefix) &&
        DataUtils.arraysEqual(component.subarray
           (component.length - Name.ContentDigestSuffix.length, component.length),
                              Name.ContentDigestSuffix))
       return component.subarray(Name.ContentDigestPrefix.length, Name.ContentDigestPrefix.length + 32);
   else
       return null;
}

// Meta GUID "%C1.M.G%C1" + ContentDigest with a 32 byte BLOB. 
Name.ContentDigestPrefix = new Uint8Array([0xc1, 0x2e, 0x4d, 0x2e, 0x47, 0xc1, 0x01, 0xaa, 0x02, 0x85]);
Name.ContentDigestSuffix = new Uint8Array([0x00]);

/**
 * Return component as an escaped string according to "NDNx URI Scheme".
 * We can't use encodeURIComponent because that doesn't encode all the characters we want to.
 */
Name.toEscapedString = function(component) {
    var result = "";
    var gotNonDot = false;
    for (var i = 0; i < component.length; ++i) {
        if (component[i] != 0x2e) {
            gotNonDot = true;
            break;
        }
    }
    if (!gotNonDot) {
        // Special case for component of zero or more periods.  Add 3 periods.
        result = "...";
        for (var i = 0; i < component.length; ++i)
            result += ".";
    }
    else {
        for (var i = 0; i < component.length; ++i) {
            var x = component[i];
            // Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
            if (x >= 0x30 && x <= 0x39 || x >= 0x41 && x <= 0x5a ||
                x >= 0x61 && x <= 0x7a || x == 0x2b || x == 0x2d || 
                x == 0x2e || x == 0x5f)
                result += String.fromCharCode(x);
            else
                result += "%" + (x < 16 ? "0" : "") + x.toString(16).toUpperCase();
        }
    }
    return result;
};

/**
 * Return component as a Uint8Array by decoding the escapedString according to "NDNx URI Scheme".
 * If escapedString is "", "." or ".." then return null, which means to skip the component in the name.
 */
Name.fromEscapedString = function(escapedString) {
    var component = unescape(escapedString.trim());
        
    if (component.match(/[^.]/) == null) {
        // Special case for component of only periods.  
        if (component.length <= 2)
            // Zero, one or two periods is illegal.  Ignore this componenent to be
            //   consistent with the C implementation.
            return null;
        else
            // Remove 3 periods.
            return DataUtils.toNumbersFromString(component.substr(3, component.length - 3));
    }
    else
        return DataUtils.toNumbersFromString(component);
}

/**
 * Return true if the N components of this name are the same as the first N components of the given name.
 * @param {Name} name The name to check.
 * @returns {Boolean} true if this matches the given name.  This always returns true if this name is empty.
 */
Name.prototype.match = function(name) {
	var i_name = this.components;
	var o_name = name.components;

	// This name is longer than the name we are checking it against.
	if (i_name.length > o_name.length)
    return false;

	// Check if at least one of given components doesn't match.
  for (var i = 0; i < i_name.length; ++i) {
    if (!DataUtils.arraysEqual(i_name[i], o_name[i]))
      return false;
  }

	return true;
};
/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents ContentObject Objects
 */

/**
 * Create a new ContentObject with the optional values.
 * 
 * @constructor
 * @param {Name} name
 * @param {SignedInfo} signedInfo
 * @param {Uint8Array} content
 */
var ContentObject = function ContentObject(name, signedInfo, content) {
	if (typeof name == 'string')
		this.name = new Name(name);
	else
		//TODO Check the class of name
		this.name = name;
	
	this.signedInfo = signedInfo;
	
	if (typeof content == 'string') 
		this.content = DataUtils.toNumbersFromString(content);
	else 
		this.content = content;
	
	this.signature = new Signature();
	
	this.startSIG = null;
	this.endSIG = null;
	
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
 
	obj.to_ndnb(enc);
	
	var num = enc.getReducedOstream();

	return num;

	
};

ContentObject.prototype.encodeContent = function encodeContent(obj){
	var enc = new BinaryXMLEncoder();
	 
	enc.writeElement(NDNProtocolDTags.Content, this.content);

	var num = enc.getReducedOstream();

	return num;

	
};

ContentObject.prototype.saveRawData = function(bytes){
	
	var sigBits = bytes.subarray(this.startSIG, this.endSIG);

	this.rawSignatureData = sigBits;
};

/**
 * @deprecated Use BinaryXmlWireFormat.decodeContentObject.
 */
ContentObject.prototype.from_ndnb = function(/*XMLDecoder*/ decoder) {
  BinaryXmlWireFormat.decodeContentObject(this, decoder);
};

/**
 * @deprecated Use BinaryXmlWireFormat.encodeContentObject.
 */
ContentObject.prototype.to_ndnb = function(/*XMLEncoder*/ encoder)  {
  BinaryXmlWireFormat.encodeContentObject(this, encoder);
};

/**
 * Encode this ContentObject for a particular wire format.
 * @param {WireFormat} wireFormat if null, use BinaryXmlWireFormat.
 * @returns {Uint8Array}
 */
ContentObject.prototype.encode = function(wireFormat) {
  wireFormat = (wireFormat || BinaryXmlWireFormat.instance);
  return wireFormat.encodeContentObject(this);
};

/**
 * Decode the input using a particular wire format and update this ContentObject.
 * @param {Uint8Array} input
 * @param {WireFormat} wireFormat if null, use BinaryXmlWireFormat.
 */
ContentObject.prototype.decode = function(input, wireFormat) {
  wireFormat = (wireFormat || BinaryXmlWireFormat.instance);
  wireFormat.decodeContentObject(this, input);
};

ContentObject.prototype.getElementLabel= function(){return NDNProtocolDTags.ContentObject;};

/**
 * Create a new Signature with the optional values.
 * @constructor
 */
var Signature = function Signature(witness, signature, digestAlgorithm) {
  this.Witness = witness;
	this.signature = signature;
	this.digestAlgorithm = digestAlgorithm
};

Signature.prototype.from_ndnb =function( decoder) {
		decoder.readStartElement(this.getElementLabel());
		
		if(LOG>4)console.log('STARTED DECODING SIGNATURE');
		
		if (decoder.peekStartElement(NDNProtocolDTags.DigestAlgorithm)) {
			if(LOG>4)console.log('DIGIEST ALGORITHM FOUND');
			this.digestAlgorithm = decoder.readUTF8Element(NDNProtocolDTags.DigestAlgorithm); 
		}
		if (decoder.peekStartElement(NDNProtocolDTags.Witness)) {
			if(LOG>4)console.log('WITNESS FOUND');
			this.Witness = decoder.readBinaryElement(NDNProtocolDTags.Witness); 
		}
		
		//FORCE TO READ A SIGNATURE

			if(LOG>4)console.log('SIGNATURE FOUND');
			this.signature = decoder.readBinaryElement(NDNProtocolDTags.SignatureBits);

		decoder.readEndElement();
	
};


Signature.prototype.to_ndnb= function( encoder){
    	
	if (!this.validate()) {
		throw new Error("Cannot encode: field values missing.");
	}
	
	encoder.writeStartElement(this.getElementLabel());
	
	if ((null != this.digestAlgorithm) && (!this.digestAlgorithm.equals(NDNDigestHelper.DEFAULT_DIGEST_ALGORITHM))) {
		encoder.writeElement(NDNProtocolDTags.DigestAlgorithm, OIDLookup.getDigestOID(this.DigestAlgorithm));
	}
	
	if (null != this.Witness) {
		// needs to handle null witness
		encoder.writeElement(NDNProtocolDTags.Witness, this.Witness);
	}

	encoder.writeElement(NDNProtocolDTags.SignatureBits, this.signature);

	encoder.writeEndElement();   		
};

Signature.prototype.getElementLabel = function() { return NDNProtocolDTags.Signature; };


Signature.prototype.validate = function() {
		return null != this.signature;
};


var ContentType = {DATA:0, ENCR:1, GONE:2, KEY:3, LINK:4, NACK:5};
var ContentTypeValue = {0:0x0C04C0, 1:0x10D091,2:0x18E344,3:0x28463F,4:0x2C834A,5:0x34008A};
var ContentTypeValueReverse = {0x0C04C0:0, 0x10D091:1,0x18E344:2,0x28463F:3,0x2C834A:4,0x34008A:5};

/**
 * Create a new SignedInfo with the optional values.
 * @constructor
 */
var SignedInfo = function SignedInfo(publisher, timestamp, type, locator, freshnessSeconds, finalBlockID) {
  this.publisher = publisher; //publisherPublicKeyDigest
  this.timestamp=timestamp; // NDN Time
  this.type=type; // ContentType
  this.locator =locator;//KeyLocator
  this.freshnessSeconds =freshnessSeconds; // Integer
  this.finalBlockID=finalBlockID; //byte array
    
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
	

    this.timestamp = new NDNTime( time );
    
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

SignedInfo.prototype.from_ndnb = function( decoder){

		decoder.readStartElement( this.getElementLabel() );
		
		if (decoder.peekStartElement(NDNProtocolDTags.PublisherPublicKeyDigest)) {
			if(LOG>4)console.log('DECODING PUBLISHER KEY');
			this.publisher = new PublisherPublicKeyDigest();
			this.publisher.from_ndnb(decoder);
		}

		if (decoder.peekStartElement(NDNProtocolDTags.Timestamp)) {
			if(LOG>4)console.log('DECODING TIMESTAMP');
			this.timestamp = decoder.readDateTime(NDNProtocolDTags.Timestamp);
		}

		if (decoder.peekStartElement(NDNProtocolDTags.Type)) {
			var binType = decoder.readBinaryElement(NDNProtocolDTags.Type);//byte [] 
		
			
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
		
		if (decoder.peekStartElement(NDNProtocolDTags.FreshnessSeconds)) {
			this.freshnessSeconds = decoder.readIntegerElement(NDNProtocolDTags.FreshnessSeconds);
			if(LOG>4)console.log('FRESHNESS IN SECONDS IS '+ this.freshnessSeconds);
		}
		
		if (decoder.peekStartElement(NDNProtocolDTags.FinalBlockID)) {
			if(LOG>4)console.log('DECODING FINAL BLOCKID');
			this.finalBlockID = decoder.readBinaryElement(NDNProtocolDTags.FinalBlockID);
		}
		
		if (decoder.peekStartElement(NDNProtocolDTags.KeyLocator)) {
			if(LOG>4)console.log('DECODING KEY LOCATOR');
			this.locator = new KeyLocator();
			this.locator.from_ndnb(decoder);
		}
				
		decoder.readEndElement();
};

SignedInfo.prototype.to_ndnb = function( encoder)  {
		if (!this.validate()) {
			throw new Error("Cannot encode : field values missing.");
		}
		encoder.writeStartElement(this.getElementLabel());
		
		if (null!=this.publisher) {
			if(LOG>3) console.log('ENCODING PUBLISHER KEY' + this.publisher.publisherPublicKeyDigest);

			this.publisher.to_ndnb(encoder);
		}

		if (null!=this.timestamp) {
			encoder.writeDateTime(NDNProtocolDTags.Timestamp, this.timestamp );
		}
		
		if (null!=this.type && this.type !=0) {
			
			encoder.writeElement(NDNProtocolDTags.type, this.type);
		}
		
		if (null!=this.freshnessSeconds) {
			encoder.writeElement(NDNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);
		}

		if (null!=this.finalBlockID) {
			encoder.writeElement(NDNProtocolDTags.FinalBlockID, this.finalBlockID);
		}

		if (null!=this.locator) {
			this.locator.to_ndnb(encoder);
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
	return NDNProtocolDTags.SignedInfo;
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
Interest.prototype.from_ndnb = function(/*XMLDecoder*/ decoder) {
  BinaryXmlWireFormat.decodeInterest(this, decoder);
};

/**
 * @deprecated Use BinaryXmlWireFormat.encodeInterest.
 */
Interest.prototype.to_ndnb = function(/*XMLEncoder*/ encoder){
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

Exclude.prototype.from_ndnb = function(/*XMLDecoder*/ decoder) {
	decoder.readStartElement(NDNProtocolDTags.Exclude);

	while (true) {
        if (decoder.peekStartElement(NDNProtocolDTags.Component))
            this.values.push(decoder.readBinaryElement(NDNProtocolDTags.Component));
        else if (decoder.peekStartElement(NDNProtocolDTags.Any)) {
            decoder.readStartElement(NDNProtocolDTags.Any);
            decoder.readEndElement();
            this.values.push(Exclude.ANY);
        }
        else if (decoder.peekStartElement(NDNProtocolDTags.Bloom)) {
            // Skip the Bloom and treat it as Any.
            decoder.readBinaryElement(NDNProtocolDTags.Bloom);
            this.values.push(Exclude.ANY);
        }
        else
            break;
	}
    
    decoder.readEndElement();
};

Exclude.prototype.to_ndnb = function(/*XMLEncoder*/ encoder)  {
	if (this.values == null || this.values.length == 0)
		return;

	encoder.writeStartElement(NDNProtocolDTags.Exclude);
    
    // TODO: Do we want to order the components (except for ANY)?
    for (var i = 0; i < this.values.length; ++i) {
        if (this.values[i] == Exclude.ANY) {
            encoder.writeStartElement(NDNProtocolDTags.Any);
            encoder.writeEndElement();
        }
        else
            encoder.writeElement(NDNProtocolDTags.Component, this.values[i]);
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
/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Key Objects
 */

/**
 * @constructor
 */
var Key = function Key(){
    /* TODO: Port from PyNDN:
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
	KEY:1,
	CERTIFICATE:2,
	KEYNAME:3
};

/**
 * @constructor
 */
var KeyLocator = function KeyLocator(input,type) { 
  this.type = type;
    
  if (type == KeyLocatorType.KEYNAME){
  	if (LOG>3) console.log('KeyLocator: SET KEYNAME');
   	this.keyName = input;
  }
  else if (type == KeyLocatorType.KEY){
   	if (LOG>3) console.log('KeyLocator: SET KEY');
   	this.publicKey = input;
  }
  else if (type == KeyLocatorType.CERTIFICATE){
   	if (LOG>3) console.log('KeyLocator: SET CERTIFICATE');
   	this.certificate = input;
  }
};

KeyLocator.prototype.from_ndnb = function(decoder) {

	decoder.readStartElement(this.getElementLabel());

	if (decoder.peekStartElement(NDNProtocolDTags.Key)) {
		try {
			var encodedKey = decoder.readBinaryElement(NDNProtocolDTags.Key);
			// This is a DER-encoded SubjectPublicKeyInfo.
			
			//TODO FIX THIS, This should create a Key Object instead of keeping bytes

			this.publicKey =   encodedKey;//CryptoUtil.getPublicKey(encodedKey);
			this.type = KeyLocatorType.KEY;
			

			if(LOG>4) console.log('PUBLIC KEY FOUND: '+ this.publicKey);
			//this.publicKey = encodedKey;
			
			
		} catch (e) {
			throw new Error("Cannot parse key: ", e);
		} 

		if (null == this.publicKey) {
			throw new Error("Cannot parse key: ");
		}

	} else if ( decoder.peekStartElement(NDNProtocolDTags.Certificate)) {
		try {
			var encodedCert = decoder.readBinaryElement(NDNProtocolDTags.Certificate);
			
			/*
			 * Certificates not yet working
			 */
			
			//CertificateFactory factory = CertificateFactory.getInstance("X.509");
			//this.certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encodedCert));
			

			this.certificate = encodedCert;
			this.type = KeyLocatorType.CERTIFICATE;

			if(LOG>4) console.log('CERTIFICATE FOUND: '+ this.certificate);
			
		} catch ( e) {
			throw new Error("Cannot decode certificate: " +  e);
		}
		if (null == this.certificate) {
			throw new Error("Cannot parse certificate! ");
		}
	} else  {
		this.type = KeyLocatorType.KEYNAME;
		
		this.keyName = new KeyName();
		this.keyName.from_ndnb(decoder);
	}
	decoder.readEndElement();
};
	

KeyLocator.prototype.to_ndnb = function( encoder) {
	
	if(LOG>4) console.log('type is is ' + this.type);
	//TODO Check if Name is missing
	if (!this.validate()) {
		throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
	}

	
	//TODO FIX THIS TOO
	encoder.writeStartElement(this.getElementLabel());
	
	if (this.type == KeyLocatorType.KEY) {
		if(LOG>5)console.log('About to encode a public key' +this.publicKey);
		encoder.writeElement(NDNProtocolDTags.Key, this.publicKey);
		
	} else if (this.type == KeyLocatorType.CERTIFICATE) {
		
		try {
			encoder.writeElement(NDNProtocolDTags.Certificate, this.certificate);
		} catch ( e) {
			throw new Error("CertificateEncodingException attempting to write key locator: " + e);
		}
		
	} else if (this.type == KeyLocatorType.KEYNAME) {
		
		this.keyName.to_ndnb(encoder);
	}
	encoder.writeEndElement();
	
};

KeyLocator.prototype.getElementLabel = function() {
	return NDNProtocolDTags.KeyLocator; 
};

KeyLocator.prototype.validate = function() {
	return (  (null != this.keyName) || (null != this.publicKey) || (null != this.certificate)   );
};

/**
 * KeyName is only used by KeyLocator.
 * @constructor
 */
var KeyName = function KeyName() {
	this.contentName = this.contentName;  //contentName
	this.publisherID = this.publisherID;  //publisherID

};

KeyName.prototype.from_ndnb=function( decoder){
	

	decoder.readStartElement(this.getElementLabel());

	this.contentName = new Name();
	this.contentName.from_ndnb(decoder);
	
	if(LOG>4) console.log('KEY NAME FOUND: ');
	
	if ( PublisherID.peek(decoder) ) {
		this.publisherID = new PublisherID();
		this.publisherID.from_ndnb(decoder);
	}
	
	decoder.readEndElement();
};

KeyName.prototype.to_ndnb = function( encoder) {
	if (!this.validate()) {
		throw new Error("Cannot encode : field values missing.");
	}
	
	encoder.writeStartElement(this.getElementLabel());
	
	this.contentName.to_ndnb(encoder);
	if (null != this.publisherID)
		this.publisherID.to_ndnb(encoder);

	encoder.writeEndElement();   		
};
	
KeyName.prototype.getElementLabel = function() { return NDNProtocolDTags.KeyName; };

KeyName.prototype.validate = function() {
		// DKS -- do we do recursive validation?
		// null signedInfo ok
		return (null != this.contentName);
};

/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Publisher and PublisherType Objects
 */

/**
 * @constructor
 */
var PublisherType = function PublisherType(tag){
    	this.KEY =(NDNProtocolDTags.PublisherPublicKeyDigest);
    	this.CERTIFICATE= (NDNProtocolDTags.PublisherCertificateDigest);
    	this.ISSUER_KEY=	(NDNProtocolDTags.PublisherIssuerKeyDigest);
    	this.ISSUER_CERTIFICATE	=(NDNProtocolDTags.PublisherIssuerCertificateDigest);

    	this.Tag = tag;
}; 

var isTypeTagVal = function(tagVal) {
		if ((tagVal == NDNProtocolDTags.PublisherPublicKeyDigest) ||
			(tagVal == NDNProtocolDTags.PublisherCertificateDigest) ||
			(tagVal == NDNProtocolDTags.PublisherIssuerKeyDigest) ||
			(tagVal == NDNProtocolDTags.PublisherIssuerCertificateDigest)) {
			return true;
		}
		return false;
};

/**
 * @constructor
 */
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


PublisherID.prototype.from_ndnb = function(decoder) {
		
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
			throw new ContentDecodingException(new Error("Cannot parse publisher ID of type : " + nextTag + "."));
		}
};

PublisherID.prototype.to_ndnb = function(encoder) {
	if (!this.validate()) {
		throw new Error("Cannot encode " + this.getClass().getName() + ": field values missing.");
	}

	encoder.writeElement(this.getElementLabel(), this.publisherID);
};
	
PublisherID.peek = function(/* XMLDecoder */ decoder) {

		//Long
		var nextTag = decoder.peekStartElementAsLong();
		
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



/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents PublisherPublicKeyDigest Objects
 */

/**
 * @constructor
 */
var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(pkd){ 
	
 	 //this.PUBLISHER_ID_LEN = 256/8;
	 this.PUBLISHER_ID_LEN = 512/8;
 	 

	 this.publisherPublicKeyDigest = pkd;
 	 //if( typeof _pkd == "object") this.publisherPublicKeyDigest = _pkd; // Byte Array
 	 //else if( typeof _pkd == "PublicKey") ;//TODO...
    
};

PublisherPublicKeyDigest.prototype.from_ndnb = function( decoder) {		

		this.publisherPublicKeyDigest = decoder.readBinaryElement(this.getElementLabel());
		
		if(LOG>4)console.log('Publisher public key digest is ' + this.publisherPublicKeyDigest);

		if (null == this.publisherPublicKeyDigest) {
			throw new Error("Cannot parse publisher key digest.");
		}
		
		//TODO check if the length of the PublisherPublicKeyDigest is correct ( Security reason)

		if (this.publisherPublicKeyDigest.length != this.PUBLISHER_ID_LEN) {
			if (LOG > 0)
                console.log('LENGTH OF PUBLISHER ID IS WRONG! Expected ' + this.PUBLISHER_ID_LEN + ", got " + this.publisherPublicKeyDigest.length);
			
			//this.publisherPublicKeyDigest = new PublisherPublicKeyDigest(this.PublisherPublicKeyDigest).PublisherKeyDigest;		
		}
	};

PublisherPublicKeyDigest.prototype.to_ndnb= function( encoder) {
		//TODO Check that the ByteArray for the key is present
		if (!this.validate()) {
			throw new Error("Cannot encode : field values missing.");
		}
		if(LOG>3) console.log('PUBLISHER KEY DIGEST IS'+this.publisherPublicKeyDigest);
		encoder.writeElement(this.getElementLabel(), this.publisherPublicKeyDigest);
};
	
PublisherPublicKeyDigest.prototype.getElementLabel = function() { return NDNProtocolDTags.PublisherPublicKeyDigest; };

PublisherPublicKeyDigest.prototype.validate =function() {
		return (null != this.publisherPublicKeyDigest);
};
/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Face Instances
 */

var NetworkProtocol = { TCP:6, UDP:17};

/**
 * @constructor
 */
var FaceInstance  = function FaceInstance(action, publisherPublicKeyDigest, faceID, ipProto, host, port, multicastInterface,
		multicastTTL, freshnessSeconds) {
	this.action = action;
	this.publisherPublicKeyDigest = publisherPublicKeyDigest;
	this.faceID = faceID;
	this.ipProto = ipProto;
	this.host = host;
	this.Port = port;
	this.multicastInterface =multicastInterface;
	this.multicastTTL =multicastTTL;
	this.freshnessSeconds = freshnessSeconds;
};

/**
 * Used by NetworkObject to decode the object from a network stream.
 */
FaceInstance.prototype.from_ndnb = function(//XMLDecoder 
	decoder) {

	decoder.readStartElement(this.getElementLabel());
	
	if (decoder.peekStartElement(NDNProtocolDTags.Action)) {
		
		this.action = decoder.readUTF8Element(NDNProtocolDTags.Action);
		
	}
	if (decoder.peekStartElement(NDNProtocolDTags.PublisherPublicKeyDigest)) {
		
		this.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
		this.publisherPublicKeyDigest.from_ndnb(decoder);
		
	}
	if (decoder.peekStartElement(NDNProtocolDTags.FaceID)) {
		
		this.faceID = decoder.readIntegerElement(NDNProtocolDTags.FaceID);
		
	}
	if (decoder.peekStartElement(NDNProtocolDTags.IPProto)) {
		
		//int
		var pI = decoder.readIntegerElement(NDNProtocolDTags.IPProto);
		
		this.ipProto = null;
		
		if (NetworkProtocol.TCP == pI) {
			
			this.ipProto = NetworkProtocol.TCP;
			
		} else if (NetworkProtocol.UDP == pI) {
			
			this.ipProto = NetworkProtocol.UDP;
			
		} else {
			
			throw new Error("FaceInstance.decoder.  Invalid " + 
					NDNProtocolDTags.tagToString(NDNProtocolDTags.IPProto) + " field: " + pI);
			
		}
	}
	
	if (decoder.peekStartElement(NDNProtocolDTags.Host)) {
		
		this.host = decoder.readUTF8Element(NDNProtocolDTags.Host);
		
	}
	
	if (decoder.peekStartElement(NDNProtocolDTags.Port)) {
		this.Port = decoder.readIntegerElement(NDNProtocolDTags.Port); 
	}
	
	if (decoder.peekStartElement(NDNProtocolDTags.MulticastInterface)) {
		this.multicastInterface = decoder.readUTF8Element(NDNProtocolDTags.MulticastInterface); 
	}
	
	if (decoder.peekStartElement(NDNProtocolDTags.MulticastTTL)) {
		this.multicastTTL = decoder.readIntegerElement(NDNProtocolDTags.MulticastTTL); 
	}
	
	if (decoder.peekStartElement(NDNProtocolDTags.FreshnessSeconds)) {
		this.freshnessSeconds = decoder.readIntegerElement(NDNProtocolDTags.FreshnessSeconds); 
	}
	decoder.readEndElement();
}

/**
 * Used by NetworkObject to encode the object to a network stream.
 */
FaceInstance.prototype.to_ndnb = function(//XMLEncoder
	encoder){

	//if (!this.validate()) {
		//throw new Error("Cannot encode : field values missing.");
		//throw new Error("")
	//}
	encoder.writeStartElement(this.getElementLabel());
	
	if (null != this.action && this.action.length != 0)
		encoder.writeElement(NDNProtocolDTags.Action, this.action);	
	
	if (null != this.publisherPublicKeyDigest) {
		this.publisherPublicKeyDigest.to_ndnb(encoder);
	}
	if (null != this.faceID) {
		encoder.writeElement(NDNProtocolDTags.FaceID, this.faceID);
	}
	if (null != this.ipProto) {
		//encoder.writeElement(NDNProtocolDTags.IPProto, this.IpProto.value());
		encoder.writeElement(NDNProtocolDTags.IPProto, this.ipProto);
	}
	if (null != this.host && this.host.length != 0) {
		encoder.writeElement(NDNProtocolDTags.Host, this.host);	
	}
	if (null != this.Port) {
		encoder.writeElement(NDNProtocolDTags.Port, this.Port);
	}
	if (null != this.multicastInterface && this.multicastInterface.length != 0) {
		encoder.writeElement(NDNProtocolDTags.MulticastInterface, this.multicastInterface);
	}
	if (null !=  this.multicastTTL) {
		encoder.writeElement(NDNProtocolDTags.MulticastTTL, this.multicastTTL);
	}
	if (null != this.freshnessSeconds) {
		encoder.writeElement(NDNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);
	}
	encoder.writeEndElement();   			
}


FaceInstance.prototype.getElementLabel = function() {
  return NDNProtocolDTags.FaceInstance;
};

/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Forwarding Entries
 */

/**
 * Create a new ForwardingEntry with the optional arguments.
 * @constructor
 * @param {String} action
 * @param {Name} prefixName
 * @param {PublisherPublicKeyDigest} ndndId
 * @param {number} faceID
 * @param {number} flags
 * @param {number} lifetime in seconds
 */
var ForwardingEntry = function ForwardingEntry(action, prefixName, ndndId, faceID, flags, lifetime) {
	this.action = action;
	this.prefixName = prefixName;
	this.ndndID = ndndId;
	this.faceID = faceID;
	this.flags = flags;
	this.lifetime = lifetime;
};

ForwardingEntry.prototype.from_ndnb =function(
	//XMLDecoder 
	decoder) 
	//throws ContentDecodingException
	{
			decoder.readStartElement(this.getElementLabel());
			if (decoder.peekStartElement(NDNProtocolDTags.Action)) {
				this.action = decoder.readUTF8Element(NDNProtocolDTags.Action); 
			}
			if (decoder.peekStartElement(NDNProtocolDTags.Name)) {
				this.prefixName = new Name();
				this.prefixName.from_ndnb(decoder) ;
			}
			if (decoder.peekStartElement(NDNProtocolDTags.PublisherPublicKeyDigest)) {
				this.NdndId = new PublisherPublicKeyDigest();
				this.NdndId.from_ndnb(decoder);
			}
			if (decoder.peekStartElement(NDNProtocolDTags.FaceID)) {
				this.faceID = decoder.readIntegerElement(NDNProtocolDTags.FaceID); 
			}
			if (decoder.peekStartElement(NDNProtocolDTags.ForwardingFlags)) {
				this.flags = decoder.readIntegerElement(NDNProtocolDTags.ForwardingFlags); 
			}
			if (decoder.peekStartElement(NDNProtocolDTags.FreshnessSeconds)) {
				this.lifetime = decoder.readIntegerElement(NDNProtocolDTags.FreshnessSeconds); 
			}
			decoder.readEndElement();
		};

ForwardingEntry.prototype.to_ndnb =function(
	//XMLEncoder 
encoder) 
{


			//if (!validate()) {
				//throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
			//}
			encoder.writeStartElement(this.getElementLabel());
			if (null != this.action && this.action.length != 0)
				encoder.writeElement(NDNProtocolDTags.Action, this.action);	
			if (null != this.prefixName) {
				this.prefixName.to_ndnb(encoder);
			}
			if (null != this.NdndId) {
				this.NdndId.to_ndnb(encoder);
			}
			if (null != this.faceID) {
				encoder.writeElement(NDNProtocolDTags.FaceID, this.faceID);
			}
			if (null != this.flags) {
				encoder.writeElement(NDNProtocolDTags.ForwardingFlags, this.flags);
			}
			if (null != this.lifetime) {
				encoder.writeElement(NDNProtocolDTags.FreshnessSeconds, this.lifetime);
			}
			encoder.writeEndElement();   			
		};

ForwardingEntry.prototype.getElementLabel = function() { return NDNProtocolDTags.ForwardingEntry; }
/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * Encapsulate an Uint8Array and support dynamic reallocation.
 */

/**
 * Create a DynamicUint8Array where this.array is a Uint8Array of size length.
 * The methods will update this.length.
 * To access the array, use this.array or call subarray.
 * @constructor
 * @param {number} length the initial length of the array.  If null, use a default.
 */
var DynamicUint8Array = function DynamicUint8Array(length) {
	if (!length)
        length = 16;
    
    this.array = new Uint8Array(length);
    this.length = length;
};

/**
 * Ensure that this.array has the length, reallocate and copy if necessary.
 * Update this.length which may be greater than length.
 */
DynamicUint8Array.prototype.ensureLength = function(length) {
    if (this.array.length >= length)
        return;
    
    // See if double is enough.
    var newLength = this.array.length * 2;
    if (length > newLength)
        // The needed length is much greater, so use it.
        newLength = length;
    
    var newArray = new Uint8Array(newLength);
    newArray.set(this.array);
    this.array = newArray;
    this.length = newLength;
};

/**
 * Call this.array.set(value, offset), reallocating if necessary. 
 */
DynamicUint8Array.prototype.set = function(value, offset) {
    this.ensureLength(value.length + offset);
    this.array.set(value, offset);
};

/**
 * Return this.array.subarray(begin, end);
 */
DynamicUint8Array.prototype.subarray = function(begin, end) {
    return this.array.subarray(begin, end);
};
/**
 * This class is used to encode ndnb binary elements (blob, type/value pairs).
 * 
 * @author: Meki Cheraoui
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

/**
 * @constructor
 */
var BinaryXMLEncoder = function BinaryXMLEncoder(){
	this.ostream = new DynamicUint8Array(100);
	this.offset =0;
	this.CODEC_NAME = "Binary";
};

/**
 * Encode utf8Content as utf8.
 */
BinaryXMLEncoder.prototype.writeUString = function(/*String*/ utf8Content) {
	this.encodeUString(utf8Content, XML_UDATA);
};


BinaryXMLEncoder.prototype.writeBlob = function(
		/*Uint8Array*/ binaryContent
		) {
	
	if(LOG >3) console.log(binaryContent);
	
	this.encodeBlob(binaryContent, binaryContent.length);
};


BinaryXMLEncoder.prototype.writeStartElement = function(
	/*String*/ tag, 
	/*TreeMap<String,String>*/ attributes
	) {

	/*Long*/ var dictionaryVal = tag; //stringToTag(tag);
	
	if (null == dictionaryVal) {
		this.encodeUString(tag, XML_TAG);
	} else {
		this.encodeTypeAndVal(XML_DTAG, dictionaryVal);
	}
	
	if (null != attributes) {
		this.writeAttributes(attributes); 
	}
};


BinaryXMLEncoder.prototype.writeEndElement = function() {
    this.ostream.ensureLength(this.offset + 1);
	this.ostream.array[this.offset] = XML_CLOSE;
	this.offset += 1;
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
			this.encodeUString(strAttr, XML_ATTR);
		} else {
			this.encodeTypeAndVal(XML_DATTR, dictionaryAttr);
		}
		// Write value
		this.encodeUString(strValue);
		
	}
}


//returns a string
stringToTag = function(/*long*/ tagVal) {
	if ((tagVal >= 0) && (tagVal < NDNProtocolDTagsStrings.length)) {
		return NDNProtocolDTagsStrings[tagVal];
	} else if (tagVal == NDNProtocolDTags.NDNProtocolDataUnit) {
		return NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT;
	}
	return null;
};

//returns a Long
tagToString =  function(/*String*/ tagName) {
	// the slow way, but right now we don't care.... want a static lookup for the forward direction
	for (var i=0; i < NDNProtocolDTagsStrings.length; ++i) {
		if ((null != NDNProtocolDTagsStrings[i]) && (NDNProtocolDTagsStrings[i] == tagName)) {
			return i;
		}
	}
	if (NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT == tagName) {
		return NDNProtocolDTags.NDNProtocolDataUnit;
	}
	return null;
};

/**
 * If Content is a string, then encode as utf8 and write UDATA.
 */
BinaryXMLEncoder.prototype.writeElement = function(
		//long 
		tag, 
		//byte[] 
		Content,
		//TreeMap<String, String> 
		attributes
		) {
	this.writeStartElement(tag, attributes);
	// Will omit if 0-length
	
	if(typeof Content === 'number') {
		if(LOG>4) console.log('GOING TO WRITE THE NUMBER .charCodeAt(0) ' + Content.toString().charCodeAt(0) );
		if(LOG>4) console.log('GOING TO WRITE THE NUMBER ' + Content.toString() );
		if(LOG>4) console.log('type of number is ' + typeof Content.toString() );
		
		this.writeUString(Content.toString());
		//whatever
	}
	else if(typeof Content === 'string'){
		if(LOG>4) console.log('GOING TO WRITE THE STRING  ' + Content );
		if(LOG>4) console.log('type of STRING is ' + typeof Content );
		
		this.writeUString(Content);
	}
	else{
		if(LOG>4) console.log('GOING TO WRITE A BLOB  ' + Content );

		this.writeBlob(Content);
	}
	
	this.writeEndElement();
}



var TypeAndVal = function TypeAndVal(_type,_val) {
	this.type = _type;
	this.val = _val;
	
};


BinaryXMLEncoder.prototype.encodeTypeAndVal = function(
		//int
		type, 
		//long 
		val
		) {
	
	if(LOG>4) console.log('Encoding type '+ type+ ' and value '+ val);
	
	if(LOG>4) console.log('OFFSET IS ' + this.offset);
	
	if ((type > XML_UDATA) || (type < 0) || (val < 0)) {
		throw new Error("Tag and value must be positive, and tag valid.");
	}
	
	// Encode backwards. Calculate how many bytes we need:
	var numEncodingBytes = this.numEncodingBytes(val);
	this.ostream.ensureLength(this.offset + numEncodingBytes);

	// Bottom 4 bits of val go in last byte with tag.
	this.ostream.array[this.offset + numEncodingBytes - 1] = 
		//(byte)
			(BYTE_MASK &
					(((XML_TT_MASK & type) | 
					 ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
					 XML_TT_NO_MORE); // set top bit for last byte
	val = val >>> XML_TT_VAL_BITS;
	
	// Rest of val goes into preceding bytes, 7 bits per byte, top bit
	// is "more" flag.
	var i = this.offset + numEncodingBytes - 2;
	while ((0 != val) && (i >= this.offset)) {
		this.ostream.array[i] = //(byte)
				(BYTE_MASK & (val & XML_REG_VAL_MASK)); // leave top bit unset
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

/**
 * Encode ustring as utf8.
 */
BinaryXMLEncoder.prototype.encodeUString = function(
		//String 
		ustring, 
		//byte 
		type) {
	
	if (null == ustring)
		return;
	if (type == XML_TAG || type == XML_ATTR && ustring.length == 0)
		return;
	
	if(LOG>3) console.log("The string to write is ");
	if(LOG>3) console.log(ustring);

	var strBytes = DataUtils.stringToUtf8Array(ustring);
	
	this.encodeTypeAndVal(type, 
						(((type == XML_TAG) || (type == XML_ATTR)) ?
								(strBytes.length-1) :
								strBytes.length));
	
	if(LOG>3) console.log("THE string to write is ");
	
	if(LOG>3) console.log(strBytes);
	
	this.writeString(strBytes);
	this.offset+= strBytes.length;
};



BinaryXMLEncoder.prototype.encodeBlob = function(
		//Uint8Array 
		blob, 
		//int 
		length) {


	if (null == blob)
		return;
	
	if(LOG>4) console.log('LENGTH OF XML_BLOB IS '+length);
	
	/*blobCopy = new Array(blob.Length);
	
	for (i = 0; i < blob.length; i++) //in InStr.ToCharArray())
	{
		blobCopy[i] = blob[i];
	}*/

	this.encodeTypeAndVal(XML_BLOB, length);

	this.writeBlobArray(blob);
	this.offset += length;
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
		//NDNTime 
		dateTime) {
	
	if(LOG>4)console.log('ENCODING DATE with LONG VALUE');
	if(LOG>4)console.log(dateTime.msec);
	
	//var binarydate = DataUtils.unsignedLongToByteArray( Math.round((dateTime.msec/1000) * 4096)  );
	

	//parse to hex
	var binarydate =  Math.round((dateTime.msec/1000) * 4096).toString(16)  ;
  if (binarydate.length % 2 == 1)
    binarydate = '0' + binarydate;

  // Hack toNumbers by appending a 0 which is ignored.
	var binarydate =  DataUtils.toNumbers( binarydate + '0') ;

	
	if(LOG>4)console.log('ENCODING DATE with BINARY VALUE');
	if(LOG>4)console.log(binarydate);
	if(LOG>4)console.log('ENCODING DATE with BINARY VALUE(HEX)');
	if(LOG>4)console.log(DataUtils.toHex(binarydate));
	
	this.writeElement(tag, binarydate);
};

// This does not update this.offset.
BinaryXMLEncoder.prototype.writeString = function(input) {
	
    if(typeof input === 'string'){
		//console.log('went here');
    	if(LOG>4) console.log('GOING TO WRITE A STRING');
    	if(LOG>4) console.log(input);
        
        this.ostream.ensureLength(this.offset + input.length);
		for (var i = 0; i < input.length; i++) {
			if(LOG>4) console.log('input.charCodeAt(i)=' + input.charCodeAt(i));
		    this.ostream.array[this.offset + i] = (input.charCodeAt(i));
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
		//Uint8Array 
		blob) {
	
	if(LOG>4) console.log('GOING TO WRITE A BLOB');
    
	this.ostream.set(blob, this.offset);
};


BinaryXMLEncoder.prototype.getReducedOstream = function() {
	return this.ostream.subarray(0, this.offset);
};

/**
 * This class is used to decode ndnb binary elements (blob, type/value pairs).
 * 
 * @author: Meki Cheraoui
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
	if ((tagVal >= 0) && (tagVal < NDNProtocolDTagsStrings.length)) {
		return NDNProtocolDTagsStrings[tagVal];
	} else if (tagVal == NDNProtocolDTags.NDNProtocolDataUnit) {
		return NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT;
	}
	return null;
};

//returns a Long
stringToTag =  function(/*String*/ tagName) {
	// the slow way, but right now we don't care.... want a static lookup for the forward direction
	for (var i=0; i < NDNProtocolDTagsStrings.length; ++i) {
		if ((null != NDNProtocolDTagsStrings[i]) && (NDNProtocolDTagsStrings[i] == tagName)) {
			return i;
		}
	}
	if (NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT == tagName) {
		return NDNProtocolDTags.NDNProtocolDataUnit;
	}
	return null;
};

/**
 * @constructor
 */
var BinaryXMLDecoder = function BinaryXMLDecoder(input){
	var MARK_LEN=512;
	var DEBUG_MAX_LEN =  32768;
	
	this.input = input;
	this.offset = 0;
};

BinaryXMLDecoder.prototype.initializeDecoding = function() {
		//if (!this.input.markSupported()) {
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
		
			//TypeAndVal 
			var tv = this.decodeTypeAndVal();
			
			if (null == tv) {
				throw new ContentDecodingException(new Error("Expected start element: " + startTag + " got something not a tag."));
			}
			
			//String 
			var decodedTag = null;
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
				console.log('expecting '+ startTag + ' but got '+ decodedTag);
				throw new ContentDecodingException(new Error("Expected start element: " + startTag + " got: " + decodedTag + "(" + tv.val() + ")"));
			}
			
			// DKS: does not read attributes out of stream if caller doesn't
			// ask for them. Should possibly peek and skip over them regardless.
			// TODO: fix this
			if (null != attributes) {
				readAttributes(attributes); 
			}
	}
	

BinaryXMLDecoder.prototype.readAttributes = function(
	// array of [attributeName, attributeValue] 
	attributes) {
	
	if (null == attributes) {
		return;
	}

	try {
		// Now need to get attributes.
		//TypeAndVal 
		var nextTV = this.peekTypeAndVal();

		while ((null != nextTV) && ((XML_ATTR == nextTV.type()) ||
				(XML_DATTR == nextTV.type()))) {

			// Decode this attribute. First, really read the type and value.
			//this.TypeAndVal 
			var thisTV = this.decodeTypeAndVal();

			//String 
			var attributeName = null;
			if (XML_ATTR == thisTV.type()) {
				// Tag value represents length-1 as attribute names cannot be empty.
				var valval ;
				if(typeof thisTV.val() == 'string'){
					valval = (parseInt(thisTV.val())) + 1;
				}
				else
					valval = (thisTV.val())+ 1;
				
				attributeName = this.decodeUString(valval);

			} else if (XML_DATTR == thisTV.type()) {
				// DKS TODO are attributes same or different dictionary?
				attributeName = tagToString(thisTV.val());
				if (null == attributeName) {
					throw new ContentDecodingException(new Error("Unknown DATTR value" + thisTV.val()));
				}
			}
			// Attribute values are always UDATA
			//String
			var attributeValue = this.decodeUString();

			//
			attributes.push([attributeName, attributeValue]);

			nextTV = this.peekTypeAndVal();
		}
	} catch ( e) {
		throw new ContentDecodingException(new Error("readStartElement", e));
	}
};

//returns a string
BinaryXMLDecoder.prototype.peekStartElementAsString = function() {
	//this.input.mark(MARK_LEN);

	//String 
	var decodedTag = null;
	var previousOffset = this.offset;
	try {
		// Have to distinguish genuine errors from wrong tags. Could either use
		// a special exception subtype, or redo the work here.
		//this.TypeAndVal 
		var tv = this.decodeTypeAndVal();

		if (null != tv) {

			if (tv.type() == XML_TAG) {
				/*if (tv.val()+1 > DEBUG_MAX_LEN) {
					throw new ContentDecodingException(new Error("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!")(;
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
			throw new ContentDecodingException(new Error("Cannot reset stream! " + e.getMessage(), e));
		}
	}
	return decodedTag;
};

BinaryXMLDecoder.prototype.peekStartElement = function(
		//String 
		startTag) {
	//String 
	if(typeof startTag == 'string'){
		var decodedTag = this.peekStartElementAsString();
		
		if ((null !=  decodedTag) && decodedTag == startTag) {
			return true;
		}
		return false;
	}
	else if(typeof startTag == 'number'){
		var decodedTag = this.peekStartElementAsLong();
		if ((null !=  decodedTag) && decodedTag == startTag) {
			return true;
		}
		return false;
	}
	else{
		throw new ContentDecodingException(new Error("SHOULD BE STRING OR NUMBER"));
	}
}
//returns Long
BinaryXMLDecoder.prototype.peekStartElementAsLong = function() {
		//this.input.mark(MARK_LEN);

		//Long
		var decodedTag = null;
		
		var previousOffset = this.offset;
		
		try {
			// Have to distinguish genuine errors from wrong tags. Could either use
			// a special exception subtype, or redo the work here.
			//this.TypeAndVal
			var tv = this.decodeTypeAndVal();

			if (null != tv) {

				if (tv.type() == XML_TAG) {
					if (tv.val()+1 > DEBUG_MAX_LEN) {
						throw new ContentDecodingException(new Error("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!"));
					}

					var valval ;
					if(typeof tv.val() == 'string'){
						valval = (parseInt(tv.val())) + 1;
					}
					else
						valval = (tv.val())+ 1;
					
					// Tag value represents length-1 as tags can never be empty.
					//String 
					var strTag = this.decodeUString(valval);
					
					decodedTag = stringToTag(strTag);
					
					//Log.info(Log.FAC_ENCODING, "Unexpected: got text tag in peekStartElement; length: " + valval + " decoded tag = " + decodedTag);
					
				} else if (tv.type() == XML_DTAG) {
					decodedTag = tv.val();					
				}

			} // else, not a type and val, probably an end element. rewind and return false.

		} catch ( e) {
			
		} finally {
			try {
				//this.input.reset();
				this.offset = previousOffset;
			} catch ( e) {
				Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
				throw new Error("Cannot reset stream! " + e.getMessage(), e);
			}
		}
		return decodedTag;
	};


// Returns a Uint8Array.
BinaryXMLDecoder.prototype.readBinaryElement = function(
		//long 
		startTag,
		//TreeMap<String, String> 
		attributes,
		//boolean
		allowNull){
	this.readStartElement(startTag, attributes);
	return this.readBlob(allowNull);	
};
	
	
BinaryXMLDecoder.prototype.readEndElement = function(){
			if(LOG>4)console.log('this.offset is '+this.offset);
			
			var next = this.input[this.offset]; 
			
			this.offset++;
			//read();
			
			if(LOG>4)console.log('XML_CLOSE IS '+XML_CLOSE);
			if(LOG>4)console.log('next is '+next);
			
			if (next != XML_CLOSE) {
				console.log("Expected end element, got: " + next);
				throw new ContentDecodingException(new Error("Expected end element, got: " + next));
			}
	};


//String	
BinaryXMLDecoder.prototype.readUString = function(){
			//String 
			var ustring = this.decodeUString();	
			this.readEndElement();
			return ustring;

	};
	

/**
 * Read a blob as well as the end element. Returns a Uint8Array (or null for missing blob).
 * If the blob is missing and allowNull is false (default), throw an exception.  Otherwise,
 *   just read the end element and return null.
 */
BinaryXMLDecoder.prototype.readBlob = function(allowNull) {
    if (this.input[this.offset] == XML_CLOSE && allowNull) {
        this.readEndElement();
        return null;
    }
    
	var blob = this.decodeBlob();	
	this.readEndElement();
	return blob;
};


//NDNTime
BinaryXMLDecoder.prototype.readDateTime = function(
	//long 
	startTag)  {
	//byte [] 
	
	var byteTimestamp = this.readBinaryElement(startTag);

	//var lontimestamp = DataUtils.byteArrayToUnsignedLong(byteTimestamp);

	byteTimestamp = DataUtils.toHex(byteTimestamp);
	
	
	byteTimestamp = parseInt(byteTimestamp, 16);

	var lontimestamp = (byteTimestamp/ 4096) * 1000;

	//if(lontimestamp<0) lontimestamp =  - lontimestamp;

	if(LOG>4) console.log('DECODED DATE WITH VALUE');
	if(LOG>4) console.log(lontimestamp);
	

	//NDNTime 
	var timestamp = new NDNTime(lontimestamp);
	//timestamp.setDateBinary(byteTimestamp);
	
	if (null == timestamp) {
		throw new ContentDecodingException(new Error("Cannot parse timestamp: " + DataUtils.printHexBytes(byteTimestamp)));
	}		
	return timestamp;
};

BinaryXMLDecoder.prototype.decodeTypeAndVal = function() {
	
	/*int*/var type = -1;
	/*long*/var val = 0;
	/*boolean*/var more = true;

	do {
		
		var next = this.input[this.offset ];
		if (next == null)
      // Quit the loop.
      return null; 
		
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
	
	if(LOG>4)console.log('TYPE is '+ type + ' VAL is '+ val);

	return new TypeAndVal(type, val);
};

//TypeAndVal
BinaryXMLDecoder.prototype.peekTypeAndVal = function() {
	//TypeAndVal 
	var tv = null;
	var previousOffset = this.offset;
	
	try {
		tv = this.decodeTypeAndVal();
	} finally {
		this.offset = previousOffset;
	}
	
	return tv;
};

//Uint8Array
BinaryXMLDecoder.prototype.decodeBlob = function(
		//int 
		blobLength) {
	
	if(null == blobLength){
		//TypeAndVal
		var tv = this.decodeTypeAndVal();

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
	//Uint8Array
	var bytes = this.input.subarray(this.offset, this.offset+ blobLength);
	this.offset += blobLength;
	
	return bytes;
};

//String
BinaryXMLDecoder.prototype.decodeUString = function(
		//int 
		byteLength) {
	if(null == byteLength ){
		var tempStreamPosition = this.offset;
			
		//TypeAndVal 
		var tv = this.decodeTypeAndVal();
		
		if(LOG>4)console.log('TV is '+tv);
		if(LOG>4)console.log(tv);
		
		if(LOG>4)console.log('Type of TV is '+typeof tv);
	
		if ((null == tv) || (XML_UDATA != tv.type())) { // if we just have closers left, will get back null
			//if (Log.isLoggable(Log.FAC_ENCODING, Level.FINEST))
				//Log.finest(Log.FAC_ENCODING, "Expected UDATA, got " + ((null == tv) ? " not a tag " : tv.type()) + ", assuming elided 0-length blob.");
			
			this.offset = tempStreamPosition;
			
			return "";
		}
			
		return this.decodeUString(tv.val());
	}
	else{
		//uint8array 
		var stringBytes = this.decodeBlob(byteLength);
		
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

BinaryXMLDecoder.prototype.readIntegerElement =function(
	//String 
	startTag) {

	//String 
	if(LOG>4) console.log('READING INTEGER '+ startTag);
	if(LOG>4) console.log('TYPE OF '+ typeof startTag);
	
	var strVal = this.readUTF8Element(startTag);
	
	return parseInt(strVal);
};

BinaryXMLDecoder.prototype.readUTF8Element =function(
			//String 
			startTag,
			//TreeMap<String, String> 
			attributes) {
			//throws Error where name == "ContentDecodingException" 

		this.readStartElement(startTag, attributes); // can't use getElementText, can't get attributes
		//String 
		var strElementText = this.readUString();
		return strElementText;
};

/**
 * Set the offset into the input, used for the next read.
 */
BinaryXMLDecoder.prototype.seek = function(
        //int
        offset) {
    this.offset = offset;
}

/*
 * Call with: throw new ContentDecodingException(new Error("message")).
 */
function ContentDecodingException(error) {
    this.message = error.message;
    // Copy lineNumber, etc. from where new Error was called.
    for (var prop in error)
        this[prop] = error[prop];
}
ContentDecodingException.prototype = new Error();
ContentDecodingException.prototype.name = "ContentDecodingException";

/**
 * This class uses BinaryXMLDecoder to follow the structure of a ndnb binary element to 
 * determine its end.
 * 
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

/**
 * @constructor
 */
var BinaryXMLStructureDecoder = function BinaryXMLDecoder() {
    this.gotElementEnd = false;
    this.offset = 0;
    this.level = 0;
    this.state = BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE;
    this.headerLength = 0;
    this.useHeaderBuffer = false;
    this.headerBuffer = new DynamicUint8Array(5);
    this.nBytesToRead = 0;
};

BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE = 0;
BinaryXMLStructureDecoder.READ_BYTES = 1;

/**
 * Continue scanning input starting from this.offset.  If found the end of the element
 *   which started at offset 0 then return true, else false.
 * If this returns false, you should read more into input and call again.
 * You have to pass in input each time because the array could be reallocated.
 * This throws an exception for badly formed ndnb.
 */
BinaryXMLStructureDecoder.prototype.findElementEnd = function(
    // Uint8Array
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
                if (this.headerLength == 0 && input[this.offset] == XML_CLOSE) {
                    ++this.offset;
                    // Close the level.
                    --this.level;
                    if (this.level == 0) {
                        // Finished.
                        this.gotElementEnd = true;
                        return true;
                    }
                    if (this.level < 0)
                        throw new Error("BinaryXMLStructureDecoder: Unexpected close tag at offset " +
                            (this.offset - 1));
                    
                    // Get ready for the next header.
                    this.startHeader();
                    break;
                }
                
                var startingHeaderLength = this.headerLength;
                while (true) {
                    if (this.offset >= input.length) {
                        // We can't get all of the header bytes from this input. Save in headerBuffer.
                        this.useHeaderBuffer = true;
                        var nNewBytes = this.headerLength - startingHeaderLength;
                        this.headerBuffer.set
                            (input.subarray(this.offset - nNewBytes, nNewBytes), startingHeaderLength);
                        
                        return false;
                    }
                    var headerByte = input[this.offset++];
                    ++this.headerLength;
                    if (headerByte & XML_TT_NO_MORE)
                        // Break and read the header.
                        break;
                }
                
                var typeAndVal;
                if (this.useHeaderBuffer) {
                    // Copy the remaining bytes into headerBuffer.
                    nNewBytes = this.headerLength - startingHeaderLength;
                    this.headerBuffer.set
                        (input.subarray(this.offset - nNewBytes, nNewBytes), startingHeaderLength);

                    typeAndVal = new BinaryXMLDecoder(this.headerBuffer.array).decodeTypeAndVal();
                }
                else {
                    // We didn't have to use the headerBuffer.
                    decoder.seek(this.offset - this.headerLength);
                    typeAndVal = decoder.decodeTypeAndVal();
                }
                
                if (typeAndVal == null)
                    throw new Error("BinaryXMLStructureDecoder: Can't read header starting at offset " +
                        (this.offset - this.headerLength));
                
                // Set the next state based on the type.
                var type = typeAndVal.t;
                if (type == XML_DATTR)
                    // We already consumed the item. READ_HEADER_OR_CLOSE again.
                    // ndnb has rules about what must follow an attribute, but we are just scanning.
                    this.startHeader();
                else if (type == XML_DTAG || type == XML_EXT) {
                    // Start a new level and READ_HEADER_OR_CLOSE again.
                    ++this.level;
                    this.startHeader();
                }
                else if (type == XML_TAG || type == XML_ATTR) {
                    if (type == XML_TAG)
                        // Start a new level and read the tag.
                        ++this.level;
                    // Minimum tag or attribute length is 1.
                    this.nBytesToRead = typeAndVal.v + 1;
                    this.state = BinaryXMLStructureDecoder.READ_BYTES;
                    // ndnb has rules about what must follow an attribute, but we are just scanning.
                }
                else if (type == XML_BLOB || type == XML_UDATA) {
                    this.nBytesToRead = typeAndVal.v;
                    this.state = BinaryXMLStructureDecoder.READ_BYTES;
                }
                else
                    throw new Error("BinaryXMLStructureDecoder: Unrecognized header type " + type);
                break;
            
            case BinaryXMLStructureDecoder.READ_BYTES:
                var nRemainingBytes = input.length - this.offset;
                if (nRemainingBytes < this.nBytesToRead) {
                    // Need more.
                    this.offset += nRemainingBytes;
                    this.nBytesToRead -= nRemainingBytes;
                    return false;
                }
                // Got the bytes.  Read a new header or close.
                this.offset += this.nBytesToRead;
                this.startHeader();
                break;
            
            default:
                // We don't expect this to happen.
                throw new Error("BinaryXMLStructureDecoder: Unrecognized state " + this.state);
        }
    }
};

/**
 * Set the state to READ_HEADER_OR_CLOSE and set up to start reading the header
 */
BinaryXMLStructureDecoder.prototype.startHeader = function() {
  this.headerLength = 0;
  this.useHeaderBuffer = false;
  this.state = BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE;    
}

/**
 *  Set the offset into the input, used for the next read.
 */
BinaryXMLStructureDecoder.prototype.seek = function(offset) {
  this.offset = offset;
}
/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * This class represents Interest Objects
 */

/**
 * Create a WireFormat base class where the encode and decode methods throw an error. You should use a derived class like BinaryXmlWireFormat.
 * @constructor
 */
var WireFormat = function WireFormat() {
};

/**
 * The override method in the derived class should encode the interest and return a Uint8Array.
 * @param {Interest} interest
 * @returns {UInt8Array}
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeInterest = function(interest) {
  throw new Error("encodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * The override method in the derived class should decode the input and put the result in interest.
 * @param {Interest} interest
 * @param {Uint8Array} input
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeInterest = function(interest, input) {
  throw new Error("decodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * The override method in the derived class should encode the contentObject and return a Uint8Array. 
 * @param {ContentObject} contentObject
 * @returns {Uint8Array}
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeContentObject = function(contentObject) {
  throw new Error("encodeContentObject is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * The override method in the derived class should decode the input and put the result in contentObject.
 * @param {ContentObject} contentObject
 * @param {Uint8Array} input
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeContentObject = function(contentObject, input) {
  throw new Error("decodeContentObject is unimplemented in the base WireFormat class.  You should use a derived class.");
};


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
/**
 * This class contains utilities to help parse the data
 * author: Meki Cheraoui, Jeff Thompson
 * See COPYING for copyright and distribution information.
 */
 
/**
 * A DataUtils has static methods for converting data.
 * @constructor
 */
var DataUtils = function DataUtils(){
};


/*
 * NOTE THIS IS CURRENTLY NOT BEING USED
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
     //input = escape(input);
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

     return output;
  };

/**
 * Uint8Array to Hex String
 */
//http://ejohn.org/blog/numbers-hex-and-colors/
DataUtils.toHex = function(args){
	if (LOG>4) console.log('ABOUT TO CONVERT '+ args);
	//console.log(args);
  	var ret = "";
  	for ( var i = 0; i < args.length; i++ )
    	ret += (args[i] < 16 ? "0" : "") + args[i].toString(16);
  	if (LOG>4) console.log('Converted to: ' + ret);
  	return ret; //.toUpperCase();
}

/**
 * Raw string to hex string.
 */
DataUtils.stringToHex = function(args){
	var ret = "";
	for (var i = 0; i < args.length; ++i) {
		var value = args.charCodeAt(i);
		ret += (value < 16 ? "0" : "") + value.toString(16);
	}
	return ret;
}

/**
 * Uint8Array to raw string.
 */
DataUtils.toString = function(args){
  //console.log(arguments);
  var ret = "";
  for ( var i = 0; i < args.length; i++ )
    ret += String.fromCharCode(args[i]);
  return ret;
}

/**
 * Hex String to Uint8Array.
 */
DataUtils.toNumbers = function(str) {
	if (typeof str == 'string') {
		var ret = new Uint8Array(Math.floor(str.length / 2));
        var i = 0;
		str.replace(/(..)/g, function(str) {
		    ret[i++] = parseInt(str, 16);
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
 * Raw String to Uint8Array.
 */
DataUtils.toNumbersFromString = function(str) {
	var bytes = new Uint8Array(str.length);
	for(var i=0;i<str.length;i++)
		bytes[i] = str.charCodeAt(i);
	return bytes;
}

/**
 * Encode str as utf8 and return as Uint8Array.
 * TODO: Use TextEncoder when available.
 */
DataUtils.stringToUtf8Array = function(str) {
    return DataUtils.toNumbersFromString(str2rstr_utf8(str));
}

/**
 * arrays is an array of Uint8Array. Return a new Uint8Array which is the concatenation of all.
 */
DataUtils.concatArrays = function(arrays) {
    var totalLength = 0;
	for (var i = 0; i < arrays.length; ++i)
        totalLength += arrays[i].length;
    
    var result = new Uint8Array(totalLength);
    var offset = 0;
	for (var i = 0; i < arrays.length; ++i) {
        result.set(arrays[i], offset);
        offset += arrays[i].length;
    }
    return result;
    
}
 
// TODO: Take Uint8Array and use TextDecoder when available.
DataUtils.decodeUtf8 = function (utftext) {
		var string = "";
		var i = 0;
		var c = 0;
        var c1 = 0;
        var c2 = 0;
 
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
				var c3 = utftext.charCodeAt(i+2);
				string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
				i += 3;
			}
 
		}
 
		return string;
	};

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
};

/**
 * Convert the big endian Uint8Array to an unsigned int.
 * Don't check for overflow.
 */
DataUtils.bigEndianToUnsignedInt = function(bytes) {
    var result = 0;
    for (var i = 0; i < bytes.length; ++i) {
        result <<= 8;
        result += bytes[i];
    }
    return result;
};

/**
 * Convert the int value to a new big endian Uint8Array and return.
 * If value is 0 or negative, return Uint8Array(0). 
 */
DataUtils.nonNegativeIntToBigEndian = function(value) {
    value = Math.round(value);
    if (value <= 0)
        return new Uint8Array(0);
    
    // Assume value is not over 64 bits.
    var size = 8;
    var result = new Uint8Array(size);
    var i = 0;
    while (value != 0) {
        ++i;
        result[size - i] = value & 0xff;
        value >>= 8;
    }
    return result.subarray(size - i, size);
};

/**
 * Modify array to randomly shuffle the elements.
 */
DataUtils.shuffle = function(array) {
    for (var i = array.length - 1; i >= 1; --i) {
        // j is from 0 to i.
        var j = Math.floor(Math.random() * (i + 1));
        var temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
};
/**
 * This file contains utilities to help encode and decode NDN objects.
 * author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 */

function encodeToHexInterest(interest){
  return DataUtils.toHex(interest.encode());
}

/**
 * @deprecated Use interest.encode().
 */
function encodeToBinaryInterest(interest) {
  return interest.encode();
}

function encodeToHexContentObject(contentObject) {
  return DataUtils.toHex(contentObject.encode());
}

/**
 * @deprecated Use contentObject.encode().
 */
function encodeToBinaryContentObject(contentObject) {
  return contentObject.encode();
}

function encodeForwardingEntry(co) {
	var enc = new BinaryXMLEncoder();
 
	co.to_ndnb(enc);
	
	var bytes = enc.getReducedOstream();

	return bytes;

	
}



function decodeHexFaceInstance(result){
	
	var numbers = DataUtils.toNumbers(result);
			
	
	var decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODING HEX FACE INSTANCE  \n'+numbers);

	var faceInstance = new FaceInstance();

	faceInstance.from_ndnb(decoder);

	return faceInstance;
	
}

function decodeHexInterest(input){
	var interest = new Interest();
	interest.decode(DataUtils.toNumbers(input));
	return interest;
}

function decodeHexContentObject(input){
	var contentObject = new ContentObject();
	contentObject.decode(DataUtils.toNumbers(input));
	return contentObject;
}

function decodeHexForwardingEntry(result){
	var numbers = DataUtils.toNumbers(result);

	var decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODED HEX FORWARDING ENTRY \n'+numbers);
	
	var forwardingEntry = new ForwardingEntry();

	forwardingEntry.from_ndnb(decoder);

	return forwardingEntry;
	
}

/**
 * Decode the Uint8Array which holds SubjectPublicKeyInfo and return an RSAKey.
 */
function decodeSubjectPublicKeyInfo(array) {
    var hex = DataUtils.toHex(array).toLowerCase();
    var a = _x509_getPublicKeyHexArrayFromCertHex(hex, _x509_getSubjectPublicKeyPosFromCertHex(hex, 0));
    var rsaKey = new RSAKey();
    rsaKey.setPublic(a[0], a[1]);
    return rsaKey;
}

/**
 * Return a user friendly HTML string with the contents of co.
 * This also outputs to console.log.
 */
function contentObjectToHtml(/* ContentObject */ co) {
    var output ="";
			
    if(co==-1)
	output+= "NO CONTENT FOUND"
    else if (co==-2)
	output+= "CONTENT NAME IS EMPTY"
    else{
	if(co.name!=null && co.name.components!=null){
	    output+= "NAME: " + co.name.to_uri();
        
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
	if(co.signature !=null && co.signature.digestAlgorithm!=null){
	    output += "DigestAlgorithm (hex): "+ DataUtils.toHex(co.signature.digestAlgorithm);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signature !=null && co.signature.witness!=null){
	    output += "Witness (hex): "+ DataUtils.toHex(co.signature.witness);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signature !=null && co.signature.signature!=null){
	    output += "Signature(hex): "+ DataUtils.toHex(co.signature.signature);
	    
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
	    var certificateHex = DataUtils.toHex(co.signedInfo.locator.certificate).toLowerCase();
	    var signature = DataUtils.toHex(co.signature.signature).toLowerCase();
	    var input = DataUtils.toString(co.rawSignatureData);
	    
	    output += "Hex Certificate: "+ certificateHex ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    var x509 = new X509();
	    x509.readCertHex(certificateHex);
	    output += "Public key (hex) modulus: " + x509.subjectPublicKeyRSA.n.toString(16) + "<br/>";
	    output += "exponent: " + x509.subjectPublicKeyRSA.e.toString(16) + "<br/>";
	    output += "<br/>";
	    
	    var result = x509.subjectPublicKeyRSA.verifyByteArray(co.rawSignatureData, null, signature);
	    if(LOG>2) console.log('result is '+result);
	    
	    var n = x509.subjectPublicKeyRSA.n;
	    var e =  x509.subjectPublicKeyRSA.e;
	    
	    if(LOG>2) console.log('PUBLIC KEY n after is ');
	    if(LOG>2) console.log(n);

	    if(LOG>2) console.log('EXPONENT e after is ');
	    if(LOG>2) console.log(e);
	    
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
	    var publickeyHex = DataUtils.toHex(co.signedInfo.locator.publicKey).toLowerCase();
	    var publickeyString = DataUtils.toString(co.signedInfo.locator.publicKey);
	    var signature = DataUtils.toHex(co.signature.signature).toLowerCase();
	    var input = DataUtils.toString(co.rawSignatureData);
	    
	    var wit = null;
	    var witHex = "";
		if (co.signature.Witness != null) {
			wit = new Witness();
			wit.decode(co.signature.Witness);
			witHex = DataUtils.toHex(co.signature.Witness);
		}
	    
	    output += "Public key: " + publickeyHex;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    if(LOG>2) console.log(" ContentName + SignedInfo + Content = "+input);
	    if(LOG>2) console.log(" PublicKeyHex = "+publickeyHex );
	    if(LOG>2) console.log(" PublicKeyString = "+publickeyString );
	    
	    if(LOG>2) console.log(" Signature "+signature );
	    if(LOG>2) console.log(" Witness "+witHex );
	    
	    if(LOG>2) console.log(" Signature NOW IS" );
	    
	    if(LOG>2) console.log(co.signature.signature);
	   
	    var rsakey = decodeSubjectPublicKeyInfo(co.signedInfo.locator.publicKey);

	    output += "Public key (hex) modulus: " + rsakey.n.toString(16) + "<br/>";
	    output += "exponent: " + rsakey.e.toString(16) + "<br/>";
	    output += "<br/>";
	   	    
	    var result = rsakey.verifyByteArray(co.rawSignatureData, wit, signature);
	    // var result = rsakey.verifyString(input, signature);
	    
	    if(LOG>2) console.log('PUBLIC KEY n after is ');
	    if(LOG>2) console.log(rsakey.n);

	    if(LOG>2) console.log('EXPONENT e after is ');
	    if(LOG>2) console.log(rsakey.e);
	    
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


/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 */

/**
 * @constructor
 */
var KeyManager = function KeyManager(){

	
//Certificate

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
//Private Key

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


/** 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

/**
 * @constructor
 */
var MerklePath = function MerkelPath() {
	this.index = null;  // int
	this.digestList = [];  // array of hex string
};

/**
 * @constructor
 */
var Witness = function Witness() {
	this.oid = null;  // string
	this.path = new MerklePath();  // MerklePath
};

function parseOID(bytes, start, end) {
    var s, n = 0, bits = 0;
    for (var i = start; i < end; ++i) {
        var v = bytes[i];
        n = (n << 7) | (v & 0x7F);
        bits += 7;
        if (!(v & 0x80)) { // finished
            if (s == undefined)
                s = parseInt(n / 40) + "." + (n % 40);
            else
                s += "." + ((bits >= 31) ? "bigint" : n);
            n = bits = 0;
        }
        s += String.fromCharCode();
    }
    return s;
}

function parseInteger(bytes, start, end) {
    var n = 0;
    for (var i = start; i < end; ++i)
        n = (n << 8) | bytes[i];
    return n;
}

Witness.prototype.decode = function(/* Uint8Array */ witness) {
	/* The asn1.js decoder has some bug and 
	 * cannot decode certain kind of witness.
	 * So we use an alternative (and dirty) hack
	 * to read witness from byte streams
	 *      ------Wentao
	 */
	/*
	var wit = DataUtils.toHex(witness).toLowerCase();
	try {
		var der = Hex.decode(wit);
		var asn1 = ASN1.decode(der);
	}
	catch (e) {
		console.log(e);
		console.log(wit);
	}
	//console.log(asn1.toPrettyString());
	
	this.oid = asn1.sub[0].sub[0].content();  // OID
	//console.log(this.oid);
	this.path.index = asn1.sub[1].sub[0].sub[0].content();  // index
	//console.log(this.path.index);
	for (i = 0; i < asn1.sub[1].sub[0].sub[1].sub.length; i++) {
		pos = asn1.sub[1].sub[0].sub[1].sub[i].stream.pos;
		str = wit.substring(2 * pos + 4, 2 * pos + 68);
		this.path.digestList.push(str);  // digest hex string
		//console.log(str);
	}
	*/
	
	// FIXME: Need to be fixed to support arbitrary ASN1 encoding,
	// But do we really nned that????  -------Wentao
	
	// The structure of Witness is fixed as follows:
	// SEQUENCE  (2 elem)
	//   SEQUENCE  (1 elem)
	//     OBJECT IDENTIFIER  1.2.840.113550.11.1.2.2
	//   OCTET STRING  (1 elem)
	//     SEQUENCE  (2 elem)
	//       INTEGER  index
	//       SEQUENCE  (n elem)
	//         OCTET STRING(32 byte) 345FB4B5E9A1D2FF450ECA87EB87601683027A1A...
	//         OCTET STRING(32 byte) DBCEE5B7A6C2B851B029324197DDBD9A655723DC...
	//         OCTET STRING(32 byte) 4C79B2D256E4CD657A27F01DCB51AC3C56A24E71...
	//         OCTET STRING(32 byte) 7F7FB169604A87EAC94378F0BDB4FC5D5899AB88...
	//         ......
	// Hence we can follow this structure to extract witness fields at fixed level
	// Tag numbers for ASN1:
	//    SEQUENCE            0x10
	//    OCT STRING          0x04
	//    INTEGER             0x02
	//    OBJECT IDENTIFIER   0x06
	var i = 0;
	var step = 0;  // count of sequence tag
	while (i < witness.length) {
		var len = 0;
		
		if (witness[i] == 0x30) {
			// Sequence (constructed)
			// There is no primitive sequence in Witness
			if ((witness[i + 1] & 0x80) != 0) {
				len = witness[i+1] & 0x7F;
			}
			step++;
		} else if (witness[i] == 0x06) {
			// Decode OID
			len = witness[i+1];  // XXX: OID will not be longer than 127 bytes
			this.oid = parseOID(witness, i + 2, i + 2 + len);
			//console.log(this.oid);
		} else if (witness[i] == 0x02) {
			// Decode node index
			len = witness[i+1];  // XXX: index will not be longer than 127 bytes
			this.path.index = parseInteger(witness, i + 2, i + 2 + len);
			//console.log(this.path.index);
		} else if (witness[i] == 0x04) {
			if ((witness[i + 1] & 0x80) != 0) {
				len = witness[i+1] & 0x7F;
			}
			if (step == 4) {
				// Start to decode digest hex string
				len = witness[i+1];  // XXX: digest hex should always be 32 bytes
				var str = DataUtils.toHex(witness.subarray(i + 2, i + 2 + len));
				this.path.digestList.push(str);  // digest hex string
				//console.log(str);
			}
		}
		i = i + 2 + len;
	}
};
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
  //console.log('Raw string comming is '+input);
  var output = Array(input.length >> 2);
  /* JavaScript automatically zeroizes a new array.
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
   */
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
	//console.log("Byte array coming is " + input);
	var output = Array(input.length >> 2);
      /* JavaScript automatically zeroizes a new array.
	  for(var i = 0; i < output.length; i++)
	    output[i] = 0;
       */
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

  /* append padding */
  m[l >> 5] |= 0x80 << (24 - l % 32);
  m[((l + 64 >> 9) << 4) + 15] = l;
 
  for(var offset = 0; offset < m.length; offset += 16)
    processBlock_sha256(m, offset, HASH, W);

  return HASH;
}

/*
 * Process a block of 16 4-byte words in m starting at offset and update HASH.  
 * offset must be a multiple of 16 and less than m.length.  W is a scratchpad Array(64).
 */
function processBlock_sha256(m, offset, HASH, W) {
    var a, b, c, d, e, f, g, h;
    var j, T1, T2;
    
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
      if (j < 16) W[j] = m[j + offset];
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

function safe_add (x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Create a Sha256, call update(data) multiple times, then call finalize().
 */
var Sha256 = function Sha256() {
    this.W = new Array(64);
    this.hash = new Array(1779033703, -1150833019, 1013904242, -1521486534,
                          1359893119, -1694144372, 528734635, 1541459225);
    this.nTotalBytes = 0;
    this.buffer = new Uint8Array(16 * 4);
    this.nBufferBytes = 0;
}

/*
 * Update the hash with data, which is Uint8Array.
 */
Sha256.prototype.update = function(data) {
    this.nTotalBytes += data.length;
    
    if (this.nBufferBytes > 0) {
        // Fill up the buffer and process it first.
        var bytesNeeded = this.buffer.length - this.nBufferBytes;
        if (data.length < bytesNeeded) {
            this.buffer.set(data, this.nBufferBytes);
            this.nBufferBytes += data.length;
            return;
        }
        else {
            this.buffer.set(data.subarray(0, bytesNeeded), this.nBufferBytes);
            processBlock_sha256(byteArray2binb(this.buffer), 0, this.hash, this.W);
            this.nBufferBytes = 0;
            // Consume the bytes from data.
            data = data.subarray(bytesNeeded, data.length);
            if (data.length == 0)
                return;
        }
    }
    
    // 2^6 is 16 * 4.
    var nBlocks = data.length >> 6;
    if (nBlocks > 0) {
        var nBytes = nBlocks * 16 * 4;
        var m = byteArray2binb(data.subarray(0, nBytes));
        for(var offset = 0; offset < m.length; offset += 16)
            processBlock_sha256(m, offset, this.hash, this.W);

        data = data.subarray(nBytes, data.length);
    }
    
    if (data.length > 0) {
        // Save the remainder in the buffer.
        this.buffer.set(data);
        this.nBufferBytes = data.length;
    }
}

/*
 * Finalize the hash and return the result as Uint8Array.
 * Only call this once.  Return values on subsequent calls are undefined.
 */
Sha256.prototype.finalize = function() {
    var m = byteArray2binb(this.buffer.subarray(0, this.nBufferBytes));
    /* append padding */
    var l = this.nBufferBytes * 8;
    m[l >> 5] |= 0x80 << (24 - l % 32);
    m[((l + 64 >> 9) << 4) + 15] = this.nTotalBytes * 8;

    for(var offset = 0; offset < m.length; offset += 16)
        processBlock_sha256(m, offset, this.hash, this.W);

    return Sha256.binb2Uint8Array(this.hash);
}

/*
 * Convert an array of big-endian words to Uint8Array.
 */
Sha256.binb2Uint8Array = function(input)
{
    var output = new Uint8Array(input.length * 4);
    var iOutput = 0;
    for (var i = 0; i < input.length * 32; i += 8)
        output[iOutput++] = (input[i>>5] >>> (24 - i % 32)) & 0xFF;
    return output;
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
    var v = b64map.indexOf(s.charAt(i));
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


//@author: Meki Cheraoui
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
function _rsasign_verifyByteArray(byteArray, witness, hSig) {
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
	  var msgHashValue = null;
	  
	  if (witness == null) {
	  	var ff = _RSASIGN_HASHBYTEFUNC[algName];
	  	msgHashValue = ff(byteArray);
	  } else {
	  	// Compute merkle hash
		  var h = hex_sha256_from_bytes(byteArray);
		  var index = witness.path.index;
		  for (var i = witness.path.digestList.length - 1; i >= 0; i--) {
		  	var str = "";
		  	if (index % 2 == 0) {
		  		str = h + witness.path.digestList[i];
		  	} else {
		  		str = witness.path.digestList[i] + h;
		  	}
		  	h = hex_sha256_from_bytes(DataUtils.toNumbers(str));
		  	index = Math.floor(index / 2);
		  }
		  msgHashValue = hex_sha256_from_bytes(DataUtils.toNumbers(h));
	  }
	  //console.log(diHashValue);
	  //console.log(msgHashValue);
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
// If pInfo is supplied, it is the position in hCert of the SubjectPublicKeyInfo.
function _x509_getSubjectPublicKeyPosFromCertHex(hCert, pInfo) {
  if (pInfo == null)
      pInfo = _x509_getSubjectPublicKeyInfoPosFromCertHex(hCert);
  if (pInfo == -1) return -1;    
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pInfo); 
  
  if (a.length != 2) return -1;
  var pBitString = a[1];
  if (hCert.substring(pBitString, pBitString + 2) != '03') return -1;
  var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hCert, pBitString);

  if (hCert.substring(pBitStringV, pBitStringV + 2) != '00') return -1;
  return pBitStringV + 2;
}

// If p is supplied, it is the public key position in hCert.
function _x509_getPublicKeyHexArrayFromCertHex(hCert, p) {
  if (p == null)
      p = _x509_getSubjectPublicKeyPosFromCertHex(hCert);
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

/**
 * read hex formatted X.509 certificate from string.
 * @name readCertHex
 * @memberOf X509#
 * @function
 * @param {String} hCert string for hex formatted X.509 certificate
 */
function _x509_readCertHex(hCert) {
  hCert = hCert.toLowerCase();
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
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
X509.prototype.readCertHex = _x509_readCertHex;
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
/**
 * @author: Meki Cherkaoui, Jeff Thompson, Wentao Shang
 * See COPYING for copyright and distribution information.
 * This class represents the top-level object for communicating with an NDN host.
 */

/**
 * Set this to a higher number to dump more debugging log messages.
 * @type Number
 */
var LOG = 0;

/**
 * Create a new NDN with the given settings.
 * This throws an exception if NDN.supported is false.
 * @constructor
 * @param {Object} settings if not null, an associative array with the following defaults:
 * {
 *   getTransport: function() { return new WebSocketTransport(); },
 *   getHostAndPort: transport.defaultGetHostAndPort, // a function, on each call it returns a new { host: host, port: port } or null if there are no more hosts.
 *   host: null, // If null, use getHostAndPort when connecting.
 *   port: 9696,
 *   onopen: function() { if (LOG > 3) console.log("NDN connection established."); },
 *   onclose: function() { if (LOG > 3) console.log("NDN connection closed."); },
 *   verify: false // If false, don't verify and call upcall with Closure.UPCALL_CONTENT_UNVERIFIED.
 * }
 */
var NDN = function NDN(settings) {
  if (!NDN.supported)
    throw new Error("The necessary JavaScript support is not available on this platform.");
    
  settings = (settings || {});
  var getTransport = (settings.getTransport || function() { return new WebSocketTransport(); });
  this.transport = getTransport();
  this.getHostAndPort = (settings.getHostAndPort || this.transport.defaultGetHostAndPort);
	this.host = (settings.host !== undefined ? settings.host : null);
	this.port = (settings.port || 9696);
  this.readyStatus = NDN.UNOPEN;
  this.verify = (settings.verify !== undefined ? settings.verify : false);
  // Event handler
  this.onopen = (settings.onopen || function() { if (LOG > 3) console.log("NDN connection established."); });
  this.onclose = (settings.onclose || function() { if (LOG > 3) console.log("NDN connection closed."); });
	this.ndndid = null;
};

NDN.UNOPEN = 0;  // created but not opened yet
NDN.OPENED = 1;  // connection to ndnd opened
NDN.CLOSED = 2;  // connection to ndnd closed

/**
 * Return true if necessary JavaScript support is available, else log an error and return false.
 */
NDN.getSupported = function() {
    try {
        var dummy = new Uint8Array(1).subarray(0, 1);
    } catch (ex) {
        console.log("NDN not available: Uint8Array not supported. " + ex);
        return false;
    }
    
    return true;
};

NDN.supported = NDN.getSupported();

NDN.ndndIdFetcher = new Name('/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY');

NDN.prototype.createRoute = function(host, port) {
	this.host=host;
	this.port=port;
};


NDN.KeyStore = new Array();

var KeyStoreEntry = function KeyStoreEntry(name, rsa, time) {
	this.keyName = name;  // KeyName
	this.rsaKey = rsa;    // RSA key
	this.timeStamp = time;  // Time Stamp
};

NDN.addKeyEntry = function(/* KeyStoreEntry */ keyEntry) {
	var result = NDN.getKeyByName(keyEntry.keyName);
	if (result == null) 
		NDN.KeyStore.push(keyEntry);
	else
		result = keyEntry;
};

NDN.getKeyByName = function(/* KeyName */ name) {
	var result = null;
	
	for (var i = 0; i < NDN.KeyStore.length; i++) {
		if (NDN.KeyStore[i].keyName.contentName.match(name.contentName)) {
            if (result == null || 
                NDN.KeyStore[i].keyName.contentName.components.length > result.keyName.contentName.components.length)
                result = NDN.KeyStore[i];
        }
	}
    
	return result;
};

// For fetching data
NDN.PITTable = new Array();

/**
 * @constructor
 */
var PITEntry = function PITEntry(interest, closure) {
	this.interest = interest;  // Interest
	this.closure = closure;    // Closure
	this.timerID = -1;  // Timer ID
};

/**
 * Return the entry from NDN.PITTable where the name conforms to the interest selectors, and
 * the interest name is the longest that matches name.
 */
NDN.getEntryForExpressedInterest = function(/*Name*/ name) {
    var result = null;
    
	for (var i = 0; i < NDN.PITTable.length; i++) {
		if (NDN.PITTable[i].interest.matches_name(name)) {
            if (result == null || 
                NDN.PITTable[i].interest.name.components.length > result.interest.name.components.length)
                result = NDN.PITTable[i];
        }
	}
    
	return result;
};

// For publishing data
NDN.CSTable = new Array();

/**
 * @constructor
 */
var CSEntry = function CSEntry(name, closure) {
	this.name = name;        // String
	this.closure = closure;  // Closure
};

function getEntryForRegisteredPrefix(name) {
	for (var i = 0; i < NDN.CSTable.length; i++) {
		if (NDN.CSTable[i].name.match(name))
			return NDN.CSTable[i];
	}
	return null;
}

/**
 * Return a function that selects a host at random from hostList and returns { host: host, port: port }.
 * If no more hosts remain, return null.
 */
NDN.makeShuffledGetHostAndPort = function(hostList, port) {
    // Make a copy.
    hostList = hostList.slice(0, hostList.length);
    DataUtils.shuffle(hostList);

    return function() {
        if (hostList.length == 0)
            return null;
        
        return { host: hostList.splice(0, 1)[0], port: port };
    };
};

/**
 * Encode name as an Interest and send the it to host:port, read the entire response and call
 *  closure.upcall(Closure.UPCALL_CONTENT (or Closure.UPCALL_CONTENT_UNVERIFIED),
 *                 new UpcallInfo(this, interest, 0, contentObject)). 
 * @param {Name} name
 * @param {Closure} closure
 * @param {Interest} template if not null, use its attributes
 */
NDN.prototype.expressInterest = function (name, closure, template) {
	var interest = new Interest(name);
  if (template != null) {
		interest.minSuffixComponents = template.minSuffixComponents;
		interest.maxSuffixComponents = template.maxSuffixComponents;
		interest.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
		interest.exclude = template.exclude;
		interest.childSelector = template.childSelector;
		interest.answerOriginKind = template.answerOriginKind;
		interest.scope = template.scope;
		interest.interestLifetime = template.interestLifetime;
  }
  else
    interest.interestLifetime = 4000;   // default interest timeout value in milliseconds.

	if (this.host == null || this.port == null) {
        if (this.getHostAndPort == null)
            console.log('ERROR: host OR port NOT SET');
        else {
            var thisNDN = this;
            this.connectAndExecute
                (function() { thisNDN.reconnectAndExpressInterest(interest, closure); });
        }
    }
    else
        this.reconnectAndExpressInterest(interest, closure);
};

/**
 * If the host and port are different than the ones in this.transport, then call
 *   this.transport.connect to change the connection (or connect for the first time).
 * Then call expressInterestHelper.
 */
NDN.prototype.reconnectAndExpressInterest = function(interest, closure) {
    if (this.transport.connectedHost != this.host || this.transport.connectedPort != this.port) {
        var thisNDN = this;
        this.transport.connect(thisNDN, function() { thisNDN.expressInterestHelper(interest, closure); });
    }
    else
        this.expressInterestHelper(interest, closure);
};

/**
 * Do the work of reconnectAndExpressInterest once we know we are connected.  Set the PITTable and call
 *   this.transport.send to send the interest.
 */
NDN.prototype.expressInterestHelper = function(interest, closure) {
    var binaryInterest = encodeToBinaryInterest(interest);
    var thisNDN = this;    
	//TODO: check local content store first
	if (closure != null) {
		var pitEntry = new PITEntry(interest, closure);
        // TODO: This needs to be a single thread-safe transaction on a global object.
		NDN.PITTable.push(pitEntry);
		closure.pitEntry = pitEntry;

        // Set interest timer.
        var timeoutMilliseconds = (interest.interestLifetime || 4000);
        var timeoutCallback = function() {
			if (LOG > 1) console.log("Interest time out: " + interest.name.to_uri());
				
			// Remove PIT entry from NDN.PITTable, even if we add it again later to re-express
            //   the interest because we don't want to match it in the mean time.
            // TODO: Make this a thread-safe operation on the global PITTable.
			var index = NDN.PITTable.indexOf(pitEntry);
			if (index >= 0) 
	            NDN.PITTable.splice(index, 1);
				
			// Raise closure callback
			if (closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, 
                  new UpcallInfo(thisNDN, interest, 0, null)) == Closure.RESULT_REEXPRESS) {
			    if (LOG > 1) console.log("Re-express interest: " + interest.name.to_uri());
                pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
                NDN.PITTable.push(pitEntry);
                thisNDN.transport.send(binaryInterest);
            }
		};
		pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
	}

	this.transport.send(binaryInterest);
};

/**
 * Register name with the connected NDN hub and receive interests with closure.upcall.
 * @param {Name} name
 * @param {Closure} closure
 * @param {number} flag
 */
NDN.prototype.registerPrefix = function(name, closure, flag) {
    var thisNDN = this;
    var onConnected = function() {
    	if (thisNDN.ndndid == null) {
            // Fetch ndndid first, then register.
            var interest = new Interest(NDN.ndndIdFetcher);
    		interest.interestLifetime = 4000; // milliseconds
            if (LOG>3) console.log('Expressing interest for ndndid from ndnd.');
            thisNDN.reconnectAndExpressInterest
               (interest, new NDN.FetchNdndidClosure(thisNDN, name, closure, flag));
        }
        else	
            thisNDN.registerPrefixHelper(name, closure, flag);
    };

	if (this.host == null || this.port == null) {
        if (this.getHostAndPort == null)
            console.log('ERROR: host OR port NOT SET');
        else
            this.connectAndExecute(onConnected);
    }
    else
        onConnected();
};

/**
 * This is a closure to receive the ContentObject for NDN.ndndIdFetcher and call
 *   registerPrefixHelper(name, callerClosure, flag).
 */
NDN.FetchNdndidClosure = function FetchNdndidClosure(ndn, name, callerClosure, flag) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.name = name;
    this.callerClosure = callerClosure;
    this.flag = flag;
};

NDN.FetchNdndidClosure.prototype.upcall = function(kind, upcallInfo) {
    if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
        console.log("Timeout while requesting the ndndid.  Cannot registerPrefix for " +
            this.name.to_uri() + " .");
        return Closure.RESULT_OK;
    }
    if (!(kind == Closure.UPCALL_CONTENT ||
          kind == Closure.UPCALL_CONTENT_UNVERIFIED))
        // The upcall is not for us.
        return Closure.RESULT_ERR;
       
    var co = upcallInfo.contentObject;
    if (!co.signedInfo || !co.signedInfo.publisher 
		|| !co.signedInfo.publisher.publisherPublicKeyDigest)
        console.log
          ("ContentObject doesn't have a publisherPublicKeyDigest. Cannot set ndndid and registerPrefix for "
           + this.name.to_uri() + " .");
    else {
		if (LOG>3) console.log('Got ndndid from ndnd.');
		this.ndn.ndndid = co.signedInfo.publisher.publisherPublicKeyDigest;
		if (LOG>3) console.log(this.ndn.ndndid);
        
        this.ndn.registerPrefixHelper(this.name, this.callerClosure, this.flag);
	}
    
    return Closure.RESULT_OK;
};

/**
 * Do the work of registerPrefix once we know we are connected with a ndndid.
 */
NDN.prototype.registerPrefixHelper = function(name, closure, flag) {
	var fe = new ForwardingEntry('selfreg', name, null, null, 3, 2147483647);
	var bytes = encodeForwardingEntry(fe);
		
	var si = new SignedInfo();
	si.setFields();
		
	var co = new ContentObject(new Name(), si, bytes); 
	co.sign();
	var coBinary = encodeToBinaryContentObject(co);
		
	//var nodename = unescape('%00%88%E2%F4%9C%91%16%16%D6%21%8E%A0c%95%A5%A6r%11%E0%A0%82%89%A6%A9%85%AB%D6%E2%065%DB%AF');
	var nodename = this.ndndid;
	var interestName = new Name(['ndnx', nodename, 'selfreg', coBinary]);

	var interest = new Interest(interestName);
	interest.scope = 1;
	if (LOG > 3) console.log('Send Interest registration packet.');
    	
    var csEntry = new CSEntry(name.getName(), closure);
	NDN.CSTable.push(csEntry);
    
    this.transport.send(encodeToBinaryInterest(interest));
};

/**
 * This is called when an entire binary XML element is received, such as a ContentObject or Interest.
 * Look up in the PITTable and call the closure callback.
 */
NDN.prototype.onReceivedElement = function(element) {
    if (LOG>3) console.log('Complete element received. Length ' + element.length + '. Start decoding.');
	var decoder = new BinaryXMLDecoder(element);
	// Dispatch according to packet type
	if (decoder.peekStartElement(NDNProtocolDTags.Interest)) {  // Interest packet
		if (LOG > 3) console.log('Interest packet received.');
				
		var interest = new Interest();
		interest.from_ndnb(decoder);
		if (LOG > 3) console.log(interest);
		var nameStr = escape(interest.name.getName());
		if (LOG > 3) console.log(nameStr);
				
		var entry = getEntryForRegisteredPrefix(nameStr);
		if (entry != null) {
			//console.log(entry);
			var info = new UpcallInfo(this, interest, 0, null);
			var ret = entry.closure.upcall(Closure.UPCALL_INTEREST, info);
			if (ret == Closure.RESULT_INTEREST_CONSUMED && info.contentObject != null) 
				this.transport.send(encodeToBinaryContentObject(info.contentObject));
		}				
	} else if (decoder.peekStartElement(NDNProtocolDTags.ContentObject)) {  // Content packet
		if (LOG > 3) console.log('ContentObject packet received.');
				
		var co = new ContentObject();
		co.from_ndnb(decoder);
				
		var pitEntry = NDN.getEntryForExpressedInterest(co.name);
		if (pitEntry != null) {
			// Cancel interest timer
			clearTimeout(pitEntry.timerID);
            
			// Remove PIT entry from NDN.PITTable
			var index = NDN.PITTable.indexOf(pitEntry);
			if (index >= 0)
				NDN.PITTable.splice(index, 1);
						
			var currentClosure = pitEntry.closure;
										
			if (this.verify == false) {
				// Pass content up without verifying the signature
				currentClosure.upcall(Closure.UPCALL_CONTENT_UNVERIFIED, new UpcallInfo(this, pitEntry.interest, 0, co));
				return;
			}
				
			// Key verification
						
			// Recursive key fetching & verification closure
			var KeyFetchClosure = function KeyFetchClosure(content, closure, key, sig, wit) {
				this.contentObject = content;  // unverified content object
				this.closure = closure;  // closure corresponding to the contentObject
				this.keyName = key;  // name of current key to be fetched
				this.sigHex = sig;  // hex signature string to be verified
				this.witness = wit;
						
				Closure.call(this);
			};
						
            var thisNDN = this;
			KeyFetchClosure.prototype.upcall = function(kind, upcallInfo) {
				if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
					console.log("In KeyFetchClosure.upcall: interest time out.");
					console.log(this.keyName.contentName.getName());
				} else if (kind == Closure.UPCALL_CONTENT) {
					//console.log("In KeyFetchClosure.upcall: signature verification passed");
								
					var rsakey = decodeSubjectPublicKeyInfo(upcallInfo.contentObject.content);
					var verified = rsakey.verifyByteArray(this.contentObject.rawSignatureData, this.witness, this.sigHex);
								
					var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
					//console.log("raise encapsulated closure");
					this.closure.upcall(flag, new UpcallInfo(thisNDN, null, 0, this.contentObject));
								
					// Store key in cache
					var keyEntry = new KeyStoreEntry(keylocator.keyName, rsakey, new Date().getTime());
					NDN.addKeyEntry(keyEntry);
					//console.log(NDN.KeyStore);
				} else if (kind == Closure.UPCALL_CONTENT_BAD) {
					console.log("In KeyFetchClosure.upcall: signature verification failed");
				}
			};
						
			if (co.signedInfo && co.signedInfo.locator && co.signature) {
				if (LOG > 3) console.log("Key verification...");
				var sigHex = DataUtils.toHex(co.signature.signature).toLowerCase();
							
				var wit = null;
				if (co.signature.Witness != null) {
					wit = new Witness();
					wit.decode(co.signature.Witness);
				}
							
				var keylocator = co.signedInfo.locator;
				if (keylocator.type == KeyLocatorType.KEYNAME) {
					if (LOG > 3) console.log("KeyLocator contains KEYNAME");
					//var keyname = keylocator.keyName.contentName.getName();
					//console.log(nameStr);
					//console.log(keyname);
								
					if (keylocator.keyName.contentName.match(co.name)) {
						if (LOG > 3) console.log("Content is key itself");
									
						var rsakey = decodeSubjectPublicKeyInfo(co.content);
						var verified = rsakey.verifyByteArray(co.rawSignatureData, wit, sigHex);
						var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;

						currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, co));

						// SWT: We don't need to store key here since the same key will be
						//      stored again in the closure.
						//var keyEntry = new KeyStoreEntry(keylocator.keyName, rsakey, new Date().getTime());
						//NDN.addKeyEntry(keyEntry);
						//console.log(NDN.KeyStore);
					} else {
						// Check local key store
						var keyEntry = NDN.getKeyByName(keylocator.keyName);
						if (keyEntry) {
							// Key found, verify now
							if (LOG > 3) console.log("Local key cache hit");
							var rsakey = keyEntry.rsaKey;
							var verified = rsakey.verifyByteArray(co.rawSignatureData, wit, sigHex);
							var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;

							// Raise callback
							currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, co));
						} else {
							// Not found, fetch now
							if (LOG > 3) console.log("Fetch key according to keylocator");
							var nextClosure = new KeyFetchClosure(co, currentClosure, keylocator.keyName, sigHex, wit);
							this.expressInterest(keylocator.keyName.contentName.getPrefix(4), nextClosure);
						}
					}
				} else if (keylocator.type == KeyLocatorType.KEY) {
					if (LOG > 3) console.log("Keylocator contains KEY");
								
					var rsakey = decodeSubjectPublicKeyInfo(co.signedInfo.locator.publicKey);
					var verified = rsakey.verifyByteArray(co.rawSignatureData, wit, sigHex);
							
					var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
					// Raise callback
					currentClosure.upcall(Closure.UPCALL_CONTENT, new UpcallInfo(this, pitEntry.interest, 0, co));

					// Since KeyLocator does not contain key name for this key,
					// we have no way to store it as a key entry in KeyStore.
				} else {
					var cert = keylocator.certificate;
					console.log("KeyLocator contains CERT");
					console.log(cert);
								
					// TODO: verify certificate
				}
			}
		}
	} else
		console.log('Incoming packet is not Interest or ContentObject. Discard now.');
};

/**
 * Assume this.getHostAndPort is not null.  This is called when this.host is null or its host
 *   is not alive.  Get a host and port, connect, then execute onConnected().
 */
NDN.prototype.connectAndExecute = function(onConnected) {
    var hostAndPort = this.getHostAndPort();
    if (hostAndPort == null) {
        console.log('ERROR: No more hosts from getHostAndPort');
        this.host = null;
        return;
    }

    if (hostAndPort.host == this.host && hostAndPort.port == this.port) {
        console.log('ERROR: The host returned by getHostAndPort is not alive: ' + 
                this.host + ":" + this.port);
        return;
    }
        
    this.host = hostAndPort.host;
    this.port = hostAndPort.port;   
    if (LOG>0) console.log("connectAndExecute: trying host from getHostAndPort: " + this.host);
    
    // Fetch any content.
    var interest = new Interest(new Name("/"));
	interest.interestLifetime = 4000; // milliseconds    

    var thisNDN = this;
	var timerID = setTimeout(function() {
        if (LOG>0) console.log("connectAndExecute: timeout waiting for host " + thisNDN.host);
        // Try again.
        thisNDN.connectAndExecute(onConnected);
	}, 3000);
  
    this.reconnectAndExpressInterest
        (interest, new NDN.ConnectClosure(this, onConnected, timerID));
};

NDN.ConnectClosure = function ConnectClosure(ndn, onConnected, timerID) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.onConnected = onConnected;
    this.timerID = timerID;
};

NDN.ConnectClosure.prototype.upcall = function(kind, upcallInfo) {
    if (!(kind == Closure.UPCALL_CONTENT ||
          kind == Closure.UPCALL_CONTENT_UNVERIFIED))
        // The upcall is not for us.
        return Closure.RESULT_ERR;
        
    // The host is alive, so cancel the timeout and continue with onConnected().
    clearTimeout(this.timerID);

    // Call NDN.onopen after success
	this.ndn.readyStatus = NDN.OPENED;
	this.ndn.onopen();

    if (LOG>0) console.log("connectAndExecute: connected to host " + this.ndn.host);
    this.onConnected();

    return Closure.RESULT_OK;
};

/**
 * A BinaryXmlElementReader lets you call onReceivedData multiple times which uses a
 * BinaryXMLStructureDecoder to detect the end of a binary XML element and calls
 * elementListener.onReceivedElement(element) with the element. 
 * This handles the case where a single call to onReceivedData may contain multiple elements.
 * @constructor
 * @param {{onReceivedElement:function}} elementListener
 */
var BinaryXmlElementReader = function BinaryXmlElementReader(elementListener) {
  this.elementListener = elementListener;
	this.dataParts = [];
  this.structureDecoder = new BinaryXMLStructureDecoder();
};

BinaryXmlElementReader.prototype.onReceivedData = function(/* Uint8Array */ data) {
    // Process multiple objects in the data.
    while(true) {
        // Scan the input to check if a whole ndnb object has been read.
        this.structureDecoder.seek(0);
        if (this.structureDecoder.findElementEnd(data)) {
            // Got the remainder of an object.  Report to the caller.
            this.dataParts.push(data.subarray(0, this.structureDecoder.offset));
            var element = DataUtils.concatArrays(this.dataParts);
            this.dataParts = [];
            try {
                this.elementListener.onReceivedElement(element);
            } catch (ex) {
                console.log("BinaryXmlElementReader: ignoring exception from onReceivedElement: " + ex);
            }
        
            // Need to read a new object.
            data = data.subarray(this.structureDecoder.offset, data.length);
            this.structureDecoder = new BinaryXMLStructureDecoder();
            if (data.length == 0)
                // No more data in the packet.
                return;
            
            // else loop back to decode.
        }
        else {
            // Save for a later call to concatArrays so that we only copy data once.
            this.dataParts.push(data);
            if (LOG>3) console.log('Incomplete packet received. Length ' + data.length + '. Wait for more input.');
                return;
        }
    }    
};
