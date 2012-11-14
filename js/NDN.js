/*
 * @author: Meki Cherkaoui, Jeff Thompson, Wentao Shang
 * See COPYING for copyright and distribution information.
 * This class represents the top-level object for communicating with an NDN host.
 */

var LOG = 3;

/**
 * settings is an associative array with the following defaults:
 * {
 *   host: 'localhost',
 *   port: 9696,
 *   getTransport: function() { return new WebSocketTransport(); }
 * }
 */
var NDN = function NDN(settings) {
    settings = (settings || {});
	this.host = (settings.host || "localhost");
	this.port = (settings.port || 9696);
    var getTransport = (settings.getTransport || function() { return new WebSocketTransport(); });
    this.transport = getTransport();    
};


/* Java Socket Bridge and XPCOM transport */

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
        interest.interestLifetime = 4200;
    
    this.transport.expressInterest(this, interest, closure);
};


NDN.prototype.registerPrefix = function(name, closure, flag) {
    return this.transport.registerPrefix(this, name, closure, flag);
}
