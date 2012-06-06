

var lwNDN = function lwNDN(host,port){
	this.host = host;
	this.port = port;
};

lwNDN.prototype.createRoute = function(host,port){
	this.host=host;
	this.port=port;
}

lwNDN.prototype.get = function(message){
	if(this.host!=null && this.port!=null){
		var output ='';
		message = message.trim();
		if(message==null || message =="" ){
			console.log('INVALID INPUT TO GET');
			return null;
		}
		
		
		//var array = ContentName.createNameArray(message);

		int = new Interest(new ContentName(message));

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


lwNDN.prototype.put = function(name,content){
	if(this.host!=null && this.port!=null){
		
		name = name.trim();
		
		var fe = new ForwardingEntry('selfreg',new ContentName(name),null, null, 3,2147483647);
		
		var bytes = encodeForwardingEntry(fe);
		
		
		var si = new SignedInfo();
		si.setFields();
		
		var co = new ContentObject(new ContentName(),si,bytes,new Signature()); 
		co.sign();
		
		var coBinary = encodeToBinaryContentObject(co);
		
		var ccnxnodename = unescape('%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F');
		
		var interestName = new ContentName(['ccnx',ccnxnodename,'selfreg',coBinary]);

		int = new Interest(interestName);
		int.Scope = 1;
		
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

	var co = new ContentObject(new ContentName(name),si,answer,new Signature()); 
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