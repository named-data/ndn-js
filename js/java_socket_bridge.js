/*
 * @author: ucla-cs
 * This class represents Interest Objects
 */

//var ccndAddr = unescape(%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F);
var ccndAddrHex = '%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F';

//var LOG = 5;
var LOG = 5;

// Global variables
var java_socket_bridge_ready_flag = false;

var ndnport =null;
var ndnurl=null;

var registeredPrefixes ={};

String.prototype.trim = function() {
	return this.replace(/^\s+|\s+$/g, "");
};

// Applet reports it is ready to use
function java_socket_bridge_ready(){
	java_socket_bridge_ready_flag = true;
}




//Sets the route to ccnx router
/**
 * Setup the router to use
 * @url the url of the remote NDN router
 * @port the port of the remote NDN router
 */
function createRoute(url, port){
	ndnport = port;
	ndnurl=url;
	
	console.log(new BinaryXMLDecoder());

	//SEND INTERST TO CCNX NODE

	
	//Now Start the receiving thread
	
}

// Connect to a given url and port
//Error -1 No countent found
//Error -2 Empty query
/**
 * Sends an interest for the given prefix and returns the response (java_socket_bridge.js)
 * @message the prefix to query for
 * @return -1 if no content is found,-2 is the array is empty, the content otherwise
 */
function queryPrefix(message){
	if(ndnport!=null && ndnurl!=null){
		var newMessage ='';


		message = message.trim();
		

		
		if(message==null || message =="" || message=="/"){
			return -2;
		}
		
		//message = decodeURIComponent(message);
		
		var array = createNameArray(message);
		
		//console.log('ARRAY IS '+ array);
		
		enc = new BinaryXMLEncoder();
 
		int = new Interest(new ContentName(array));

		int.encode(enc);
		
		var hex = toHex(enc.getReducedOstream());
		
		
		
		//console.log('Connecting and start '+ ndnurl +':'+ndnport+'-'+message);


		var result = get_java_socket_bridge().connectAndStart(ndnurl,ndnport,hex);
		
		console.log('BINARY RESPONSE IS ' +result);
		
		
		//result[0] and result[1] should be 0 and 4 if there is a content object found
		if(result==null || result==undefined || result =="" || result[0] != '0'||result[1]!='4'){
			return -1;
		}
		
		else{
			
			var numbers = toNumbers(result);
			
			console.log('HEX RESPONSE IS \n'+numbers);
			decoder = new BinaryXMLDecoder(numbers);
			
			
			co = new ContentObject();
        
			co.decode(decoder);

			if(LOG>2) console.log(co);

			return co;
			

		}
		

	}


	else{

		alert('ERROR URL OR PORT NOT SET');

		return -3;

	}

}

var registerStarted = false;
function registerPrefix(name, content){
	
	registeredPrefixes[name] = content ;
	
	if(registerStarted == false){
		var result = get_java_socket_bridge().connectAndStartAndPublish();
		
		startRegisterPrefix();
		
		registerStarted = true;
	}
	sendForwardingEntry(10);
}


function unRegisterPrefix(name){
	
	delete registeredPrefixes[name];

}




function on_socket_received_interest(IP, port, interestBinary){
	console.log('WOOOO RECEIVED STUFF' );
	var interest = decodeHexInterest(interestBinary);
	
	console.log('WOOO received interest' + interest.Name.Components);
	
	var stringName = "";
	
	for(var i=0;i<interest.Name.Components.length;i++){
		stringName += "/"+ interest.Name.Components[i];
	}

	if(registeredPrefix[stringName]!=null){
		if(LOG>1)console.log("CANNOT FIND THE OBJECT OF NAME " + stringName );
	}
	else{
		var co = new ContentObject(interest.Name, null,registeredPrefix[stringName],null );
		
		var hex = encodeToHexContentObject(co);
		
		get_java_socket_bridge().sendContentObject(IP,port,hex);
		
		
	}
}




// Connect to a given url and port
//Error -1 No countent found
//Error -2 Empty query
function startRegisterPrefix(){
	if(LOG>2) console.log('START REGISTER PREFIX');
	
	if(ndnport!=null && ndnurl!=null){
		var newMessage ='';
		
		

		name = name.trim();
		
		

		///////////////////////
		var face = new FaceInstance('newface',null,null, 17, '127.0.0.1',9876,null,null,null);
		
		var encoder1 = new BinaryXMLEncoder();
		 
		face.encode(encoder1);

		var faceInstanceBinary = encoder1.getReducedOstream();

		
		var si = new SignedInfo();
		si.setFields();
		
		var co = new ContentObject(new ContentName(),si,faceInstanceBinary,new Signature()); 
		co.sign();
		
		var encoder2 = new BinaryXMLEncoder();

		co.encode(encoder2);

		var coBinary = encoder2.getReducedOstream();
		
		//if(LOG>3)console.log('ADDESS OF CCND IS'+unescape('%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F'));
		
		//var interestName = new ContentName(['ccnx',co.SignedInfo.Publisher.PublisherPublicKeyDigest,'newface',coBinary]);
		var interestName = new ContentName(['ccnx',unescape('%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F'),'newface',coBinary]);
		//var interestName = new ContentName(['ccnx','%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F','newface',coBinary]);

		//var interestName = new ContentName(['ccnx','1234','newface',coBinary]);
		//var interestName = new ContentName(['ccnx',co.SignedInfo.Publisher.PublisherPublicKeyDigest,'newface',coBinary]);
		int = new Interest(interestName,face);
		
		var hex = encodeToHexInterest(int);
		/////////////////
		
		
		
		if(LOG>4)console.log('Interst name of Conntection Message is '+ interestName);
		

		if(LOG>4) console.log('Connecting and start '+ ndnurl +':'+ndnport+'-'+hex);
		//console.log('Connecting and start '+ ndnurl +':'+ndnport+'-'+message);
		
		var result = get_java_socket_bridge().connectAndStart(ndnurl,ndnport,hex);

		
		//TODO MOVE THIS
		
		//result[0] and result[1] should be 0 and 4 if there is a content object found
		if(result==null || result==undefined || result =="" || result[0] != '0'||result[1]!='4'){
			return -1;
		}
		
		if(LOG>4) console.log('RECEIVED THE FOLLOWING DATA: ' +co.Content);
			
		else{
			
			co = decodeHexContentObject(result);
			
			if(LOG>4) console.log('RECEIVED THE FOLLOWING DATA: ' +co.Content);
			
			return co;
		}
	}
	else{

		alert('ERROR URL OR PORT NOT SET');

		return -3;

	}	

}


// Connect to a given url and port
//Error -1 No countent found
//Error -2 Empty query
function sendForwardingEntry(faceID){
	if(LOG>2) console.log('START REGISTER PREFIX');
	
	if(ndnport!=null && ndnurl!=null){
		var newMessage ='';
		
		

		name = name.trim();
		
		

		///////////////////////
		var face = new ForwardingEntry('prefixreg',new ContentName(['helloworld']),null, faceID, 1,null);
		
		var encoder1 = new BinaryXMLEncoder();
		 
		face.encode(encoder1);

		var faceInstanceBinary = encoder1.getReducedOstream();

		

		var si = new SignedInfo();
		si.setFields();
		
		var co = new ContentObject(new ContentName(),si,faceInstanceBinary,new Signature()); 
		co.sign();
		
		var encoder2 = new BinaryXMLEncoder();

		co.encode(encoder2);

		var coBinary = encoder2.getReducedOstream();



		var interestName = new ContentName(['ccnx',unescape('%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F'),'prefixreg',coBinary]);
		//var interestName = new ContentName(['ccnx',co.SignedInfo.Publisher.PublisherPublicKeyDigest,'newface',coBinary]);
		//var interestName = new ContentName(['ccnx','%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F','newface',coBinary]);

		//var interestName = new ContentName(['ccnx','1234','newface',coBinary]);
		//var interestName = new ContentName(['ccnx',co.SignedInfo.Publisher.PublisherPublicKeyDigest,'prefixreg',coBinary]);

		int = new Interest(interestName,face);
		
		var hex = encodeToHexInterest(int);
		/////////////////


		
		if(LOG>4)console.log('Interst name of Conntection Message is '+ interestName);
		

		if(LOG>4) console.log('Connecting and start '+ ndnurl +':'+ndnport+'-'+hex);
		//console.log('Connecting and start '+ ndnurl +':'+ndnport+'-'+message);
		
		var result = get_java_socket_bridge().connectAndStart(ndnurl,ndnport,hex);
		
		if(LOG>3)console.log('BINARY RESPONSE IS ' +result);
		
		
		//result[0] and result[1] should be 0 and 4 if there is a content object found
		if(result==null || result==undefined || result =="" || result[0] != '0'||result[1]!='4'){
			return -1;
		}
		
		if(LOG>4) console.log('RECEIVED THE FOLLOWING DATA: ' +co.Content);
			
		else{
			
			co = decodeHexContentObject(result);
			
			if(LOG>4) console.log('RECEIVED THE FOLLOWING DATA: ' +co.Content);
			
			return co;
		}
	}
	else{

		alert('ERROR URL OR PORT NOT SET');

		return -3;

	}	

}


/**
 * Computes the size in bytes of the ContentObject once encoded
 * @param co the content object to encode
 * @returns the size in bytes of the encoded ContentObject
 */
function getContentObjectSize(co){
	var enc = new BinaryXMLEncoder();
	
	co.encode(enc);
	
	return enc.getReducedOstream().length;
}




function encodeToHexInterest(int){
	
	var enc = new BinaryXMLEncoder();
 
	int.encode(enc);
	
	var hex = toHex(enc.getReducedOstream());

	return hex;

	
}


function encodeToHexContentObject(co){
	var enc = new BinaryXMLEncoder();
 
	co.encode(enc);
	
	var reducedOstream = enc.getReducedOstream();
	
	if(LOG>3) console.log("In encodeToHexContentObject, reducedOstream: ", reducedOstream);
	
	var hex = toHex(reducedOstream);

	return hex;

	
}

function decodeHexInterest(result){
	var numbers = toNumbers(result);
			
	
	decoder = new BinaryXMLDecoder(numbers);
	if(LOG>3)console.log('DECODED HEX INTERST  \n'+numbers);

	i = new Interest();

	i.decode(decoder);

	return i;
	
}

function decodeHexContentObject(result){
	var numbers = toNumbers(result);

	decoder = new BinaryXMLDecoder(numbers);
	if(LOG>3)console.log('DECODED HEX CONTENT OBJECT \n'+numbers);
	
	co = new ContentObject();

	co.decode(decoder);

	return co;
	
}




// Get something from the socket
function on_socket_get(message){}

// Report an error
function on_socket_error(message){
	alert('Received error message \n' +message);
}

// Get the applet object
function get_java_socket_bridge(){
	return document.getElementById('JavaSocketBridge');
}