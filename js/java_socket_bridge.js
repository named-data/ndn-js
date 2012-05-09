/*
 * @author: ucla-cs
 * This class represents Interest Objects
 */

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
function createRoute(url, port){
	ndnport = port;
	ndnurl=url;
	
	console.log(new BinaryXMLDecoder());

	//SEND INTERST TO CCNX NODE
	startRegisterPrefix();
	
	//Now Start the receiving thread
	var result = get_java_socket_bridge().connectAndStartAndPublish();
	
	
}

// Connect to a given url and port
//Error -1 No countent found
//Error -2 Empty query
function queryPrefix(message){
	if(ndnport!=null && ndnurl!=null){
		var newMessage ='';


		message = message.trim();
		

		
		if(message==null || message =="" || message=="/"){
			return -2;
		}
		
		//message = decodeURIComponent(message);
		message = unescape(message);
		
		var array = message.split('/');

		
		if(message[0]=="/")
			array=array.slice(1,array.length);
			
		if(message[message.length-1]=="/")
			array=array.slice(0,array.length-1);
		
		
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

			//console.log(co);
			
			return co;
			

		}
		

	}

	else{

		alert('ERROR URL OR PORT NOT SET');

		return -3;

	}

}


function on_socket_received_interest(IP, port, interestBinary){
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

function registerPrefix(name, content){
	
	registeredPrefixes[name] = content ;

}


function unRegisterPrefix(name){
	
	delete registeredPrefixes[name];

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

		

		var co = new ContentObject(null,null,faceInstanceBinary,null); 
		
		var encoder2 = new BinaryXMLEncoder();
		
		co.encode(encoder2);

		var coBinary = encoder2.getReducedOstream();



		var interestName = new ContentName(['ccnx','1234','newface',faceInstanceBinary]);
		//var interestName = new ContentName(['ccnx','1234','newface',coBinary]);

		int = new Interest(interestName,face);
		
		var hex = encodeToHexInterest(int);
		/////////////////


		
		if(LOG>4)console.log('Interst name of Conntection Message is '+ interestName);
		

		if(LOG>4) console.log('Connecting and start '+ ndnurl +':'+ndnport+'-'+hex);
		//console.log('Connecting and start '+ ndnurl +':'+ndnport+'-'+message);
		
		var result = get_java_socket_bridge().connectAndStart(ndnurl,ndnport,hex);
		
		console.log('BINARY RESPONSE IS ' +result);
		
		//TODO MOVE THIS
		sendForwardingEntry(10);
		
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
		var face = new ForwardingEntry('prefixreg',new ContentName('helloworld'),null, faceID, 1,null);
		
		var encoder1 = new BinaryXMLEncoder();
		 
		face.encode(encoder1);

		var faceInstanceBinary = encoder1.getReducedOstream();

		

		var co = new ContentObject(null,null,faceInstanceBinary,null); 
		
		var encoder2 = new BinaryXMLEncoder();
		
		co.encode(encoder2);

		var coBinary = encoder2.getReducedOstream();



		var interestName = new ContentName(['ccnx','1234','prefixreg',faceInstanceBinary]);
		//var interestName = new ContentName(['ccnx','1234','newface',coBinary]);

		int = new Interest(interestName,face);
		
		var hex = encodeToHexInterest(int);
		/////////////////


		
		if(LOG>4)console.log('Interst name of Conntection Message is '+ interestName);
		

		if(LOG>4) console.log('Connecting and start '+ ndnurl +':'+ndnport+'-'+hex);
		//console.log('Connecting and start '+ ndnurl +':'+ndnport+'-'+message);
		
		var result = get_java_socket_bridge().connectAndStart(ndnurl,ndnport,hex);
		
		console.log('BINARY RESPONSE IS ' +result);
		
		
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



function createNameArray(name){
	if(name==null || name =="" || name=="/"){
			return -2;
		}
		
	//message = decodeURIComponent(message);
	name = unescape(name);
	
	var array = name.split('/');

	
	if(name[0]=="/")
		array=array.slice(1,array.length);
		
	if(name[name.length-1]=="/")
		array=array.slice(0,array.length-1);
	
	return array;
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
	
	var hex = toHex(enc.getReducedOstream());

	return hex;

	
}

function decodeHexInterest(result){
	var numbers = toNumbers(result);
			
	
	decoder = new BinaryXMLDecoder(numbers);
	console.log('DECODED HEX INTERST  \n'+numbers);
	
	
	i = new Interest();

	i.decode(decoder);

	return i;
	
}

function decodeHexContentObject(result){
	var numbers = toNumbers(result);

	decoder = new BinaryXMLDecoder(numbers);
	console.log('DECODED HEX CONTENT OBJECT \n'+numbers);
	
	co = new ContentObject();

	co.decode(decoder);

	return co;
	
}


//http://ejohn.org/blog/numbers-hex-and-colors/
function toHex(arguments){
  //console.log(arguments);
  var ret = "";
  for ( var i = 0; i < arguments.length; i++ )
    ret += (arguments[i] < 16 ? "0" : "") + arguments[i].toString(16);
  return ret.toUpperCase();
}

function toString(arguments){
  //console.log(arguments);
  var ret = "";
  for ( var i = 0; i < arguments.length; i++ )
    ret += String.fromCharCode(arguments[i]);
  return ret;
}

function toNumbers( str ){
  var ret = [];
   str.replace(/(..)/g, function(str){
    ret.push( parseInt( str, 16 ) );
  });
  return ret;
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