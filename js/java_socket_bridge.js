/*
 * @author: ucla-cs
 * This class represents Interest Objects
 */

// Global variables
var java_socket_bridge_ready_flag = false;

var ndnport =null;
var ndnurl=null;

// Applet reports it is ready to use
function java_socket_bridge_ready(){
	java_socket_bridge_ready_flag = true;
}

//Sets the route to ccnx router
function createRoute(url, port){
	ndnport = port;
	ndnurl=url;
}

// Connect to a given url and port
//Error -1 No countent found
//Error -2 Empty query
function queryPrefix(message){
	if(ndnport!=null && ndnurl!=null){
		var newMessage ='';
		
		String.prototype.trim = function() {
			return this.replace(/^\s+|\s+$/g, "");
		};

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
	alert('NO CONTENT FOUND\nERROR MESSAGE:' +message);
}

// Get the applet object
function get_java_socket_bridge(){
	return document.getElementById('JavaSocketBridge');
}