// JavaScript Document


var Decoder = function Decoder(){
	
	
	//PRIVATE FUNCTIONS
	

}


//PUBLIC FUNCTIONS

Decoder.prototype.decodeFile = function(filename){
	var fs = require('fs');

	var file = fs.readFile(filename, function(err,data){
  		if(err) {
   		 console.error("Could not open file: %s", err);
   		 process.exit(1);
  		}
		
		//console.log(data);
		//console.log(data.toString('binary'));
		for( i=0;i<data.length ;i++) {
			var v = data[i];
			console.log(v.toString(2)+'\n');
		}

		console.log( require('./TAG.js').d.CCN_DTAG_Any);
		var a =new Buffer('aGVsbG8gd29ybGQK','base64');
		console.log(a.toString('base64'));

	});
}



var decoder = new Decoder();
var file = decoder.decodeFile('/Users/eastman/Desktop/CCN/ccnx-0.5.0rc1/hello');

