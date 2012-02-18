// JavaScript Document
/*
	@author: Meki Cherkaoui
*/
var DTAGS = require('./TAG').d;
var TT = require('./TAG').tt;


var Encoder = function Encoder(){
	
	
};
/*
	TT bits specify the type of nodes

*/
var CCN_TT_BITS=3;
var CCN_TT_MASK=((1 << CCN_TT_BITS) - 1);
var CCN_MAX_TINY=((1 << (7-CCN_TT_BITS)) - 1);
var CCN_TT_HBIT=((1 << 7));

Encoder.prototype.encodeContentObject = function(_ContentObject){
	
	//var slit = function splitNumber(number){
	//};
	var i = 0;
	
	var addToBuffer = function addToBuffer(buffer,number,tt){
		
		var sizeOfBuffer = 1+8*((sizeof(number)+6)/7);
		
		splitNumbers = new Buffer(sizeOfBuffer);
		
		number >>= 7-CCN_TT_BITS;
		
		splitNumbers.write((CCN_TT_HBIT & ~require('./TAG').d.CCN_CLOSE) |
  			((number & CCN_MAX_TINY) << CCN_TT_BITS) |
  			(CCN_TT_MASK & tt));
		
		var index = 1;
		while(number>0){
			splitNumbers.write( number & ~CCN_TT_HBIT |require('./TAG').d.CCN_CLOSE);
			index++;
			number>>=7;
		}
		
		for( i=0, j=sizeofBuffer-1;i <sizeOfBuffer;i++,j--) {
		
			buffer[index+i] = splitNumbers[j];
		}
		
	};
	//NOTE NUMBETR= SIZE
	var addToBufferData = function addToBuffer(buffer,data,tt){
		
		var number = sizeof(data);
		var sizeOfBuffer = 1+8*((sizeof(number)+6)/7);
		
		splitNumbers = new Buffer(sizeOfBuffer);
		
		number >>= 7-CCN_TT_BITS;
		
		splitNumbers.write((CCN_TT_HBIT & ~require('./TAG').d.CCN_CLOSE) |
  			((number & CCN_MAX_TINY) << CCN_TT_BITS) |
  			(CCN_TT_MASK & tt));
		
		
		while(number>0){
			splitNumbers.write( number & ~CCN_TT_HBIT |require('./TAG').d.CCN_CLOSE);
			index++;
			number>>=7;
		}
		
		for( i=0, j=sizeofBuffer-1;i <sizeOfBuffer;i++,j--) {
		
			buffer[index+i] = splitNumbers[j];
		}
		
		for(i=0;i<10;i++){
			buffer[index+i] = data[i];
		}
		
	};
	
	//NOTE NUMBETR= SIZE
	var addName = function addToBuffer(buffer,name){
		
		for(i=0;i<name.size;i++){
			tt = require('./TAG').tt.CCN_BLOB ;
			addToBufferData(buffer,_ContentObject.moSignature.SignatureBits,tt);
			addCloseTag(buffer);
		}
		
	};
	
	
	var addCloseTag = function addCloseTag(buffer){
		var tag = DTAGS.CCN_CLOSE;
		buffer.write(tag);
	}; 
	
	var buffer = new Buffer(1000);
	 
	var tag = DTAGS.CCN_DTAG_ContentObject;
	var tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);
	
	
	tag = DTAGS.CCN_Signature;
	tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);
	
	
	tag = DTAGS.CCN_SignatureBits;
	tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);
	
	tt = TT.CCN_BLOB ;
	addToBufferData(buffer,_ContentObject.moSignature.SignatureBits,tt);
	
	addCloseTag(buffer);
	
	addCloseTag(buffer);
	
	tag = DTAGS.CCN_Name;
	tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);


	addName(buffer,_ContentObject.moName,tt);

	addCloseTag(buffer);
	
	tag = DTAGS.CCN_DTAG_SignedInfo;
	tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);

	tag = DTAGS.CCN_DTAG_PublisherPublicKeyDigest;
	tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);
	
	addToBufferData(buffer,_ContentObject.moSignedInfo.msPublisherPublicKeyDigest ,tt);
	
	addCloseTag(buffer);
	
	tag = DTAGS.CCN_DTAG_Timestamp;
	tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);
	
	addToBufferData(buffer,_ContentObject.moSignedInfo.msTimestamp ,tt);
	
	addCloseTag(buffer);
	
	tag = DTAGS.CCN_DTAG_KeyLocator;
	tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);
	
	tag = DTAGS.CCN_DTAG_key;
	tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);
	
	addToBufferData(buffer,_ContentObject.moSignedInfo.msKeyLocator ,tt);
	
	addCloseTag(buffer);
	
	addCloseTag(buffer);
	
	tag = DTAGS.CCN_DTAG_Content;
	tt = TT.CCN_DTAG ;
	addToBuffer(buffer,tag,tt);
	
	addToBufferData(buffer,_ContentObject.msContent,tt);
	
	addCloseTag(buffer);
	
	addCloseTag(buffer);

}


Encoder.prototype.encodeContentObjectToFile = function(_filename){
	
	
	var content = "hello world";
	
	var name = new require('./Name').Name(['hello']);
	
	var sigInfo = new require('./SignatureInfo').SignatureInfo(new Buffer('h7exThsbBBViA/knAnWd2lMdaAgW/lcI6EIAK6ln4Ut8/owZ0tobVQ4YJ3lHkl3qwzldAqLT8RayMU8cxpqrT6sa/nHFatbiObj2GrAAKbsJRSiV/ESzeVXPUHdbNJ75iDc5wjqvC4aJL8tGJt8vAOjJ7fy4MWD+mgFBYqn+1bw='));
	
	var sig = new require('./Signature').Signature(new Buffer("IEh0BFqfrJjrt9+txLvRqxWm5AZTScbIOoRghE6rMYU=",'base64'), new Buffer('BPMrnKOi','base64'), new Buffer('MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9lWVVnBeVwEml703J0byLmBtmCX6iU/XQ9Q8aHfkIrE5pp5fa3SwFkJRKboSeH7tzccU9/dvngCZW4dX0SbhTDZx9qNar69kOBhJNkn8vbFch8dDknn9qEWfK+WDZb/Wvqi0lZzN3cqlEyObOuFmyWiMdnsqHNXT/mCJchT847wIDAQAB','base64'));

	sig.generateSignature(name,sigInfo,content);
	
	var co = new require('./ContentObject').ContentObject(sig,name,sigInfo,content);
	
	var buffer = this.encodeContentObject(co);
	
	fs.writeFile(_filename);
	
}


var Encoder = new Encoder();

var file = Encoder.decodeFile('/Users/eastman/Desktop/CCN/ccnx-0.5.0rc1/hello');


