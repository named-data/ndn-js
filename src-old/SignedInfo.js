// JavaScript Document
var SignedInfo = function SignedInfo(_PublisherPublicKeyDigest,_Timestamp,_Type,  _KeyLocator,_FreshnessSeconds,_FinalBlockID){
	
	this.PublisherPublicKeyDigest = _PublisherPublicKeyDigest;
	this.Timestamp = _Timestamp;
	this.FreshnessSeconds = _FinalBlockID;
	this.FinalBlockID = _FinalBlockID;
	this.KeyLocator= _KeyLocator;
}

exports.SignedInfo = SignedInfo;

