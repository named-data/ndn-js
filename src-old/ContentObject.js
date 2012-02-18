// JavaScript Document

var ContentObject = function ContentObject(_Signature,_Name,_SignedInfo,_Content){
	
	this.Signature = _Signature;
	this.Name = _Name;
	this.SignedInfo = _SignedInfo;
	this.Content=_Content;
	
};

exports.ContentObject = ContentObject;
