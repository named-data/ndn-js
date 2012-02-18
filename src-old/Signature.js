// JavaScript Document
var Signature = function(_DigestAlgorithm, _Witness, _SignatureBits){
	this.DigestAlgorithm = _DigestAlgorithm;
	this.Witness = _Witness;
	this.SignatureBits = _SignatureBits;
}

exports.Signature = Signature;