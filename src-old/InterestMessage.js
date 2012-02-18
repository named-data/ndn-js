// JavaScript Document

var InterestMessage = function InterestMessage(_Name,_MinSuffixComponents,_MaxSuffixComponents,_PublisherPublicKeyDigest, _Exclude, _ChildSelector,_AnswerOriginKind,_Scope,_InterestLifetime,_Nonce){
	
	this.Name = _Name;
	this.MinSuffixComponents = _MinSuffixComponents;
	this.MaxSuffixComponents = _MaxSuffixComponents;
	this.PublisherPublicKeyDigest=_PublisherPublicKeyDigest;
	this.Exclude=_Exclude;
	this.ChildSelector=_ChildSelector;
	this.Scope=_Scope;
	this.InterestLifetime=_InterestLifetime;
	this.Nonce = _Nonce;
	
};

exports.InterestMessage = InterestMessage;
