/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class contains all CCNx tags
 */


var CCNProtocolDTags = {

	/**
	 * Note if you add one of these, add it to the reverse string map as well.
	 * Emphasize getting the work done at compile time over trying to make something
	 * flexible and developer error-proof.
	 */

	 Any : 13,
	 Name : 14,
	 Component : 15,
	 Certificate : 16,
	 Collection : 17,
	 CompleteName : 18,
	 Content : 19,
	 SignedInfo : 20,
	 ContentDigest : 21,
	 ContentHash : 22,
	 Count : 24,
	 Header : 25,
	 Interest : 26,	/* 20090915 */
	 Key : 27,
	 KeyLocator : 28,
	 KeyName : 29,
	 Length : 30,
	 Link : 31,
	 LinkAuthenticator : 32,
	 NameComponentCount : 33,	/* DeprecatedInInterest */
	 RootDigest : 36,
	 Signature : 37,
	 Start : 38,
	 Timestamp : 39,
	 Type : 40,
	 Nonce : 41,
	 Scope : 42,
	 Exclude : 43,
	 Bloom : 44,
	 BloomSeed : 45,
	 AnswerOriginKind : 47,
	 InterestLifetime : 48,
	 Witness : 53,
	 SignatureBits : 54,
	 DigestAlgorithm : 55,
	 BlockSize : 56,
	 FreshnessSeconds : 58,
	 FinalBlockID : 59,
	 PublisherPublicKeyDigest : 60,
	 PublisherCertificateDigest : 61,
	 PublisherIssuerKeyDigest : 62,
	 PublisherIssuerCertificateDigest : 63,
	 ContentObject : 64,	/* 20090915 */
	 WrappedKey : 65,
	 WrappingKeyIdentifier : 66,
	 WrapAlgorithm : 67,
	 KeyAlgorithm : 68,
	 Label : 69,
	 EncryptedKey : 70,
	 EncryptedNonceKey : 71,
	 WrappingKeyName : 72,
	 Action : 73,
	 FaceID : 74,
	 IPProto : 75,
	 Host : 76,
	 Port : 77,
	 MulticastInterface : 78,
	 ForwardingFlags : 79,
	 FaceInstance : 80,
	 ForwardingEntry : 81,
	 MulticastTTL : 82,
	 MinSuffixComponents : 83,
	 MaxSuffixComponents : 84,
	 ChildSelector : 85,
	 RepositoryInfo : 86,
	 Version : 87,
	 RepositoryVersion : 88,
	 GlobalPrefix : 89,
	 LocalName : 90,
	 Policy : 91,
	 Namespace : 92,
	 GlobalPrefixName : 93,
	 PolicyVersion : 94,
	 KeyValueSet : 95,
	 KeyValuePair : 96,
	 IntegerValue : 97,
	 DecimalValue : 98,
	 StringValue : 99,
	 BinaryValue : 100,
	 NameValue : 101,
	 Entry : 102,
	 ACL : 103,
	 ParameterizedName : 104,
	 Prefix : 105,
	 Suffix : 106,
	 Root : 107,
	 ProfileName : 108,
	 Parameters : 109,
	 InfoString : 110,
	// 111 unallocated
	 StatusResponse : 112,
	 StatusCode : 113,
	 StatusText : 114,

	// Sync protocol
	 SyncNode : 115,
	 SyncNodeKind : 116,
	 SyncNodeElement : 117,
	 SyncVersion : 118,
	 SyncNodeElements : 119,
	 SyncContentHash : 120,
	 SyncLeafCount : 121,
	 SyncTreeDepth : 122,
	 SyncByteCount : 123,
	 ConfigSlice : 124,
	 ConfigSliceList : 125,
	 ConfigSliceOp : 126,

	// Remember to keep in sync with schema/tagnames.csvsdict
	 CCNProtocolDataUnit : 17702112,
	 CCNPROTOCOL_DATA_UNIT : "CCNProtocolDataUnit"
};

var CCNProtocolDTagsStrings = [
	null, null, null, null, null, null, null, null, null, null, null,
	null, null,
	"Any", "Name", "Component", "Certificate", "Collection", "CompleteName",
	"Content", "SignedInfo", "ContentDigest", "ContentHash", null, "Count", "Header",
	"Interest", "Key", "KeyLocator", "KeyName", "Length", "Link", "LinkAuthenticator",
	"NameComponentCount", null, null, "RootDigest", "Signature", "Start", "Timestamp", "Type",
	"Nonce", "Scope", "Exclude", "Bloom", "BloomSeed", null, "AnswerOriginKind",
	"InterestLifetime", null, null, null, null, "Witness", "SignatureBits", "DigestAlgorithm", "BlockSize",
	null, "FreshnessSeconds", "FinalBlockID", "PublisherPublicKeyDigest", "PublisherCertificateDigest",
	"PublisherIssuerKeyDigest", "PublisherIssuerCertificateDigest", "ContentObject",
	"WrappedKey", "WrappingKeyIdentifier", "WrapAlgorithm", "KeyAlgorithm", "Label",
	"EncryptedKey", "EncryptedNonceKey", "WrappingKeyName", "Action", "FaceID", "IPProto",
	"Host", "Port", "MulticastInterface", "ForwardingFlags", "FaceInstance",
	"ForwardingEntry", "MulticastTTL", "MinSuffixComponents", "MaxSuffixComponents", "ChildSelector",
	"RepositoryInfo", "Version", "RepositoryVersion", "GlobalPrefix", "LocalName",
	"Policy", "Namespace", "GlobalPrefixName", "PolicyVersion", "KeyValueSet", "KeyValuePair",
	"IntegerValue", "DecimalValue", "StringValue", "BinaryValue", "NameValue", "Entry",
	"ACL", "ParameterizedName", "Prefix", "Suffix", "Root", "ProfileName", "Parameters",
	"InfoString", null,
    "StatusResponse", "StatusCode", "StatusText", "SyncNode", "SyncNodeKind", "SyncNodeElement",
    "SyncVersion", "SyncNodeElements", "SyncContentHash", "SyncLeafCount", "SyncTreeDepth", "SyncByteCount",
    "ConfigSlice", "ConfigSliceList", "ConfigSliceOp" ];


//TESTING
//console.log(exports.CCNProtocolDTagsStrings[17]);

