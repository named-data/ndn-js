/*! rsasign-1.2.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// rsa-sign.js - adding signing functions to RSAKey class.
//
//
// version: 1.2.1 (08 May 2012)
//
// Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license/
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.

//
// Depends on:
//   function sha1.hex(s) of sha1.js
//   jsbn.js
//   jsbn2.js
//   rsa.js
//   rsa2.js
//

// keysize / pmstrlen
//  512 /  128
// 1024 /  256
// 2048 /  512
// 4096 / 1024

/**
 * @property {Dictionary} _RSASIGN_DIHEAD
 * @description Array of head part of hexadecimal DigestInfo value for hash algorithms.
 * You can add any DigestInfo hash algorith for signing.
 * See PKCS#1 v2.1 spec (p38).
 */
var _RSASIGN_DIHEAD = [];
_RSASIGN_DIHEAD['sha1'] =      "3021300906052b0e03021a05000414";
_RSASIGN_DIHEAD['sha256'] =    "3031300d060960864801650304020105000420";
_RSASIGN_DIHEAD['sha384'] =    "3041300d060960864801650304020205000430";
_RSASIGN_DIHEAD['sha512'] =    "3051300d060960864801650304020305000440";
_RSASIGN_DIHEAD['md2'] =       "3020300c06082a864886f70d020205000410";
_RSASIGN_DIHEAD['md5'] =       "3020300c06082a864886f70d020505000410";
_RSASIGN_DIHEAD['ripemd160'] = "3021300906052b2403020105000414";

/**
 * @property {Dictionary} _RSASIGN_HASHHEXFUNC
 * @description Array of functions which calculate hash and returns it as hexadecimal.
 * You can add any hash algorithm implementations.
 */
var _RSASIGN_HASHHEXFUNC = [];
_RSASIGN_HASHHEXFUNC['sha1'] =      function(s){return hex_sha1(s);};  // http://pajhome.org.uk/crypt/md5/md5.html
_RSASIGN_HASHHEXFUNC['sha256'] =    function(s){return hex_sha256(s);} // http://pajhome.org.uk/crypt/md5/md5.html
_RSASIGN_HASHHEXFUNC['sha512'] =    function(s){return hex_sha512(s);} // http://pajhome.org.uk/crypt/md5/md5.html
_RSASIGN_HASHHEXFUNC['md5'] =       function(s){return hex_md5(s);};   // http://pajhome.org.uk/crypt/md5/md5.html
_RSASIGN_HASHHEXFUNC['ripemd160'] = function(s){return hex_rmd160(s);};   // http://pajhome.org.uk/crypt/md5/md5.html

//@author axelcdv
var _RSASIGN_HASHBYTEFUNC = [];
_RSASIGN_HASHBYTEFUNC['sha256'] = 	function(byteArray){return hex_sha256_from_bytes(byteArray);};

//_RSASIGN_HASHHEXFUNC['sha1'] =   function(s){return sha1.hex(s);}   // http://user1.matsumoto.ne.jp/~goma/js/hash.html
//_RSASIGN_HASHHEXFUNC['sha256'] = function(s){return sha256.hex;}    // http://user1.matsumoto.ne.jp/~goma/js/hash.html

var _RE_HEXDECONLY = new RegExp("");
_RE_HEXDECONLY.compile("[^0-9a-f]", "gi");

// ========================================================================
// Signature Generation
// ========================================================================

function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg) {
  var pmStrLen = keySize / 4;
  var hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
  var sHashHex = hashFunc(s);

  var sHead = "0001";
  var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
  var sMid = "";
  var fLen = pmStrLen - sHead.length - sTail.length;
  for (var i = 0; i < fLen; i += 2) {
    sMid += "ff";
  }
  sPaddedMessageHex = sHead + sMid + sTail;
  return sPaddedMessageHex;
}


//@author: Meki Cheraoui
function _rsasign_getHexPaddedDigestInfoForStringHEX(s, keySize, hashAlg) {
  var pmStrLen = keySize / 4;
  var hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
  var sHashHex = hashFunc(s);

  var sHead = "0001";
  var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
  var sMid = "";
  var fLen = pmStrLen - sHead.length - sTail.length;
  for (var i = 0; i < fLen; i += 2) {
    sMid += "ff";
  }
  sPaddedMessageHex = sHead + sMid + sTail;
  return sPaddedMessageHex;
}

/**
 * Apply padding, then computes the hash of the given byte array, according to the key size and with the hash algorithm
 * @param byteArray (byte[])
 * @param keySize (int)
 * @param hashAlg the hash algorithm to apply (string)
 * @return the hash of byteArray
 */
function _rsasign_getHexPaddedDigestInfoForByteArray(byteArray, keySize, hashAlg){
	var pmStrLen = keySize / 4;
	var hashFunc = _RSASIGN_HASHBYTEFUNC[hashAlg];
	var sHashHex = hashFunc(byteArray); //returns hex hash
	
	var sHead = "0001";
	  var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
	  var sMid = "";
	  var fLen = pmStrLen - sHead.length - sTail.length;
	  for (var i = 0; i < fLen; i += 2) {
	    sMid += "ff";
	  }
	  sPaddedMessageHex = sHead + sMid + sTail;
	  return sPaddedMessageHex;
}

function _zeroPaddingOfSignature(hex, bitLength) {
  var s = "";
  var nZero = bitLength / 4 - hex.length;
  for (var i = 0; i < nZero; i++) {
    s = s + "0";
  }
  return s + hex;
}

/**
 * sign for a message string with RSA private key.<br/>
 * @name signString
 * @memberOf RSAKey#
 * @function
 * @param {String} s message string to be signed.
 * @param {String} hashAlg hash algorithm name for signing.<br/>
 * @return returns hexadecimal string of signature value.
 */
function _rsasign_signString(s, hashAlg) {
  //alert("this.n.bitLength() = " + this.n.bitLength());
  var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
  var biPaddedMessage = parseBigInt(hPM, 16);
  var biSign = this.doPrivate(biPaddedMessage);
  var hexSign = biSign.toString(16);
  return _zeroPaddingOfSignature(hexSign, this.n.bitLength());
}

//@author: ucla-cs
function _rsasign_signStringHEX(s, hashAlg) {
  //alert("this.n.bitLength() = " + this.n.bitLength());
  var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
  var biPaddedMessage = parseBigInt(hPM, 16);
  var biSign = this.doPrivate(biPaddedMessage);
  var hexSign = biSign.toString(16);
  return _zeroPaddingOfSignature(hexSign, this.n.bitLength());
}


/**
 * Sign a message byteArray with an RSA private key
 * @name signByteArray
 * @memberOf RSAKey#
 * @function
 * @param {byte[]} byteArray
 * @param {Sring} hashAlg the hash algorithm to apply
 * @param {RSAKey} rsa key to sign with: hack because the context is lost here
 * @return hexadecimal string of signature value
 */
function _rsasign_signByteArray(byteArray, hashAlg, rsaKey) {
	var hPM = _rsasign_getHexPaddedDigestInfoForByteArray(byteArray, rsaKey.n.bitLength(), hashAlg); ///hack because the context is lost here
	var biPaddedMessage = parseBigInt(hPM, 16);
	var biSign = rsaKey.doPrivate(biPaddedMessage); //hack because the context is lost here
	var hexSign = biSign.toString(16);
	return _zeroPaddingOfSignature(hexSign, rsaKey.n.bitLength()); //hack because the context is lost here
}

/**
 * Sign a byte array with the Sha-256 algorithm
 * @param {byte[]} byteArray
 * @return hexadecimal string of signature value
 */
function _rsasign_signByteArrayWithSHA256(byteArray){
	return _rsasign_signByteArray(byteArray, 'sha256', this); //Hack because the context is lost in the next function
}


function _rsasign_signStringWithSHA1(s) {
  return _rsasign_signString(s, 'sha1');
}

function _rsasign_signStringWithSHA256(s) {
  return _rsasign_signString(s, 'sha256');
}

// ========================================================================
// Signature Verification
// ========================================================================

function _rsasign_getDecryptSignatureBI(biSig, hN, hE) {
  var rsa = new RSAKey();
  rsa.setPublic(hN, hE);
  var biDecryptedSig = rsa.doPublic(biSig);
  return biDecryptedSig;
}

function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE) {
  var biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
  var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
  return hDigestInfo;
}

function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo) {
  for (var algName in _RSASIGN_DIHEAD) {
    var head = _RSASIGN_DIHEAD[algName];
    var len = head.length;
    if (hDigestInfo.substring(0, len) == head) {
      var a = [algName, hDigestInfo.substring(len)];
      return a;
    }
  }
  return [];
}

function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE) {
  var hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
  var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  if (digestInfoAry.length == 0) return false;
  var algName = digestInfoAry[0];
  var diHashValue = digestInfoAry[1];
  var ff = _RSASIGN_HASHHEXFUNC[algName];
  var msgHashValue = ff(sMsg);
  return (diHashValue == msgHashValue);
}

function _rsasign_verifyHexSignatureForMessage(hSig, sMsg) {
  var biSig = parseBigInt(hSig, 16);
  var result = _rsasign_verifySignatureWithArgs(sMsg, biSig,
						this.n.toString(16),
						this.e.toString(16));
  return result;
}

/**
 * verifies a sigature for a message string with RSA public key.<br/>
 * @name verifyString
 * @memberOf RSAKey#
 * @function
 * @param {String} sMsg message string to be verified.
 * @param {String} hSig hexadecimal string of siganture.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0
 */
function _rsasign_verifyString(sMsg, hSig) {
  hSig = hSig.replace(_RE_HEXDECONLY, '');
  
  if(LOG>3)console.log('n is '+this.n);
  if(LOG>3)console.log('e is '+this.e);
  
  if (hSig.length != this.n.bitLength() / 4) return 0;
  hSig = hSig.replace(/[ \n]+/g, "");
  var biSig = parseBigInt(hSig, 16);
  var biDecryptedSig = this.doPublic(biSig);
  var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
  var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  
  if (digestInfoAry.length == 0) return false;
  var algName = digestInfoAry[0];
  var diHashValue = digestInfoAry[1];
  var ff = _RSASIGN_HASHHEXFUNC[algName];
  var msgHashValue = ff(sMsg);
  return (diHashValue == msgHashValue);
}

/**
 * verifies a sigature for a message byte array with RSA public key.<br/>
 * @name verifyByteArray
 * @memberOf RSAKey#
 * @function
 * @param {byte[]} byteArray message byte array to be verified.
 * @param {String} hSig hexadecimal string of signature.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0 
 */
function _rsasign_verifyByteArray(byteArray, witness, hSig) {
	hSig = hSig.replace(_RE_HEXDECONLY, '');
	  
	  if(LOG>3)console.log('n is '+this.n);
	  if(LOG>3)console.log('e is '+this.e);
	  
	  if (hSig.length != this.n.bitLength() / 4) return 0;
	  hSig = hSig.replace(/[ \n]+/g, "");
	  var biSig = parseBigInt(hSig, 16);
	  var biDecryptedSig = this.doPublic(biSig);
	  var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
	  var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
	  
	  if (digestInfoAry.length == 0) return false;
	  var algName = digestInfoAry[0];
	  var diHashValue = digestInfoAry[1];
	  var msgHashValue = null;
	  
	  if (witness == null) {
	  	var ff = _RSASIGN_HASHBYTEFUNC[algName];
	  	msgHashValue = ff(byteArray);
	  } else {
	  	// Compute merkle hash
		  var h = hex_sha256_from_bytes(byteArray);
		  var index = witness.path.index;
		  for (var i = witness.path.digestList.length - 1; i >= 0; i--) {
		  	var str = "";
		  	if (index % 2 == 0) {
		  		str = h + witness.path.digestList[i];
		  	} else {
		  		str = witness.path.digestList[i] + h;
		  	}
		  	h = hex_sha256_from_bytes(DataUtils.toNumbers(str));
		  	index = Math.floor(index / 2);
		  }
		  msgHashValue = hex_sha256_from_bytes(DataUtils.toNumbers(h));
	  }
	  //console.log(diHashValue);
	  //console.log(msgHashValue);
	  return (diHashValue == msgHashValue);
}


RSAKey.prototype.signString = _rsasign_signString;

RSAKey.prototype.signByteArray = _rsasign_signByteArray; //@author axelcdv
RSAKey.prototype.signByteArrayWithSHA256 = _rsasign_signByteArrayWithSHA256; //@author axelcdv

RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;
RSAKey.prototype.sign = _rsasign_signString;
RSAKey.prototype.signWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signWithSHA256 = _rsasign_signStringWithSHA256;


/*RSAKey.prototype.signStringHEX = _rsasign_signStringHEX;
RSAKey.prototype.signStringWithSHA1HEX = _rsasign_signStringWithSHA1HEX;
RSAKey.prototype.signStringWithSHA256HEX = _rsasign_signStringWithSHA256HEX;
RSAKey.prototype.signHEX = _rsasign_signStringHEX;
RSAKey.prototype.signWithSHA1HEX = _rsasign_signStringWithSHA1HEX;
RSAKey.prototype.signWithSHA256HEX = _rsasign_signStringWithSHA256HEX;
*/

RSAKey.prototype.verifyByteArray = _rsasign_verifyByteArray;
RSAKey.prototype.verifyString = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;
RSAKey.prototype.verify = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForByteArrayMessage = _rsasign_verifyHexSignatureForMessage;

/*
RSAKey.prototype.verifyStringHEX = _rsasign_verifyStringHEX;
RSAKey.prototype.verifyHexSignatureForMessageHEX = _rsasign_verifyHexSignatureForMessageHEX;
RSAKey.prototype.verifyHEX = _rsasign_verifyStringHEX;
RSAKey.prototype.verifyHexSignatureForByteArrayMessageHEX = _rsasign_verifyHexSignatureForMessageHEX;
*/
	
	
/**
 * @name RSAKey
 * @class
 * @description Tom Wu's RSA Key class and extension
 */
