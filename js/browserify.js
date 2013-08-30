/** 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

// Library namespace
var ndn = {};

var exports = ndn;

var require = function (ignore) { return ndn; };

// Factory method to create node.js compatible buffer objects
var Buffer = function Buffer (data, fmt) {
    var obj;

    if (typeof data == 'number')
	obj = new Uint8Array(data);
    else if (typeof data == 'string') {
        if (fmt == null || fmt == 'ascii') {
	    obj = new Uint8Array(data.length);
	    for (var i = 0; i < data.length; i++)
		obj[i] = data.charCodeAt(i);
	} else if (fmt == 'hex') {
	    obj = new Uint8Array(Math.floor(data.length / 2));
	    var i = 0;
	    data.replace(/(..)/g, function(ss) {
		    obj[i++] = parseInt(ss, 16);
		});
	} else if (fmt == 'base64') {
	    var hex = b64tohex(data);
	    obj = new Uint8Array(Math.floor(hex.length / 2));
	    var i = 0;
	    hex.replace(/(..)/g, function(ss) {
		    obj[i++] = parseInt(ss, 16);
		});
	} else 
	    throw new Error('Buffer: unknown encoding format ' + fmt);
    } else if (data instanceof Uint8Array) {
	obj = data.subarray(0);
    } else
	throw new Error('Buffer: unknown data type.');

    obj.__proto__ = Buffer.prototype;

    obj.toString = function (encoding) {
	if (encoding == null) {
	    var ret = "";
	    for (var i = 0; i < this.length; i++ )
		ret += String.fromCharCode(this[i]);
	    return ret;
	}

	var ret = "";
	for (var i = 0; i < this.length; i++)
	    ret += (this[i] < 16 ? "0" : "") + this[i].toString(16);

	if (encoding == 'hex') {
	    return ret;
	} else if (encoding == 'base64') {
	    return hex2b64(ret);
	} else
	    throw new Error('Buffer.toString: unknown encoding format ' + encoding);
    };

    obj.slice = function (begin, end) {
	return new Buffer(obj.subarray(begin, end));
    };

    obj.copy = function (target, targetStart) {
	target.set(this, targetStart);
    };

    return obj;
};

Buffer.prototype = Uint8Array.prototype;

Buffer.concat = function (arrays) {
    var totalLength = 0;
    for (var i = 0; i < arrays.length; ++i)
	totalLength += arrays[i].length;
    
    var result = new Buffer(totalLength);
    var offset = 0;
    for (var i = 0; i < arrays.length; ++i) {
	result.set(arrays[i], offset);
	offset += arrays[i].length;
    }
    return result;
};

// Factory method to create hasher objects
exports.createHash = function (alg) {
    if (alg != 'sha256')
	throw new Error('createHash: unsupported algorithm.');

    var obj = {};

    obj.md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});

    obj.update = function (buf) {
	this.md.updateHex(buf.toString('hex'));
    };

    obj.digest = function () {
	return new Buffer(this.md.digest(), 'hex');
    };

    return obj;
};

// Factory method to create RSA signer objects
exports.createSign = function (alg) {
    if (alg != 'RSA-SHA256')
	throw new Error('createSign: unsupported algorithm.');

    var obj = {};

    obj.arr = [];

    obj.update = function (buf) {
	this.arr.push(buf);
    };

    obj.sign = function (keypem) {
	var rsa = new RSAKey();
	rsa.readPrivateKeyFromPEMString(keypem);
	var signer = new KJUR.crypto.Signature({"alg": "SHA256withRSA", "prov": "cryptojs/jsrsa"});
	signer.initSign(rsa);
	for (var i = 0; i < this.arr.length; i++)
	    signer.updateHex(this.arr[i].toString('hex'));

	return new Buffer(signer.sign(), 'hex');
    };

    return obj;
};

// Factory method to create RSA verifier objects
exports.createVerify = function (alg) {
    if (alg != 'RSA-SHA256')
	throw new Error('createSign: unsupported algorithm.');

    var obj = {};
    
    obj.arr = [];

    obj.update = function (buf) {
	this.arr.push(buf);
    };

    var getSubjectPublicKeyPosFromHex = function (hPub) {  
	var a = ASN1HEX.getPosArrayOfChildren_AtObj(hPub, 0); 
	if (a.length != 2) return -1;
	var pBitString = a[1];
	if (hPub.substring(pBitString, pBitString + 2) != '03') return -1;
	var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hPub, pBitString);
	if (hPub.substring(pBitStringV, pBitStringV + 2) != '00') return -1;
	return pBitStringV + 2;
    };

    var readPublicDER = function (pub_der) {
	var hex = pub_der.toString('hex');
	var p = getSubjectPublicKeyPosFromHex(hex);
	var a = ASN1HEX.getPosArrayOfChildren_AtObj(hex, p);
	if (a.length != 2) return null;
	var hN = ASN1HEX.getHexOfV_AtObj(hex, a[0]);
	var hE = ASN1HEX.getHexOfV_AtObj(hex, a[1]);
	var rsaKey = new RSAKey();
	rsaKey.setPublic(hN, hE);
	return rsaKey;
    };

    obj.verify = function (keypem, sig) {
	var key = new ndn.Key();
	key.fromPemString(keypem);

	var rsa = readPublicDER(key.publicToDER());
	var signer = new KJUR.crypto.Signature({"alg": "SHA256withRSA", "prov": "cryptojs/jsrsa"});
	signer.initVerifyByPublicKey(rsa);
	for (var i = 0; i < this.arr.length; i++)
	    signer.updateHex(this.arr[i].toString('hex'));
	var hSig = this.signature.signature.toString('hex');
	return signer.verify(hSig);
    };

    return obj;
};

//XXX: pure hack
exports.TcpTransport = WebSocketTransport;
