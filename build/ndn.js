
var ndn = ndn || {};

var exports = ndn;

var require = function(ignore) { return ndn; };


var internalBuf = function internalBuf(data, format) 
{
  var obj;

  if (typeof data == 'number')
    obj = new Uint8Array(data);
  else if (typeof data == 'string') {
    if (format == null || format == 'utf8') {
      var utf8 = internalBuf.str2rstr_utf8(data);
      obj = new Uint8Array(utf8.length);
      for (var i = 0; i < utf8.length; i++)
        obj[i] = utf8.charCodeAt(i);
    } 
    else if (format == 'binary') {
      obj = new Uint8Array(data.length);
      for (var i = 0; i < data.length; i++)
        obj[i] = data.charCodeAt(i);
    } 
    else if (format == 'hex') {
      obj = new Uint8Array(Math.floor(data.length / 2));
      var i = 0;
      data.replace(/(..)/g, function(ss) {
        obj[i++] = parseInt(ss, 16);
      });
    } 
    else if (format == 'base64') {
      var hex = b64tohex(data);
      obj = new Uint8Array(Math.floor(hex.length / 2));
      var i = 0;
      hex.replace(/(..)/g, function(ss) {
        obj[i++] = parseInt(ss, 16);
      });
    } 
    else 
      throw new Error('Buffer: unknown encoding format ' + format);
  } 
  else if (typeof data == 'object' && (data instanceof Uint8Array || data instanceof internalBuf)) {
    
    if (format == false)
      obj = data.subarray(0);
    else
      obj = new Uint8Array(data);
  }
  else if (typeof data == 'object' && data instanceof ArrayBuffer)
    
    obj = new Uint8Array(data);
  else if (typeof data == 'object')
    
    
    obj = new Uint8Array(data);
  else
    throw new Error('Buffer: unknown data type.');

  try {
    obj.__proto__ = internalBuf.prototype;
  } catch(ex) {
    throw new Error("Buffer: Set obj.__proto__ exception: " + ex);
  }

  obj.__proto__.toString = function(encoding) {
    if (encoding == null) {
      var ret = "";
      for (var i = 0; i < this.length; i++)
        ret += String.fromCharCode(this[i]);
      return ret;
    }

    var ret = "";
    for (var i = 0; i < this.length; i++)
      ret += (this[i] < 16 ? "0" : "") + this[i].toString(16);

    if (encoding == 'hex')
      return ret;
    else if (encoding == 'base64')
      return hex2b64(ret);
    else
      throw new Error('Buffer.toString: unknown encoding format ' + encoding);
  };

  obj.__proto__.slice = function(begin, end) {
    if (end !== undefined)
      return new internalBuf(this.subarray(begin, end), false);
    else
      return new internalBuf(this.subarray(begin), false);
  };

  obj.__proto__.copy = function(target, targetStart) {
    if (targetStart !== undefined)
      target.set(this, targetStart);
    else
      target.set(this);
  };

  return obj;
};

 internalBuf.prototype = Uint8Array.prototype;

 internalBuf.concat = function(arrays) 
{
  var totalLength = 0;
  for (var i = 0; i < arrays.length; ++i)
    totalLength += arrays[i].length;
    
  var result = new internalBuf(totalLength);
  var offset = 0;
  for (var i = 0; i < arrays.length; ++i) {
    result.set(arrays[i], offset);
    offset += arrays[i].length;
  }
  return result;
};

 internalBuf.str2rstr_utf8 = function(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while (++i < input.length)
  {
    
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if (0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    
    if (x <= 0x7F)
      output += String.fromCharCode(x);
    else if (x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if (x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if (x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
};


exports.createHash = function(alg) 
{
  if (alg != 'sha256')
    throw new Error('createHash: unsupported algorithm.');

  var obj = {};

  obj.md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});

  obj.update = function(buf) {
    this.md.updateHex(buf.toString('hex'));
  };

  obj.digest = function() {
    return new internalBuf(this.md.digest(), 'hex');
  };

  return obj;
};


exports.createSign = function(alg) 
{
  if (alg != 'RSA-SHA256')
    throw new Error('createSign: unsupported algorithm.');

  var obj = {};

  obj.arr = [];

  obj.update = function(buf) {
    this.arr.push(buf);
  };

  obj.sign = function(keypem) {
    var rsa = new RSAKey();
    rsa.readPrivateKeyFromPEMString(keypem);
    var signer = new KJUR.crypto.Signature({alg: "SHA256withRSA", prov: "cryptojs/jsrsa"});
    signer.initSign(rsa);
    for (var i = 0; i < this.arr.length; ++i)
      signer.updateHex(this.arr[i].toString('hex'));

    return new internalBuf(signer.sign(), 'hex');
  };

  return obj;
};


exports.createVerify = function(alg) 
{
  if (alg != 'RSA-SHA256')
    throw new Error('createSign: unsupported algorithm.');

  var obj = {};
    
  obj.arr = [];

  obj.update = function(buf) {
    this.arr.push(buf);
  };

  var getSubjectPublicKeyPosFromHex = function(hPub) {  
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hPub, 0); 
    if (a.length != 2) 
      return -1;
    var pBitString = a[1];
    if (hPub.substring(pBitString, pBitString + 2) != '03') 
      return -1;
    var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hPub, pBitString);
    if (hPub.substring(pBitStringV, pBitStringV + 2) != '00') 
      return -1;
    return pBitStringV + 2;
  };

  var readPublicDER = function(pub_der) {
    var hex = pub_der.toString('hex'); 
    var p = getSubjectPublicKeyPosFromHex(hex);
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hex, p);
    if (a.length != 2) 
      return null;
    var hN = ASN1HEX.getHexOfV_AtObj(hex, a[0]);
    var hE = ASN1HEX.getHexOfV_AtObj(hex, a[1]);
    var rsaKey = new RSAKey();
    rsaKey.setPublic(hN, hE);
    return rsaKey;
  };

  obj.verify = function(keypem, sig) {
    var key = new ndn.Key();
    key.fromPemString(keypem);

    var rsa = readPublicDER(key.publicToDER());
    var signer = new KJUR.crypto.Signature({alg: "SHA256withRSA", prov: "cryptojs/jsrsa"});
    signer.initVerifyByPublicKey(rsa);
    for (var i = 0; i < this.arr.length; i++)
      signer.updateHex(this.arr[i].toString('hex'));
    var hSig = sig.toString('hex'); 
    return signer.verify(hSig);
  };

  return obj;
};

exports.randomBytes = function(size)
{
  
  var result = new internalBuf(size);
  for (var i = 0; i < size; ++i)
    result[i] = Math.floor(Math.random() * 256);
  return result;
};

exports.internalBuf = internalBuf;
;
var CryptoJS = CryptoJS || (function (Math, undefined) {
    
    var C = {};

    
    var C_lib = C.lib = {};

    
    var Base = C_lib.Base = (function () {
        function F() {}

        return {
            
            extend: function (overrides) {
                
                F.prototype = this;
                var subtype = new F();

                
                if (overrides) {
                    subtype.mixIn(overrides);
                }

                
                if (!subtype.hasOwnProperty('init')) {
                    subtype.init = function () {
                        subtype.$super.init.apply(this, arguments);
                    };
                }

                
                subtype.init.prototype = subtype;

                
                subtype.$super = this;

                return subtype;
            },

            
            create: function () {
                var instance = this.extend();
                instance.init.apply(instance, arguments);

                return instance;
            },

            
            init: function () {
            },

            
            mixIn: function (properties) {
                for (var propertyName in properties) {
                    if (properties.hasOwnProperty(propertyName)) {
                        this[propertyName] = properties[propertyName];
                    }
                }

                
                if (properties.hasOwnProperty('toString')) {
                    this.toString = properties.toString;
                }
            },

            
            clone: function () {
                return this.init.prototype.extend(this);
            }
        };
    }());

    
    var WordArray = C_lib.WordArray = Base.extend({
        
        init: function (words, sigBytes) {
            words = this.words = words || [];

            if (sigBytes != undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 4;
            }
        },

        
        toString: function (encoder) {
            return (encoder || Hex).stringify(this);
        },

        
        concat: function (wordArray) {
            
            var thisWords = this.words;
            var thatWords = wordArray.words;
            var thisSigBytes = this.sigBytes;
            var thatSigBytes = wordArray.sigBytes;

            
            this.clamp();

            
            if (thisSigBytes % 4) {
                
                for (var i = 0; i < thatSigBytes; i++) {
                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                }
            } else if (thatWords.length > 0xffff) {
                
                for (var i = 0; i < thatSigBytes; i += 4) {
                    thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
                }
            } else {
                
                thisWords.push.apply(thisWords, thatWords);
            }
            this.sigBytes += thatSigBytes;

            
            return this;
        },

        
        clamp: function () {
            
            var words = this.words;
            var sigBytes = this.sigBytes;

            
            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
            words.length = Math.ceil(sigBytes / 4);
        },

        
        clone: function () {
            var clone = Base.clone.call(this);
            clone.words = this.words.slice(0);

            return clone;
        },

        
        random: function (nBytes) {
            var words = [];
            for (var i = 0; i < nBytes; i += 4) {
                words.push((Math.random() * 0x100000000) | 0);
            }

            return new WordArray.init(words, nBytes);
        }
    });

    
    var C_enc = C.enc = {};

    
    var Hex = C_enc.Hex = {
        
        stringify: function (wordArray) {
            
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            
            var hexChars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                hexChars.push((bite >>> 4).toString(16));
                hexChars.push((bite & 0x0f).toString(16));
            }

            return hexChars.join('');
        },

        
        parse: function (hexStr) {
            
            var hexStrLength = hexStr.length;

            
            var words = [];
            for (var i = 0; i < hexStrLength; i += 2) {
                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
            }

            return new WordArray.init(words, hexStrLength / 2);
        }
    };

    
    var Latin1 = C_enc.Latin1 = {
        
        stringify: function (wordArray) {
            
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            
            var latin1Chars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                latin1Chars.push(String.fromCharCode(bite));
            }

            return latin1Chars.join('');
        },

        
        parse: function (latin1Str) {
            
            var latin1StrLength = latin1Str.length;

            
            var words = [];
            for (var i = 0; i < latin1StrLength; i++) {
                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
            }

            return new WordArray.init(words, latin1StrLength);
        }
    };

    
    var Utf8 = C_enc.Utf8 = {
        
        stringify: function (wordArray) {
            try {
                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
            } catch (e) {
                throw new Error('Malformed UTF-8 data');
            }
        },

        
        parse: function (utf8Str) {
            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
        }
    };

    
    var internalBufedBlockAlgorithm = C_lib.internalBufedBlockAlgorithm = Base.extend({
        
        reset: function () {
            
            this._data = new WordArray.init();
            this._nDataBytes = 0;
        },

        
        _append: function (data) {
            
            if (typeof data == 'string') {
                data = Utf8.parse(data);
            }

            
            this._data.concat(data);
            this._nDataBytes += data.sigBytes;
        },

        
        _process: function (doFlush) {
            
            var data = this._data;
            var dataWords = data.words;
            var dataSigBytes = data.sigBytes;
            var blockSize = this.blockSize;
            var blockSizeBytes = blockSize * 4;

            
            var nBlocksReady = dataSigBytes / blockSizeBytes;
            if (doFlush) {
                
                nBlocksReady = Math.ceil(nBlocksReady);
            } else {
                
                
                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
            }

            
            var nWordsReady = nBlocksReady * blockSize;

            
            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

            
            if (nWordsReady) {
                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                    
                    this._doProcessBlock(dataWords, offset);
                }

                
                var processedWords = dataWords.splice(0, nWordsReady);
                data.sigBytes -= nBytesReady;
            }

            
            return new WordArray.init(processedWords, nBytesReady);
        },

        
        clone: function () {
            var clone = Base.clone.call(this);
            clone._data = this._data.clone();

            return clone;
        },

        _minBufferSize: 0
    });

    
    var Hasher = C_lib.Hasher = internalBufedBlockAlgorithm.extend({
        
        cfg: Base.extend(),

        
        init: function (cfg) {
            
            this.cfg = this.cfg.extend(cfg);

            
            this.reset();
        },

        
        reset: function () {
            
            internalBufedBlockAlgorithm.reset.call(this);

            
            this._doReset();
        },

        
        update: function (messageUpdate) {
            
            this._append(messageUpdate);

            
            this._process();

            
            return this;
        },

        
        finalize: function (messageUpdate) {
            
            if (messageUpdate) {
                this._append(messageUpdate);
            }

            
            var hash = this._doFinalize();

            return hash;
        },

        blockSize: 512/32,

        
        _createHelper: function (hasher) {
            return function (message, cfg) {
                return new hasher.init(cfg).finalize(message);
            };
        },

        
        _createHmacHelper: function (hasher) {
            return function (message, key) {
                return new C_algo.HMAC.init(hasher, key).finalize(message);
            };
        }
    });

    
    var C_algo = C.algo = {};

    return C;
}(Math));
;(function (Math) {
    
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;
    var Hasher = C_lib.Hasher;
    var C_algo = C.algo;

    
    var H = [];
    var K = [];

    
    (function () {
        function isPrime(n) {
            var sqrtN = Math.sqrt(n);
            for (var factor = 2; factor <= sqrtN; factor++) {
                if (!(n % factor)) {
                    return false;
                }
            }

            return true;
        }

        function getFractionalBits(n) {
            return ((n - (n | 0)) * 0x100000000) | 0;
        }

        var n = 2;
        var nPrime = 0;
        while (nPrime < 64) {
            if (isPrime(n)) {
                if (nPrime < 8) {
                    H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
                }
                K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

                nPrime++;
            }

            n++;
        }
    }());

    
    var W = [];

    
    var SHA256 = C_algo.SHA256 = Hasher.extend({
        _doReset: function () {
            this._hash = new WordArray.init(H.slice(0));
        },

        _doProcessBlock: function (M, offset) {
            
            var H = this._hash.words;

            
            var a = H[0];
            var b = H[1];
            var c = H[2];
            var d = H[3];
            var e = H[4];
            var f = H[5];
            var g = H[6];
            var h = H[7];

            
            for (var i = 0; i < 64; i++) {
                if (i < 16) {
                    W[i] = M[offset + i] | 0;
                } else {
                    var gamma0x = W[i - 15];
                    var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
                                  ((gamma0x << 14) | (gamma0x >>> 18)) ^
                                   (gamma0x >>> 3);

                    var gamma1x = W[i - 2];
                    var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
                                  ((gamma1x << 13) | (gamma1x >>> 19)) ^
                                   (gamma1x >>> 10);

                    W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
                }

                var ch  = (e & f) ^ (~e & g);
                var maj = (a & b) ^ (a & c) ^ (b & c);

                var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
                var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

                var t1 = h + sigma1 + ch + K[i] + W[i];
                var t2 = sigma0 + maj;

                h = g;
                g = f;
                f = e;
                e = (d + t1) | 0;
                d = c;
                c = b;
                b = a;
                a = (t1 + t2) | 0;
            }

            
            H[0] = (H[0] + a) | 0;
            H[1] = (H[1] + b) | 0;
            H[2] = (H[2] + c) | 0;
            H[3] = (H[3] + d) | 0;
            H[4] = (H[4] + e) | 0;
            H[5] = (H[5] + f) | 0;
            H[6] = (H[6] + g) | 0;
            H[7] = (H[7] + h) | 0;
        },

        _doFinalize: function () {
            
            var data = this._data;
            var dataWords = data.words;

            var nBitsTotal = this._nDataBytes * 8;
            var nBitsLeft = data.sigBytes * 8;

            
            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
            data.sigBytes = dataWords.length * 4;

            
            this._process();

            
            return this._hash;
        },

        clone: function () {
            var clone = Hasher.clone.call(this);
            clone._hash = this._hash.clone();

            return clone;
        }
    });

    
    C.SHA256 = Hasher._createHelper(SHA256);

    
    C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
}(Math));
;var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64pad="=";

function hex2b64(h) {
  var i;
  var c;
  var ret = "";
  for(i = 0; i+3 <= h.length; i+=3) {
    c = parseInt(h.substring(i,i+3),16);
    ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
  }
  if(i+1 == h.length) {
    c = parseInt(h.substring(i,i+1),16);
    ret += b64map.charAt(c << 2);
  }
  else if(i+2 == h.length) {
    c = parseInt(h.substring(i,i+2),16);
    ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
  }
  if (b64pad) while((ret.length & 3) > 0) ret += b64pad;
  return ret;
}


function b64tohex(s) {
  var ret = ""
  var i;
  var k = 0; 
  var slop;
  for(i = 0; i < s.length; ++i) {
    if(s.charAt(i) == b64pad) break;
    v = b64map.indexOf(s.charAt(i));
    if(v < 0) continue;
    if(k == 0) {
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 1;
    }
    else if(k == 1) {
      ret += int2char((slop << 2) | (v >> 4));
      slop = v & 0xf;
      k = 2;
    }
    else if(k == 2) {
      ret += int2char(slop);
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 3;
    }
    else {
      ret += int2char((slop << 2) | (v >> 4));
      ret += int2char(v & 0xf);
      k = 0;
    }
  }
  if(k == 1)
    ret += int2char(slop << 2);
  return ret;
}


function b64toBA(s) {
  
  var h = b64tohex(s);
  var i;
  var a = new Array();
  for(i = 0; 2*i < h.length; ++i) {
    a[i] = parseInt(h.substring(2*i,2*i+2),16);
  }
  return a;
}
;




function parseBigInt(str,r) {
  return new BigInteger(str,r);
}

function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}


function pkcs1pad2(s,n) {
  if(n < s.length + 11) { 
    alert("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { 
      ba[--n] = c;
    }
    else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    }
    else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var rng = new SecureRandom();
  var x = new Array();
  while(n > 2) { 
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}


function oaep_mgf1_arr(seed, len, hash)
{
    var mask = '', i = 0;

    while (mask.length < len)
    {
        mask += hash(String.fromCharCode.apply(String, seed.concat([
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff])));
        i += 1;
    }

    return mask;
}

var SHA1_SIZE = 20;


function oaep_pad(s, n, hash)
{
    if (s.length + 2 * SHA1_SIZE + 2 > n)
    {
        throw "Message too long for RSA";
    }

    var PS = '', i;

    for (i = 0; i < n - s.length - 2 * SHA1_SIZE - 2; i += 1)
    {
        PS += '\x00';
    }

    var DB = rstr_sha1('') + PS + '\x01' + s;
    var seed = new Array(SHA1_SIZE);
    new SecureRandom().nextBytes(seed);
    
    var dbMask = oaep_mgf1_arr(seed, DB.length, hash || rstr_sha1);
    var maskedDB = [];

    for (i = 0; i < DB.length; i += 1)
    {
        maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    var seedMask = oaep_mgf1_arr(maskedDB, seed.length, rstr_sha1);
    var maskedSeed = [0];

    for (i = 0; i < seed.length; i += 1)
    {
        maskedSeed[i + 1] = seed[i] ^ seedMask.charCodeAt(i);
    }

    return new BigInteger(maskedSeed.concat(maskedDB));
}


function RSAKey() {
  this.n = null;
  this.e = 0;
  this.d = null;
  this.p = null;
  this.q = null;
  this.dmp1 = null;
  this.dmq1 = null;
  this.coeff = null;
}


function RSASetPublic(N,E) {
  if (typeof N !== "string")
  {
    this.n = N;
    this.e = E;
  }
  else if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
  }
  else
    alert("Invalid RSA public key");
}


function RSADoPublic(x) {
  return x.modPowInt(this.e, this.n);
}


function RSAEncrypt(text) {
  var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}


function RSAEncryptOAEP(text, hash) {
  var m = oaep_pad(text, (this.n.bitLength()+7)>>3, hash);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}








RSAKey.prototype.doPublic = RSADoPublic;


RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
RSAKey.prototype.encryptOAEP = RSAEncryptOAEP;

;




function pkcs1unpad2(d,n) {
  var b = d.toByteArray();
  var i = 0;
  while(i < b.length && b[i] == 0) ++i;
  if(b.length-i != n-1 || b[i] != 2)
    return null;
  ++i;
  while(b[i] != 0)
    if(++i >= b.length) return null;
  var ret = "";
  while(++i < b.length) {
    var c = b[i] & 255;
    if(c < 128) { 
      ret += String.fromCharCode(c);
    }
    else if((c > 191) && (c < 224)) {
      ret += String.fromCharCode(((c & 31) << 6) | (b[i+1] & 63));
      ++i;
    }
    else {
      ret += String.fromCharCode(((c & 15) << 12) | ((b[i+1] & 63) << 6) | (b[i+2] & 63));
      i += 2;
    }
  }
  return ret;
}


function oaep_mgf1_str(seed, len, hash)
{
    var mask = '', i = 0;

    while (mask.length < len)
    {
        mask += hash(seed + String.fromCharCode.apply(String, [
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff]));
        i += 1;
    }

    return mask;
}

var SHA1_SIZE = 20;


function oaep_unpad(d, n, hash)
{
    d = d.toByteArray();

    var i;

    for (i = 0; i < d.length; i += 1)
    {
        d[i] &= 0xff;
    }

    while (d.length < n)
    {
        d.unshift(0);
    }

    d = String.fromCharCode.apply(String, d);

    if (d.length < 2 * SHA1_SIZE + 2)
    {
        throw "Cipher too short";
    }

    var maskedSeed = d.substr(1, SHA1_SIZE)
    var maskedDB = d.substr(SHA1_SIZE + 1);

    var seedMask = oaep_mgf1_str(maskedDB, SHA1_SIZE, hash || rstr_sha1);
    var seed = [], i;

    for (i = 0; i < maskedSeed.length; i += 1)
    {
        seed[i] = maskedSeed.charCodeAt(i) ^ seedMask.charCodeAt(i);
    }

    var dbMask = oaep_mgf1_str(String.fromCharCode.apply(String, seed),
                           d.length - SHA1_SIZE, rstr_sha1);

    var DB = [];

    for (i = 0; i < maskedDB.length; i += 1)
    {
        DB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    DB = String.fromCharCode.apply(String, DB);

    if (DB.substr(0, SHA1_SIZE) !== rstr_sha1(''))
    {
        throw "Hash mismatch";
    }

    DB = DB.substr(SHA1_SIZE);

    var first_one = DB.indexOf('\x01');
    var last_zero = (first_one != -1) ? DB.substr(0, first_one).lastIndexOf('\x00') : -1;

    if (last_zero + 1 != first_one)
    {
        throw "Malformed data";
    }

    return DB.substr(first_one + 1);
}


function RSASetPrivate(N,E,D) {
  if (typeof N !== "string")
  {
    this.n = N;
    this.e = E;
    this.d = D;
  }
  else if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
    this.d = parseBigInt(D,16);
  }
  else
    alert("Invalid RSA private key");
}


function RSASetPrivateEx(N,E,D,P,Q,DP,DQ,C) {
  
  if (N == null) throw "RSASetPrivateEx N == null";
  if (E == null) throw "RSASetPrivateEx E == null";
  if (N.length == 0) throw "RSASetPrivateEx N.length == 0";
  if (E.length == 0) throw "RSASetPrivateEx E.length == 0";

  if (N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
    this.d = parseBigInt(D,16);
    this.p = parseBigInt(P,16);
    this.q = parseBigInt(Q,16);
    this.dmp1 = parseBigInt(DP,16);
    this.dmq1 = parseBigInt(DQ,16);
    this.coeff = parseBigInt(C,16);
  } else {
    alert("Invalid RSA private key in RSASetPrivateEx");
  }
}


function RSAGenerate(B,E) {
  var rng = new SecureRandom();
  var qs = B>>1;
  this.e = parseInt(E,16);
  var ee = new BigInteger(E,16);
  for(;;) {
    for(;;) {
      this.p = new BigInteger(B-qs,1,rng);
      if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
    }
    for(;;) {
      this.q = new BigInteger(qs,1,rng);
      if(this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
    }
    if(this.p.compareTo(this.q) <= 0) {
      var t = this.p;
      this.p = this.q;
      this.q = t;
    }
    var p1 = this.p.subtract(BigInteger.ONE);	
    var q1 = this.q.subtract(BigInteger.ONE);	
    var phi = p1.multiply(q1);
    if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
      this.n = this.p.multiply(this.q);	
      this.d = ee.modInverse(phi);	
      this.dmp1 = this.d.mod(p1);	
      this.dmq1 = this.d.mod(q1);	
      this.coeff = this.q.modInverse(this.p);	
      break;
    }
  }
}


function RSADoPrivate(x) {
  if(this.p == null || this.q == null)
    return x.modPow(this.d, this.n);

  
  var xp = x.mod(this.p).modPow(this.dmp1, this.p); 
  var xq = x.mod(this.q).modPow(this.dmq1, this.q); 

  while(xp.compareTo(xq) < 0)
    xp = xp.add(this.p);
  
  
  
  
  return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}



function RSADecrypt(ctext) {
  var c = parseBigInt(ctext, 16);
  var m = this.doPrivate(c);
  if(m == null) return null;
  return pkcs1unpad2(m, (this.n.bitLength()+7)>>3);
}



function RSADecryptOAEP(ctext, hash) {
  var c = parseBigInt(ctext, 16);
  var m = this.doPrivate(c);
  if(m == null) return null;
  return oaep_unpad(m, (this.n.bitLength()+7)>>3, hash);
}









RSAKey.prototype.doPrivate = RSADoPrivate;


RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.decrypt = RSADecrypt;
RSAKey.prototype.decryptOAEP = RSADecryptOAEP;

;





if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};


KJUR.crypto.Util = new function() {
    this.DIGESTINFOHEAD = {
	'sha1':      "3021300906052b0e03021a05000414",
        'sha224':    "302d300d06096086480165030402040500041c",
	'sha256':    "3031300d060960864801650304020105000420",
	'sha384':    "3041300d060960864801650304020205000430",
	'sha512':    "3051300d060960864801650304020305000440",
	'md2':       "3020300c06082a864886f70d020205000410",
	'md5':       "3020300c06082a864886f70d020505000410",
	'ripemd160': "3021300906052b2403020105000414"
    };

    
    this.getDigestInfoHex = function(hHash, alg) {
	if (typeof this.DIGESTINFOHEAD[alg] == "undefined")
	    throw "alg not supported in Util.DIGESTINFOHEAD: " + alg;
	return this.DIGESTINFOHEAD[alg] + hHash;
    };

    
    this.getPaddedDigestInfoHex = function(hHash, alg, keySize) {
	var hDigestInfo = this.getDigestInfoHex(hHash, alg);
	var pmStrLen = keySize / 4; 

	if (hDigestInfo.length + 22 > pmStrLen) 
	    throw "key is too short for SigAlg: keylen=" + keySize + "," + alg;

	var hHead = "0001";
	var hTail = "00" + hDigestInfo;
	var hMid = "";
	var fLen = pmStrLen - hHead.length - hTail.length;
	for (var i = 0; i < fLen; i += 2) {
	    hMid += "ff";
	}
	var hPaddedMessage = hHead + hMid + hTail;
	return hPaddedMessage;
    };

    
    this.sha1 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha1', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    
    this.sha256 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    
    this.sha512 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    
    this.md5 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'md5', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    
    this.ripemd160 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'ripemd160', 'prov':'cryptojs'});
        return md.digestString(s);
    };
};


KJUR.crypto.MessageDigest = function(params) {
    var md = null;
    var algName = null;
    var provName = null;
    var _CryptoJSMdName = {
	'md5': 'CryptoJS.algo.MD5',
	'sha1': 'CryptoJS.algo.SHA1',
	'sha224': 'CryptoJS.algo.SHA224',
	'sha256': 'CryptoJS.algo.SHA256',
	'sha384': 'CryptoJS.algo.SHA384',
	'sha512': 'CryptoJS.algo.SHA512',
	'ripemd160': 'CryptoJS.algo.RIPEMD160'
    };

    
    this.setAlgAndProvider = function(alg, prov) {
	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(alg) != -1 &&
	    prov == 'cryptojs') {
	    try {
		this.md = eval(_CryptoJSMdName[alg]).create();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var wHex = CryptoJS.enc.Hex.parse(hex);
		this.md.update(wHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return hash.toString(CryptoJS.enc.Hex);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
	if (':sha256:'.indexOf(alg) != -1 &&
	    prov == 'sjcl') {
	    try {
		this.md = new sjcl.hash.sha256();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var baHex = sjcl.codec.hex.toBits(hex);
		this.md.update(baHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return sjcl.codec.hex.fromBits(hash);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
    };

    
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    
    this.digest = function() {
	throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    
    this.digestString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    
    this.digestHex = function(hex) {
	throw "digestHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    if (typeof params != "undefined") {
	if (typeof params['alg'] != "undefined") {
	    this.algName = params['alg'];
	    this.provName = params['prov'];
	    this.setAlgAndProvider(params['alg'], params['prov']);
	}
    }
};



KJUR.crypto.Signature = function(params) {
    var prvKey = null; 
    var pubKey = null; 

    var md = null; 
    var sig = null;
    var algName = null;
    var provName = null;
    var algProvName = null;
    var mdAlgName = null;
    var pubkeyAlgName = null;
    var state = null;

    var sHashHex = null; 
    var hDigestInfo = null;
    var hPaddedDigestInfo = null;
    var hSign = null;

    this._setAlgNames = function() {
	if (this.algName.match(/^(.+)with(.+)$/)) {
	    this.mdAlgName = RegExp.$1.toLowerCase();
	    this.pubkeyAlgName = RegExp.$2.toLowerCase();
	}
    };

    this._zeroPaddingOfSignature = function(hex, bitLength) {
	var s = "";
	var nZero = bitLength / 4 - hex.length;
	for (var i = 0; i < nZero; i++) {
	    s = s + "0";
	}
	return s + hex;
    };

    
    this.setAlgAndProvider = function(alg, prov) {
	this._setAlgNames();
	if (prov != 'cryptojs/jsrsa')
	    throw "provider not supported: " + prov;

	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(this.mdAlgName) != -1) {
	    try {
		this.md = new KJUR.crypto.MessageDigest({'alg':this.mdAlgName,'prov':'cryptojs'});
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + this.mdAlgName + "/" + ex;
	    }

	    this.initSign = function(prvKey) {
		this.prvKey = prvKey;
		this.state = "SIGN";
	    };

	    this.initVerifyByPublicKey = function(rsaPubKey) {
		this.pubKey = rsaPubKey;
		this.state = "VERIFY";
	    };

	    this.initVerifyByCertificatePEM = function(certPEM) {
		var x509 = new X509();
		x509.readCertPEM(certPEM);
		this.pubKey = x509.subjectPublicKeyRSA;
		this.state = "VERIFY";
	    };

	    this.updateString = function(str) {
		this.md.updateString(str);
	    };
	    this.updateHex = function(hex) {
		this.md.updateHex(hex);
	    };
	    this.sign = function() {
                var util = KJUR.crypto.Util;
		var keyLen = this.prvKey.n.bitLength();
		this.sHashHex = this.md.digest();
		this.hDigestInfo = util.getDigestInfoHex(this.sHashHex, this.mdAlgName);
		this.hPaddedDigestInfo = 
                    util.getPaddedDigestInfoHex(this.sHashHex, this.mdAlgName, keyLen);

		var biPaddedDigestInfo = parseBigInt(this.hPaddedDigestInfo, 16);
		this.hoge = biPaddedDigestInfo.toString(16);

		var biSign = this.prvKey.doPrivate(biPaddedDigestInfo);
		this.hSign = this._zeroPaddingOfSignature(biSign.toString(16), keyLen);
		return this.hSign;
	    };
	    this.signString = function(str) {
		this.updateString(str);
		this.sign();
	    };
	    this.signHex = function(hex) {
		this.updateHex(hex);
		this.sign();
	    };
	    this.verify = function(hSigVal) {
                var util = KJUR.crypto.Util;
		var keyLen = this.pubKey.n.bitLength();
		this.sHashHex = this.md.digest();

		var biSigVal = parseBigInt(hSigVal, 16);
		var biPaddedDigestInfo = this.pubKey.doPublic(biSigVal);
		this.hPaddedDigestInfo = biPaddedDigestInfo.toString(16);
                var s = this.hPaddedDigestInfo;
                s = s.replace(/^1ff+00/, '');

		var hDIHEAD = KJUR.crypto.Util.DIGESTINFOHEAD[this.mdAlgName];
                if (s.indexOf(hDIHEAD) != 0) {
		    return false;
		}
		var hHashFromDI = s.substr(hDIHEAD.length);
		
		return (hHashFromDI == this.sHashHex);
	    };
	}
    };

    
    this.initVerifyByPublicKey = function(rsaPubKey) {
	throw "initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov=" + this.algProvName;
    };

    
    this.initVerifyByCertificatePEM = function(certPEM) {
	throw "initVerifyByCertificatePEM(certPEM) not supported for this alg:prov=" + this.algProvName;
    };

    
    this.initSign = function(prvKey) {
	throw "initSign(prvKey) not supported for this alg:prov=" + this.algProvName;
    };

    
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg:prov=" + this.algProvName;
    };

    
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    
    this.sign = function() {
	throw "sign() not supported for this alg:prov=" + this.algProvName;
    };

    
    this.signString = function(str) {
	throw "digestString(str) not supported for this alg:prov=" + this.algProvName;
    };

    
    this.signHex = function(hex) {
	throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    
    this.verify = function(hSigVal) {
	throw "verify(hSigVal) not supported for this alg:prov=" + this.algProvName;
    };

    if (typeof params != "undefined") {
	if (typeof params['alg'] != "undefined") {
	    this.algName = params['alg'];
	    this.provName = params['prov'];
	    this.algProvName = params['alg'] + ":" + params['prov'];
	    this.setAlgAndProvider(params['alg'], params['prov']);
	    this._setAlgNames();
	}
	if (typeof params['prvkeypem'] != "undefined") {
	    if (typeof params['prvkeypas'] != "undefined") {
		throw "both prvkeypem and prvkeypas parameters not supported";
	    } else {
		try {
		    var prvKey = new RSAKey();
		    prvKey.readPrivateKeyFromPEMString(params['prvkeypem']);
		    this.initSign(prvKey);
		} catch (ex) {
		    throw "fatal error to load pem private key: " + ex;
		}
	    }
	}
    }
};

;


























function _rsapem_pemToBase64(sPEMPrivateKey) {
  var s = sPEMPrivateKey;
  s = s.replace("-----BEGIN RSA PRIVATE KEY-----", "");
  s = s.replace("-----END RSA PRIVATE KEY-----", "");
  s = s.replace(/[ \n]+/g, "");
  return s;
}

function _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey) {
  var a = new Array();
  var v1 = ASN1HEX.getStartPosOfV_AtObj(hPrivateKey, 0);
  var n1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, v1);
  var e1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, n1);
  var d1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, e1);
  var p1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, d1);
  var q1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, p1);
  var dp1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, q1);
  var dq1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, dp1);
  var co1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, dq1);
  a.push(v1, n1, e1, d1, p1, q1, dp1, dq1, co1);
  return a;
}

function _rsapem_getHexValueArrayOfChildrenFromHex(hPrivateKey) {
  var posArray = _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey);
  var v =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[0]);
  var n =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[1]);
  var e =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[2]);
  var d =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[3]);
  var p =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[4]);
  var q =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[5]);
  var dp = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[6]);
  var dq = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[7]);
  var co = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[8]);
  var a = new Array();
  a.push(v, n, e, d, p, q, dp, dq, co);
  return a;
}


function _rsapem_readPrivateKeyFromASN1HexString(keyHex) {
  var a = _rsapem_getHexValueArrayOfChildrenFromHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
}


function _rsapem_readPrivateKeyFromPEMString(keyPEM) {
  var keyB64 = _rsapem_pemToBase64(keyPEM);
  var keyHex = b64tohex(keyB64) 
  var a = _rsapem_getHexValueArrayOfChildrenFromHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
}

RSAKey.prototype.readPrivateKeyFromPEMString = _rsapem_readPrivateKeyFromPEMString;
RSAKey.prototype.readPrivateKeyFromASN1HexString = _rsapem_readPrivateKeyFromASN1HexString;
;
































var _RSASIGN_DIHEAD = [];
_RSASIGN_DIHEAD['sha1'] =      "3021300906052b0e03021a05000414";
_RSASIGN_DIHEAD['sha256'] =    "3031300d060960864801650304020105000420";
_RSASIGN_DIHEAD['sha384'] =    "3041300d060960864801650304020205000430";
_RSASIGN_DIHEAD['sha512'] =    "3051300d060960864801650304020305000440";
_RSASIGN_DIHEAD['md2'] =       "3020300c06082a864886f70d020205000410";
_RSASIGN_DIHEAD['md5'] =       "3020300c06082a864886f70d020505000410";
_RSASIGN_DIHEAD['ripemd160'] = "3021300906052b2403020105000414";


var _RSASIGN_HASHHEXFUNC = [];
_RSASIGN_HASHHEXFUNC['sha1'] =      function(s){return KJUR.crypto.Util.sha1(s);};
_RSASIGN_HASHHEXFUNC['sha256'] =    function(s){return KJUR.crypto.Util.sha256(s);}
_RSASIGN_HASHHEXFUNC['sha512'] =    function(s){return KJUR.crypto.Util.sha512(s);}
_RSASIGN_HASHHEXFUNC['md5'] =       function(s){return KJUR.crypto.Util.md5(s);};
_RSASIGN_HASHHEXFUNC['ripemd160'] = function(s){return KJUR.crypto.Util.ripemd160(s);};




var _RE_HEXDECONLY = new RegExp("");
_RE_HEXDECONLY.compile("[^0-9a-f]", "gi");





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

function _zeroPaddingOfSignature(hex, bitLength) {
    var s = "";
    var nZero = bitLength / 4 - hex.length;
    for (var i = 0; i < nZero; i++) {
	s = s + "0";
    }
    return s + hex;
}


function _rsasign_signString(s, hashAlg) {
    
    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
    var biPaddedMessage = parseBigInt(hPM, 16);
    var biSign = this.doPrivate(biPaddedMessage);
    var hexSign = biSign.toString(16);
    return _zeroPaddingOfSignature(hexSign, this.n.bitLength());
}

function _rsasign_signStringWithSHA1(s) {
    return _rsasign_signString.call(this, s, 'sha1');
}

function _rsasign_signStringWithSHA256(s) {
    return _rsasign_signString.call(this, s, 'sha256');
}


function pss_mgf1_str(seed, len, hash) {
    var mask = '', i = 0;

    while (mask.length < len) {
        mask += hash(seed + String.fromCharCode.apply(String, [
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff]));
        i += 1;
    }

    return mask;
}


function _rsasign_signStringPSS(s, hashAlg, sLen) {
    var hashFunc = _RSASIGN_HASHRAWFUNC[hashAlg];
    var mHash = hashFunc(s);
    var hLen = mHash.length;
    var emBits = this.n.bitLength() - 1;
    var emLen = Math.ceil(emBits / 8);
    var i;

    if (sLen === -1) {
        sLen = hLen; 
    } else if ((sLen === -2) || (sLen === undefined)) {
        sLen = emLen - hLen - 2; 
    } else if (sLen < -2) {
        throw "invalid salt length";
    }

    if (emLen < (hLen + sLen + 2)) {
        throw "data too long";
    }

    var salt = '';

    if (sLen > 0) {
        salt = new Array(sLen);
        new SecureRandom().nextBytes(salt);
        salt = String.fromCharCode.apply(String, salt);
    }

    var H = hashFunc('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash + salt);
    var PS = [];

    for (i = 0; i < emLen - sLen - hLen - 2; i += 1) {
        PS[i] = 0x00;
    }

    var DB = String.fromCharCode.apply(String, PS) + '\x01' + salt;
    var dbMask = pss_mgf1_str(H, DB.length, hashFunc);
    var maskedDB = [];

    for (i = 0; i < DB.length; i += 1) {
        maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    var mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
    maskedDB[0] &= ~mask;

    for (i = 0; i < hLen; i++) {
        maskedDB.push(H.charCodeAt(i));
    }

    maskedDB.push(0xbc);

    return _zeroPaddingOfSignature(
            this.doPrivate(new BigInteger(maskedDB)).toString(16),
            this.n.bitLength());
}





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


function _rsasign_verifyString(sMsg, hSig) {
    hSig = hSig.replace(_RE_HEXDECONLY, '');
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


function _rsasign_verifyStringPSS(sMsg, hSig, hashAlg, sLen) {
    if (hSig.length !== this.n.bitLength() / 4) {
        return false;
    }

    var hashFunc = _RSASIGN_HASHRAWFUNC[hashAlg];
    var mHash = hashFunc(sMsg);
    var hLen = mHash.length;
    var emBits = this.n.bitLength() - 1;
    var emLen = Math.ceil(emBits / 8);
    var i;

    if (sLen === -1) {
        sLen = hLen; 
    } else if ((sLen === -2) || (sLen === undefined)) {
        sLen = emLen - hLen - 2; 
    } else if (sLen < -2) {
        throw "invalid salt length";
    }

    if (emLen < (hLen + sLen + 2)) {
        throw "data too long";
    }

    var em = this.doPublic(parseBigInt(hSig, 16)).toByteArray();

    for (i = 0; i < em.length; i += 1) {
        em[i] &= 0xff;
    }

    while (em.length < emLen) {
        em.unshift(0);
    }

    if (em[emLen -1] !== 0xbc) {
        throw "encoded message does not end in 0xbc";
    }

    em = String.fromCharCode.apply(String, em);

    var maskedDB = em.substr(0, emLen - hLen - 1);
    var H = em.substr(maskedDB.length, hLen);

    var mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;

    if ((maskedDB.charCodeAt(0) & mask) !== 0) {
        throw "bits beyond keysize not zero";
    }

    var dbMask = pss_mgf1_str(H, maskedDB.length, hashFunc);
    var DB = [];

    for (i = 0; i < maskedDB.length; i += 1) {
        DB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    DB[0] &= ~mask;

    var checkLen = emLen - hLen - sLen - 2;

    for (i = 0; i < checkLen; i += 1) {
        if (DB[i] !== 0x00) {
            throw "leftmost octets not zero";
        }
    }

    if (DB[checkLen] !== 0x01) {
        throw "0x01 marker not found";
    }

    return H === hashFunc('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash +
                          String.fromCharCode.apply(String, DB.slice(-sLen)));
}

RSAKey.prototype.signString = _rsasign_signString;
RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;
RSAKey.prototype.sign = _rsasign_signString;
RSAKey.prototype.signWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signWithSHA256 = _rsasign_signStringWithSHA256;
RSAKey.prototype.signStringPSS = _rsasign_signStringPSS;
RSAKey.prototype.signPSS = _rsasign_signStringPSS;
RSAKey.SALT_LEN_HLEN = -1;
RSAKey.SALT_LEN_MAX = -2;

RSAKey.prototype.verifyString = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;
RSAKey.prototype.verify = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForByteArrayMessage = _rsasign_verifyHexSignatureForMessage;
RSAKey.prototype.verifyStringPSS = _rsasign_verifyStringPSS;
RSAKey.prototype.verifyPSS = _rsasign_verifyStringPSS;
RSAKey.SALT_LEN_RECOVER = -2;


;































function _asnhex_getByteLengthOfL_AtObj(s, pos) {
  if (s.substring(pos + 2, pos + 3) != '8') return 1;
  var i = parseInt(s.substring(pos + 3, pos + 4));
  if (i == 0) return -1; 		
  if (0 < i && i < 10) return i + 1;	
  return -2;				
}



function _asnhex_getHexOfL_AtObj(s, pos) {
  var len = _asnhex_getByteLengthOfL_AtObj(s, pos);
  if (len < 1) return '';
  return s.substring(pos + 2, pos + 2 + len * 2);
}










function _asnhex_getIntOfL_AtObj(s, pos) {
  var hLength = _asnhex_getHexOfL_AtObj(s, pos);
  if (hLength == '') return -1;
  var bi;
  if (parseInt(hLength.substring(0, 1)) < 8) {
     bi = parseBigInt(hLength, 16);
  } else {
     bi = parseBigInt(hLength.substring(2), 16);
  }
  return bi.intValue();
}


function _asnhex_getStartPosOfV_AtObj(s, pos) {
  var l_len = _asnhex_getByteLengthOfL_AtObj(s, pos);
  if (l_len < 0) return l_len;
  return pos + (l_len + 1) * 2;
}


function _asnhex_getHexOfV_AtObj(s, pos) {
  var pos1 = _asnhex_getStartPosOfV_AtObj(s, pos);
  var len = _asnhex_getIntOfL_AtObj(s, pos);
  return s.substring(pos1, pos1 + len * 2);
}


function _asnhex_getHexOfTLV_AtObj(s, pos) {
  var hT = s.substr(pos, 2);
  var hL = _asnhex_getHexOfL_AtObj(s, pos);
  var hV = _asnhex_getHexOfV_AtObj(s, pos);
  return hT + hL + hV;
}


function _asnhex_getPosOfNextSibling_AtObj(s, pos) {
  var pos1 = _asnhex_getStartPosOfV_AtObj(s, pos);
  var len = _asnhex_getIntOfL_AtObj(s, pos);
  return pos1 + len * 2;
}


function _asnhex_getPosArrayOfChildren_AtObj(h, pos) {
  var a = new Array();
  var p0 = _asnhex_getStartPosOfV_AtObj(h, pos);
  a.push(p0);

  var len = _asnhex_getIntOfL_AtObj(h, pos);
  var p = p0;
  var k = 0;
  while (1) {
    var pNext = _asnhex_getPosOfNextSibling_AtObj(h, p);
    if (pNext == null || (pNext - p0  >= (len * 2))) break;
    if (k >= 200) break;

    a.push(pNext);
    p = pNext;

    k++;
  }

  return a;
}


function _asnhex_getNthChildIndex_AtObj(h, idx, nth) {
  var a = _asnhex_getPosArrayOfChildren_AtObj(h, idx);
  return a[nth];
}




function _asnhex_getDecendantIndexByNthList(h, currentIndex, nthList) {
  if (nthList.length == 0) {
    return currentIndex;
  }
  var firstNth = nthList.shift();
  var a = _asnhex_getPosArrayOfChildren_AtObj(h, currentIndex);
  return _asnhex_getDecendantIndexByNthList(h, a[firstNth], nthList);
}


function _asnhex_getDecendantHexTLVByNthList(h, currentIndex, nthList) {
  var idx = _asnhex_getDecendantIndexByNthList(h, currentIndex, nthList);
  return _asnhex_getHexOfTLV_AtObj(h, idx);
}


function _asnhex_getDecendantHexVByNthList(h, currentIndex, nthList) {
  var idx = _asnhex_getDecendantIndexByNthList(h, currentIndex, nthList);
  return _asnhex_getHexOfV_AtObj(h, idx);
}




function ASN1HEX() {
  return ASN1HEX;
}

ASN1HEX.getByteLengthOfL_AtObj = _asnhex_getByteLengthOfL_AtObj;
ASN1HEX.getHexOfL_AtObj = _asnhex_getHexOfL_AtObj;
ASN1HEX.getIntOfL_AtObj = _asnhex_getIntOfL_AtObj;
ASN1HEX.getStartPosOfV_AtObj = _asnhex_getStartPosOfV_AtObj;
ASN1HEX.getHexOfV_AtObj = _asnhex_getHexOfV_AtObj;
ASN1HEX.getHexOfTLV_AtObj = _asnhex_getHexOfTLV_AtObj;
ASN1HEX.getPosOfNextSibling_AtObj = _asnhex_getPosOfNextSibling_AtObj;
ASN1HEX.getPosArrayOfChildren_AtObj = _asnhex_getPosArrayOfChildren_AtObj;
ASN1HEX.getNthChildIndex_AtObj = _asnhex_getNthChildIndex_AtObj;
ASN1HEX.getDecendantIndexByNthList = _asnhex_getDecendantIndexByNthList;
ASN1HEX.getDecendantHexVByNthList = _asnhex_getDecendantHexVByNthList;
ASN1HEX.getDecendantHexTLVByNthList = _asnhex_getDecendantHexTLVByNthList;
;





















function _x509_pemToBase64(sCertPEM) {
  var s = sCertPEM;
  s = s.replace("-----BEGIN CERTIFICATE-----", "");
  s = s.replace("-----END CERTIFICATE-----", "");
  s = s.replace(/[ \n]+/g, "");
  return s;
}

function _x509_pemToHex(sCertPEM) {
  var b64Cert = _x509_pemToBase64(sCertPEM);
  var hCert = b64tohex(b64Cert);
  return hCert;
}

function _x509_getHexTbsCertificateFromCert(hCert) {
  var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
  return pTbsCert;
}



function _x509_getSubjectPublicKeyInfoPosFromCertHex(hCert) {
  var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pTbsCert); 
  if (a.length < 1) return -1;
  if (hCert.substring(a[0], a[0] + 10) == "a003020102") { 
    if (a.length < 6) return -1;
    return a[6];
  } else {
    if (a.length < 5) return -1;
    return a[5];
  }
}


function _x509_getSubjectPublicKeyPosFromCertHex(hCert) {
  var pInfo = _x509_getSubjectPublicKeyInfoPosFromCertHex(hCert);
  if (pInfo == -1) return -1;    
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pInfo); 
  if (a.length != 2) return -1;
  var pBitString = a[1];
  if (hCert.substring(pBitString, pBitString + 2) != '03') return -1;
  var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hCert, pBitString);

  if (hCert.substring(pBitStringV, pBitStringV + 2) != '00') return -1;
  return pBitStringV + 2;
}

function _x509_getPublicKeyHexArrayFromCertHex(hCert) {
  var p = _x509_getSubjectPublicKeyPosFromCertHex(hCert);
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p); 
  if (a.length != 2) return [];
  var hN = ASN1HEX.getHexOfV_AtObj(hCert, a[0]);
  var hE = ASN1HEX.getHexOfV_AtObj(hCert, a[1]);
  if (hN != null && hE != null) {
    return [hN, hE];
  } else {
    return [];
  }
}

function _x509_getPublicKeyHexArrayFromCertPEM(sCertPEM) {
  var hCert = _x509_pemToHex(sCertPEM);
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
  return a;
}



function _x509_getSerialNumberHex() {
  return ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 1]);
}


function _x509_getIssuerHex() {
  return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]);
}


function _x509_getIssuerString() {
  return _x509_hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]));
}


function _x509_getSubjectHex() {
  return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]);
}


function _x509_getSubjectString() {
  return _x509_hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]));
}


function _x509_getNotBefore() {
  var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 0]);
  s = s.replace(/(..)/g, "%$1");
  s = decodeURIComponent(s);
  return s;
}


function _x509_getNotAfter() {
  var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 1]);
  s = s.replace(/(..)/g, "%$1");
  s = decodeURIComponent(s);
  return s;
}



_x509_DN_ATTRHEX = {
    "0603550406": "C",
    "060355040a": "O",
    "060355040b": "OU",
    "0603550403": "CN",
    "0603550405": "SN",
    "0603550408": "ST",
    "0603550407": "L" };

function _x509_hex2dn(hDN) {
  var s = "";
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hDN, 0);
  for (var i = 0; i < a.length; i++) {
    var hRDN = ASN1HEX.getHexOfTLV_AtObj(hDN, a[i]);
    s = s + "/" + _x509_hex2rdn(hRDN);
  }
  return s;
}

function _x509_hex2rdn(hRDN) {
    var hType = ASN1HEX.getDecendantHexTLVByNthList(hRDN, 0, [0, 0]);
    var hValue = ASN1HEX.getDecendantHexVByNthList(hRDN, 0, [0, 1]);
    var type = "";
    try { type = _x509_DN_ATTRHEX[hType]; } catch (ex) { type = hType; }
    hValue = hValue.replace(/(..)/g, "%$1");
    var value = decodeURIComponent(hValue);
    return type + "=" + value;
}





function _x509_readCertPEM(sCertPEM) {
  var hCert = _x509_pemToHex(sCertPEM);
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
  var rsa = new RSAKey();
  rsa.setPublic(a[0], a[1]);
  this.subjectPublicKeyRSA = rsa;
  this.subjectPublicKeyRSA_hN = a[0];
  this.subjectPublicKeyRSA_hE = a[1];
  this.hex = hCert;
}

function _x509_readCertPEMWithoutRSAInit(sCertPEM) {
  var hCert = _x509_pemToHex(sCertPEM);
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
  this.subjectPublicKeyRSA.setPublic(a[0], a[1]);
  this.subjectPublicKeyRSA_hN = a[0];
  this.subjectPublicKeyRSA_hE = a[1];
  this.hex = hCert;
}


function X509() {
  this.subjectPublicKeyRSA = null;
  this.subjectPublicKeyRSA_hN = null;
  this.subjectPublicKeyRSA_hE = null;
  this.hex = null;
}

X509.prototype.readCertPEM = _x509_readCertPEM;
X509.prototype.readCertPEMWithoutRSAInit = _x509_readCertPEMWithoutRSAInit;
X509.prototype.getSerialNumberHex = _x509_getSerialNumberHex;
X509.prototype.getIssuerHex = _x509_getIssuerHex;
X509.prototype.getSubjectHex = _x509_getSubjectHex;
X509.prototype.getIssuerString = _x509_getIssuerString;
X509.prototype.getSubjectString = _x509_getSubjectString;
X509.prototype.getNotBefore = _x509_getNotBefore;
X509.prototype.getNotAfter = _x509_getNotAfter;

;






var dbits;


var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);


function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}


function nbi() { return new BigInteger(null); }









function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}



function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}


function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { 
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;


var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}


function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}


function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}


function nbv(i) { var r = nbi(); r.fromInt(i); return r; }


function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; 
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}


function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}


function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}


function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }


function bnAbs() { return (this.s<0)?this.negate():this; }


function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}


function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}


function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}


function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}


function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}


function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}


function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}


function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}



function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}


function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}



function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}


function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}


function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;











function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		
  y = (y*(2-(x&0xf)*y))&0xf;	
  y = (y*(2-(x&0xff)*y))&0xff;	
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	
  
  
  y = (y*(2-x*y%this.DV))%this.DV;		
  
  return (y>0)?this.DV-y:-y;
}


function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}


function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}


function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}


function montReduce(x) {
  while(x.t <= this.mt2)	
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}


function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }


function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;


function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }


function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}


function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}


BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;


BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;


BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
;









function bnClone() { var r = nbi(); this.copyTo(r); return r; }


function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}


function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }


function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }


function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }


function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}


function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}


function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}


function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); 
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}


function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }


function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}


function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }


function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }


function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }


function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }


function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}


function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}


function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}


function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}


function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}


function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}


function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}


function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}


function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}


function bnSetBit(n) { return this.changeBit(n,op_or); }


function bnClearBit(n) { return this.changeBit(n,op_andnot); }


function bnFlipBit(n) { return this.changeBit(n,op_xor); }


function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}


function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }


function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }


function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }


function bnSquare() { var r = nbi(); this.squareTo(r); return r; }


function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }


function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }


function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}


function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}


function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}


function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;


function bnPow(e) { return this.exp(e,new NullExp()); }



function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; 
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}



function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; 
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}


function Barrett(m) {
  
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }


function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}


function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }


function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;


function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}


function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}


function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}


function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];


function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}


function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}


BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;


BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;


BigInteger.prototype.square = bnSquare;









;
var Log = function Log() 
{
}

exports.Log = Log;


Log.LOG = 0;
;var NDNProtocolDTags = {

  

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
   Interest : 26,  
   Key : 27,
   KeyLocator : 28,
   KeyName : 29,
   Length : 30,
   Link : 31,
   LinkAuthenticator : 32,
   NameComponentCount : 33,  
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
   Data : 64,  
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
  
   StatusResponse : 112,
   StatusCode : 113,
   StatusText : 114,

  
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

  
   NDNProtocolDataUnit : 17702112,
   NDNPROTOCOL_DATA_UNIT : "NDNProtocolDataUnit"
};

exports.NDNProtocolDTags = NDNProtocolDTags;

var NDNProtocolDTagsStrings = [
  null, null, null, null, null, null, null, null, null, null, null,
  null, null,
  "Any", "Name", "Component", "Certificate", "Collection", "CompleteName",
  "Content", "SignedInfo", "ContentDigest", "ContentHash", null, "Count", "Header",
  "Interest", "Key", "KeyLocator", "KeyName", "Length", "Link", "LinkAuthenticator",
  "NameComponentCount", null, null, "RootDigest", "Signature", "Start", "Timestamp", "Type",
  "Nonce", "Scope", "Exclude", "Bloom", "BloomSeed", null, "AnswerOriginKind",
  "InterestLifetime", null, null, null, null, "Witness", "SignatureBits", "DigestAlgorithm", "BlockSize",
  null, "FreshnessSeconds", "FinalBlockID", "PublisherPublicKeyDigest", "PublisherCertificateDigest",
  "PublisherIssuerKeyDigest", "PublisherIssuerCertificateDigest", "Data",
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

exports.NDNProtocolDTagsStrings = NDNProtocolDTagsStrings;



var NDNTime = function NDNTime(input) 
{
  this.NANOS_MAX = 999877929;
  
  if (typeof input =='number')
    this.msec = input;
  else {
    if (LOG > 1) console.log('UNRECOGNIZED TYPE FOR TIME');
  }
};

exports.NDNTime = NDNTime;

NDNTime.prototype.getJavascriptDate = function() 
{
  var d = new Date();
  d.setTime(this.msec);
  return d
};  



var ExponentialReExpressClosure = function ExponentialReExpressClosure(callerClosure, settings) 
{
  
  Closure.call(this);
    
  this.callerClosure = callerClosure;
  settings = (settings || {});
  this.maxInterestLifetime = (settings.maxInterestLifetime || 16000);
};

exports.ExponentialReExpressClosure = ExponentialReExpressClosure;


ExponentialReExpressClosure.prototype.upcall = function(kind, upcallInfo) 
{
  try {
    if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
      var interestLifetime = upcallInfo.interest.interestLifetime;
      if (interestLifetime == null)
        return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);
            
      var nextInterestLifetime = interestLifetime * 2;
      if (nextInterestLifetime > this.maxInterestLifetime)
        return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);
            
      var nextInterest = upcallInfo.interest.clone();
      nextInterest.interestLifetime = nextInterestLifetime;
      
      upcallInfo.face.expressInterest(nextInterest.name, this, nextInterest);
      return Closure.RESULT_OK;
    }  
    else
      return this.callerClosure.upcall(kind, upcallInfo);
  } catch (ex) {
    console.log("ExponentialReExpressClosure.upcall exception: " + ex);
    return Closure.RESULT_ERR;
  }
};
;
var Blob = function Blob(value, copy) 
{
  if (copy == null)
    copy = true;
  
  if (value == null)
    this.buffer = null;
  else if (typeof value === 'object' && value instanceof Blob)
    
    this.buffer = value.buffer;
  else {
    if (typeof value === 'string')
      
      this.buffer = new internalBuf(value, 'utf8');
    else {
      if (copy)
        
        this.buffer = new internalBuf(value);
      else {
        if (typeof value === 'object' && value instanceof internalBuf)
          
          this.buffer = value;
        else
          
          this.buffer = new internalBuf(value);
      }
    }
  }
};

exports.Blob = Blob;


Blob.prototype.size = function()
{
  if (this.buffer != null)
    return this.buffer.length;
  else
    return 0;
};


Blob.prototype.buf = function()
{
  return this.buffer;
};


Blob.prototype.isNull = function()
{
  return this.buffer == null;
};


Blob.prototype.toHex = function() 
{  
  if (this.buffer == null)
    return "";
  else
    return this.buffer.toString('hex');



var SignedBlob = function SignedBlob(value, signedPortionBeginOffset, signedPortionEndOffset) 
{
  
  Blob.call(this, value);
  
  if (this.buffer == null) {
    this.signedPortionBeginOffset = 0;
    this.signedPortionEndOffset = 0;
  }
  else if (typeof value === 'object' && value instanceof SignedBlob) {
    
    this.signedPortionBeginOffset = signedPortionBeginOffset == null ? 
      value.signedPortionBeginOffset : signedPortionBeginOffset;
    this.signedPortionEndOffset = signedPortionEndOffset == null ? 
      value.signedPortionEndOffset : signedPortionEndOffset;
  }
  else {
    this.signedPortionBeginOffset = signedPortionBeginOffset || 0;
    this.signedPortionEndOffset = signedPortionEndOffset || 0;
  }
  
  if (this.buffer == null)
    this.signedBuffer = null;
  else
    this.signedBuffer = this.buffer.slice
      (this.signedPortionBeginOffset, this.signedPortionEndOffset);
};

SignedBlob.prototype = new Blob();
SignedBlob.prototype.name = "SignedBlob";

exports.SignedBlob = SignedBlob;


SignedBlob.prototype.signedSize = function()
{
  if (this.signedBuffer != null)
    return this.signedBuffer.length;
  else
    return 0;
};


SignedBlob.prototype.signedBuf = function()
{
  if (this.signedBuffer != null)
    return this.signedBuffer;
  else
    return null;
};


SignedBlob.prototype.getSignedPortionBeginOffset = function()
{
  return this.signedPortionBeginOffset;
};


SignedBlob.prototype.getSignedPortionEndOffset = function()
{
  return this.signedPortionEndOffset;
};
;
var DynamicBuffer = function DynamicBuffer(length) 
{
  if (!length)
    length = 16;
    
  this.array = new internalBuf(length);
};

exports.DynamicBuffer = DynamicBuffer;


DynamicBuffer.prototype.ensureLength = function(length) 
{
  if (this.array.length >= length)
    return;
    
  
  var newLength = this.array.length * 2;
  if (length > newLength)
    
    newLength = length;
    
  var newArray = new internalBuf(newLength);
  this.array.copy(newArray);
  this.array = newArray;
};


DynamicBuffer.prototype.copy = function(value, offset) 
{
  this.ensureLength(value.length + offset);
    
  if (typeof value == 'object' && value instanceof internalBuf)
    value.copy(this.array, offset);
  else
    
    new internalBuf(value).copy(this.array, offset);
};


DynamicBuffer.prototype.ensureLengthFromBack = function(length) 
{
  if (this.array.length >= length)
    return;
    
  
  var newLength = this.array.length * 2;
  if (length > newLength)
    
    newLength = length;
    
  var newArray = new internalBuf(newLength);
  
  this.array.copy(newArray, newArray.length - this.array.length);
  this.array = newArray;
};


DynamicBuffer.prototype.copyFromBack = function(value, offsetFromBack) 
{
  this.ensureLengthFromBack(offsetFromBack);

  if (typeof value == 'object' && value instanceof internalBuf)
    value.copy(this.array, this.array.length - offsetFromBack);
  else
    
    new internalBuf(value).copy(this.array, this.array.length - offsetFromBack);
};


DynamicBuffer.prototype.slice = function(begin, end) 
{
  return this.array.slice(begin, end);
};
;
var DataUtils = function()
{
};

exports.DataUtils = new DataUtils();



DataUtils.prototype.keyStr = "ABCDEFGHIJKLMNOP" +
                   "QRSTUVWXYZabcdef" +
                   "ghijklmnopqrstuv" +
                   "wxyz0123456789+/" +
                   "=";
               

DataUtils.prototype.stringtoBase64 = function stringtoBase64(input) 
{
   
   var output = "";
   var chr1, chr2, chr3 = "";
   var enc1, enc2, enc3, enc4 = "";
   var i = 0;

   do {
    chr1 = input.charCodeAt(i++);
    chr2 = input.charCodeAt(i++);
    chr3 = input.charCodeAt(i++);

    enc1 = chr1 >> 2;
    enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
    enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
    enc4 = chr3 & 63;

    if (isNaN(chr2))
       enc3 = enc4 = 64;
    else if (isNaN(chr3))
       enc4 = 64;

    output = output +
       DataUtils.keyStr.charAt(enc1) +
       DataUtils.keyStr.charAt(enc2) +
       DataUtils.keyStr.charAt(enc3) +
       DataUtils.keyStr.charAt(enc4);
    chr1 = chr2 = chr3 = "";
    enc1 = enc2 = enc3 = enc4 = "";
   } while (i < input.length);

   return output;
};


DataUtils.prototype.base64toString = function base64toString(input) 
{
  var output = "";
  var chr1, chr2, chr3 = "";
  var enc1, enc2, enc3, enc4 = "";
  var i = 0;

  
  var base64test = /[^A-Za-z0-9\+\/\=]/g;
  
  if (base64test.exec(input)) {
    alert("There were invalid base64 characters in the input text.\n" +
          "Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='\n" +
          "Expect errors in decoding.");
  }
  
  input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

  do {
    enc1 = DataUtils.keyStr.indexOf(input.charAt(i++));
    enc2 = DataUtils.keyStr.indexOf(input.charAt(i++));
    enc3 = DataUtils.keyStr.indexOf(input.charAt(i++));
    enc4 = DataUtils.keyStr.indexOf(input.charAt(i++));

    chr1 = (enc1 << 2) | (enc2 >> 4);
    chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
    chr3 = ((enc3 & 3) << 6) | enc4;

    output = output + String.fromCharCode(chr1);

    if (enc3 != 64)
      output = output + String.fromCharCode(chr2);

    if (enc4 != 64)
      output = output + String.fromCharCode(chr3);

    chr1 = chr2 = chr3 = "";
    enc1 = enc2 = enc3 = enc4 = "";
  } while (i < input.length);

  return output;
};


DataUtils.prototype.toHex = function(buffer) 
{
  return buffer.toString('hex');
};


DataUtils.prototype.stringToHex = function(args) 
{
  var ret = "";
  for (var i = 0; i < args.length; ++i) {
    var value = args.charCodeAt(i);
    ret += (value < 16 ? "0" : "") + value.toString(16);
  }
  return ret;
};


DataUtils.prototype.toString = function(buffer) 
{
  return buffer.toString();
};


DataUtils.prototype.toNumbers = function(str) 
{
  return new internalBuf(str, 'hex');
};


DataUtils.prototype.hexToRawString = function(str) 
{
  if (typeof str =='string') {
  var ret = "";
  str.replace(/(..)/g, function(s) {
    ret += String.fromCharCode(parseInt(s, 16));
  });
  return ret;
  }
};


DataUtils.prototype.toNumbersFromString = function(str) 
{
  return new internalBuf(str, 'binary');
};


DataUtils.prototype.stringToUtf8Array = function(str) 
{
  return new internalBuf(str, 'utf8');
};


DataUtils.prototype.concatArrays = function(arrays) 
{
  return internalBuf.concat(arrays);
};
 

DataUtils.prototype.decodeUtf8 = function(utftext) 
{
  var string = "";
  var i = 0;
  var c = 0;
    var c1 = 0;
    var c2 = 0;
 
  while (i < utftext.length) {
    c = utftext.charCodeAt(i);
 
    if (c < 128) {
      string += String.fromCharCode(c);
      i++;
    }
    else if (c > 191 && c < 224) {
      c2 = utftext.charCodeAt(i + 1);
      string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
      i += 2;
    }
    else {
      c2 = utftext.charCodeAt(i+1);
      var c3 = utftext.charCodeAt(i+2);
      string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
      i += 3;
    }
  }
 
  return string;
};


DataUtils.prototype.arraysEqual = function(a1, a2) 
{
  
  if (!a1.slice)
    throw new Error("DataUtils.arraysEqual: a1 is not an array");
  if (!a2.slice)
    throw new Error("DataUtils.arraysEqual: a2 is not an array");
    
  if (a1.length != a2.length)
    return false;
  
  for (var i = 0; i < a1.length; ++i) {
    if (a1[i] != a2[i])
      return false;
  }

  return true;
};


DataUtils.prototype.bigEndianToUnsignedInt = function(bytes) 
{
  var result = 0;
  for (var i = 0; i < bytes.length; ++i) {
    result <<= 8;
    result += bytes[i];
  }
  return result;
};


DataUtils.prototype.nonNegativeIntToBigEndian = function(value) 
{
  value = Math.round(value);
  if (value <= 0)
    return new internalBuf(0);
  
  
  var size = 8;
  var result = new internalBuf(size);
  var i = 0;
  while (value != 0) {
    ++i;
    result[size - i] = value & 0xff;
    value >>= 8;
  }
  return result.slice(size - i, size);
};


DataUtils.prototype.shuffle = function(array) 
{
  for (var i = array.length - 1; i >= 1; --i) {
    
    var j = Math.floor(Math.random() * (i + 1));
    var temp = array[i];
    array[i] = array[j];
    array[j] = temp;
  }
};
;var DateFormat = function() 
{
  var  token = /d{1,4}|m{1,4}|yy(?:yy)?|([HhMsTt])\1?|[LloSZ]|"[^"]*"|'[^']*'/g,
    timezone = /\b(?:[PMCEA][SDP]T|(?:Pacific|Mountain|Central|Eastern|Atlantic) (?:Standard|Daylight|Prevailing) Time|(?:GMT|UTC)(?:[-+]\d{4})?)\b/g,
    timezoneClip = /[^-+\dA-Z]/g,
    pad = function(val, len) {
      val = String(val);
      len = len || 2;
      while (val.length < len) val = "0" + val;
      return val;
    };

  
  return function(date, mask, utc) {
    var dF = dateFormat;

    
    if (arguments.length == 1 && Object.prototype.toString.call(date) == "[object String]" && !/\d/.test(date)) {
      mask = date;
      date = undefined;
    }

    
    date = date ? new Date(date) : new Date;
    if (isNaN(date)) throw SyntaxError("invalid date");

    mask = String(dF.masks[mask] || mask || dF.masks["default"]);

    
    if (mask.slice(0, 4) == "UTC:") {
      mask = mask.slice(4);
      utc = true;
    }

    var  _ = utc ? "getUTC" : "get",
      d = date[_ + "Date"](),
      D = date[_ + "Day"](),
      m = date[_ + "Month"](),
      y = date[_ + "FullYear"](),
      H = date[_ + "Hours"](),
      M = date[_ + "Minutes"](),
      s = date[_ + "Seconds"](),
      L = date[_ + "Milliseconds"](),
      o = utc ? 0 : date.getTimezoneOffset(),
      flags = {
        d:    d,
        dd:   pad(d),
        ddd:  dF.i18n.dayNames[D],
        dddd: dF.i18n.dayNames[D + 7],
        m:    m + 1,
        mm:   pad(m + 1),
        mmm:  dF.i18n.monthNames[m],
        mmmm: dF.i18n.monthNames[m + 12],
        yy:   String(y).slice(2),
        yyyy: y,
        h:    H % 12 || 12,
        hh:   pad(H % 12 || 12),
        H:    H,
        HH:   pad(H),
        M:    M,
        MM:   pad(M),
        s:    s,
        ss:   pad(s),
        l:    pad(L, 3),
        L:    pad(L > 99 ? Math.round(L / 10) : L),
        t:    H < 12 ? "a"  : "p",
        tt:   H < 12 ? "am" : "pm",
        T:    H < 12 ? "A"  : "P",
        TT:   H < 12 ? "AM" : "PM",
        Z:    utc ? "UTC" : (String(date).match(timezone) || [""]).pop().replace(timezoneClip, ""),
        o:    (o > 0 ? "-" : "+") + pad(Math.floor(Math.abs(o) / 60) * 100 + Math.abs(o) % 60, 4),
        S:    ["th", "st", "nd", "rd"][d % 10 > 3 ? 0 : (d % 100 - d % 10 != 10) * d % 10]
      };

    return mask.replace(token, function($0) {
      return $0 in flags ? flags[$0] : $0.slice(1, $0.length - 1);
    });
  };
}();


DateFormat.masks = {
  "default":      "ddd mmm dd yyyy HH:MM:ss",
  shortDate:      "m/d/yy",
  mediumDate:     "mmm d, yyyy",
  longDate:       "mmmm d, yyyy",
  fullDate:       "dddd, mmmm d, yyyy",
  shortTime:      "h:MM TT",
  mediumTime:     "h:MM:ss TT",
  longTime:       "h:MM:ss TT Z",
  isoDate:        "yyyy-mm-dd",
  isoTime:        "HH:MM:ss",
  isoDateTime:    "yyyy-mm-dd'T'HH:MM:ss",
  isoUtcDateTime: "UTC:yyyy-mm-dd'T'HH:MM:ss'Z'"
};


DateFormat.i18n = {
  dayNames: [
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
  ],
  monthNames: [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"
  ]
};


Date.prototype.format = function(mask, utc) {
  return dateFormat(this, mask, utc);
};
;
function DecodingException(error) 
{
  this.message = error.message;
  
  for (var prop in error)
      this[prop] = error[prop];
}
DecodingException.prototype = new Error();
DecodingException.prototype.name = "DecodingException";

exports.DecodingException = DecodingException;







var XML_EXT = 0x00; 
  
var XML_TAG = 0x01; 
  
var XML_DTAG = 0x02; 
  
var XML_ATTR = 0x03; 
 
var XML_DATTR = 0x04; 
  
var XML_BLOB = 0x05; 
  
var XML_UDATA = 0x06; 
  
var XML_CLOSE = 0x0;

var XML_SUBTYPE_PROCESSING_INSTRUCTIONS = 16; 


var XML_TT_BITS = 3;
var XML_TT_MASK = ((1 << XML_TT_BITS) - 1);
var XML_TT_VAL_BITS = XML_TT_BITS + 1;
var XML_TT_VAL_MASK = ((1 << (XML_TT_VAL_BITS)) - 1);
var XML_REG_VAL_BITS = 7;
var XML_REG_VAL_MASK = ((1 << XML_REG_VAL_BITS) - 1);
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); 
var BYTE_MASK = 0xFF;
var LONG_BYTES = 8;
var LONG_BITS = 64;
  
var bits_11 = 0x0000007FF;
var bits_18 = 0x00003FFFF;
var bits_32 = 0x0FFFFFFFF;


var BinaryXMLEncoder = function BinaryXMLEncoder(initiaLength) 
{
  if (!initiaLength)
    initiaLength = 16;
  
  this.ostream = new DynamicBuffer(initiaLength);
  this.offset = 0;
  this.CODEC_NAME = "Binary";
};

exports.BinaryXMLEncoder = BinaryXMLEncoder;


BinaryXMLEncoder.prototype.writeUString = function(utf8Content) 
{
  this.encodeUString(utf8Content, XML_UDATA);
};

BinaryXMLEncoder.prototype.writeBlob = function(
     binaryContent) 
{  
  if (LOG >3) console.log(binaryContent);
  
  this.encodeBlob(binaryContent, binaryContent.length);
};


BinaryXMLEncoder.prototype.writeElementStartDTag = function(tag)
{
  this.encodeTypeAndVal(XML_DTAG, tag);
};


BinaryXMLEncoder.prototype.writeStartElement = function(
   tag, 
   attributes) 
{
   var dictionaryVal = tag; 
  
  if (null == dictionaryVal)
    this.encodeUString(tag, XML_TAG);
  else
    this.encodeTypeAndVal(XML_DTAG, dictionaryVal);
  
  if (null != attributes)
    this.writeAttributes(attributes); 
};


BinaryXMLEncoder.prototype.writeElementClose = function() 
{
  this.ostream.ensureLength(this.offset + 1);
  this.ostream.array[this.offset] = XML_CLOSE;
  this.offset += 1;
};


BinaryXMLEncoder.prototype.writeEndElement = function() 
{
  this.writeElementClose();
};


BinaryXMLEncoder.prototype.writeAttributes = function( attributes) 
{
  if (null == attributes)
    return;

  

  for (var i = 0; i< attributes.length;i++) {
    var strAttr = attributes[i].k;
    var strValue = attributes[i].v;

    var dictionaryAttr = stringToTag(strAttr);
    if (null == dictionaryAttr)
      
      
      
      
      this.encodeUString(strAttr, XML_ATTR);
    else
      this.encodeTypeAndVal(XML_DATTR, dictionaryAttr);

    
    this.encodeUString(strValue);    
  }
};


stringToTag = function( tagVal) 
{
  if (tagVal >= 0 && tagVal < NDNProtocolDTagsStrings.length)
    return NDNProtocolDTagsStrings[tagVal];
  else if (tagVal == NDNProtocolDTags.NDNProtocolDataUnit)
    return NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT;
  
  return null;
};


tagToString =  function( tagName) 
{
  
  for (var i = 0; i < NDNProtocolDTagsStrings.length; ++i) {
    if (null != NDNProtocolDTagsStrings[i] && NDNProtocolDTagsStrings[i] == tagName)
      return i;
  }
  
  if (NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT == tagName)
    return NDNProtocolDTags.NDNProtocolDataUnit;

  return null;
};


BinaryXMLEncoder.prototype.writeDTagElement = function(tag, content)
{
  this.writeElementStartDTag(tag);
  
  if (typeof content === 'number')
    this.writeUString(content.toString());
  else if (typeof content === 'string')
    this.writeUString(content);
  else
    this.writeBlob(content);
  
  this.writeElementClose();
};


BinaryXMLEncoder.prototype.writeElement = function(
    
    tag, 
    
    Content,
    
    attributes) 
{
  this.writeStartElement(tag, attributes);
  
  
  if (typeof Content === 'number') {
    if (LOG > 4) console.log('GOING TO WRITE THE NUMBER .charCodeAt(0) ' + Content.toString().charCodeAt(0));
    if (LOG > 4) console.log('GOING TO WRITE THE NUMBER ' + Content.toString());
    if (LOG > 4) console.log('type of number is ' + typeof Content.toString());
    
    this.writeUString(Content.toString());
  }
  else if (typeof Content === 'string') {
    if (LOG > 4) console.log('GOING TO WRITE THE STRING  ' + Content);
    if (LOG > 4) console.log('type of STRING is ' + typeof Content);
    
    this.writeUString(Content);
  }
  else {
    if (LOG > 4) console.log('GOING TO WRITE A BLOB  ' + Content);

    this.writeBlob(Content);
  }
  
  this.writeElementClose();
};

var TypeAndVal = function TypeAndVal(_type,_val) 
{
  this.type = _type;
  this.val = _val;  
};

BinaryXMLEncoder.prototype.encodeTypeAndVal = function(
    
    type, 
    
    val) 
{  
  if (LOG > 4) console.log('Encoding type '+ type+ ' and value '+ val);
  
  if (LOG > 4) console.log('OFFSET IS ' + this.offset);
  
  if (type > XML_UDATA || type < 0 || val < 0)
    throw new Error("Tag and value must be positive, and tag valid.");
  
  
  var numEncodingBytes = this.numEncodingBytes(val);
  this.ostream.ensureLength(this.offset + numEncodingBytes);

  
  this.ostream.array[this.offset + numEncodingBytes - 1] = 
    
      (BYTE_MASK &
          (((XML_TT_MASK & type) | 
           ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
           XML_TT_NO_MORE); 
  val = val >>> XML_TT_VAL_BITS;
  
  
  
  var i = this.offset + numEncodingBytes - 2;
  while (0 != val && i >= this.offset) {
    this.ostream.array[i] = 
        (BYTE_MASK & (val & XML_REG_VAL_MASK)); 
    val = val >>> XML_REG_VAL_BITS;
    --i;
  }
  
  if (val != 0)
    throw new Error("This should not happen: miscalculated encoding");

  this.offset+= numEncodingBytes;
  
  return numEncodingBytes;
};


BinaryXMLEncoder.prototype.encodeUString = function(
    
    ustring, 
    
    type) 
{  
  if (null == ustring)
    return;
  if (type == XML_TAG || type == XML_ATTR && ustring.length == 0)
    return;
  
  if (LOG > 3) console.log("The string to write is ");
  if (LOG > 3) console.log(ustring);

  var strBytes = DataUtils.stringToUtf8Array(ustring);
  
  this.encodeTypeAndVal(type, 
            (((type == XML_TAG) || (type == XML_ATTR)) ?
                (strBytes.length-1) :
                strBytes.length));
  
  if (LOG > 3) console.log("THE string to write is ");
  
  if (LOG > 3) console.log(strBytes);
  
  this.writeString(strBytes);
  this.offset+= strBytes.length;
};


BinaryXMLEncoder.prototype.encodeBlob = function(
    
    blob, 
    
    length) 
{
  if (null == blob)
    return;
  
  if (LOG > 4) console.log('LENGTH OF XML_BLOB IS '+length);
  
  this.encodeTypeAndVal(XML_BLOB, length);
  this.writeBlobArray(blob);
  this.offset += length;
};

var ENCODING_LIMIT_1_BYTE = ((1 << (XML_TT_VAL_BITS)) - 1);
var ENCODING_LIMIT_2_BYTES = ((1 << (XML_TT_VAL_BITS + XML_REG_VAL_BITS)) - 1);
var ENCODING_LIMIT_3_BYTES = ((1 << (XML_TT_VAL_BITS + 2 * XML_REG_VAL_BITS)) - 1);

BinaryXMLEncoder.prototype.numEncodingBytes = function(
    
    x) 
{
  if (x <= ENCODING_LIMIT_1_BYTE) return (1);
  if (x <= ENCODING_LIMIT_2_BYTES) return (2);
  if (x <= ENCODING_LIMIT_3_BYTES) return (3);
  
  var numbytes = 1;
  
  
  
  x = x >>> XML_TT_VAL_BITS;
  while (x != 0) {
        numbytes++;
    x = x >>> XML_REG_VAL_BITS;
  }
  return (numbytes);
};


BinaryXMLEncoder.prototype.writeDateTimeDTagElement = function(tag, dateTime)
{  
  
  var binarydate =  Math.round((dateTime.msec/1000) * 4096).toString(16)  ;
  if (binarydate.length % 2 == 1)
    binarydate = '0' + binarydate;

  this.writeDTagElement(tag, DataUtils.toNumbers(binarydate));
};


BinaryXMLEncoder.prototype.writeDateTime = function(
    
    tag, 
    
    dateTime) 
{  
  
  var binarydate =  Math.round((dateTime.msec/1000) * 4096).toString(16)  ;
  if (binarydate.length % 2 == 1)
    binarydate = '0' + binarydate;

  this.writeElement(tag, DataUtils.toNumbers(binarydate));
};


BinaryXMLEncoder.prototype.writeString = function(input) 
{
  if (typeof input === 'string') {
    if (LOG > 4) console.log('GOING TO WRITE A STRING');
    if (LOG > 4) console.log(input);
        
    this.ostream.ensureLength(this.offset + input.length);
    for (var i = 0; i < input.length; i++) {
      if (LOG > 4) console.log('input.charCodeAt(i)=' + input.charCodeAt(i));
      this.ostream.array[this.offset + i] = (input.charCodeAt(i));
    }
  }
  else
  {
    if (LOG > 4) console.log('GOING TO WRITE A STRING IN BINARY FORM');
    if (LOG > 4) console.log(input);
    
    this.writeBlobArray(input);
  }
};

BinaryXMLEncoder.prototype.writeBlobArray = function(
    
    blob) 
{  
  if (LOG > 4) console.log('GOING TO WRITE A BLOB');
    
  this.ostream.copy(blob, this.offset);
};

BinaryXMLEncoder.prototype.getReducedOstream = function() 
{
  return this.ostream.slice(0, this.offset);
};






var XML_EXT = 0x00; 
  
var XML_TAG = 0x01; 
  
var XML_DTAG = 0x02; 
  
var XML_ATTR = 0x03; 
 
var XML_DATTR = 0x04; 
  
var XML_BLOB = 0x05; 
  
var XML_UDATA = 0x06; 
  
var XML_CLOSE = 0x0;

var XML_SUBTYPE_PROCESSING_INSTRUCTIONS = 16; 
  

var XML_TT_BITS = 3;
var XML_TT_MASK = ((1 << XML_TT_BITS) - 1);
var XML_TT_VAL_BITS = XML_TT_BITS + 1;
var XML_TT_VAL_MASK = ((1 << (XML_TT_VAL_BITS)) - 1);
var XML_REG_VAL_BITS = 7;
var XML_REG_VAL_MASK = ((1 << XML_REG_VAL_BITS) - 1);
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); 
var BYTE_MASK = 0xFF;
var LONG_BYTES = 8;
var LONG_BITS = 64;
  
var bits_11 = 0x0000007FF;
var bits_18 = 0x00003FFFF;
var bits_32 = 0x0FFFFFFFF;




tagToString = function( tagVal) 
{
  if (tagVal >= 0 && tagVal < NDNProtocolDTagsStrings.length) {
    return NDNProtocolDTagsStrings[tagVal];
  } 
  else if (tagVal == NDNProtocolDTags.NDNProtocolDataUnit) {
    return NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT;
  }
  
  return null;
};


stringToTag =  function( tagName) 
{
  
  for (var i=0; i < NDNProtocolDTagsStrings.length; ++i) {
    if (null != NDNProtocolDTagsStrings[i] && NDNProtocolDTagsStrings[i] == tagName)
      return i;
  }
  if (NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT == tagName) {
    return NDNProtocolDTags.NDNProtocolDataUnit;
  }
  
  return null;
};


var BinaryXMLDecoder = function BinaryXMLDecoder(input) 
{
  var MARK_LEN=512;
  var DEBUG_MAX_LEN =  32768;
  
  this.input = input;
  this.offset = 0;
  
  this.previouslyPeekedDTagStartOffset = -1;
};

exports.BinaryXMLDecoder = BinaryXMLDecoder;


BinaryXMLDecoder.prototype.readElementStartDTag = function(expectedTag)
{
  if (this.offset == this.previouslyPeekedDTagStartOffset) {
    
    if (this.previouslyPeekedDTag != expectedTag)
      throw new DecodingException(new Error("Did not get the expected DTAG " + expectedTag + ", got " + this.previouslyPeekedDTag));

    
    this.offset = this.previouslyPeekedDTagEndOffset;
  }
  else {
    var typeAndValue = this.decodeTypeAndVal();
    if (typeAndValue == null || typeAndValue.type() != XML_DTAG)
      throw new DecodingException(new Error("Header type is not a DTAG"));

    if (typeAndValue.val() != expectedTag)
      throw new DecodingException(new Error("Expected start element: " + expectedTag + " got: " + typeAndValue.val()));
  }  
};


BinaryXMLDecoder.prototype.readStartElement = function(
    
    startTag,
    
    attributes)
{
  
  var tv = this.decodeTypeAndVal();
      
  if (null == tv)
    throw new DecodingException(new Error("Expected start element: " + startTag + " got something not a tag."));
      
  
  var decodedTag = null;
      
  if (tv.type() == XML_TAG) {
    
    var valval;
        
    if (typeof tv.val() == 'string')
      valval = (parseInt(tv.val())) + 1;
    else
      valval = (tv.val())+ 1;
        
    decodedTag = this.decodeUString(valval);
  } 
  else if (tv.type() == XML_DTAG)
    decodedTag = tv.val();
      
  if (null ==  decodedTag || decodedTag != startTag) {
    console.log('expecting '+ startTag + ' but got '+ decodedTag);
    throw new DecodingException(new Error("Expected start element: " + startTag + " got: " + decodedTag + "(" + tv.val() + ")"));
  }
      
  
  
  
  if (null != attributes)
    readAttributes(attributes); 
};
  

BinaryXMLDecoder.prototype.readAttributes = function(
  
  attributes) 
{
  if (null == attributes)
    return;

  try {
    
    
    var nextTV = this.peekTypeAndVal();

    while (null != nextTV && (XML_ATTR == nextTV.type() || XML_DATTR == nextTV.type())) {
      
      
      var thisTV = this.decodeTypeAndVal();

      
      var attributeName = null;
      if (XML_ATTR == thisTV.type()) {
        
        var valval ;
        if (typeof thisTV.val() == 'string')
          valval = (parseInt(thisTV.val())) + 1;
        else
          valval = (thisTV.val())+ 1;
        
        attributeName = this.decodeUString(valval);
      } 
      else if (XML_DATTR == thisTV.type()) {
        
        attributeName = tagToString(thisTV.val());
        if (null == attributeName)
          throw new DecodingException(new Error("Unknown DATTR value" + thisTV.val()));
      }
      
      
      
      var attributeValue = this.decodeUString();

      attributes.push([attributeName, attributeValue]);
      nextTV = this.peekTypeAndVal();
    }
  } 
  catch (e) {
    throw new DecodingException(new Error("readStartElement", e));
  }
};


BinaryXMLDecoder.prototype.peekStartElementAsString = function() 
{
  
  var decodedTag = null;
  var previousOffset = this.offset;
  try {
    
    
    
    var tv = this.decodeTypeAndVal();

    if (null != tv) {
      if (tv.type() == XML_TAG) {
        
        var valval ;
        if (typeof tv.val() == 'string')
          valval = (parseInt(tv.val())) + 1;
        else
          valval = (tv.val())+ 1;
        
        decodedTag = this.decodeUString(valval);
      }
      else if (tv.type() == XML_DTAG)
        decodedTag = tagToString(tv.val());          
    } 
  } 
  catch (e) {
  } 
  finally {
    try {
      this.offset = previousOffset;
    } 
    catch (e) {
      Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
      throw new DecodingException(new Error("Cannot reset stream! " + e.getMessage(), e));
    }
  }
  
  return decodedTag;
};


BinaryXMLDecoder.prototype.peekDTag = function(expectedTag)
{
  if (this.offset == this.previouslyPeekedDTagStartOffset)
    
    return this.previouslyPeekedDTag == expectedTag;
  else {
    
    if (this.input[this.offset] == XML_CLOSE)
      return false;

    var saveOffset = this.offset;
    var typeAndValue = this.decodeTypeAndVal();
    
    this.previouslyPeekedDTagEndOffset = this.offset;
    
    this.offset = saveOffset;

    if (typeAndValue != null && typeAndValue.type() == XML_DTAG) {
      this.previouslyPeekedDTagStartOffset = saveOffset;
      this.previouslyPeekedDTag = typeAndValue.val();

      return typeAndValue.val() == expectedTag;
    }
    else
      return false;
  }  
};


BinaryXMLDecoder.prototype.peekStartElement = function(
    
    startTag) 
{
  
  if (typeof startTag == 'string') {
    var decodedTag = this.peekStartElementAsString();
    
    if (null !=  decodedTag && decodedTag == startTag)
      return true;

    return false;
  }
  else if (typeof startTag == 'number') {
    var decodedTag = this.peekStartElementAsLong();
    if (null !=  decodedTag && decodedTag == startTag)
      return true;

    return false;
  }
  else
    throw new DecodingException(new Error("SHOULD BE STRING OR NUMBER"));
};


BinaryXMLDecoder.prototype.peekStartElementAsLong = function() 
{
  
  var decodedTag = null;    
  var previousOffset = this.offset;
  
  try {
    
    
    
    var tv = this.decodeTypeAndVal();

    if (null != tv) {
      if (tv.type() == XML_TAG) {
        if (tv.val() + 1 > DEBUG_MAX_LEN)
          throw new DecodingException(new Error("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!"));

        var valval;
        if (typeof tv.val() == 'string')
          valval = (parseInt(tv.val())) + 1;
        else
          valval = (tv.val())+ 1;
        
        
        
        var strTag = this.decodeUString(valval);
        
        decodedTag = stringToTag(strTag);
      } 
      else if (tv.type() == XML_DTAG)
        decodedTag = tv.val();          
    } 

  } 
  catch (e) {  
  } 
  finally {
    try {
      
      this.offset = previousOffset;
    } catch (e) {
      Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
      throw new Error("Cannot reset stream! " + e.getMessage(), e);
    }
  }
  
  return decodedTag;
};


BinaryXMLDecoder.prototype.readBinaryDTagElement = function(expectedTag, allowNull)
{
  this.readElementStartDTag(expectedTag);
  return this.readBlob(allowNull);  
};


BinaryXMLDecoder.prototype.readBinaryElement = function(
    
    startTag,
    
    attributes,
    
    allowNull) 
{
  this.readStartElement(startTag, attributes);
  return this.readBlob(allowNull);  
};


BinaryXMLDecoder.prototype.readElementClose = function() 
{
  var next = this.input[this.offset++];     
  if (next != XML_CLOSE)
    throw new DecodingException(new Error("Expected end element, got: " + next));
};


BinaryXMLDecoder.prototype.readEndElement = function() 
{
  if (LOG > 4) console.log('this.offset is '+this.offset);
  
  var next = this.input[this.offset]; 
  
  this.offset++;
  
  if (LOG > 4) console.log('XML_CLOSE IS '+XML_CLOSE);
  if (LOG > 4) console.log('next is '+next);
  
  if (next != XML_CLOSE) {
    console.log("Expected end element, got: " + next);
    throw new DecodingException(new Error("Expected end element, got: " + next));
  }
};


BinaryXMLDecoder.prototype.readUString = function() 
{
  
  var ustring = this.decodeUString();  
  this.readElementClose();
  return ustring;
};
  

BinaryXMLDecoder.prototype.readBlob = function(allowNull) 
{
  if (this.input[this.offset] == XML_CLOSE && allowNull) {
    this.readElementClose();
    return null;
  }
    
  var blob = this.decodeBlob();  
  this.readElementClose();
  return blob;
};


BinaryXMLDecoder.prototype.readDateTimeDTagElement = function(expectedTag)  
{
  var byteTimestamp = this.readBinaryDTagElement(expectedTag);
  byteTimestamp = DataUtils.toHex(byteTimestamp);
  byteTimestamp = parseInt(byteTimestamp, 16);
  
  var lontimestamp = (byteTimestamp/ 4096) * 1000;

  var timestamp = new NDNTime(lontimestamp);  
  if (null == timestamp)
    throw new DecodingException(new Error("Cannot parse timestamp: " + DataUtils.printHexBytes(byteTimestamp)));

  return timestamp;
};


BinaryXMLDecoder.prototype.readDateTime = function(
  
  startTag)  
{
  var byteTimestamp = this.readBinaryElement(startTag);
  byteTimestamp = DataUtils.toHex(byteTimestamp);
  byteTimestamp = parseInt(byteTimestamp, 16);
  
  var lontimestamp = (byteTimestamp/ 4096) * 1000;

  if (LOG > 4) console.log('DECODED DATE WITH VALUE');
  if (LOG > 4) console.log(lontimestamp);
  
  
  var timestamp = new NDNTime(lontimestamp);  
  if (null == timestamp)
    throw new DecodingException(new Error("Cannot parse timestamp: " + DataUtils.printHexBytes(byteTimestamp)));

  return timestamp;
};

BinaryXMLDecoder.prototype.decodeTypeAndVal = function() 
{
  
   var type = -1;
   var val = 0;
   var more = true;

  do {
    var next = this.input[this.offset ];
    if (next == null)
      
      return null; 
    
    if (next < 0)
      return null; 

    if (0 == next && 0 == val)
      return null;
    
    more = (0 == (next & XML_TT_NO_MORE));
    
    if  (more) {
      val = val << XML_REG_VAL_BITS;
      val |= (next & XML_REG_VAL_MASK);
    } 
    else {
      type = next & XML_TT_MASK;
      val = val << XML_TT_VAL_BITS;
      val |= ((next >>> XML_TT_BITS) & XML_TT_VAL_MASK);
    }
    
    this.offset++;
  } while (more);
  
  if (LOG > 4) console.log('TYPE is '+ type + ' VAL is '+ val);

  return new TypeAndVal(type, val);
};


BinaryXMLDecoder.prototype.peekTypeAndVal = function() 
{
  
  var tv = null;
  var previousOffset = this.offset;
  
  try {
    tv = this.decodeTypeAndVal();
  } 
  finally {
    this.offset = previousOffset;
  }
  
  return tv;
};


BinaryXMLDecoder.prototype.decodeBlob = function(
    
    blobLength) 
{  
  if (null == blobLength) {
    
    var tv = this.decodeTypeAndVal();

    var valval ;
    if (typeof tv.val() == 'string')
      valval = (parseInt(tv.val()));
    else
      valval = (tv.val());
    
    return this.decodeBlob(valval);
  }
  
  
  var bytes = new internalBuf(this.input.slice(this.offset, this.offset+ blobLength));
  this.offset += blobLength;
  
  return bytes;
};


BinaryXMLDecoder.prototype.decodeUString = function(
    
    byteLength) 
{
  if (null == byteLength) {
    var tempStreamPosition = this.offset;
      
    
    var tv = this.decodeTypeAndVal();
    
    if (LOG > 4) console.log('TV is '+tv);
    if (LOG > 4) console.log(tv);
    
    if (LOG > 4) console.log('Type of TV is '+typeof tv);
  
    
    if (null == tv || XML_UDATA != tv.type()) {
      this.offset = tempStreamPosition;      
      return "";
    }
      
    return this.decodeUString(tv.val());
  }
  else {
    
    var stringBytes = this.decodeBlob(byteLength);
    
    
    return DataUtils.toString(stringBytes);    
  }
};


var TypeAndVal = function TypeAndVal(_type,_val) 
{
  this.t = _type;
  this.v = _val;
};

TypeAndVal.prototype.type = function() 
{
  return this.t;
};

TypeAndVal.prototype.val = function() 
{
  return this.v;
};


BinaryXMLDecoder.prototype.readIntegerDTagElement = function(expectedTag)
{
  return parseInt(this.readUTF8DTagElement(expectedTag));
};


BinaryXMLDecoder.prototype.readIntegerElement = function(
  
  startTag) 
{
  
  if (LOG > 4) console.log('READING INTEGER '+ startTag);
  if (LOG > 4) console.log('TYPE OF '+ typeof startTag);
  
  var strVal = this.readUTF8Element(startTag);
  
  return parseInt(strVal);
};


BinaryXMLDecoder.prototype.readUTF8DTagElement = function(expectedTag)
{
  this.readElementStartDTag(expectedTag);
  return this.readUString();;
};


BinaryXMLDecoder.prototype.readUTF8Element = function(
    
    startTag,
    
    attributes) 
{
  

  
  this.readStartElement(startTag, attributes);
  
  var strElementText = this.readUString();
  return strElementText;
};


BinaryXMLDecoder.prototype.seek = function(offset) 
{
  this.offset = offset;
};



var XML_EXT = 0x00; 
var XML_TAG = 0x01; 
var XML_DTAG = 0x02; 
var XML_ATTR = 0x03; 
var XML_DATTR = 0x04; 
var XML_BLOB = 0x05; 
var XML_UDATA = 0x06;   
var XML_CLOSE = 0x0;

var XML_SUBTYPE_PROCESSING_INSTRUCTIONS = 16; 

var XML_TT_BITS = 3;
var XML_TT_MASK = ((1 << XML_TT_BITS) - 1);
var XML_TT_VAL_BITS = XML_TT_BITS + 1;
var XML_TT_VAL_MASK = ((1 << (XML_TT_VAL_BITS)) - 1);
var XML_REG_VAL_BITS = 7;
var XML_REG_VAL_MASK = ((1 << XML_REG_VAL_BITS) - 1);
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); 


var BinaryXMLStructureDecoder = function BinaryXMLDecoder() 
{
  this.gotElementEnd = false;
  this.offset = 0;
  this.level = 0;
  this.state = BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE;
  this.headerLength = 0;
  this.useHeaderBuffer = false;
  this.headerBuffer = new DynamicBuffer(5);
  this.nBytesToRead = 0;
};

exports.BinaryXMLStructureDecoder = BinaryXMLStructureDecoder;

BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE = 0;
BinaryXMLStructureDecoder.READ_BYTES = 1;


BinaryXMLStructureDecoder.prototype.findElementEnd = function(
  
  input)
{
  if (this.gotElementEnd)
    
    return true;

  var decoder = new BinaryXMLDecoder(input);
  
  while (true) {
    if (this.offset >= input.length)
      
      return false;
  
    switch (this.state) {
      case BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE:               
        
        if (this.headerLength == 0 && input[this.offset] == XML_CLOSE) {
          ++this.offset;
          
          --this.level;
          if (this.level == 0) {
            
            this.gotElementEnd = true;
            return true;
          }
          if (this.level < 0)
            throw new Error("BinaryXMLStructureDecoder: Unexpected close tag at offset " + (this.offset - 1));
              
          
          this.startHeader();
          break;
        }
        
        var startingHeaderLength = this.headerLength;
        while (true) {
          if (this.offset >= input.length) {
            
            this.useHeaderBuffer = true;
            var nNewBytes = this.headerLength - startingHeaderLength;
            this.headerBuffer.copy(input.slice(this.offset - nNewBytes, nNewBytes), startingHeaderLength);
              
            return false;
          }
          var headerByte = input[this.offset++];
          ++this.headerLength;
          if (headerByte & XML_TT_NO_MORE)
            
            break;
        }
        
        var typeAndVal;
        if (this.useHeaderBuffer) {
          
          nNewBytes = this.headerLength - startingHeaderLength;
          this.headerBuffer.copy(input.slice(this.offset - nNewBytes, nNewBytes), startingHeaderLength);

          typeAndVal = new BinaryXMLDecoder(this.headerBuffer.array).decodeTypeAndVal();
        }
        else {
          
          decoder.seek(this.offset - this.headerLength);
          typeAndVal = decoder.decodeTypeAndVal();
        }
        
        if (typeAndVal == null)
          throw new Error("BinaryXMLStructureDecoder: Can't read header starting at offset " +
                          (this.offset - this.headerLength));
        
        
        var type = typeAndVal.t;
        if (type == XML_DATTR)
          
          
          this.startHeader();
        else if (type == XML_DTAG || type == XML_EXT) {
          
          ++this.level;
          this.startHeader();
        }
        else if (type == XML_TAG || type == XML_ATTR) {
          if (type == XML_TAG)
            
            ++this.level;
          
          this.nBytesToRead = typeAndVal.v + 1;
          this.state = BinaryXMLStructureDecoder.READ_BYTES;
          
        }
        else if (type == XML_BLOB || type == XML_UDATA) {
          this.nBytesToRead = typeAndVal.v;
          this.state = BinaryXMLStructureDecoder.READ_BYTES;
        }
        else
          throw new Error("BinaryXMLStructureDecoder: Unrecognized header type " + type);
        break;
    
      case BinaryXMLStructureDecoder.READ_BYTES:
        var nRemainingBytes = input.length - this.offset;
        if (nRemainingBytes < this.nBytesToRead) {
          
          this.offset += nRemainingBytes;
          this.nBytesToRead -= nRemainingBytes;
          return false;
        }
        
        this.offset += this.nBytesToRead;
        this.startHeader();
        break;
    
      default:
        
        throw new Error("BinaryXMLStructureDecoder: Unrecognized state " + this.state);
    }
  }
};


BinaryXMLStructureDecoder.prototype.startHeader = function() 
{
  this.headerLength = 0;
  this.useHeaderBuffer = false;
  this.state = BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE;    
};


BinaryXMLStructureDecoder.prototype.seek = function(offset) 
{
  this.offset = offset;
};
;
var Tlv = function Tlv()
{
}

exports.Tlv = Tlv;

Tlv.Interest =         5;
Tlv.Data =             6;
Tlv.Name =             7;
Tlv.NameComponent =    8;
Tlv.Selectors =        9;
Tlv.Nonce =            10;
Tlv.Scope =            11;
Tlv.InterestLifetime = 12;
Tlv.MinSuffixComponents = 13;
Tlv.MaxSuffixComponents = 14;
Tlv.PublisherPublicKeyLocator = 15;
Tlv.Exclude =          16;
Tlv.ChildSelector =    17;
Tlv.MustBeFresh =      18;
Tlv.Any =              19;
Tlv.MetaInfo =         20;
Tlv.Content =          21;
Tlv.SignatureInfo =    22;
Tlv.SignatureValue =   23;
Tlv.ContentType =      24;
Tlv.FreshnessPeriod =  25;
Tlv.FinalBlockId =     26;
Tlv.SignatureType =    27;
Tlv.KeyLocator =       28;
Tlv.KeyLocatorDigest = 29;
Tlv.FaceInstance =     128;
Tlv.ForwardingEntry =  129;
Tlv.StatusResponse =   130;
Tlv.Action =           131;
Tlv.FaceID =           132;
Tlv.IPProto =          133;
Tlv.Host =             134;
Tlv.Port =             135;
Tlv.MulticastInterface = 136;
Tlv.MulticastTTL =     137;
Tlv.ForwardingFlags =  138;
Tlv.StatusCode =       139;
Tlv.StatusText =       140;

Tlv.SignatureType_DigestSha256 = 0;
Tlv.SignatureType_SignatureSha256WithRsa = 1;



var TlvEncoder = function TlvEncoder(initialCapacity)
{
  initialCapacity = initialCapacity || 16;
  this.output = new DynamicBuffer(initialCapacity);
  
  
  this.length = 0;
};

exports.TlvEncoder = TlvEncoder;


TlvEncoder.prototype.getLength = function()
{
  return this.length;
};


TlvEncoder.prototype.writeVarNumber = function(varNumber)
{
  if (varNumber < 253) {
    this.length += 1;
    this.output.ensureLengthFromBack(this.length);
    this.output.array[this.output.array.length - this.length] = varNumber & 0xff;
  }
  else if (varNumber <= 0xffff) {
    this.length += 3;
    this.output.ensureLengthFromBack(this.length);
    var offset = this.output.array.length - this.length;
    this.output.array[offset] = 253;
    this.output.array[offset + 1] = (varNumber >> 8) & 0xff;
    this.output.array[offset + 2] = varNumber & 0xff;
  }
  else if (varNumber <= 0xffffffff) {
    this.length += 5;
    this.output.ensureLengthFromBack(this.length);
    var offset = this.output.array.length - this.length;
    this.output.array[offset] = 254;
    this.output.array[offset + 1] = (varNumber >> 24) & 0xff;
    this.output.array[offset + 2] = (varNumber >> 16) & 0xff;
    this.output.array[offset + 3] = (varNumber >> 8) & 0xff;
    this.output.array[offset + 4] = varNumber & 0xff;
  }
  else {
    this.length += 9;
    this.output.ensureLengthFromBack(this.length);
    var offset = this.output.array.length - this.length;
    this.output.array[offset] = 255;
    this.output.array[offset + 1] = (varNumber >> 56) & 0xff;
    this.output.array[offset + 2] = (varNumber >> 48) & 0xff;
    this.output.array[offset + 3] = (varNumber >> 40) & 0xff;
    this.output.array[offset + 4] = (varNumber >> 32) & 0xff;
    this.output.array[offset + 5] = (varNumber >> 24) & 0xff;
    this.output.array[offset + 6] = (varNumber >> 16) & 0xff;
    this.output.array[offset + 7] = (varNumber >> 8) & 0xff;
    this.output.array[offset + 8] = varNumber & 0xff;
  }
};


TlvEncoder.prototype.writeTypeAndLength = function(type, length)
{
  
  this.writeVarNumber(length);
  this.writeVarNumber(type);
};


TlvEncoder.prototype.writeNonNegativeIntegerTlv = function(type, value)
{
  if (value < 0)
    throw new Error("TLV integer value may not be negative");

  
  value = Math.round(value)

  
  var saveNBytes = this.length;
  if (value < 253) {
    this.length += 1;
    this.output.ensureLengthFromBack(this.length);
    this.output.array[this.output.array.length - this.length] = value & 0xff;
  }
  else if (value <= 0xffff) {
    this.length += 2;
    this.output.ensureLengthFromBack(this.length);
    var offset = this.output.array.length - this.length;
    this.output.array[offset]     = (value >> 8) & 0xff;
    this.output.array[offset + 1] = value & 0xff;
  }
  else if (value <= 0xffffffff) {
    this.length += 4;
    this.output.ensureLengthFromBack(this.length);
    var offset = this.output.array.length - this.length;
    this.output.array[offset]     = (value >> 24) & 0xff;
    this.output.array[offset + 1] = (value >> 16) & 0xff;
    this.output.array[offset + 2] = (value >> 8) & 0xff;
    this.output.array[offset + 3] = value & 0xff;
  }
  else {
    this.length += 8;
    this.output.ensureLengthFromBack(this.length);
    var offset = this.output.array.length - this.length;
    this.output.array[offset]     = (value >> 56) & 0xff;
    this.output.array[offset + 1] = (value >> 48) & 0xff;
    this.output.array[offset + 2] = (value >> 40) & 0xff;
    this.output.array[offset + 3] = (value >> 32) & 0xff;
    this.output.array[offset + 4] = (value >> 24) & 0xff;
    this.output.array[offset + 5] = (value >> 16) & 0xff;
    this.output.array[offset + 6] = (value >> 8) & 0xff;
    this.output.array[offset + 7] = value & 0xff;
  }

  this.writeTypeAndLength(type, this.length - saveNBytes);
};


TlvEncoder.prototype.writeOptionalNonNegativeIntegerTlv = function(type, value)
{
  if (value != null && value >= 0)
    this.writeNonNegativeIntegerTlv(type, value);
};


TlvEncoder.prototype.writeBlobTlv = function(type, value)
{
  if (value == null) {
    this.writeTypeAndLength(type, 0);
    return;
  }

  
  this.length += value.length;
  this.output.copyFromBack(value, this.length);

  this.writeTypeAndLength(type, value.length);
};


TlvEncoder.prototype.writeOptionalBlobTlv = function(type, value)
{
  if (value != null && value.length > 0)
    this.writeBlobTlv(type, value);
};


TlvEncoder.prototype.getOutput = function()
{
  return this.output.array.slice(this.output.array.length - this.length);
};



var TlvDecoder = function TlvDecoder(input)
{
  this.input = input;
  this.offset = 0;
};

exports.TlvDecoder = TlvDecoder;


TlvDecoder.prototype.readVarNumber = function() 
{
  
  var firstOctet = this.input[this.offset];
  this.offset += 1;
  if (firstOctet < 253)
    return firstOctet;
  else
    return this.readExtendedVarNumber(firstOctet);
};


TlvDecoder.prototype.readExtendedVarNumber = function(firstOctet) 
{
  
  if (firstOctet == 253) {
    result = ((this.input[this.offset] << 8) +
           this.input[this.offset + 1]);
    this.offset += 2;
  }
  else if (firstOctet == 254) {
    result = ((this.input[this.offset] << 24) +
          (this.input[this.offset + 1] << 16) +
          (this.input[this.offset + 2] << 8) +
           this.input[this.offset + 3]);
    this.offset += 4;
  }
  else {
    result = ((this.input[this.offset] << 56) +
          (this.input[this.offset + 1] << 48) +
          (this.input[this.offset + 2] << 40) +
          (this.input[this.offset + 3] << 32) +
          (this.input[this.offset + 4] << 24) +
          (this.input[this.offset + 5] << 16) +
          (this.input[this.offset + 6] << 8) +
           this.input[this.offset + 7]);
    this.offset += 8;
  }
  
  return result;
};


TlvDecoder.prototype.readTypeAndLength = function(expectedType) 
{
  var type = this.readVarNumber();
  if (type != expectedType)
    throw new DecodingException("Did not get the expected TLV type");

  var length = this.readVarNumber();
  if (this.offset + length > this.input.length)
    throw new DecodingException("TLV length exceeds the buffer length");

  return length;
};


TlvDecoder.prototype.readNestedTlvsStart = function(expectedType) 
{
  return this.readTypeAndLength(expectedType) + this.offset;
};


TlvDecoder.prototype.finishNestedTlvs = function(endOffset) 
{
  
  if (this.offset == endOffset)
    return;

  
  while (this.offset < endOffset) {
    
    this.readVarNumber();
    
    var length = this.readVarNumber();
    this.offset += length;

    if (this.offset > this.input.length)
      throw new DecodingException("TLV length exceeds the buffer length");
  }
  
  if (this.offset != endOffset)
    throw new DecodingException
      ("TLV length does not equal the total length of the nested TLVs");
};


TlvDecoder.prototype.peekType = function(expectedType, endOffset) 
{
  if (this.offset >= endOffset)
    
    return false;
  else {
    var saveOffset = this.offset;
    var type = this.readVarNumber();
    
    this.offset = saveOffset;

    return type == expectedType;
  }
};


TlvDecoder.prototype.readNonNegativeInteger = function(length) 
{
  var result;
  if (length == 1)
    result = this.input[this.offset];
  else if (length == 2)
    result = ((this.input[this.offset] << 8) +
           this.input[this.offset + 1]);
  else if (length == 4)
    result = ((this.input[this.offset] << 24) +
          (this.input[this.offset + 1] << 16) +
          (this.input[this.offset + 2] << 8) +
           this.input[this.offset + 3]);
  else if (length == 8)
    result = ((this.input[this.offset] << 56) +
          (this.input[this.offset + 1] << 48) +
          (this.input[this.offset + 2] << 40) +
          (this.input[this.offset + 3] << 32) +
          (this.input[this.offset + 4] << 24) +
          (this.input[this.offset + 5] << 16) +
          (this.input[this.offset + 6] << 8) +
           this.input[this.offset + 7]);
  else
    throw new DecodingException("Invalid length for a TLV nonNegativeInteger");

  this.offset += length;
  return result;
};


TlvDecoder.prototype.readNonNegativeIntegerTlv = function(expectedType) 
{
  var length = this.readTypeAndLength(expectedType);
  return this.readNonNegativeInteger(length);
};


TlvDecoder.prototype.readOptionalNonNegativeIntegerTlv = function
  (expectedType, endOffset) 
{
  if (this.peekType(expectedType, endOffset))
    return this.readNonNegativeIntegerTlv(expectedType);
  else
    return null;
};


TlvDecoder.prototype.readBlobTlv = function(expectedType) 
{
  var length = this.readTypeAndLength(expectedType);
  var result = this.input.slice(this.offset, this.offset + length);

  
  this.offset += length;
  return result;
};


TlvDecoder.prototype.readOptionalBlobTlv = function(expectedType, endOffset) 
{
  if (this.peekType(expectedType, endOffset))
    return this.readBlobTlv(expectedType);
  else
    return null;
};


TlvDecoder.prototype.readBooleanTlv = function(expectedType, endOffset) 
{
  if (this.peekType(expectedType, endOffset)) {
    var length = this.readTypeAndLength(expectedType);
    
    this.offset += length;
    return true;
  }
  else
    return false;
};


TlvDecoder.prototype.getOffset = function() 
{
  return this.offset;
};


TlvDecoder.prototype.seek = function(offset) 
{
  this.offset = offset;
};  



var TlvStructureDecoder = function TlvStructureDecoder()
{
  this.gotElementEnd = false;
  this.offset = 0;
  this.state = TlvStructureDecoder.READ_TYPE;
  this.headerLength = 0;
  this.useHeaderBuffer = false;
  
  
  this.headerBuffer = new internalBuf(8);
  this.nBytesToRead = 0;
};

exports.TlvStructureDecoder = TlvStructureDecoder;

TlvStructureDecoder.READ_TYPE =         0;
TlvStructureDecoder.READ_TYPE_BYTES =   1;
TlvStructureDecoder.READ_LENGTH =       2;
TlvStructureDecoder.READ_LENGTH_BYTES = 3;
TlvStructureDecoder.READ_VALUE_BYTES =  4;


TlvStructureDecoder.prototype.findElementEnd = function(input)
{
  if (this.gotElementEnd)
    
    return true;

  var decoder = new TlvDecoder(input);

  while (true) {
    if (this.offset >= input.length)
      
      return false;

    if (this.state == TlvStructureDecoder.READ_TYPE) {
      var firstOctet = input[this.offset];
      this.offset += 1;
      if (firstOctet < 253)
        
        this.state = TlvStructureDecoder.READ_LENGTH;
      else {
        
        if (firstOctet == 253)
          this.nBytesToRead = 2;
        else if (firstOctet == 254)
          this.nBytesToRead = 4;
        else
          
          this.nBytesToRead = 8;

        this.state = TlvStructureDecoder.READ_TYPE_BYTES;
      }
    }
    else if (this.state == TlvStructureDecoder.READ_TYPE_BYTES) {
      var nRemainingBytes = input.length - this.offset;
      if (nRemainingBytes < this.nBytesToRead) {
        
        this.offset += nRemainingBytes;
        this.nBytesToRead -= nRemainingBytes;
        return false;
      }

      
      this.offset += this.nBytesToRead;
      this.state = TlvStructureDecoder.READ_LENGTH;
    }
    else if (this.state == TlvStructureDecoder.READ_LENGTH) {
      var firstOctet = input[this.offset];
      this.offset += 1;
      if (firstOctet < 253) {
        
        
        this.nBytesToRead = firstOctet;
        if (this.nBytesToRead == 0) {
          
          this.gotElementEnd = true;
          return true;
        }

        this.state = TlvStructureDecoder.READ_VALUE_BYTES;
      }
      else {
        
        
        if (firstOctet == 253)
          this.nBytesToRead = 2;
        else if (firstOctet == 254)
          this.nBytesToRead = 4;
        else
          
          this.nBytesToRead = 8;

        
        this.firstOctet = firstOctet;
        this.state = TlvStructureDecoder.READ_LENGTH_BYTES;
      }
    }
    else if (this.state == TlvStructureDecoder.READ_LENGTH_BYTES) {
      var nRemainingBytes = input.length - this.offset;
      if (!this.useHeaderBuffer && nRemainingBytes >= this.nBytesToRead) {
        
        decoder.seek(this.offset);

        this.nBytesToRead = decoder.readExtendedVarNumber(this.firstOctet);
        
        this.offset = decoder.getOffset();
      }
      else {
        this.useHeaderBuffer = true;

        var nNeededBytes = this.nBytesToRead - this.headerLength;
        if (nNeededBytes > nRemainingBytes) {
          
          
          if (this.headerLength + nRemainingBytes > this.headerBuffer.length)
            
            throw new Error
              ("Cannot store more header bytes than the size of headerBuffer");
          input.slice(this.offset, this.offset + nRemainingBytes).copy
            (this.headerBuffer, this.headerLength);
          this.offset += nRemainingBytes;
          this.headerLength += nRemainingBytes;

          return false;
        }

        
        
        if (this.headerLength + nNeededBytes > this.headerBuffer.length)
          
          throw new Error
            ("Cannot store more header bytes than the size of headerBuffer");
        input.slice(this.offset, this.offset + nNeededBytes).copy
          (this.headerBuffer, this.headerLength);
        this.offset += nNeededBytes;

        
        var bufferDecoder = new TlvDecoder(this.headerBuffer);
        
        this.nBytesToRead = bufferDecoder.readExtendedVarNumber(this.firstOctet);
      }
      
      if (this.nBytesToRead == 0) {
        
        this.gotElementEnd = true;
        return true;
      }

      
      this.state = TlvStructureDecoder.READ_VALUE_BYTES;
    }
    else if (this.state == TlvStructureDecoder.READ_VALUE_BYTES) {
      nRemainingBytes = input.length - this.offset;
      if (nRemainingBytes < this.nBytesToRead) {
        
        this.offset += nRemainingBytes;
        this.nBytesToRead -= nRemainingBytes;
        return false;
      }

      
      this.offset += this.nBytesToRead;
      this.gotElementEnd = true;
      return true;
    }
    else
      
      throw new Error("findElementEnd: unrecognized state");
  }
};


TlvStructureDecoder.prototype.getOffset = function()
{
  return this.offset;
};


TlvStructureDecoder.prototype.seek = function(offset)
{
  this.offset = offset;
};
;
var WireFormat = function WireFormat() {
};

exports.WireFormat = WireFormat;


WireFormat.prototype.encodeInterest = function(interest) 
{
  throw new Error("encodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};


WireFormat.prototype.decodeInterest = function(interest, input) 
{
  throw new Error("decodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};


WireFormat.prototype.encodeData = function(data) 
{
  throw new Error("encodeData is unimplemented in the base WireFormat class.  You should use a derived class.");
};


WireFormat.prototype.decodeData = function(data, input) 
{
  throw new Error("decodeData is unimplemented in the base WireFormat class.  You should use a derived class.");
};


WireFormat.setDefaultWireFormat = function(wireFormat)
{
  WireFormat.defaultWireFormat = wireFormat;
};


WireFormat.getDefaultWireFormat = function()
{
  return WireFormat.defaultWireFormat;
};












var ElementReader = function ElementReader(elementListener) 
{
  this.elementListener = elementListener;
  this.dataParts = [];
  this.binaryXmlStructureDecoder = new BinaryXMLStructureDecoder();
  this.tlvStructureDecoder = new TlvStructureDecoder();
  this.useTlv = null;
};

exports.ElementReader = ElementReader;

ElementReader.prototype.onReceivedData = function( data) 
{
  
  while (true) {
    if (this.dataParts.length == 0) {
      
      if (data.length <= 0)
        
        return;
      
      
      
      
      if (data[0] == Tlv.Interest || data[0] == Tlv.Data || data[0] == 0x80)
        this.useTlv = true;
      else
        
        this.useTlv = false;
    }

    var gotElementEnd;
    var offset;
    if (this.useTlv) {
      
      this.tlvStructureDecoder.seek(0);
      gotElementEnd = this.tlvStructureDecoder.findElementEnd(data);
      offset = this.tlvStructureDecoder.getOffset();
    }
    else {
      
      this.binaryXmlStructureDecoder.seek(0);
      gotElementEnd = this.binaryXmlStructureDecoder.findElementEnd(data);
      offset = this.binaryXmlStructureDecoder.offset;
    }
    
    if (gotElementEnd) {
      
      this.dataParts.push(data.slice(0, offset));
      var element = DataUtils.concatArrays(this.dataParts);
      this.dataParts = [];
      try {
        this.elementListener.onReceivedElement(element);
      } catch (ex) {
          console.log("ElementReader: ignoring exception from onReceivedElement: " + ex);
      }
  
      
      data = data.slice(offset, data.length);
      this.binaryXmlStructureDecoder = new BinaryXMLStructureDecoder();
      this.tlvStructureDecoder = new TlvStructureDecoder();
      if (data.length == 0)
        
        return;
      
      
    }
    else {
      
      this.dataParts.push(data);
      if (LOG > 3) console.log('Incomplete packet received. Length ' + data.length + '. Wait for more input.');
        return;
    }
  }    
};






var NameEnumeration = function NameEnumeration(face, onComponents) 
{
  this.face = face;
  this.onComponents = onComponents;
  this.contentParts = [];
  
  var self = this;
  this.onData = function(interest, data) { self.processData(data); };
  this.onTimeout = function(interest) { self.processTimeout(); };
};

exports.NameEnumeration = NameEnumeration;


NameEnumeration.getComponents = function(face, prefix, onComponents)
{
  var command = new Name(prefix);
  
  command.add([0xc1, 0x2e, 0x45, 0x2e, 0x62, 0x65])
  
  var enumeration = new NameEnumeration(face, onComponents);
  face.expressInterest(command, enumeration.onData, enumeration.onTimeout);
};


NameEnumeration.prototype.processData = function(data) 
{
  try {
    if (!NameEnumeration.endsWithSegmentNumber(data.name))
      
      this.onComponents(null);
    else {
      var segmentNumber = DataUtils.bigEndianToUnsignedInt
          (data.name.get(data.name.size() - 1).getValue());

      
      var expectedSegmentNumber = this.contentParts.length;
      if (segmentNumber != expectedSegmentNumber)
        
        this.face.expressInterest
          (data.name.getPrefix(-1).addSegment(expectedSegmentNumber), this.onData, this.onTimeout);
      else {
        
        this.contentParts.push(data.content);

        if (data.signedInfo != null && data.signedInfo.finalBlockID != null) {
          var finalSegmentNumber = DataUtils.bigEndianToUnsignedInt(data.signedInfo.finalBlockID);
          if (segmentNumber == finalSegmentNumber) {
            
            this.onComponents(NameEnumeration.parseComponents(Buffer.concat(this.contentParts)));
            return;
          }
        }

        
        this.face.expressInterest
          (data.name.getPrefix(-1).addSegment(expectedSegmentNumber + 1), this.onData, this.onTimeout);
      }
    }
  } catch (ex) {
    console.log("NameEnumeration: ignoring exception: " + ex);
  }
};


NameEnumeration.prototype.processTimeout = function()
{
  try {
    this.onComponents(null);
  } catch (ex) {
    console.log("NameEnumeration: ignoring exception: " + ex);
  }
};


NameEnumeration.parseComponents = function(content)
{
  var components = [];
  var decoder = new BinaryXMLDecoder(content);
  
  decoder.readElementStartDTag(NDNProtocolDTags.Collection);
 
  while (decoder.peekDTag(NDNProtocolDTags.Link)) {
    decoder.readElementStartDTag(NDNProtocolDTags.Link);    
    decoder.readElementStartDTag(NDNProtocolDTags.Name);
    
    components.push(new internalBuf(decoder.readBinaryDTagElement(NDNProtocolDTags.Component)));
    
    decoder.readElementClose();  
    decoder.readElementClose();  
  }

  decoder.readElementClose();
  return components;
};


NameEnumeration.endsWithSegmentNumber = function(name) {
  return name.components != null && name.size() >= 1 &&
         name.get(name.size() - 1).getValue().length >= 1 &&
         name.get(name.size() - 1).getValue()[0] == 0;
};




var WebSocketTransport = function WebSocketTransport() 
{    
  if (!WebSocket)
    throw new Error("WebSocket support is not available on this platform.");
    
  this.ws = null;
  this.connectedHost = null; 
  this.connectedPort = null; 
  this.elementReader = null;
  this.defaultGetHostAndPort = Face.makeShuffledGetHostAndPort
    (["A.ws.ndn.ucla.edu", "B.ws.ndn.ucla.edu", "C.ws.ndn.ucla.edu", "D.ws.ndn.ucla.edu", 
      "E.ws.ndn.ucla.edu", "F.ws.ndn.ucla.edu", "G.ws.ndn.ucla.edu", "H.ws.ndn.ucla.edu", 
      "I.ws.ndn.ucla.edu", "J.ws.ndn.ucla.edu", "K.ws.ndn.ucla.edu", "L.ws.ndn.ucla.edu", 
      "M.ws.ndn.ucla.edu", "N.ws.ndn.ucla.edu"],
     9696);
};

exports.WebSocketTransport = WebSocketTransport;


WebSocketTransport.prototype.connect = function(face, onopenCallback) 
{
  this.close();
  
  this.ws = new WebSocket('ws:' + face.host + ':' + face.port);
  if (LOG > 0) console.log('ws connection created.');
    this.connectedHost = face.host;
    this.connectedPort = face.port;
  
  this.ws.binaryType = "arraybuffer";
  
  this.elementReader = new ElementReader(face);
  var self = this;
  this.ws.onmessage = function(ev) {
    var result = ev.data;
    
      
    if (result == null || result == undefined || result == "") {
      console.log('INVALID ANSWER');
    } 
    else if (result instanceof ArrayBuffer) {
      var bytearray = new internalBuf(result);
          
      if (LOG > 3) console.log('BINARY RESPONSE IS ' + bytearray.toString('hex'));
      
      try {
        
        self.elementReader.onReceivedData(bytearray);
      } catch (ex) {
        console.log("NDN.ws.onmessage exception: " + ex);
        return;
      }
    }
  }
  
  this.ws.onopen = function(ev) {
    if (LOG > 3) console.log(ev);
    if (LOG > 3) console.log('ws.onopen: WebSocket connection opened.');
    if (LOG > 3) console.log('ws.onopen: ReadyState: ' + this.readyState);
    

    onopenCallback();
  }
  
  this.ws.onerror = function(ev) {
    console.log('ws.onerror: ReadyState: ' + this.readyState);
    console.log(ev);
    console.log('ws.onerror: WebSocket error: ' + ev.data);
  }
  
  this.ws.onclose = function(ev) {
    console.log('ws.onclose: WebSocket connection closed.');
    self.ws = null;
    
    
    face.readyStatus = Face.CLOSED;
    face.onclose();
    
  }
};


WebSocketTransport.prototype.send = function(data) 
{
  if (this.ws != null) {
    
    
    
    
    
    
    
    var bytearray = new Uint8Array(data.length);
    bytearray.set(data);
    this.ws.send(bytearray.buffer);
    if (LOG > 3) console.log('ws.send() returned.');
  }
  else
    console.log('WebSocket connection is not established.');
};


WebSocketTransport.prototype.close = function()
{
  if (this.ws != null)
    delete this.ws;
}

;
exports.TcpTransport = ndn.WebSocketTransport;
;
var Closure = function Closure() 
{
  
  
  
  
  
  this.ndn_data = null;  
  this.ndn_data_dirty = false; 
};

exports.Closure = Closure;


Closure.RESULT_ERR               = -1; 
Closure.RESULT_OK                =  0; 
Closure.RESULT_REEXPRESS         =  1; 
Closure.RESULT_INTEREST_CONSUMED =  2; 
Closure.RESULT_VERIFY            =  3; 
Closure.RESULT_FETCHKEY          =  4; 
                                       


Closure.UPCALL_FINAL              = 0; 
Closure.UPCALL_INTEREST           = 1; 
Closure.UPCALL_CONSUMED_INTEREST  = 2; 
Closure.UPCALL_CONTENT            = 3; 
Closure.UPCALL_INTEREST_TIMED_OUT = 4; 
Closure.UPCALL_CONTENT_UNVERIFIED = 5; 
Closure.UPCALL_CONTENT_BAD        = 6; 


Closure.prototype.upcall = function(kind, upcallInfo) 
{
  
  return Closure.RESULT_OK;
};


var UpcallInfo = function UpcallInfo(face, interest, matchedComps, data) 
{
  this.face = face;  
  this.ndn = face;   
  this.interest = interest;  
  this.matchedComps = matchedComps;  
  this.data = data;  
  this.contentObject = data; 
};

UpcallInfo.prototype.toString = function() 
{
  var ret = "face = " + this.face;
  ret += "\nInterest = " + this.interest;
  ret += "\nmatchedComps = " + this.matchedComps;
  ret += "\nData: " + this.data;
  return ret;
};

exports.UpcallInfo = UpcallInfo;




var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(pkd) 
{ 
 this.PUBLISHER_ID_LEN = 512/8;
 this.publisherPublicKeyDigest = pkd;
};

exports.PublisherPublicKeyDigest = PublisherPublicKeyDigest;

PublisherPublicKeyDigest.prototype.from_ndnb = function(decoder) 
{
  this.publisherPublicKeyDigest = decoder.readBinaryDTagElement(this.getElementLabel());
    
  if (LOG > 4) console.log('Publisher public key digest is ' + this.publisherPublicKeyDigest);

  if (null == this.publisherPublicKeyDigest)
    throw new Error("Cannot parse publisher key digest.");
    
  

  if (this.publisherPublicKeyDigest.length != this.PUBLISHER_ID_LEN) {
    if (LOG > 0)
      console.log('LENGTH OF PUBLISHER ID IS WRONG! Expected ' + this.PUBLISHER_ID_LEN + ", got " + this.publisherPublicKeyDigest.length);
      
    
  }
};

PublisherPublicKeyDigest.prototype.to_ndnb= function(encoder) 
{
  
  if (!this.validate())
    throw new Error("Cannot encode : field values missing.");

  if (LOG > 3) console.log('PUBLISHER KEY DIGEST IS'+this.publisherPublicKeyDigest);
  encoder.writeDTagElement(this.getElementLabel(), this.publisherPublicKeyDigest);
};
  
PublisherPublicKeyDigest.prototype.getElementLabel = function() { return NDNProtocolDTags.PublisherPublicKeyDigest; };

PublisherPublicKeyDigest.prototype.validate = function() 
{
    return null != this.publisherPublicKeyDigest;
};





var PublisherType = function PublisherType(tag) 
{
  this.KEY = NDNProtocolDTags.PublisherPublicKeyDigest;
  this.CERTIFICATE = NDNProtocolDTags.PublisherCertificateDigest;
  this.ISSUER_KEY = NDNProtocolDTags.PublisherIssuerKeyDigest;
  this.ISSUER_CERTIFICATE = NDNProtocolDTags.PublisherIssuerCertificateDigest;

  this.Tag = tag;
}; 


var PublisherID = function PublisherID() 
{
  this.PUBLISHER_ID_DIGEST_ALGORITHM = "SHA-256";
  this.PUBLISHER_ID_LEN = 256/8;
    
  

  
  this.publisherID =null;
    
  
  
  this.publisherType = null;
};

exports.PublisherID = PublisherID;

PublisherID.prototype.from_ndnb = function(decoder) 
{    
  
  var nextTag = PublisherID.peekAndGetNextDTag(decoder);
    
  this.publisherType = new PublisherType(nextTag); 
    
  if (nextTag < 0)
    throw new Error("Invalid publisher ID, got unexpected type");

  this.publisherID = decoder.readBinaryDTagElement(nextTag);
  if (null == this.publisherID)
    throw new DecodingException(new Error("Cannot parse publisher ID of type : " + nextTag + "."));
};

PublisherID.prototype.to_ndnb = function(encoder) 
{
  if (!this.validate())
    throw new Error("Cannot encode " + this.getClass().getName() + ": field values missing.");

  encoder.writeDTagElement(this.getElementLabel(), this.publisherID);
};


PublisherID.peekAndGetNextDTag = function(decoder) 
{
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest))
    return             NDNProtocolDTags.PublisherPublicKeyDigest;
  if (decoder.peekDTag(NDNProtocolDTags.PublisherCertificateDigest))
    return             NDNProtocolDTags.PublisherCertificateDigest;
  if (decoder.peekDTag(NDNProtocolDTags.PublisherIssuerKeyDigest))
    return             NDNProtocolDTags.PublisherIssuerKeyDigest;
  if (decoder.peekDTag(NDNProtocolDTags.PublisherIssuerCertificateDigest))
    return             NDNProtocolDTags.PublisherIssuerCertificateDigest;
  
  return -1;
};
  
PublisherID.peek = function( decoder) 
{
  return PublisherID.peekAndGetNextDTag(decoder) >= 0;
};

PublisherID.prototype.getElementLabel = function()
{ 
  return this.publisherType.Tag;
};

PublisherID.prototype.validate = function() 
{
  return null != id() && null != type();
};








var Name = function Name(components) 
{
  if (typeof components == 'string') {    
    if (LOG > 3) console.log('Content Name String ' + components);
    this.components = Name.createNameArray(components);
  }
  else if (typeof components === 'object') {    
    this.components = [];
    if (components instanceof Name)
      this.append(components);
    else {
      for (var i = 0; i < components.length; ++i)
        this.append(components[i]);
    }
  }
  else if (components == null)
    this.components = [];
  else
    if (LOG > 1) console.log("NO CONTENT NAME GIVEN");
};

exports.Name = Name;


Name.Component = function NameComponent(value) 
{
  if (typeof value === 'string')
    this.value = DataUtils.stringToUtf8Array(value);
  else if (typeof value === 'object' && value instanceof Name.Component)
    this.value = new internalBuf(value.value);
  else if (typeof value === 'object' && value instanceof Blob)
    this.value = new internalBuf(value.buf());
  else if (typeof value === 'object' && value instanceof internalBuf)
    this.value = new internalBuf(value);
  else if (typeof value === 'object' && typeof ArrayBuffer !== 'undefined' &&  value instanceof ArrayBuffer) {
    
    this.value = new internalBuf(new ArrayBuffer(value.byteLength));
    this.value.set(new internalBuf(value));
  }
  else if (typeof value === 'object')
    
    
    this.value = new internalBuf(value);
  else 
    throw new Error("Name.Component constructor: Invalid type");
}


Name.Component.prototype.getValue = function() 
{
  return this.value;
}


Name.Component.prototype.toEscapedString = function() 
{
  return Name.toEscapedString(this.value);
}


Name.Component.prototype.equals = function(other) 
{
  return DataUtils.arraysEqual(this.value, other.value);
}


Name.prototype.getName = function() 
{
  return this.toUri();
};


Name.createNameArray = function(uri) 
{
  uri = uri.trim();
  if (uri.length <= 0)
    return [];

  var iColon = uri.indexOf(':');
  if (iColon >= 0) {
    
    var iFirstSlash = uri.indexOf('/');
    if (iFirstSlash < 0 || iColon < iFirstSlash)
      
      uri = uri.substr(iColon + 1, uri.length - iColon - 1).trim();
  }
    
  if (uri[0] == '/') {
    if (uri.length >= 2 && uri[1] == '/') {
      
      var iAfterAuthority = uri.indexOf('/', 2);
      if (iAfterAuthority < 0)
        
        return [];
      else
        uri = uri.substr(iAfterAuthority + 1, uri.length - iAfterAuthority - 1).trim();
    }
    else
      uri = uri.substr(1, uri.length - 1).trim();
  }

  var array = uri.split('/');
    
  
  for (var i = 0; i < array.length; ++i) {
    var value = Name.fromEscapedString(array[i]);
        
    if (value == null) {
      
      array.splice(i, 1);
      --i;  
      continue;
    }
    else
      array[i] = new Name.Component(value);
  }

  return array;
};

Name.prototype.from_ndnb = function( decoder)  
{
  decoder.readElementStartDTag(this.getElementLabel());
    
  this.components = [];

  while (decoder.peekDTag(NDNProtocolDTags.Component))
    this.append(decoder.readBinaryDTagElement(NDNProtocolDTags.Component));
    
  decoder.readElementClose();
};

Name.prototype.to_ndnb = function( encoder)  
{    
  if (this.components == null) 
    throw new Error("CANNOT ENCODE EMPTY CONTENT NAME");

  encoder.writeElementStartDTag(this.getElementLabel());
  var count = this.size();
  for (var i=0; i < count; i++)
    encoder.writeDTagElement(NDNProtocolDTags.Component, this.components[i].getValue());
  
  encoder.writeElementClose();
};

Name.prototype.getElementLabel = function() 
{
  return NDNProtocolDTags.Name;
};


Name.prototype.append = function(component) 
{
  if (typeof component == 'object' && component instanceof Name) {
    var components;
    if (component == this)
      
      components = this.components.slice(0, this.components.length);
    else
      components = component.components;
      
    for (var i = 0; i < components.length; ++i)
      this.components.push(new Name.Component(components[i]));
  }
  else
    
    this.components.push(new Name.Component(component));

  return this;
};


Name.prototype.add = function(component)
{
  return this.append(component);
};


Name.prototype.clear = function()
{
  this.components = [];  
};


Name.prototype.toUri = function() 
{  
  if (this.size() == 0)
    return "/";
    
  var result = "";
  
  for (var i = 0; i < this.size(); ++i)
    result += "/"+ Name.toEscapedString(this.components[i].getValue());
  
  return result;  
};


Name.prototype.to_uri = function() 
{
  return this.toUri();
};


Name.prototype.appendSegment = function(segment) 
{
  var segmentNumberBigEndian = DataUtils.nonNegativeIntToBigEndian(segment);
  
  var segmentNumberComponent = new internalBuf(segmentNumberBigEndian.length + 1);
  segmentNumberComponent[0] = 0;
  segmentNumberBigEndian.copy(segmentNumberComponent, 1);

  this.components.push(new Name.Component(segmentNumberComponent));
  return this;
};


Name.prototype.appendVersion = function(version) 
{
  var segmentNumberBigEndian = DataUtils.nonNegativeIntToBigEndian(version);
  
  var segmentNumberComponent = new internalBuf(segmentNumberBigEndian.length + 1);
  segmentNumberComponent[0] = 0xfD;
  segmentNumberBigEndian.copy(segmentNumberComponent, 1);

  this.components.push(new Name.Component(segmentNumberComponent));
  return this;
};


Name.prototype.addSegment = function(number) 
{
  return this.appendSegment(number);
};


Name.prototype.getSubName = function(iStartComponent, nComponents)
{
  if (nComponents == undefined)
    nComponents = this.components.length - iStartComponent;
  
  var result = new Name();

  var iEnd = iStartComponent + nComponents;
  for (var i = iStartComponent; i < iEnd && i < this.components.length; ++i)
    result.components.push(this.components[i]);

  return result;  
};


Name.prototype.getPrefix = function(nComponents) 
{
  if (nComponents < 0)
    return this.getSubName(0, this.components.length + nComponents);
  else
    return this.getSubName(0, nComponents);
};


Name.prototype.cut = function(minusComponents) 
{
  return new Name(this.components.slice(0, this.components.length - minusComponents));
};


Name.prototype.size = function() 
{
  return this.components.length;
};


Name.prototype.get = function(i) 
{
  if (i >= 0) {
    if (i >= this.components.length)
      throw new Error("Name.get: Index is out of bounds");

    return new Name.Component(this.components[i]);
  }
  else {
    
    if (i < -this.components.length)
      throw new Error("Name.get: Index is out of bounds");

    return new Name.Component(this.components[this.components.length - (-i)]);
  }
};


Name.prototype.getComponentCount = function() 
{
  return this.components.length;
};


Name.prototype.getComponent = function(i) 
{
  return new internalBuf(this.components[i].getValue());
};


Name.prototype.indexOfFileName = function() 
{
  for (var i = this.size() - 1; i >= 0; --i) {
    var component = this.components[i].getValue();
    if (component.length <= 0)
      continue;
        
    if (component[0] == 0 || component[0] == 0xC0 || component[0] == 0xC1 || 
        (component[0] >= 0xF5 && component[0] <= 0xFF))
      continue;
        
    return i;
  }
    
  return -1;
};


Name.prototype.equals = function(name) 
{
  if (this.components.length != name.components.length)
    return false;
    
  
  for (var i = this.components.length - 1; i >= 0; --i) {
    if (!this.components[i].equals(name.components[i]))
      return false;
  }
    
  return true;
};


Name.prototype.equalsName = function(name)
{
  return this.equals(name);
};


Name.prototype.getContentDigestValue = function() 
{
  for (var i = this.size() - 1; i >= 0; --i) {
    var digestValue = Name.getComponentContentDigestValue(this.components[i]);
    if (digestValue != null)
      return digestValue;
  }
    
  return null;
};


Name.getComponentContentDigestValue = function(component) 
{
  if (typeof component == 'object' && component instanceof Name.Component)
    component = component.getValue();

  var digestComponentLength = Name.ContentDigestPrefix.length + 32 + Name.ContentDigestSuffix.length; 
  
  if (component.length == digestComponentLength &&
      DataUtils.arraysEqual(component.slice(0, Name.ContentDigestPrefix.length), 
                            Name.ContentDigestPrefix) &&
      DataUtils.arraysEqual(component.slice
         (component.length - Name.ContentDigestSuffix.length, component.length),
                            Name.ContentDigestSuffix))
   return component.slice(Name.ContentDigestPrefix.length, Name.ContentDigestPrefix.length + 32);
 else
   return null;
};


Name.ContentDigestPrefix = new internalBuf([0xc1, 0x2e, 0x4d, 0x2e, 0x47, 0xc1, 0x01, 0xaa, 0x02, 0x85]);
Name.ContentDigestSuffix = new internalBuf([0x00]);



Name.toEscapedString = function(value) 
{
  if (typeof value == 'object' && value instanceof Name.Component)
    value = value.getValue();
  
  var result = "";
  var gotNonDot = false;
  for (var i = 0; i < value.length; ++i) {
    if (value[i] != 0x2e) {
      gotNonDot = true;
      break;
    }
  }
  if (!gotNonDot) {
    
    result = "...";
    for (var i = 0; i < value.length; ++i)
      result += ".";
  }
  else {
    for (var i = 0; i < value.length; ++i) {
      var x = value[i];
      
      if (x >= 0x30 && x <= 0x39 || x >= 0x41 && x <= 0x5a ||
          x >= 0x61 && x <= 0x7a || x == 0x2b || x == 0x2d || 
          x == 0x2e || x == 0x5f)
        result += String.fromCharCode(x);
      else
        result += "%" + (x < 16 ? "0" : "") + x.toString(16).toUpperCase();
    }
  }
  return result;
};


Name.fromEscapedString = function(escapedString) 
{
  var value = unescape(escapedString.trim());
        
  if (value.match(/[^.]/) == null) {
    
    if (value.length <= 2)
      
      
      return null;
    else
      
      return DataUtils.toNumbersFromString(value.substr(3, value.length - 3));
  }
  else
    return DataUtils.toNumbersFromString(value);
};


Name.prototype.match = function(name) 
{
  var i_name = this.components;
  var o_name = name.components;

  
  if (i_name.length > o_name.length)
    return false;

  
  for (var i = 0; i < i_name.length; ++i) {
    if (!i_name[i].equals(o_name[i]))
      return false;
  }

  return true;
};




var Key = function Key() 
{
  this.publicKeyDer = null;     
  this.publicKeyDigest = null;  
  this.publicKeyPem = null;     
  this.privateKeyPem = null;    
};

exports.Key = Key;



Key.prototype.publicToDER = function() 
{
  return this.publicKeyDer;  
};

Key.prototype.privateToDER = function() 
{
  
  
  var lines = this.privateKeyPem.split('\n');
  priKey = "";
  for (var i = 1; i < lines.length - 1; i++)
    priKey += lines[i];
  
  return new internalBuf(priKey, 'base64');    
};

Key.prototype.publicToPEM = function() 
{
  return this.publicKeyPem;
};

Key.prototype.privateToPEM = function() 
{
  return this.privateKeyPem;
};

Key.prototype.getKeyID = function() 
{
  return this.publicKeyDigest;
};

exports.Key = Key;

Key.prototype.readDerPublicKey = function(pub_der) 
{
  if (LOG > 4) console.log("Encode DER public key:\n" + pub_der.toString('hex'));

  this.publicKeyDer = pub_der;

  var hash = require("crypto").createHash('sha256');
  hash.update(this.publicKeyDer);
  this.publicKeyDigest = new internalBuf(hash.digest());
    
  var keyStr = pub_der.toString('base64'); 
  var keyPem = "-----BEGIN PUBLIC KEY-----\n";
  for (var i = 0; i < keyStr.length; i += 64)
  keyPem += (keyStr.substr(i, 64) + "\n");
  keyPem += "-----END PUBLIC KEY-----";
  this.publicKeyPem = keyPem;

  if (LOG > 4) console.log("Convert public key to PEM format:\n" + this.publicKeyPem);
};


Key.prototype.fromPemString = function(pub, pri) 
{
  if (pub == null && pri == null)
    throw new Error('Cannot create Key object if both public and private PEM string is empty.');

  
  if (pub != null) {
    this.publicKeyPem = pub;
    if (LOG > 4) console.log("Key.publicKeyPem: \n" + this.publicKeyPem);
  
    
    
    var lines = pub.split('\n');
    pub = "";
    for (var i = 1; i < lines.length - 1; i++)
      pub += lines[i];
    this.publicKeyDer = new internalBuf(pub, 'base64');
    if (LOG > 4) console.log("Key.publicKeyDer: \n" + this.publicKeyDer.toString('hex'));
  
    var hash = require("crypto").createHash('sha256');
    hash.update(this.publicKeyDer);
    this.publicKeyDigest = new internalBuf(hash.digest());
    if (LOG > 4) console.log("Key.publicKeyDigest: \n" + this.publicKeyDigest.toString('hex'));
  }
    
  
  if (pri != null) {
    this.privateKeyPem = pri;
    if (LOG > 4) console.log("Key.privateKeyPem: \n" + this.privateKeyPem);
  }
};

Key.prototype.fromPem = Key.prototype.fromPemString;


Key.createFromPEM = function(obj) 
{
    var key = new Key();
    key.fromPemString(obj.pub, obj.pri);
    return key;
};






var KeyLocatorType = {
  KEYNAME: 1,
  KEY_LOCATOR_DIGEST: 2,
  KEY: 3,
  CERTIFICATE: 4
};

exports.KeyLocatorType = KeyLocatorType;


var KeyLocator = function KeyLocator(input,type) 
{ 
  if (typeof input === 'object' && input instanceof KeyLocator) {
    
    this.type = input.type;
    this.keyName = new KeyName();
    if (input.keyName != null) {
      this.keyName.contentName = input.keyName.contentName == null ? 
        null : new Name(input.keyName.contentName);
      this.keyName.publisherID = input.keyName.publisherID;
    }
    this.keyData = input.keyData == null ? null : new internalBuf(input.keyData);
    this.publicKey = input.publicKey == null ? null : new internalBuf(input.publicKey);
    this.certificate = input.certificate == null ? null : new internalBuf(input.certificate);
  }
  else {
    this.type = type;
    this.keyName = new KeyName();

    if (type == KeyLocatorType.KEYNAME)
      this.keyName = input;
    else if (type == KeyLocatorType.KEY_LOCATOR_DIGEST)
      this.keyData = new internalBuf(input);
    else if (type == KeyLocatorType.KEY) {
      this.keyData = new internalBuf(input);
      
      this.publicKey = this.keyData;
    }
    else if (type == KeyLocatorType.CERTIFICATE) {
      this.keyData = new internalBuf(input);
      
      this.certificate = this.keyData;
    }
  }
};

exports.KeyLocator = KeyLocator;


KeyLocator.prototype.getType = function() { return this.type; };


KeyLocator.prototype.getKeyName = function() 
{ 
  if (this.keyName == null)
    this.keyName = new KeyName();
  if (this.keyName.contentName == null)
    this.keyName.contentName = new Name();
  
  return this.keyName.contentName;
};


KeyLocator.prototype.getKeyData = function() 
{ 
  if (this.type == KeyLocatorType.KEY)
    return this.publicKey;
  else if (this.type == KeyLocatorType.CERTIFICATE)
    return this.certificate;
  else
    return this.keyData;
};


KeyLocator.prototype.setType = function(type) { this.type = type; }; 


KeyLocator.prototype.setKeyName = function(name) 
{ 
  if (this.keyName == null)
    this.keyName = new KeyName();
  
  this.keyName.contentName = typeof name === 'object' && name instanceof Name ?
                             new Name(name) : new Name(); 
}; 


KeyLocator.prototype.setKeyData = function(keyData)
{
  var value = keyData;
  if (value != null)
    
    value = new internalBuf(value);
  
  this.keyData = value;
  
  this.publicKey = value;
  this.certificate = value;
};


KeyLocator.prototype.clear = function() 
{
  this.type = null;
  this.keyName = null;
  this.keyData = null;
  this.publicKey = null;
  this.certificate = null;
};

KeyLocator.prototype.from_ndnb = function(decoder) {

  decoder.readElementStartDTag(this.getElementLabel());

  if (decoder.peekDTag(NDNProtocolDTags.Key)) 
  {
    try {
      var encodedKey = decoder.readBinaryDTagElement(NDNProtocolDTags.Key);
      
      
      

      this.publicKey =   encodedKey;
      this.type = KeyLocatorType.KEY;    

      if (LOG > 4) console.log('PUBLIC KEY FOUND: '+ this.publicKey);
    } 
    catch (e) {
      throw new Error("Cannot parse key: ", e);
    } 

    if (null == this.publicKey)
      throw new Error("Cannot parse key: ");
  } 
  else if (decoder.peekDTag(NDNProtocolDTags.Certificate)) {
    try {
      var encodedCert = decoder.readBinaryDTagElement(NDNProtocolDTags.Certificate);
      
      
      
      this.certificate = encodedCert;
      this.type = KeyLocatorType.CERTIFICATE;

      if (LOG > 4) console.log('CERTIFICATE FOUND: '+ this.certificate);      
    } 
    catch (e) {
      throw new Error("Cannot decode certificate: " +  e);
    }
    if (null == this.certificate)
      throw new Error("Cannot parse certificate! ");
  } else  {
    this.type = KeyLocatorType.KEYNAME;
    
    this.keyName = new KeyName();
    this.keyName.from_ndnb(decoder);
  }
  decoder.readElementClose();
};  

KeyLocator.prototype.to_ndnb = function(encoder) 
{
  if (LOG > 4) console.log('type is is ' + this.type);

  if (this.type == KeyLocatorType.KEY_LOCATOR_DIGEST)
    
    
    return;

  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (this.type == KeyLocatorType.KEY) {
    if (LOG > 5) console.log('About to encode a public key' +this.publicKey);
    encoder.writeDTagElement(NDNProtocolDTags.Key, this.publicKey);  
  } 
  else if (this.type == KeyLocatorType.CERTIFICATE) {  
    try {
      encoder.writeDTagElement(NDNProtocolDTags.Certificate, this.certificate);
    } 
    catch (e) {
      throw new Error("CertificateEncodingException attempting to write key locator: " + e);
    }    
  } 
  else if (this.type == KeyLocatorType.KEYNAME)
    this.keyName.to_ndnb(encoder);

  encoder.writeElementClose();
};

KeyLocator.prototype.getElementLabel = function() 
{
  return NDNProtocolDTags.KeyLocator; 
};


var KeyName = function KeyName() 
{
  this.contentName = new Name();  
  this.publisherID = this.publisherID;  
};

exports.KeyName = KeyName;

KeyName.prototype.from_ndnb = function(decoder) 
{
  decoder.readElementStartDTag(this.getElementLabel());

  this.contentName = new Name();
  this.contentName.from_ndnb(decoder);
  
  if (LOG > 4) console.log('KEY NAME FOUND: ');
  
  if (PublisherID.peek(decoder)) {
    this.publisherID = new PublisherID();
    this.publisherID.from_ndnb(decoder);
  }
  
  decoder.readElementClose();
};

KeyName.prototype.to_ndnb = function(encoder)
{
  encoder.writeElementStartDTag(this.getElementLabel());
  
  this.contentName.to_ndnb(encoder);
  if (null != this.publisherID)
    this.publisherID.to_ndnb(encoder);

  encoder.writeElementClose();       
};
  
KeyName.prototype.getElementLabel = function() { return NDNProtocolDTags.KeyName; };




var KeyManager = function KeyManager()
{
  this.certificate = 
  "MIIBmzCCAQQCCQC32FyQa61S7jANBgkqhkiG9w0BAQUFADASMRAwDgYDVQQDEwd" +
  "heGVsY2R2MB4XDTEyMDQyODIzNDQzN1oXDTEyMDUyODIzNDQzN1owEjEQMA4GA1" +
  "UEAxMHYXhlbGNkdjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4X0wp9goq" +
  "xuECxdULcr2IHr9Ih4Iaypg0Wy39URIup8/CLzQmdsh3RYqd55hqonu5VTTpH3i" +
  "MLx6xZDVJAZ8OJi7pvXcQ2C4Re2kjL2c8SanI0RfDhlS1zJadfr1VhRPmpivcYa" +
  "wJ4aFuOLAi+qHFxtN7lhcGCgpW1OV60oXd58CAwEAATANBgkqhkiG9w0BAQUFAA" +
  "OBgQDLOrA1fXzSrpftUB5Ro6DigX1Bjkf7F5Bkd69hSVp+jYeJFBBlsILQAfSxU" +
  "ZPQtD+2Yc3iCmSYNyxqu9PcufDRJlnvB7PG29+L3y9lR37tetzUV9eTscJ7rdp8" +
  "Wt6AzpW32IJ/54yKNfP7S6ZIoIG+LP6EIxq6s8K1MXRt8uBJKw==";

  
    this.publicKey = 
  "-----BEGIN PUBLIC KEY-----\n" +
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhfTCn2CirG4QLF1QtyvYgev0i\n" +
  "HghrKmDRbLf1REi6nz8IvNCZ2yHdFip3nmGqie7lVNOkfeIwvHrFkNUkBnw4mLum\n" +
  "9dxDYLhF7aSMvZzxJqcjRF8OGVLXMlp1+vVWFE+amK9xhrAnhoW44sCL6ocXG03u\n" +
  "WFwYKClbU5XrShd3nwIDAQAB\n" +
  "-----END PUBLIC KEY-----";
  
    this.privateKey = 
  "-----BEGIN RSA PRIVATE KEY-----\n" +
  "MIICXQIBAAKBgQDhfTCn2CirG4QLF1QtyvYgev0iHghrKmDRbLf1REi6nz8IvNCZ\n" +
  "2yHdFip3nmGqie7lVNOkfeIwvHrFkNUkBnw4mLum9dxDYLhF7aSMvZzxJqcjRF8O\n" +
  "GVLXMlp1+vVWFE+amK9xhrAnhoW44sCL6ocXG03uWFwYKClbU5XrShd3nwIDAQAB\n" +
  "AoGAGkv6T6jC3WmhFZYL6CdCWvlc6gysmKrhjarrLTxgavtFY6R5g2ft5BXAsCCV\n" +
  "bUkWxkIFSKqxpVNl0gKZCNGEzPDN6mHJOQI/h0rlxNIHAuGfoAbCzALnqmyZivhJ\n" +
  "APGijAyKuU9tczsst5+Kpn+bn7ehzHQuj7iwJonS5WbojqECQQD851K8TpW2GrRi\n" +
  "zNgG4dx6orZxAaon/Jnl8lS7soXhllQty7qG+oDfzznmdMsiznCqEABzHUUKOVGE\n" +
  "9RWPN3aRAkEA5D/w9N55d0ibnChFJlc8cUAoaqH+w+U3oQP2Lb6AZHJpLptN4y4b\n" +
  "/uf5d4wYU5/i/gC7SSBH3wFhh9bjRLUDLwJAVOx8vN0Kqt7myfKNbCo19jxjVSlA\n" +
  "8TKCn1Oznl/BU1I+rC4oUaEW25DjmX6IpAR8kq7S59ThVSCQPjxqY/A08QJBAIRa\n" +
  "F2zGPITQk3r/VumemCvLWiRK/yG0noc9dtibqHOWbCtcXtOm/xDWjq+lis2i3ssO\n" +
  "vYrvrv0/HcDY+Dv1An0CQQCLJtMsfSg4kvG/FRY5UMhtMuwo8ovYcMXt4Xv/LWaM\n" +
  "hndD67b2UGawQCRqr5ghRTABWdDD/HuuMBjrkPsX0861\n" +
  "-----END RSA PRIVATE KEY-----";
  
  this.key = null;
};


KeyManager.prototype.getKey = function()
{
  if (this.key === null) {
    this.key = new Key();
    this.key.fromPemString(this.publicKey, this.privateKey);
  }
  
  return this.key;
}

var globalKeyManager = globalKeyManager || new KeyManager();
exports.globalKeyManager = globalKeyManager;












var ContentType = {
  BLOB:0,
  
  DATA:0, 
  LINK:1, 
  KEY: 2, 
  
  ENCR:3, 
  GONE:4, 
  NACK:5
};

exports.ContentType = ContentType;


var MetaInfo = function MetaInfo(publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockID, skipSetFields) 
{
  if (typeof publisherOrMetaInfo === 'object' && 
      publisherOrMetaInfo instanceof MetaInfo) {
    
    var metaInfo = publisherOrMetaInfo;
    this.publisher = metaInfo.publisher;
    this.timestamp = metaInfo.timestamp;
    this.type = metaInfo.type;
    this.locator = metaInfo.locator == null ? 
      new KeyLocator() : new KeyLocator(metaInfo.locator);
    this.freshnessSeconds = metaInfo.freshnessSeconds;
    this.finalBlockID = metaInfo.finalBlockID;
  }
  else {
    this.publisher = publisherOrMetaInfo; 
    this.timestamp = timestamp; 
    this.type = type; 
    this.locator = locator == null ? new KeyLocator() : new KeyLocator(locator);
    this.freshnessSeconds = freshnessSeconds; 
    this.finalBlockID = finalBlockID; 

    if (!skipSetFields)
      this.setFields();
  }
};

exports.MetaInfo = MetaInfo;


MetaInfo.prototype.getType = function()
{
  return this.type;
};


MetaInfo.prototype.getFreshnessPeriod = function()
{
  
  if (this.freshnessSeconds == null || this.freshnessSeconds < 0)
    return null;
  else
    
    return this.freshnessSeconds * 1000.0;
};


MetaInfo.prototype.getFinalBlockID = function()
{
  
  return this.finalBlockID;
};


MetaInfo.prototype.setType = function(type)
{
  this.type = type == null || type < 0 ? ContentType.BLOB : type;
};


MetaInfo.prototype.setFreshnessPeriod = function(freshnessPeriod)
{
  
  if (freshnessPeriod == null || freshnessPeriod < 0)
    this.freshnessSeconds = null;
  else
    
    this.freshnessSeconds = freshnessPeriod / 1000.0;
};

MetaInfo.prototype.setFinalBlockID = function(finalBlockID)
{
  
  if (finalBlockID == null)
    this.finalBlockID = null;
  else if (typeof finalBlockID === 'object' && finalBlockID instanceof Blob)
    this.finalBlockID = finalBlockID.buf();
  else if (typeof finalBlockID === 'object' && finalBlockID instanceof Name.Component)
    this.finalBlockID = finalBlockID.getValue();
  else 
    this.finalBlockID = new internalBuf(finalBlockID);
};

MetaInfo.prototype.setFields = function() 
{
  var key = globalKeyManager.getKey();
  this.publisher = new PublisherPublicKeyDigest(key.getKeyID());

  var d = new Date();
    
  var time = d.getTime();  

  this.timestamp = new NDNTime(time);
    
  if (LOG > 4) console.log('TIME msec is');

  if (LOG > 4) console.log(this.timestamp.msec);

  
  this.type = ContentType.BLOB;
  
  if (LOG > 4) console.log('PUBLIC KEY TO WRITE TO DATA PACKET IS ');
  if (LOG > 4) console.log(key.publicToDER().toString('hex'));

  this.locator = new KeyLocator(key.getKeyID(), KeyLocatorType.KEY_LOCATOR_DIGEST);
};

MetaInfo.prototype.from_ndnb = function(decoder) 
{
  decoder.readElementStartDTag(this.getElementLabel());
  
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    if (LOG > 4) console.log('DECODING PUBLISHER KEY');
    this.publisher = new PublisherPublicKeyDigest();
    this.publisher.from_ndnb(decoder);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Timestamp)) {
    if (LOG > 4) console.log('DECODING TIMESTAMP');
    this.timestamp = decoder.readDateTimeDTagElement(NDNProtocolDTags.Timestamp);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Type)) {
    var binType = decoder.readBinaryDTagElement(NDNProtocolDTags.Type);
    
    if (LOG > 4) console.log('Binary Type of of Signed Info is '+binType);

    this.type = binType;
    
    
    if (null == this.type)
      throw new Error("Cannot parse signedInfo type: bytes.");
  } 
  else
    this.type = ContentType.DATA; 
  
  if (decoder.peekDTag(NDNProtocolDTags.FreshnessSeconds)) {
    this.freshnessSeconds = decoder.readIntegerDTagElement(NDNProtocolDTags.FreshnessSeconds);
    if (LOG > 4) console.log('FRESHNESS IN SECONDS IS '+ this.freshnessSeconds);
  }
  
  if (decoder.peekDTag(NDNProtocolDTags.FinalBlockID)) {
    if (LOG > 4) console.log('DECODING FINAL BLOCKID');
    this.finalBlockID = decoder.readBinaryDTagElement(NDNProtocolDTags.FinalBlockID);
  }
  
  if (decoder.peekDTag(NDNProtocolDTags.KeyLocator)) {
    if (LOG > 4) console.log('DECODING KEY LOCATOR');
    this.locator = new KeyLocator();
    this.locator.from_ndnb(decoder);
  }
      
  decoder.readElementClose();
};


MetaInfo.prototype.to_ndnb = function(encoder, keyLocator)  {
  if (!this.validate())
    throw new Error("Cannot encode : field values missing.");

  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (null != this.publisher) {
    
    if (LOG > 3) console.log('ENCODING PUBLISHER KEY' + this.publisher.publisherPublicKeyDigest);
    this.publisher.to_ndnb(encoder);
  }
  else {
    if (null != keyLocator &&
        keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST && 
        keyLocator.getKeyData() != null &&
        keyLocator.getKeyData().length > 0)
      
      
      encoder.writeDTagElement
        (NDNProtocolDTags.PublisherPublicKeyDigest, keyLocator.getKeyData());
  }

  if (null != this.timestamp)
    encoder.writeDateTimeDTagElement(NDNProtocolDTags.Timestamp, this.timestamp);
  
  if (null != this.type && this.type != 0)
    encoder.writeDTagElement(NDNProtocolDTags.type, this.type);
  
  if (null != this.freshnessSeconds)
    encoder.writeDTagElement(NDNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);

  if (null != this.finalBlockID)
    encoder.writeDTagElement(NDNProtocolDTags.FinalBlockID, this.finalBlockID);

  if (null != keyLocator)
    keyLocator.to_ndnb(encoder);

  encoder.writeElementClose();       
};
  
MetaInfo.prototype.valueToType = function() 
{
  return null;  
};

MetaInfo.prototype.getElementLabel = function() { 
  return NDNProtocolDTags.SignedInfo;
};

MetaInfo.prototype.validate = function() 
{
  
  
  if (null == this.timestamp)
    return false;
  return true;
};


var SignedInfo = function SignedInfo(publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockID) 
{
  
  MetaInfo.call(this, publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockID); 
}


SignedInfo.prototype = new MetaInfo(null, null, null, null, null, null, true);

exports.SignedInfo = SignedInfo;








var Signature = function Signature(witnessOrSignatureObject, signature, digestAlgorithm) 
{
  if (typeof witnessOrSignatureObject === 'object' && 
      witnessOrSignatureObject instanceof Signature) {
    
    this.keyLocator = new KeyLocator(witnessOrSignatureObject.keyLocator);
    this.signature = witnessOrSignatureObject.signature;
    
    this.witness = witnessOrSignatureObject.witness;
    
    this.digestAlgorithm = witnessOrSignatureObject.digestAlgorithm;
  }
  else {
    this.keyLocator = new KeyLocator();
    this.signature = signature;
    
    this.witness = witnessOrSignatureObject;
    
    this.digestAlgorithm = digestAlgorithm;
  }
};

exports.Signature = Signature;


Signature.prototype.clone = function()
{
  return new Signature(this);
};


Signature.prototype.getKeyLocator = function()
{
  return this.keyLocator;
};


Signature.prototype.getSignature = function()
{
  return this.signature;
};


Signature.prototype.setKeyLocator = function(keyLocator)
{
  this.keyLocator = typeof keyLocator === 'object' && keyLocator instanceof KeyLocator ?
                    new KeyLocator(keyLocator) : new KeyLocator();
};
  

Signature.prototype.setSignature = function(signature)
{
  if (signature == null)
    this.signature = null;
  else if (typeof signature === 'object' && signature instanceof Blob)
    this.signature = new internalBuf(signature.buf());
  else
    this.signature = new internalBuf(signature);
};

Signature.prototype.from_ndnb = function(decoder) 
{
  decoder.readElementStartDTag(this.getElementLabel());
    
  if (LOG > 4) console.log('STARTED DECODING SIGNATURE');
    
  if (decoder.peekDTag(NDNProtocolDTags.DigestAlgorithm)) {
    if (LOG > 4) console.log('DIGIEST ALGORITHM FOUND');
    this.digestAlgorithm = decoder.readUTF8DTagElement(NDNProtocolDTags.DigestAlgorithm); 
  }
  if (decoder.peekDTag(NDNProtocolDTags.Witness)) {
    if (LOG > 4) console.log('WITNESS FOUND');
    this.witness = decoder.readBinaryDTagElement(NDNProtocolDTags.Witness); 
  }
    
  

  if (LOG > 4) console.log('SIGNATURE FOUND');
  this.signature = decoder.readBinaryDTagElement(NDNProtocolDTags.SignatureBits);

  decoder.readElementClose();
};

Signature.prototype.to_ndnb = function(encoder) 
{      
  if (!this.validate())
    throw new Error("Cannot encode: field values missing.");
  
  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (null != this.digestAlgorithm && !this.digestAlgorithm.equals(NDNDigestHelper.DEFAULT_DIGEST_ALGORITHM))
    encoder.writeDTagElement(NDNProtocolDTags.DigestAlgorithm, OIDLookup.getDigestOID(this.DigestAlgorithm));
  
  if (null != this.witness)
    
    encoder.writeDTagElement(NDNProtocolDTags.Witness, this.witness);

  encoder.writeDTagElement(NDNProtocolDTags.SignatureBits, this.signature);

  encoder.writeElementClose();       
};

Signature.prototype.getElementLabel = function() { return NDNProtocolDTags.Signature; };

Signature.prototype.validate = function() 
{
  return null != this.signature;
};













var Data = function Data(name, metaInfoOrContent, arg3) 
{
  if (typeof name === 'string')
    this.name = new Name(name);
  else
    this.name = typeof name === 'object' && name instanceof Name ?
       new Name(name) : new Name();

  var metaInfo;
  var content;
  if (typeof metaInfoOrContent === 'object' && 
      metaInfoOrContent instanceof MetaInfo) {
    metaInfo = metaInfoOrContent;
    content = arg3;
  }
  else {
    metaInfo = null;
    content = metaInfoOrContent;
  }
    
  
  this.signedInfo = typeof metaInfo === 'object' && metaInfo instanceof MetaInfo ?
       new MetaInfo(metaInfo) : new MetaInfo();
  
  if (typeof content === 'string') 
    this.content = DataUtils.toNumbersFromString(content);
  else if (typeof content === 'object' && content instanceof Blob)
    this.content = content.buf();
  else 
    this.content = content;
  
  this.signature = new Signature();
  
  this.wireEncoding = SignedBlob();
};

exports.Data = Data;


Data.prototype.getName = function() 
{
  return this.name;
};


Data.prototype.getMetaInfo = function() 
{
  return this.signedInfo;
};


Data.prototype.getSignature = function() 
{
  return this.signature;
};


Data.prototype.getContent = function() 
{
  return this.content;
};


Data.prototype.setName = function(name) 
{
  this.name = typeof name === 'object' && name instanceof Name ?
    new Name(name) : new Name();

  
  this.wireEncoding = SignedBlob();
  return this;
};


Data.prototype.setMetaInfo = function(metaInfo) 
{
  this.signedInfo = typeof metaInfo === 'object' && metaInfo instanceof MetaInfo ?
    new MetaInfo(metaInfo) : new MetaInfo();

  
  this.wireEncoding = SignedBlob();
  return this;
};


Data.prototype.setSignature = function(signature) 
{
  this.signature = typeof signature === 'object' && signature instanceof Signature ?
    signature.clone() : new Signature();

  
  this.wireEncoding = SignedBlob();
  return this;
};


Data.prototype.setContent = function(content) 
{
  if (typeof content === 'string') 
    this.content = DataUtils.toNumbersFromString(content);
  else if (typeof content === 'object' && content instanceof Blob)
    this.content = content.buf();
  else 
    this.content = new internalBuf(content);

  
  this.wireEncoding = SignedBlob();
  return this;
};

Data.prototype.sign = function(wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
 
  if (this.getSignatureOrMetaInfoKeyLocator() == null ||
      this.getSignatureOrMetaInfoKeyLocator().getType() == null)
    this.getMetaInfo().setFields();
  
  if (this.wireEncoding == null || this.wireEncoding.isNull()) {
    
    
    this.getSignature().setSignature(new internalBuf(128));
    this.wireEncode(wireFormat);
  }
  
  var rsa = require("crypto").createSign('RSA-SHA256');
  rsa.update(this.wireEncoding.signedBuf());
    
  var sig = new internalBuf(rsa.sign(globalKeyManager.privateKey));
  this.signature.signature = sig;
};

Data.prototype.verify = function( key) 
{
  if (key == null || key.publicKeyPem == null)
    throw new Error('Cannot verify Data without a public key.');

  if (this.wireEncoding == null || this.wireEncoding.isNull())
    
    this.wireEncode();
  var verifier = require('crypto').createVerify('RSA-SHA256');
  verifier.update(this.wireEncoding.signedBuf());
  return verifier.verify(key.publicKeyPem, this.signature.signature);
};

Data.prototype.getElementLabel = function() { return NDNProtocolDTags.Data; };


Data.prototype.wireEncode = function(wireFormat) 
{
  var wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  var result = wireFormat.encodeData(this);
  
  this.wireEncoding = new SignedBlob
    (result.encoding, result.signedPortionBeginOffset, 
     result.signedPortionEndOffset);
  return this.wireEncoding;
};


Data.prototype.wireDecode = function(input, wireFormat) 
{
  var wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ? 
                     input.buf() : input;
  var result = wireFormat.decodeData(this, decodeBuffer);
  
  
  
  this.wireEncoding = new SignedBlob
    (new Blob(input, true), result.signedPortionBeginOffset, 
     result.signedPortionEndOffset);
};


Data.prototype.getSignatureOrMetaInfoKeyLocator = function()
{
  if (this.signature != null && this.signature.getKeyLocator() != null &&
      this.signature.getKeyLocator().getType() != null &&
      this.signature.getKeyLocator().getType() >= 0)
    
    return this.signature.getKeyLocator();
  
  if (this.signedInfo != null && this.signedInfo.locator != null &&
      this.signedInfo.locator.type != null &&
      this.signedInfo.locator.type >= 0) {
    
    
    return this.signedInfo.locator;
  }
  
  
  if (this.signature != null && this.signature.getKeyLocator() != null)
    return this.signature.getKeyLocator();
  else
    return new KeyLocator();
}





Data.prototype.from_ndnb = function( decoder) 
{
  BinaryXmlWireFormat.decodeData(this, decoder);
};


Data.prototype.to_ndnb = function( encoder)
{
  BinaryXmlWireFormat.encodeData(this, encoder);
};


Data.prototype.encode = function(wireFormat) 
{
  wireFormat = (wireFormat || BinaryXmlWireFormat.get());
  return wireFormat.encodeData(this).buf();
};


Data.prototype.decode = function(input, wireFormat) 
{
  wireFormat = (wireFormat || BinaryXmlWireFormat.get());
  wireFormat.decodeData(this, input);
};


var ContentObject = function ContentObject(name, signedInfo, content) 
{
  
  Data.call(this, name, signedInfo, content); 
}

ContentObject.prototype = new Data();

exports.ContentObject = ContentObject;







var Exclude = function Exclude(values) 
{ 
  this.values = [];
  
  if (typeof values === 'object' && values instanceof Exclude)
    
    this.values = values.values.slice(0);
  else if (values) {
    for (var i = 0; i < values.length; ++i) {
      if (values[i] == Exclude.ANY)
        this.appendAny();
      else
        this.appendComponent(values[i]);
    }
  }
};

exports.Exclude = Exclude;

Exclude.ANY = "*";


Exclude.prototype.size = function() { return this.values.length; };


Exclude.prototype.get = function(i) { return this.values[i]; };


Exclude.prototype.appendAny = function() 
{
  this.values.push(Exclude.ANY);
  return this;
};


Exclude.prototype.appendComponent = function(component) 
{
  this.values.push(new Name.Component(component));
  return this;
};


Exclude.prototype.clear = function() 
{
  this.values = [];
};

Exclude.prototype.from_ndnb = function( decoder) 
{
  decoder.readElementStartDTag(NDNProtocolDTags.Exclude);

  while (true) {
    if (decoder.peekDTag(NDNProtocolDTags.Component))
      this.appendComponent(decoder.readBinaryDTagElement(NDNProtocolDTags.Component));
    else if (decoder.peekDTag(NDNProtocolDTags.Any)) {
      decoder.readElementStartDTag(NDNProtocolDTags.Any);
      decoder.readElementClose();
      this.appendAny();
    }
    else if (decoder.peekDTag(NDNProtocolDTags.Bloom)) {
      
      decoder.readBinaryDTagElement(NDNProtocolDTags.Bloom);
      this.appendAny();
    }
    else
      break;
  }
    
  decoder.readElementClose();
};

Exclude.prototype.to_ndnb = function( encoder)  
{
  if (this.values == null || this.values.length == 0)
    return;

  encoder.writeElementStartDTag(NDNProtocolDTags.Exclude);
    
  
  for (var i = 0; i < this.values.length; ++i) {
    if (this.values[i] == Exclude.ANY) {
      encoder.writeElementStartDTag(NDNProtocolDTags.Any);
      encoder.writeElementClose();
    }
    else
      encoder.writeDTagElement(NDNProtocolDTags.Component, this.values[i].getValue());
  }

  encoder.writeElementClose();
};


Exclude.prototype.toUri = function() 
{
  if (this.values == null || this.values.length == 0)
    return "";

  var result = "";
  for (var i = 0; i < this.values.length; ++i) {
    if (i > 0)
      result += ",";
        
    if (this.values[i] == Exclude.ANY)
      result += "*";
    else
      result += Name.toEscapedString(this.values[i].getValue());
  }
  return result;
};


Exclude.prototype.matches = function( component) 
{
  if (typeof component == 'object' && component instanceof Name.Component)
    component = component.getValue();

  for (var i = 0; i < this.values.length; ++i) {
    if (this.values[i] == Exclude.ANY) {
      var lowerBound = null;
      if (i > 0)
        lowerBound = this.values[i - 1];
      
      
      var iUpperBound;
      var upperBound = null;
      for (iUpperBound = i + 1; iUpperBound < this.values.length; ++iUpperBound) {
        if (this.values[iUpperBound] != Exclude.ANY) {
          upperBound = this.values[iUpperBound];
          break;
        }
      }
      
      
      
      if (upperBound != null) {
        if (lowerBound != null) {
          if (Exclude.compareComponents(component, lowerBound) > 0 &&
              Exclude.compareComponents(component, upperBound) < 0)
            return true;
        }
        else {
          if (Exclude.compareComponents(component, upperBound) < 0)
            return true;
        }
          
        
        i = iUpperBound - 1;
      }
      else {
        if (lowerBound != null) {
            if (Exclude.compareComponents(component, lowerBound) > 0)
              return true;
        }
        else
          
          return true;
      }
    }
    else {
      if (DataUtils.arraysEqual(component, this.values[i].getValue()))
        return true;
    }
  }
  
  return false;
};


Exclude.compareComponents = function(component1, component2) 
{
  if (typeof component1 == 'object' && component1 instanceof Name.Component)
    component1 = component1.getValue();
  if (typeof component2 == 'object' && component2 instanceof Name.Component)
    component2 = component2.getValue();

  if (component1.length < component2.length)
    return -1;
  if (component1.length > component2.length)
    return 1;
  
  for (var i = 0; i < component1.length; ++i) {
    if (component1[i] < component2[i])
      return -1;
    if (component1[i] > component2[i])
      return 1;
  }

  return 0;
};








var Interest = function Interest
   (nameOrInterest, minSuffixComponents, maxSuffixComponents, publisherPublicKeyDigest, exclude, 
    childSelector, answerOriginKind, scope, interestLifetimeMilliseconds, nonce) 
{
  if (typeof nameOrInterest === 'object' && nameOrInterest instanceof Interest) {
    
    var interest = nameOrInterest;
    if (interest.name)
      
      this.name = new Name(interest.name);
    this.maxSuffixComponents = interest.maxSuffixComponents;
    this.minSuffixComponents = interest.minSuffixComponents;

    this.publisherPublicKeyDigest = interest.publisherPublicKeyDigest;
    this.keyLocator = new KeyLocator(interest.keyLocator);
    this.exclude = new Exclude(interest.exclude);
    this.childSelector = interest.childSelector;
    this.answerOriginKind = interest.answerOriginKind;
    this.scope = interest.scope;
    this.interestLifetime = interest.interestLifetime;
    if (interest.nonce)
      
      this.nonce = new internalBuf(interest.nonce);    
  }  
  else {
    this.name = typeof nameOrInterest === 'object' && nameOrInterest instanceof Name ?
                new Name(nameOrInterest) : new Name();
    this.maxSuffixComponents = maxSuffixComponents;
    this.minSuffixComponents = minSuffixComponents;

    this.publisherPublicKeyDigest = publisherPublicKeyDigest;
    this.keyLocator = new KeyLocator();
    this.exclude = typeof exclude === 'object' && exclude instanceof Exclude ?
                   new Exclude(exclude) : new Exclude();
    this.childSelector = childSelector;
    this.answerOriginKind = answerOriginKind;
    this.scope = scope;
    this.interestLifetime = interestLifetimeMilliseconds;
    if (nonce)
      
      this.nonce = new internalBuf(nonce);
  }
};

exports.Interest = Interest;

Interest.RECURSIVE_POSTFIX = "*";

Interest.CHILD_SELECTOR_LEFT = 0;
Interest.CHILD_SELECTOR_RIGHT = 1;

Interest.ANSWER_NO_CONTENT_STORE = 0;
Interest.ANSWER_CONTENT_STORE = 1;
Interest.ANSWER_GENERATED = 2;
Interest.ANSWER_STALE = 4;    
Interest.MARK_STALE = 16;    

Interest.DEFAULT_ANSWER_ORIGIN_KIND = Interest.ANSWER_CONTENT_STORE | Interest.ANSWER_GENERATED;


Interest.prototype.matchesName = function( name) 
{
  if (!this.name.match(name))
    return false;
    
  if (this.minSuffixComponents != null &&
      
      !(name.size() + 1 - this.name.size() >= this.minSuffixComponents))
    return false;
  if (this.maxSuffixComponents != null &&
      
      !(name.size() + 1 - this.name.size() <= this.maxSuffixComponents))
    return false;
  if (this.exclude != null && name.size() > this.name.size() &&
      this.exclude.matches(name.components[this.name.size()]))
    return false;
    
  return true;
};


Interest.prototype.matches_name = function( name) 
{
  return this.matchesName(name);
};


Interest.prototype.clone = function() 
{
  return new Interest
     (this.name, this.minSuffixComponents, this.maxSuffixComponents, 
      this.publisherPublicKeyDigest, this.exclude, this.childSelector, this.answerOriginKind, 
      this.scope, this.interestLifetime, this.nonce);
};


Interest.prototype.getName = function() { return this.name; };


Interest.prototype.getMinSuffixComponents = function() 
{ 
  return this.minSuffixComponents; 
};


Interest.prototype.getMaxSuffixComponents = function() 
{ 
  return this.maxSuffixComponents; 
};


Interest.prototype.getKeyLocator = function() 
{ 
  return this.keyLocator; 
};


Interest.prototype.getExclude = function() { return this.exclude; };


Interest.prototype.getChildSelector = function() 
{ 
  return this.childSelector; 
};


Interest.prototype.getAnswerOriginKind = function() 
{ 
  return this.answerOriginKind; 
};
  
  
  

Interest.prototype.getMustBeFresh = function() 
{
  if (this.answerOriginKind == null || this.answerOriginKind < 0)
    return true;
  else
    return (this.answerOriginKind & Interest.ANSWER_STALE) == 0;
};


Interest.prototype.getNonce = function() { return this.nonce; };


Interest.prototype.getScope = function() { return this.scope; };


Interest.prototype.getInterestLifetimeMilliseconds = function() 
{ 
  return this.interestLifetime; 
};

Interest.prototype.setName = function(name)
{
  
  this.nonce = null;
  
  this.name = typeof name === 'object' && name instanceof Interest ?
              new Name(name) : new Name();
};
                
Interest.prototype.setMinSuffixComponents = function(minSuffixComponents)
{
  
  this.nonce = null;
  
  this.minSuffixComponents = minSuffixComponents;
};

Interest.prototype.setMaxSuffixComponents = function(maxSuffixComponents)
{
  
  this.nonce = null;
  
  this.maxSuffixComponents = maxSuffixComponents;
};


Interest.prototype.setExclude = function(exclude)
{
  
  this.nonce = null;
  
  this.exclude = typeof exclude === 'object' && exclude instanceof Exclude ?
                 new Exclude(exclude) : new Exclude();
};

Interest.prototype.setChildSelector = function(childSelector)
{
  
  this.nonce = null;
  
  this.childSelector = childSelector;
};


Interest.prototype.setAnswerOriginKind = function(answerOriginKind)
{
  
  this.nonce = null;
  
  this.answerOriginKind = answerOriginKind;
};


Interest.prototype.setMustBeFresh = function(mustBeFresh)
{
  
  this.nonce = null;
  
  if (this.answerOriginKind == null || this.answerOriginKind < 0) {
    
    if (!mustBeFresh)
      
      this.answerOriginKind = Interest.ANSWER_STALE; 
  }
  else {
    if (mustBeFresh)
      
      this.answerOriginKind &= ~Interest.ANSWER_STALE;
    else
      
      this.answerOriginKind |= Interest.ANSWER_STALE;
  }
};

Interest.prototype.setScope = function(scope)
{
  
  this.nonce = null;
  
  this.scope = scope;
};

Interest.prototype.setInterestLifetimeMilliseconds = function(interestLifetimeMilliseconds)
{
  
  this.nonce = null;
  
  this.interestLifetime = interestLifetimeMilliseconds;
};


Interest.prototype.setNonce = function(nonce)
{
  if (nonce)
    
    this.nonce = new internalBuf(nonce);
  else
    this.nonce = null;
};


Interest.prototype.toUri = function() 
{  
  var selectors = "";
  
  if (this.minSuffixComponents != null)
    selectors += "&ndn.MinSuffixComponents=" + this.minSuffixComponents;
  if (this.maxSuffixComponents != null)
    selectors += "&ndn.MaxSuffixComponents=" + this.maxSuffixComponents;
  if (this.childSelector != null)
    selectors += "&ndn.ChildSelector=" + this.childSelector;
  if (this.answerOriginKind != null)
    selectors += "&ndn.AnswerOriginKind=" + this.answerOriginKind;
  if (this.scope != null)
    selectors += "&ndn.Scope=" + this.scope;
  if (this.interestLifetime != null)
    selectors += "&ndn.InterestLifetime=" + this.interestLifetime;
  if (this.publisherPublicKeyDigest != null)
    selectors += "&ndn.PublisherPublicKeyDigest=" + Name.toEscapedString(this.publisherPublicKeyDigest.publisherPublicKeyDigest);
  if (this.nonce != null)
    selectors += "&ndn.Nonce=" + Name.toEscapedString(this.nonce);
  if (this.exclude != null && this.exclude.size() > 0)
    selectors += "&ndn.Exclude=" + this.exclude.toUri();

  var result = this.name.toUri();
  if (selectors != "")
    
    result += "?" + selectors.substr(1);
  
  return result;
};


Interest.prototype.wireEncode = function(wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return wireFormat.encodeInterest(this);
};


Interest.prototype.wireDecode = function(input, wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ? 
                     input.buf() : input;
  wireFormat.decodeInterest(this, decodeBuffer);
};






Interest.prototype.from_ndnb = function( decoder) 
{
  BinaryXmlWireFormat.decodeInterest(this, decoder);
};


Interest.prototype.to_ndnb = function( encoder) 
{
  BinaryXmlWireFormat.encodeInterest(this, encoder);
};


Interest.prototype.encode = function(wireFormat) 
{
  return this.wireEncode(BinaryXmlWireFormat.get()).buf();
};


Interest.prototype.decode = function(input, wireFormat) 
{
  this.wireDecode(input, BinaryXmlWireFormat.get())
};




var FaceInstance  = function FaceInstance(action, publisherPublicKeyDigest, faceID, ipProto, host, port, multicastInterface,
    multicastTTL, freshnessSeconds) 
{
  this.action = action;
  this.publisherPublicKeyDigest = publisherPublicKeyDigest;
  this.faceID = faceID;
  this.ipProto = ipProto;
  this.host = host;
  this.Port = port;
  this.multicastInterface =multicastInterface;
  this.multicastTTL =multicastTTL;
  this.freshnessSeconds = freshnessSeconds;
};

exports.FaceInstance = FaceInstance;

FaceInstance.NetworkProtocol = { TCP:6, UDP:17};


FaceInstance.prototype.from_ndnb = function(
  
  decoder) 
{
  decoder.readElementStartDTag(this.getElementLabel());
  
  if (decoder.peekDTag(NDNProtocolDTags.Action))   
    this.action = decoder.readUTF8DTagElement(NDNProtocolDTags.Action);
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    this.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
    this.publisherPublicKeyDigest.from_ndnb(decoder);
  }
  if (decoder.peekDTag(NDNProtocolDTags.FaceID))
    this.faceID = decoder.readIntegerDTagElement(NDNProtocolDTags.FaceID);
  if (decoder.peekDTag(NDNProtocolDTags.IPProto)) {
    
    var pI = decoder.readIntegerDTagElement(NDNProtocolDTags.IPProto);
    
    this.ipProto = null;
    
    if (FaceInstance.NetworkProtocol.TCP == pI)
      this.ipProto = FaceInstance.NetworkProtocol.TCP;
    else if (FaceInstance.NetworkProtocol.UDP == pI)
      this.ipProto = FaceInstance.NetworkProtocol.UDP;
    else
      throw new Error("FaceInstance.decoder.  Invalid NDNProtocolDTags.IPProto field: " + pI);
  }
  
  if (decoder.peekDTag(NDNProtocolDTags.Host))
    this.host = decoder.readUTF8DTagElement(NDNProtocolDTags.Host);
  if (decoder.peekDTag(NDNProtocolDTags.Port))
    this.Port = decoder.readIntegerDTagElement(NDNProtocolDTags.Port); 
  if (decoder.peekDTag(NDNProtocolDTags.MulticastInterface))
    this.multicastInterface = decoder.readUTF8DTagElement(NDNProtocolDTags.MulticastInterface); 
  if (decoder.peekDTag(NDNProtocolDTags.MulticastTTL))
    this.multicastTTL = decoder.readIntegerDTagElement(NDNProtocolDTags.MulticastTTL); 
  if (decoder.peekDTag(NDNProtocolDTags.FreshnessSeconds))
    this.freshnessSeconds = decoder.readIntegerDTagElement(NDNProtocolDTags.FreshnessSeconds); 

  decoder.readElementClose();
};


FaceInstance.prototype.to_ndnb = function(
  
  encoder) 
{
  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (null != this.action && this.action.length != 0)
    encoder.writeDTagElement(NDNProtocolDTags.Action, this.action);  
  if (null != this.publisherPublicKeyDigest)
    this.publisherPublicKeyDigest.to_ndnb(encoder);
  if (null != this.faceID)
    encoder.writeDTagElement(NDNProtocolDTags.FaceID, this.faceID);
  if (null != this.ipProto)
    encoder.writeDTagElement(NDNProtocolDTags.IPProto, this.ipProto);
  if (null != this.host && this.host.length != 0)
    encoder.writeDTagElement(NDNProtocolDTags.Host, this.host);  
  if (null != this.Port)
    encoder.writeDTagElement(NDNProtocolDTags.Port, this.Port);
  if (null != this.multicastInterface && this.multicastInterface.length != 0)
    encoder.writeDTagElement(NDNProtocolDTags.MulticastInterface, this.multicastInterface);
  if (null !=  this.multicastTTL)
    encoder.writeDTagElement(NDNProtocolDTags.MulticastTTL, this.multicastTTL);
  if (null != this.freshnessSeconds)
    encoder.writeDTagElement(NDNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);

  encoder.writeElementClose();         
};

FaceInstance.prototype.getElementLabel = function() 
{
  return NDNProtocolDTags.FaceInstance;
};






var ForwardingEntry = function ForwardingEntry(action, prefixName, ndndId, faceID, flags, lifetime) 
{
  this.action = action;
  this.prefixName = prefixName;
  this.ndndID = ndndId;
  this.faceID = faceID;
  this.flags = flags;
  this.lifetime = lifetime;
};

exports.ForwardingEntry = ForwardingEntry;

ForwardingEntry.ACTIVE         = 1;
ForwardingEntry.CHILD_INHERIT  = 2;
ForwardingEntry.ADVERTISE      = 4;
ForwardingEntry.LAST           = 8;
ForwardingEntry.CAPTURE       = 16;
ForwardingEntry.LOCAL         = 32;
ForwardingEntry.TAP           = 64;
ForwardingEntry.CAPTURE_OK   = 128;

ForwardingEntry.prototype.from_ndnb = function(
  
  decoder) 
  
{
  decoder.readElementStartDTag(this.getElementLabel());
  if (decoder.peekDTag(NDNProtocolDTags.Action))
    this.action = decoder.readUTF8DTagElement(NDNProtocolDTags.Action); 
  if (decoder.peekDTag(NDNProtocolDTags.Name)) {
    this.prefixName = new Name();
    this.prefixName.from_ndnb(decoder) ;
  }
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    this.NdndId = new PublisherPublicKeyDigest();
    this.NdndId.from_ndnb(decoder);
  }
  if (decoder.peekDTag(NDNProtocolDTags.FaceID))
    this.faceID = decoder.readIntegerDTagElement(NDNProtocolDTags.FaceID); 
  if (decoder.peekDTag(NDNProtocolDTags.ForwardingFlags))
    this.flags = decoder.readIntegerDTagElement(NDNProtocolDTags.ForwardingFlags); 
  if (decoder.peekDTag(NDNProtocolDTags.FreshnessSeconds))
    this.lifetime = decoder.readIntegerDTagElement(NDNProtocolDTags.FreshnessSeconds); 

  decoder.readElementClose();
};

ForwardingEntry.prototype.to_ndnb = function(
  
  encoder) 
{
  encoder.writeElementStartDTag(this.getElementLabel());
  if (null != this.action && this.action.length != 0)
    encoder.writeDTagElement(NDNProtocolDTags.Action, this.action);  
  if (null != this.prefixName)
    this.prefixName.to_ndnb(encoder);
  if (null != this.NdndId)
    this.NdndId.to_ndnb(encoder);
  if (null != this.faceID)
    encoder.writeDTagElement(NDNProtocolDTags.FaceID, this.faceID);
  if (null != this.flags)
    encoder.writeDTagElement(NDNProtocolDTags.ForwardingFlags, this.flags);
  if (null != this.lifetime)
    encoder.writeDTagElement(NDNProtocolDTags.FreshnessSeconds, this.lifetime);

  encoder.writeElementClose();         
};

ForwardingEntry.prototype.getElementLabel = function() { return NDNProtocolDTags.ForwardingEntry; }



var ForwardingFlags = function ForwardingFlags() 
{
  this.active = true;
  this.childInherit = true;
  this.advertise = false;
  this.last = false;
  this.capture = false;
  this.local = false;
  this.tap = false;
  this.captureOk = false;
}

exports.ForwardingFlags = ForwardingFlags;


ForwardingFlags.prototype.getForwardingEntryFlags = function()
{
  var result = 0;
  
  if (this.active)
    result |= ForwardingEntry.ACTIVE;
  if (this.childInherit)
    result |= ForwardingEntry.CHILD_INHERIT;
  if (this.advertise)
    result |= ForwardingEntry.ADVERTISE;
  if (this.last)
    result |= ForwardingEntry.LAST;
  if (this.capture)
    result |= ForwardingEntry.CAPTURE;
  if (this.local)
    result |= ForwardingEntry.LOCAL;
  if (this.tap)
    result |= ForwardingEntry.TAP;
  if (this.captureOk)
    result |= ForwardingEntry.CAPTURE_OK;
  
  return result;
};


ForwardingFlags.prototype.setForwardingEntryFlags = function(forwardingEntryFlags)
{
  this.active = ((forwardingEntryFlags & ForwardingEntry.ACTIVE) != 0);
  this.childInherit = ((forwardingEntryFlags & ForwardingEntry.CHILD_INHERIT) != 0);
  this.advertise = ((forwardingEntryFlags & ForwardingEntry.ADVERTISE) != 0);
  this.last = ((forwardingEntryFlags & ForwardingEntry.LAST) != 0);
  this.capture = ((forwardingEntryFlags & ForwardingEntry.CAPTURE) != 0);
  this.local = ((forwardingEntryFlags & ForwardingEntry.LOCAL) != 0);
  this.tap = ((forwardingEntryFlags & ForwardingEntry.TAP) != 0);
  this.captureOk = ((forwardingEntryFlags & ForwardingEntry.CAPTURE_OK) != 0);
};


ForwardingFlags.prototype.getActive = function() { return this.active; };


ForwardingFlags.prototype.getChildInherit = function() { return this.childInherit; };


ForwardingFlags.prototype.getAdvertise = function() { return this.advertise; };


ForwardingFlags.prototype.getLast = function() { return this.last; };


ForwardingFlags.prototype.getCapture = function() { return this.capture; };


ForwardingFlags.prototype.getLocal = function() { return this.local; };


ForwardingFlags.prototype.getTap = function() { return this.tap; };


ForwardingFlags.prototype.getCaptureOk = function() { return this.captureOk; };

  
ForwardingFlags.prototype.setActive = function(value) { this.active = value; };

  
ForwardingFlags.prototype.setChildInherit = function(value) { this.childInherit = value; };

  
ForwardingFlags.prototype.setAdvertise = function(value) { this.advertise = value; };

  
ForwardingFlags.prototype.setLast = function(value) { this.last = value; };

  
ForwardingFlags.prototype.setCapture = function(value) { this.capture = value; };

  
ForwardingFlags.prototype.setLocal = function(value) { this.local = value; };

  
ForwardingFlags.prototype.setTap = function(value) { this.tap = value; };

  
ForwardingFlags.prototype.setCaptureOk = function(value) { this.captureOk = value; };














var BinaryXmlWireFormat = function BinaryXmlWireFormat() 
{
  
  WireFormat.call(this);
};

exports.BinaryXmlWireFormat = BinaryXmlWireFormat;


BinaryXmlWireFormat.instance = null;


BinaryXmlWireFormat.prototype.encodeInterest = function(interest) 
{
  var encoder = new BinaryXMLEncoder();
  BinaryXmlWireFormat.encodeInterest(interest, encoder);  
  return new Blob(encoder.getReducedOstream(), false);  
};


BinaryXmlWireFormat.prototype.decodeInterest = function(interest, input) 
{
  var decoder = new BinaryXMLDecoder(input);
  BinaryXmlWireFormat.decodeInterest(interest, decoder);
};


BinaryXmlWireFormat.prototype.encodeData = function(data) 
{
  var encoder = new BinaryXMLEncoder(1500);
  var result = BinaryXmlWireFormat.encodeData(data, encoder);
  result.encoding = new Blob(encoder.getReducedOstream(), false);
  return result;
};


BinaryXmlWireFormat.prototype.encodeContentObject = function(data)
{
  return this.encodeData(data);
};


BinaryXmlWireFormat.prototype.decodeData = function(data, input) 
{
  var decoder = new BinaryXMLDecoder(input);
  return BinaryXmlWireFormat.decodeData(data, decoder);
};


BinaryXmlWireFormat.prototype.decodeContentObject = function(data, input) 
{
  this.decodeData(data, input);
};


BinaryXmlWireFormat.get = function()
{
  if (BinaryXmlWireFormat.instance === null)
    BinaryXmlWireFormat.instance = new BinaryXmlWireFormat();
  return BinaryXmlWireFormat.instance;
};


BinaryXmlWireFormat.encodeInterest = function(interest, encoder) 
{
  encoder.writeElementStartDTag(NDNProtocolDTags.Interest);
    
  interest.name.to_ndnb(encoder);
  
  if (null != interest.minSuffixComponents) 
    encoder.writeDTagElement(NDNProtocolDTags.MinSuffixComponents, interest.minSuffixComponents);  

  if (null != interest.maxSuffixComponents) 
    encoder.writeDTagElement(NDNProtocolDTags.MaxSuffixComponents, interest.maxSuffixComponents);

  if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST && 
      interest.getKeyLocator().getKeyData() != null &&
      interest.getKeyLocator().getKeyData().length > 0)
    
    encoder.writeDTagElement
      (NDNProtocolDTags.PublisherPublicKeyDigest, 
       interest.getKeyLocator().getKeyData());
  else {
    if (null != interest.publisherPublicKeyDigest)
      interest.publisherPublicKeyDigest.to_ndnb(encoder);
  }
    
  if (null != interest.exclude)
    interest.exclude.to_ndnb(encoder);
    
  if (null != interest.childSelector) 
    encoder.writeDTagElement(NDNProtocolDTags.ChildSelector, interest.childSelector);

  if (interest.DEFAULT_ANSWER_ORIGIN_KIND != interest.answerOriginKind && interest.answerOriginKind!=null) 
    encoder.writeDTagElement(NDNProtocolDTags.AnswerOriginKind, interest.answerOriginKind);
    
  if (null != interest.scope) 
    encoder.writeDTagElement(NDNProtocolDTags.Scope, interest.scope);
    
  if (null != interest.interestLifetime) 
    encoder.writeDTagElement(NDNProtocolDTags.InterestLifetime, 
                DataUtils.nonNegativeIntToBigEndian((interest.interestLifetime / 1000.0) * 4096));
    
  if (null != interest.nonce)
    encoder.writeDTagElement(NDNProtocolDTags.Nonce, interest.nonce);
    
  encoder.writeElementClose();
};


BinaryXmlWireFormat.decodeInterest = function(interest, decoder) 
{
  decoder.readElementStartDTag(NDNProtocolDTags.Interest);

  interest.name = new Name();
  interest.name.from_ndnb(decoder);

  if (decoder.peekDTag(NDNProtocolDTags.MinSuffixComponents))
    interest.minSuffixComponents = decoder.readIntegerDTagElement(NDNProtocolDTags.MinSuffixComponents);
  else
    interest.minSuffixComponents = null;

  if (decoder.peekDTag(NDNProtocolDTags.MaxSuffixComponents)) 
    interest.maxSuffixComponents = decoder.readIntegerDTagElement(NDNProtocolDTags.MaxSuffixComponents);
  else
    interest.maxSuffixComponents = null;
      
  
  interest.getKeyLocator().clear();
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    interest.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
    interest.publisherPublicKeyDigest.from_ndnb(decoder);
  }
  else
    interest.publisherPublicKeyDigest = null;
  if (interest.publisherPublicKeyDigest != null &&
      interest.publisherPublicKeyDigest.publisherPublicKeyDigest != null &&
      interest.publisherPublicKeyDigest.publisherPublicKeyDigest.length > 0) {
    
    
    interest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    interest.getKeyLocator().setKeyData
      (interest.publisherPublicKeyDigest.publisherPublicKeyDigest);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Exclude)) {
    interest.exclude = new Exclude();
    interest.exclude.from_ndnb(decoder);
  }
  else
    interest.exclude = null;
    
  if (decoder.peekDTag(NDNProtocolDTags.ChildSelector))
    interest.childSelector = decoder.readIntegerDTagElement(NDNProtocolDTags.ChildSelector);
  else
    interest.childSelector = null;
    
  if (decoder.peekDTag(NDNProtocolDTags.AnswerOriginKind))
    interest.answerOriginKind = decoder.readIntegerDTagElement(NDNProtocolDTags.AnswerOriginKind);
  else
    interest.answerOriginKind = null;
    
  if (decoder.peekDTag(NDNProtocolDTags.Scope))
    interest.scope = decoder.readIntegerDTagElement(NDNProtocolDTags.Scope);
  else
    interest.scope = null;

  if (decoder.peekDTag(NDNProtocolDTags.InterestLifetime))
    interest.interestLifetime = 1000.0 * DataUtils.bigEndianToUnsignedInt
               (decoder.readBinaryDTagElement(NDNProtocolDTags.InterestLifetime)) / 4096;
  else
    interest.interestLifetime = null;              
    
  if (decoder.peekDTag(NDNProtocolDTags.Nonce))
    interest.nonce = decoder.readBinaryDTagElement(NDNProtocolDTags.Nonce);
  else
    interest.nonce = null;
    
  decoder.readElementClose();
};


BinaryXmlWireFormat.encodeData = function(data, encoder)  
{
  
  encoder.writeElementStartDTag(data.getElementLabel());

  if (null != data.signature) 
    data.signature.to_ndnb(encoder);
    
  var signedPortionBeginOffset = encoder.offset;

  if (null != data.name) 
    data.name.to_ndnb(encoder);
  
  if (null != data.signedInfo) 
    
    
    data.signedInfo.to_ndnb(encoder, data.getSignatureOrMetaInfoKeyLocator());

  encoder.writeDTagElement(NDNProtocolDTags.Content, data.content);
  
  var signedPortionEndOffset = encoder.offset;
  
  encoder.writeElementClose();
  
  return { signedPortionBeginOffset: signedPortionBeginOffset, 
           signedPortionEndOffset: signedPortionEndOffset };  
};


BinaryXmlWireFormat.decodeData = function(data, decoder) 
{
  
  decoder.readElementStartDTag(data.getElementLabel());

  if (decoder.peekDTag(NDNProtocolDTags.Signature)) {
    data.signature = new Signature();
    data.signature.from_ndnb(decoder);
  }
  else
    data.signature = null;
    
  var signedPortionBeginOffset = decoder.offset;

  data.name = new Name();
  data.name.from_ndnb(decoder);
    
  if (decoder.peekDTag(NDNProtocolDTags.SignedInfo)) {
    data.signedInfo = new MetaInfo();
    data.signedInfo.from_ndnb(decoder);
    if (data.signedInfo.locator != null && data.getSignature() != null)
      
      
      data.getSignature().keyLocator = data.signedInfo.locator;
  }
  else
    data.signedInfo = null;

  data.content = decoder.readBinaryDTagElement(NDNProtocolDTags.Content, true);
    
  var signedPortionEndOffset = decoder.offset;
    
  decoder.readElementClose();
    
  return { signedPortionBeginOffset: signedPortionBeginOffset, 
           signedPortionEndOffset: signedPortionEndOffset };  
};
;var crypto = require('crypto');












var Tlv0_1a2WireFormat = function Tlv0_1a2WireFormat() 
{
  
  WireFormat.call(this);
};

Tlv0_1a2WireFormat.prototype = new WireFormat();
Tlv0_1a2WireFormat.prototype.name = "Tlv0_1a2WireFormat";

exports.Tlv0_1a2WireFormat = Tlv0_1a2WireFormat;


Tlv0_1a2WireFormat.instance = null;


Tlv0_1a2WireFormat.prototype.encodeInterest = function(interest) 
{
  var encoder = new TlvEncoder();
  var saveLength = encoder.getLength();
  
  
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds());
  encoder.writeOptionalNonNegativeIntegerTlv(Tlv.Scope, interest.getScope());
  
  
  if (interest.getNonce() == null || interest.getNonce().length == 0)
    
    encoder.writeBlobTlv(Tlv.Nonce, require("crypto").randomBytes(4));
  else if (interest.getNonce().length < 4) {
    var nonce = internalBuf(4);
    
    interest.getNonce().copy(nonce);

    
    for (var i = interest.getNonce().length; i < 4; ++i)
      nonce[i] = require("crypto").randomBytes(1)[0];

    encoder.writeBlobTlv(Tlv.Nonce, nonce);
  }
  else if (interest.getNonce().length == 4)
    
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce());
  else
    
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().slice(0, 4));
  
  Tlv0_1a2WireFormat.encodeSelectors(interest, encoder);
  Tlv0_1a2WireFormat.encodeName(interest.getName(), encoder);
  
  encoder.writeTypeAndLength(Tlv.Interest, encoder.getLength() - saveLength);
      
  return new Blob(encoder.getOutput(), false);
};


Tlv0_1a2WireFormat.prototype.decodeInterest = function(interest, input) 
{
  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
  Tlv0_1a2WireFormat.decodeName(interest.getName(), decoder);
  if (decoder.peekType(Tlv.Selectors, endOffset))
    Tlv0_1a2WireFormat.decodeSelectors(interest, decoder);
  
  var nonce = decoder.readBlobTlv(Tlv.Nonce);
  interest.setScope(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.Scope, endOffset));
  interest.setInterestLifetimeMilliseconds
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.InterestLifetime, endOffset));

  
  interest.setNonce(nonce);

  decoder.finishNestedTlvs(endOffset);
};


Tlv0_1a2WireFormat.prototype.encodeData = function(data) 
{
  var encoder = new TlvEncoder(1500);
  var saveLength = encoder.getLength();
  
  
  
  
  encoder.writeBlobTlv(Tlv.SignatureValue, data.getSignature().getSignature());
  var signedPortionEndOffsetFromBack = encoder.getLength();

  
  
  Tlv0_1a2WireFormat.encodeSignatureSha256WithRsaValue
    (data.getSignature(), encoder, data.getSignatureOrMetaInfoKeyLocator());
  encoder.writeBlobTlv(Tlv.Content, data.getContent());
  Tlv0_1a2WireFormat.encodeMetaInfo(data.getMetaInfo(), encoder);
  Tlv0_1a2WireFormat.encodeName(data.getName(), encoder);
  var signedPortionBeginOffsetFromBack = encoder.getLength();

  encoder.writeTypeAndLength(Tlv.Data, encoder.getLength() - saveLength);
  var signedPortionBeginOffset = 
    encoder.getLength() - signedPortionBeginOffsetFromBack;
  var signedPortionEndOffset = encoder.getLength() - signedPortionEndOffsetFromBack;

  return { encoding: new Blob(encoder.getOutput(), false),
           signedPortionBeginOffset: signedPortionBeginOffset, 
           signedPortionEndOffset: signedPortionEndOffset };  
};


Tlv0_1a2WireFormat.prototype.decodeData = function(data, input) 
{
  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Data);
  var signedPortionBeginOffset = decoder.getOffset();

  Tlv0_1a2WireFormat.decodeName(data.getName(), decoder);
  Tlv0_1a2WireFormat.decodeMetaInfo(data.getMetaInfo(), decoder);
  data.setContent(decoder.readBlobTlv(Tlv.Content));
  Tlv0_1a2WireFormat.decodeSignatureInfo(data, decoder);
  if (data.getSignature() != null && 
      data.getSignature().getKeyLocator() != null && 
      data.getMetaInfo() != null)
    
    
    data.getMetaInfo().locator = data.getSignature().getKeyLocator();

  var signedPortionEndOffset = decoder.getOffset();
  
  
  data.getSignature().setSignature(decoder.readBlobTlv(Tlv.SignatureValue));

  decoder.finishNestedTlvs(endOffset);
  return { signedPortionBeginOffset: signedPortionBeginOffset, 
           signedPortionEndOffset: signedPortionEndOffset };  
};


Tlv0_1a2WireFormat.get = function()
{
  if (Tlv0_1a2WireFormat.instance === null)
    Tlv0_1a2WireFormat.instance = new Tlv0_1a2WireFormat();
  return Tlv0_1a2WireFormat.instance;
};

Tlv0_1a2WireFormat.encodeName = function(name, encoder)
{
  var saveLength = encoder.getLength();

  
  for (var i = name.size() - 1; i >= 0; --i)
    encoder.writeBlobTlv(Tlv.NameComponent, name.get(i).getValue());

  encoder.writeTypeAndLength(Tlv.Name, encoder.getLength() - saveLength);
};
        
Tlv0_1a2WireFormat.decodeName = function(name, decoder)
{
  name.clear();
  
  var endOffset = decoder.readNestedTlvsStart(Tlv.Name);      
  while (decoder.getOffset() < endOffset)
      name.append(decoder.readBlobTlv(Tlv.NameComponent));

  decoder.finishNestedTlvs(endOffset);
};


Tlv0_1a2WireFormat.encodeSelectors = function(interest, encoder)
{
  var saveLength = encoder.getLength();

  
  if (interest.getMustBeFresh())
    encoder.writeTypeAndLength(Tlv.MustBeFresh, 0);
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.ChildSelector, interest.getChildSelector());
  if (interest.getExclude().size() > 0)
    Tlv0_1a2WireFormat.encodeExclude(interest.getExclude(), encoder);
  
  if (interest.getKeyLocator().getType() != null)
    Tlv0_1a2WireFormat.encodeKeyLocator(interest.getKeyLocator(), encoder);
  else {
    
    
    
    if (null != interest.publisherPublicKeyDigest) {
      var savePublisherPublicKeyDigestLength = encoder.getLength();
      encoder.writeBlobTlv
        (Tlv.KeyLocatorDigest, 
         interest.publisherPublicKeyDigest.publisherPublicKeyDigest);
      encoder.writeTypeAndLength
        (Tlv.KeyLocator, encoder.getLength() - savePublisherPublicKeyDigestLength);
    }
  }
  
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents());
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MinSuffixComponents, interest.getMinSuffixComponents());

  
  if (encoder.getLength() != saveLength)
    encoder.writeTypeAndLength(Tlv.Selectors, encoder.getLength() - saveLength);
};

Tlv0_1a2WireFormat.decodeSelectors = function(interest, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Selectors);

  interest.setMinSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MinSuffixComponents, endOffset));
  interest.setMaxSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MaxSuffixComponents, endOffset));

  
  interest.publisherPublicKeyDigest = null;
  if (decoder.peekType(Tlv.KeyLocator, endOffset)) {
    Tlv0_1a2WireFormat.decodeKeyLocator(interest.getKeyLocator(), decoder);
    if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST) {
      
      interest.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
      interest.publisherPublicKeyDigest.publisherPublicKeyDigest =
        interest.getKeyLocator().getKeyData();
    }
  }
  else
    interest.getKeyLocator().clear();

  if (decoder.peekType(Tlv.Exclude, endOffset))
    Tlv0_1a2WireFormat.decodeExclude(interest.getExclude(), decoder);
  else
    interest.getExclude().clear();

  interest.setChildSelector(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ChildSelector, endOffset));
  interest.setMustBeFresh(decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset));

  decoder.finishNestedTlvs(endOffset);
};
  
Tlv0_1a2WireFormat.encodeExclude = function(exclude, encoder)
{
  var saveLength = encoder.getLength();

  
  
  for (var i = exclude.size() - 1; i >= 0; --i) {
    var entry = exclude.get(i);

    if (entry == Exclude.ANY)
      encoder.writeTypeAndLength(Tlv.Any, 0);
    else
      encoder.writeBlobTlv(Tlv.NameComponent, entry.getValue());
  }
  
  encoder.writeTypeAndLength(Tlv.Exclude, encoder.getLength() - saveLength);
};
  
Tlv0_1a2WireFormat.decodeExclude = function(exclude, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Exclude);

  exclude.clear();
  while (true) {
    if (decoder.peekType(Tlv.NameComponent, endOffset))
      exclude.appendComponent(decoder.readBlobTlv(Tlv.NameComponent));
    else if (decoder.readBooleanTlv(Tlv.Any, endOffset))
      exclude.appendAny();
    else
      
      break;
  }
  
  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1a2WireFormat.encodeKeyLocator = function(keyLocator, encoder)
{
  var saveLength = encoder.getLength();

  
  if (keyLocator.getType() != null) {
    if (keyLocator.getType() == KeyLocatorType.KEYNAME)
      Tlv0_1a2WireFormat.encodeName(keyLocator.getKeyName(), encoder);
    else if (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
             keyLocator.getKeyData().length > 0)
      encoder.writeBlobTlv(Tlv.KeyLocatorDigest, keyLocator.getKeyData());
    else
      throw new Error("Unrecognized KeyLocatorType " + keyLocator.getType());
  }
  
  encoder.writeTypeAndLength(Tlv.KeyLocator, encoder.getLength() - saveLength);
};

Tlv0_1a2WireFormat.decodeKeyLocator = function(keyLocator, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.KeyLocator);

  keyLocator.clear();

  if (decoder.getOffset() == endOffset)
    
    return;

  if (decoder.peekType(Tlv.Name, endOffset)) {
    
    keyLocator.setType(KeyLocatorType.KEYNAME);
    Tlv0_1a2WireFormat.decodeName(keyLocator.getKeyName(), decoder);
  }
  else if (decoder.peekType(Tlv.KeyLocatorDigest, endOffset)) {
    
    keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    keyLocator.setKeyData(decoder.readBlobTlv(Tlv.KeyLocatorDigest));
  }
  else
    throw new DecodingException
      ("decodeKeyLocator: Unrecognized key locator type");

  decoder.finishNestedTlvs(endOffset);
};


Tlv0_1a2WireFormat.encodeSignatureSha256WithRsaValue = function
  (signature, encoder, keyLocator)
{
  var saveLength = encoder.getLength();

  
  Tlv0_1a2WireFormat.encodeKeyLocator(keyLocator, encoder);
  encoder.writeNonNegativeIntegerTlv
    (Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithRsa);

  encoder.writeTypeAndLength(Tlv.SignatureInfo, encoder.getLength() - saveLength);
};

Tlv0_1a2WireFormat.decodeSignatureInfo = function(data, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);

  var signatureType = decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
  
  
  if (signatureType == Tlv.SignatureType_SignatureSha256WithRsa) {
      var signature = {}
      signature.sig = Signature
      data.setSignature(signature.sig());
      
      
      var signatureInfo = data.getSignature();
      Tlv0_1a2WireFormat.decodeKeyLocator
        (signatureInfo.getKeyLocator(), decoder);
  }
  else
      throw new DecodingException
       ("decodeSignatureInfo: unrecognized SignatureInfo type" + signatureType);

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1a2WireFormat.encodeMetaInfo = function(metaInfo, encoder)
{
  var saveLength = encoder.getLength();

  
  
  var finalBlockIdBuf = metaInfo.getFinalBlockID();
  if (finalBlockIdBuf != null && finalBlockIdBuf.length > 0) {
    
    var finalBlockIdSaveLength = encoder.getLength();
    encoder.writeBlobTlv(Tlv.NameComponent, finalBlockIdBuf);
    encoder.writeTypeAndLength
      (Tlv.FinalBlockId, encoder.getLength() - finalBlockIdSaveLength);
  }

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod());
  if (metaInfo.getType() != ContentType.BLOB) {
    
    if (metaInfo.getType() == ContentType.LINK ||
        metaInfo.getType() == ContentType.KEY)
      
      
      encoder.writeNonNegativeIntegerTlv(Tlv.ContentType, metaInfo.getType());
    else
      throw new Error("unrecognized TLV ContentType");
  }

  encoder.writeTypeAndLength(Tlv.MetaInfo, encoder.getLength() - saveLength);
};

Tlv0_1a2WireFormat.decodeMetaInfo = function(metaInfo, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.MetaInfo);  

  
  
  
  metaInfo.setType(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ContentType, endOffset));
  metaInfo.setFreshnessPeriod
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.FreshnessPeriod, endOffset));
  if (decoder.peekType(Tlv.FinalBlockId, endOffset)) {
    var finalBlockIdEndOffset = decoder.readNestedTlvsStart(Tlv.FinalBlockId);
    metaInfo.setFinalBlockID(decoder.readBlobTlv(Tlv.NameComponent));
    decoder.finishNestedTlvs(finalBlockIdEndOffset);
  }
  else
    metaInfo.setFinalBlockID(null);

  decoder.finishNestedTlvs(endOffset);
};




var TlvWireFormat = function TlvWireFormat() 
{
  
  Tlv0_1a2WireFormat.call(this);
};

TlvWireFormat.prototype = new Tlv0_1a2WireFormat();
TlvWireFormat.prototype.name = "TlvWireFormat";

exports.TlvWireFormat = TlvWireFormat;


TlvWireFormat.instance = null;


TlvWireFormat.get = function()
{
  if (TlvWireFormat.instance === null)
    TlvWireFormat.instance = new TlvWireFormat();
  return TlvWireFormat.instance;
};



WireFormat.setDefaultWireFormat(TlvWireFormat.get());













var EncodingUtils = function EncodingUtils() 
{
};

exports.EncodingUtils = EncodingUtils;

EncodingUtils.encodeToHexInterest = function(interest, wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return DataUtils.toHex(interest.wireEncode(wireFormat).buf());
};

EncodingUtils.encodeToHexData = function(data, wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return DataUtils.toHex(data.wireEncode(wireFormat).buf());
};


EncodingUtils.encodeToHexContentObject = function(data, wireFormat) 
{
  return EncodingUtils.encodeToHexData(data, wireFormat);
}

EncodingUtils.encodeForwardingEntry = function(data) 
{
  var enc = new BinaryXMLEncoder();
  data.to_ndnb(enc);
  var bytes = enc.getReducedOstream();

  return bytes;
};

EncodingUtils.decodeHexFaceInstance = function(result) 
{  
  var numbers = DataUtils.toNumbers(result); 
  var decoder = new BinaryXMLDecoder(numbers);
  
  if (LOG > 3) console.log('DECODING HEX FACE INSTANCE  \n'+numbers);

  var faceInstance = new FaceInstance();
  faceInstance.from_ndnb(decoder);
  
  return faceInstance;
};

EncodingUtils.decodeHexInterest = function(input, wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  var interest = new Interest();
  interest.wireDecode(DataUtils.toNumbers(input), wireFormat);
  return interest;
};

EncodingUtils.decodeHexData = function(input, wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  var data = new Data();
  data.wireDecode(DataUtils.toNumbers(input), wireFormat);
  return data;
};


EncodingUtils.decodeHexContentObject = function(input, wireFormat) 
{
  return EncodingUtils.decodeHexData(input, wireFormat);
}

EncodingUtils.decodeHexForwardingEntry = function(result) 
{
  var numbers = DataUtils.toNumbers(result);
  var decoder = new BinaryXMLDecoder(numbers);
  
  if (LOG > 3) console.log('DECODED HEX FORWARDING ENTRY \n'+numbers);
  
  var forwardingEntry = new ForwardingEntry();
  forwardingEntry.from_ndnb(decoder);
  return forwardingEntry;
};


EncodingUtils.decodeSubjectPublicKeyInfo = function(array) 
{
  var hex = DataUtils.toHex(array).toLowerCase();
  var a = _x509_getPublicKeyHexArrayFromCertHex(hex, _x509_getSubjectPublicKeyPosFromCertHex(hex, 0));
  var rsaKey = new RSAKey();
  rsaKey.setPublic(a[0], a[1]);
  return rsaKey;
}


EncodingUtils.dataToHtml = function( data) 
{
  var output ="";
      
  if (data == -1)
    output+= "NO CONTENT FOUND"
  else if (data == -2)
    output+= "CONTENT NAME IS EMPTY"
  else {
    if (data.name != null && data.name.components != null) {
      output+= "NAME: " + data.name.toUri();
        
      output+= "<br />";
      output+= "<br />";
    }
    if (data.content != null) {
      output += "CONTENT(ASCII): "+ DataUtils.toString(data.content);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.content != null) {
      output += "CONTENT(hex): "+ DataUtils.toHex(data.content);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signature != null && data.signature.digestAlgorithm != null) {
      output += "DigestAlgorithm (hex): "+ DataUtils.toHex(data.signature.digestAlgorithm);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signature != null && data.signature.witness != null) {
      output += "Witness (hex): "+ DataUtils.toHex(data.signature.witness);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signature != null && data.signature.signature != null) {
      output += "Signature(hex): "+ DataUtils.toHex(data.signature.signature);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signedInfo != null && data.signedInfo.publisher != null && data.signedInfo.publisher.publisherPublicKeyDigest != null) {
      output += "Publisher Public Key Digest(hex): "+ DataUtils.toHex(data.signedInfo.publisher.publisherPublicKeyDigest);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signedInfo != null && data.signedInfo.timestamp != null) {
      var d = new Date();
      d.setTime(data.signedInfo.timestamp.msec);
      
      var bytes = [217, 185, 12, 225, 217, 185, 12, 225];
      
      output += "TimeStamp: "+d;
      output+= "<br />";
      output += "TimeStamp(number): "+ data.signedInfo.timestamp.msec;
      
      output+= "<br />";
    }
    if (data.signedInfo != null && data.signedInfo.finalBlockID != null) {
      output += "FinalBlockID: "+ DataUtils.toHex(data.signedInfo.finalBlockID);
      output+= "<br />";
    }
    if (data.signedInfo != null && data.signedInfo.locator != null && data.signedInfo.locator.type) {
      output += "keyLocator: ";
      if (data.signedInfo.locator.type == KeyLocatorType.KEY)
        output += "Key: " + DataUtils.toHex(data.signedInfo.locator.publicKey).toLowerCase() + "<br />";
      else if (data.signedInfo.locator.type == KeyLocatorType.KEY_LOCATOR_DIGEST)
        output += "KeyLocatorDigest: " + DataUtils.toHex(data.signedInfo.locator.getKeyData()).toLowerCase() + "<br />";
      else if (data.signedInfo.locator.type == KeyLocatorType.CERTIFICATE)
        output += "Certificate: " + DataUtils.toHex(data.signedInfo.locator.certificate).toLowerCase() + "<br />";
      else if (data.signedInfo.locator.type == KeyLocatorType.KEYNAME)
        output += "KeyName: " + data.signedInfo.locator.keyName.contentName.to_uri() + "<br />";
      else
        output += "[unrecognized ndn_KeyLocatorType " + data.signedInfo.locator.type + "]<br />";      
    }
  }

  return output;
};


EncodingUtils.contentObjectToHtml = function(data) 
{
  return EncodingUtils.dataToHtml(data);
}





var encodeToHexInterest = function(interest) { return EncodingUtils.encodeToHexInterest(interest); }
var encodeToHexContentObject = function(data) { return EncodingUtils.encodeToHexData(data); }
var encodeForwardingEntry = function(data) { return EncodingUtils.encodeForwardingEntry(data); }
var decodeHexFaceInstance = function(input) { return EncodingUtils.decodeHexFaceInstance(input); }
var decodeHexInterest = function(input) { return EncodingUtils.decodeHexInterest(input); }
var decodeHexContentObject = function(input) { return EncodingUtils.decodeHexData(input); }
var decodeHexForwardingEntry = function(input) { return EncodingUtils.decodeHexForwardingEntry(input); }
var decodeSubjectPublicKeyInfo = function(input) { return EncodingUtils.decodeSubjectPublicKeyInfo(input); }
var contentObjectToHtml = function(data) { return EncodingUtils.dataToHtml(data); }


function encodeToBinaryInterest(interest) { return interest.wireEncode().buf(); }

function encodeToBinaryContentObject(data) { return data.wireEncode().buf(); }
;var crypto = require('crypto');






















var Face = function Face(settings) 
{
  if (!Face.supported)
    throw new Error("The necessary JavaScript support is not available on this platform.");
    
  settings = (settings || {});
  
  var getTransport = (settings.getTransport || function() { return new TcpTransport(); });
  this.transport = getTransport();
  this.getHostAndPort = (settings.getHostAndPort || this.transport.defaultGetHostAndPort);
  this.host = (settings.host !== undefined ? settings.host : null);
  this.port = (settings.port || (typeof WebSocketTransport != 'undefined' ? 9696 : 6363));
  this.readyStatus = Face.UNOPEN;
  this.verify = (settings.verify !== undefined ? settings.verify : false);
  
  this.onopen = (settings.onopen || function() { if (LOG > 3) console.log("Face connection established."); });
  this.onclose = (settings.onclose || function() { if (LOG > 3) console.log("Face connection closed."); });
  this.ndndid = null;
};

exports.Face = Face;

Face.UNOPEN = 0;  
Face.OPENED = 1;  
Face.CLOSED = 2;  


Face.getSupported = function() 
{
  try {
    var dummy = new internalBuf(1).slice(0, 1);
  } 
  catch (ex) {
    console.log("NDN not available: internalBuf not supported. " + ex);
    return false;
  }
    
  return true;
};

Face.supported = Face.getSupported();

Face.ndndIdFetcher = new Name('/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY');

Face.prototype.createRoute = function(host, port) 
{
  this.host=host;
  this.port=port;
};

Face.KeyStore = new Array();

var KeyStoreEntry = function KeyStoreEntry(name, rsa, time) 
{
  this.keyName = name;  
  this.rsaKey = rsa;    
  this.timeStamp = time;  
};

Face.addKeyEntry = function( keyEntry) 
{
  var result = Face.getKeyByName(keyEntry.keyName);
  if (result == null) 
    Face.KeyStore.push(keyEntry);
  else
    result = keyEntry;
};

Face.getKeyByName = function( name) 
{
  var result = null;
  
  for (var i = 0; i < Face.KeyStore.length; i++) {
    if (Face.KeyStore[i].keyName.contentName.match(name.contentName)) {
      if (result == null || Face.KeyStore[i].keyName.contentName.components.length > result.keyName.contentName.components.length)
        result = Face.KeyStore[i];
    }
  }
    
  return result;
};

Face.prototype.close = function() 
{
  if (this.readyStatus != Face.OPENED)
    throw new Error('Cannot close because Face connection is not opened.');

  this.readyStatus = Face.CLOSED;
  this.transport.close();
};


Face.PITTable = new Array();


var PITEntry = function PITEntry(interest, closure) 
{
  this.interest = interest;  
  this.closure = closure;    
  this.timerID = -1;  
};




Face.extractEntriesForExpressedInterest = function(name) 
{
  var result = [];
    
  
  for (var i = Face.PITTable.length - 1; i >= 0; --i) {
    var entry = Face.PITTable[i];
    if (entry.interest.matchesName(name)) {
      
      clearTimeout(entry.timerID);

      result.push(entry);
      Face.PITTable.splice(i, 1);
    }
  }

  return result;
};


Face.registeredPrefixTable = new Array();


var RegisteredPrefix = function RegisteredPrefix(prefix, closure) 
{
  this.prefix = prefix;        
  this.closure = closure;  
};


function getEntryForRegisteredPrefix(name) 
{
  var iResult = -1;
  
  for (var i = 0; i < Face.registeredPrefixTable.length; i++) {
    if (LOG > 3) console.log("Registered prefix " + i + ": checking if " + Face.registeredPrefixTable[i].prefix + " matches " + name);
    if (Face.registeredPrefixTable[i].prefix.match(name)) {
      if (iResult < 0 || 
          Face.registeredPrefixTable[i].prefix.size() > Face.registeredPrefixTable[iResult].prefix.size())
        
        iResult = i;
    }
  }
  
  if (iResult >= 0)
    return Face.registeredPrefixTable[iResult];
  else
    return null;
}


Face.makeShuffledGetHostAndPort = function(hostList, port) 
{
  
  hostList = hostList.slice(0, hostList.length);
  DataUtils.shuffle(hostList);

  return function() {
    if (hostList.length == 0)
      return null;
      
    return { host: hostList.splice(0, 1)[0], port: port };
  };
};


Face.prototype.expressInterest = function(interestOrName, arg2, arg3, arg4) 
{
  

  
  
  if (arg2 && arg2.upcall && typeof arg2.upcall == 'function') {
    
    if (arg3)
      this.expressInterestWithClosure(interestOrName, arg2, arg3);
    else
      this.expressInterestWithClosure(interestOrName, arg2);
    return;
  }
  
  var interest;
  var onData;
  var onTimeout;
  
  
  if (typeof interestOrName == 'object' && interestOrName instanceof Interest) {
    
    interest = new Interest(interestOrName);
    onData = arg2;
    onTimeout = (arg3 ? arg3 : function() {});
  }
  else {
    
    interest = new Interest(interestOrName);
    
    
    if (arg2 && typeof arg2 == 'object' && arg2 instanceof Interest) {
      var template = arg2;
      interest.minSuffixComponents = template.minSuffixComponents;
      interest.maxSuffixComponents = template.maxSuffixComponents;
      interest.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
      interest.exclude = template.exclude;
      interest.childSelector = template.childSelector;
      interest.answerOriginKind = template.answerOriginKind;
      interest.scope = template.scope;
      interest.interestLifetime = template.interestLifetime;

      onData = arg3;
      onTimeout = (arg4 ? arg4 : function() {});
    }
    
    
    else {
      interest.interestLifetime = 4000;   
      onData = arg2;
      onTimeout = (arg3 ? arg3 : function() {});
    }
  }
  
  
  
  this.expressInterestWithClosure(interest, new Face.CallbackClosure(onData, onTimeout));
}

Face.CallbackClosure = function FaceCallbackClosure(onData, onTimeout, onInterest, prefix, transport) {
  
  Closure.call(this);
  
  this.onData = onData;
  this.onTimeout = onTimeout;
  this.onInterest = onInterest;
  this.prefix = prefix;
  this.transport = transport;
};

Face.CallbackClosure.prototype.upcall = function(kind, upcallInfo) {
  if (kind == Closure.UPCALL_CONTENT || kind == Closure.UPCALL_CONTENT_UNVERIFIED)
    this.onData(upcallInfo.interest, upcallInfo.data);
  else if (kind == Closure.UPCALL_INTEREST_TIMED_OUT)
    this.onTimeout(upcallInfo.interest);
  else if (kind == Closure.UPCALL_INTEREST)
    
    this.onInterest(this.prefix, upcallInfo.interest, this.transport)
  
  return Closure.RESULT_OK;
};


Face.prototype.expressInterestWithClosure = function(name, closure, template) 
{
  var interest = new Interest(name);
  if (template != null) {
    interest.minSuffixComponents = template.minSuffixComponents;
    interest.maxSuffixComponents = template.maxSuffixComponents;
    interest.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
    interest.exclude = template.exclude;
    interest.childSelector = template.childSelector;
    interest.answerOriginKind = template.answerOriginKind;
    interest.scope = template.scope;
    interest.interestLifetime = template.interestLifetime;
  }
  else
    interest.interestLifetime = 4000;   
  
  if (this.host == null || this.port == null) {
    if (this.getHostAndPort == null)
      console.log('ERROR: host OR port NOT SET');
    else {
      var thisNDN = this;
      this.connectAndExecute(function() { thisNDN.reconnectAndExpressInterest(interest, closure); });
    }
  }
  else
    this.reconnectAndExpressInterest(interest, closure);
};


Face.prototype.reconnectAndExpressInterest = function(interest, closure) 
{
  if (this.transport.connectedHost != this.host || this.transport.connectedPort != this.port) {
    var thisNDN = this;
    this.transport.connect(thisNDN, function() { thisNDN.expressInterestHelper(interest, closure); });
    this.readyStatus = Face.OPENED;
  }
  else
    this.expressInterestHelper(interest, closure);
};


Face.prototype.expressInterestHelper = function(interest, closure) 
{
  var binaryInterest = interest.wireEncode();
  var thisNDN = this;    
  
  if (closure != null) {
    var pitEntry = new PITEntry(interest, closure);
    
    Face.PITTable.push(pitEntry);
    closure.pitEntry = pitEntry;

    
    var timeoutMilliseconds = (interest.interestLifetime || 4000);
    var timeoutCallback = function() {
      if (LOG > 1) console.log("Interest time out: " + interest.name.toUri());
        
      
      
      
      var index = Face.PITTable.indexOf(pitEntry);
      if (index >= 0) 
        Face.PITTable.splice(index, 1);
        
      
      if (closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, new UpcallInfo(thisNDN, interest, 0, null)) == Closure.RESULT_REEXPRESS) {
        if (LOG > 1) console.log("Re-express interest: " + interest.name.toUri());
        pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
        Face.PITTable.push(pitEntry);
        thisNDN.transport.send(binaryInterest.buf());
      }
    };
  
    pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
  }

  this.transport.send(binaryInterest.buf());
};


Face.prototype.registerPrefix = function(prefix, arg2, arg3, arg4) 
{
  

  
  
  if (arg2 && arg2.upcall && typeof arg2.upcall == 'function') {
    
    if (arg3)
      this.registerPrefixWithClosure(prefix, arg2, arg3);
    else
      this.registerPrefixWithClosure(prefix, arg2);
    return;
  }

  
  
  var onInterest = arg2;
  var onRegisterFailed = (arg3 ? arg3 : function() {});
  var intFlags = (arg4 ? arg4.getForwardingEntryFlags() : new ForwardingFlags().getForwardingEntryFlags());
  this.registerPrefixWithClosure(prefix, new Face.CallbackClosure(null, null, onInterest, prefix, this.transport), 
                                 intFlags, onRegisterFailed);
}


Face.prototype.registerPrefixWithClosure = function(prefix, closure, intFlags, onRegisterFailed) 
{
  intFlags = intFlags | 3;
  var thisNDN = this;
  var onConnected = function() {
    if (thisNDN.ndndid == null) {
      
      var interest = new Interest(Face.ndndIdFetcher);
      interest.interestLifetime = 4000; 
      if (LOG > 3) console.log('Expressing interest for ndndid from ndnd.');
      thisNDN.reconnectAndExpressInterest
        (interest, new Face.FetchNdndidClosure(thisNDN, prefix, closure, intFlags, onRegisterFailed));
    }
    else  
      thisNDN.registerPrefixHelper(prefix, closure, flags, onRegisterFailed);
  };

  if (this.host == null || this.port == null) {
    if (this.getHostAndPort == null)
      console.log('ERROR: host OR port NOT SET');
    else
      this.connectAndExecute(onConnected);
  }
  else
    onConnected();
};


Face.FetchNdndidClosure = function FetchNdndidClosure(face, prefix, callerClosure, flags, onRegisterFailed) 
{
  
  Closure.call(this);
    
  this.face = face;
  this.prefix = prefix;
  this.callerClosure = callerClosure;
  this.flags = flags;
  this.onRegisterFailed = onRegisterFailed;
};

Face.FetchNdndidClosure.prototype.upcall = function(kind, upcallInfo) 
{
  if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
    console.log("Timeout while requesting the ndndid.  Cannot registerPrefix for " + this.prefix.toUri() + " .");
    if (this.onRegisterFailed)
      this.onRegisterFailed(this.prefix);
    return Closure.RESULT_OK;
  }
  if (!(kind == Closure.UPCALL_CONTENT ||
        kind == Closure.UPCALL_CONTENT_UNVERIFIED))
    
    return Closure.RESULT_ERR;
       
  if (LOG > 3) console.log('Got ndndid from ndnd.');
  
  var hash = require("crypto").createHash('sha256');
  hash.update(upcallInfo.data.getContent());
  this.face.ndndid = new internalBuf(hash.digest());
  if (LOG > 3) console.log(this.face.ndndid);
  
  this.face.registerPrefixHelper
    (this.prefix, this.callerClosure, this.flags, this.onRegisterFailed);
    
  return Closure.RESULT_OK;
};

Face.RegisterResponseClosure = function RegisterResponseClosure
  (prefix, onRegisterFailed) 
{
  
  Closure.call(this);
    
  this.prefix = prefix;
  this.onRegisterFailed = onRegisterFailed;
};

Face.RegisterResponseClosure.prototype.upcall = function(kind, upcallInfo) 
{
  if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
    if (this.onRegisterFailed)
      this.onRegisterFailed(this.prefix);
    return Closure.RESULT_OK;
  }
  if (!(kind == Closure.UPCALL_CONTENT ||
        kind == Closure.UPCALL_CONTENT_UNVERIFIED))
    
    return Closure.RESULT_ERR;
       
  var expectedName = new Name("/ndnx/.../selfreg");
  
  if (upcallInfo.data.getName().size() < 4 ||
      !upcallInfo.data.getName().get(0).equals(expectedName.get(0)) ||
      !upcallInfo.data.getName().get(2).equals(expectedName.get(2))) {
    this.onRegisterFailed(this.prefix);
    return;
  }
  
  
  return Closure.RESULT_OK;
};


Face.prototype.registerPrefixHelper = function
  (prefix, closure, flags, onRegisterFailed) 
{
  var fe = new ForwardingEntry('selfreg', prefix, null, null, flags, null);
    
  
  var encoder = new BinaryXMLEncoder();
  fe.to_ndnb(encoder);
  var bytes = encoder.getReducedOstream();
    
  var si = new MetaInfo();
  si.setFields();
    
  
  var data = new Data(new Name().append(require("crypto").randomBytes(4)), si, bytes); 
  
  data.sign(BinaryXmlWireFormat.get());
  var coBinary = data.wireEncode(BinaryXmlWireFormat.get());;
    
  var nodename = this.ndndid;
  var interestName = new Name(['ndnx', nodename, 'selfreg', coBinary]);

  var interest = new Interest(interestName);
  interest.setInterestLifetimeMilliseconds(4000.0);
  interest.setScope(1);
  if (LOG > 3) console.log('Send Interest registration packet.');
      
  Face.registeredPrefixTable.push(new RegisteredPrefix(prefix, closure));
    
  this.reconnectAndExpressInterest
    (interest, new Face.RegisterResponseClosure(prefix, onRegisterFailed));
};


Face.prototype.onReceivedElement = function(element) 
{
  if (LOG > 3) console.log('Complete element received. Length ' + element.length + '. Start decoding.');
  
  var interest = null;
  var data = null;
  
  
  
  if (element[0] == Tlv.Interest || element[0] == Tlv.Data) {
    var decoder = new TlvDecoder (element);  
    if (decoder.peekType(Tlv.Interest, element.length)) {
      interest = new Interest();
      interest.wireDecode(element, TlvWireFormat.get());
    }
    else if (decoder.peekType(Tlv.Data, element.length)) {
      data = new Data();
      data.wireDecode(element, TlvWireFormat.get());
    }
  }
  else {
    
    var decoder = new BinaryXMLDecoder(element);
    if (decoder.peekDTag(NDNProtocolDTags.Interest)) {
      interest = new Interest();
      interest.wireDecode(element, BinaryXmlWireFormat.get());
    }
    else if (decoder.peekDTag(NDNProtocolDTags.Data)) {
      data = new Data();
      data.wireDecode(element, BinaryXmlWireFormat.get());
    }
  }

  
  if (interest !== null) {
    if (LOG > 3) console.log('Interest packet received.');
        
    var entry = getEntryForRegisteredPrefix(interest.name);
    if (entry != null) {
      if (LOG > 3) console.log("Found registered prefix for " + interest.name.toUri());
      var info = new UpcallInfo(this, interest, 0, null);
      var ret = entry.closure.upcall(Closure.UPCALL_INTEREST, info);
      if (ret == Closure.RESULT_INTEREST_CONSUMED && info.data != null) 
        this.transport.send(info.data.wireEncode().buf());
    }        
  } 
  else if (data !== null) {
    if (LOG > 3) console.log('Data packet received.');
        
    var pendingInterests = Face.extractEntriesForExpressedInterest(data.name);
    
    for (var i = 0; i < pendingInterests.length; ++i) {
      var pitEntry = pendingInterests[i];
      var currentClosure = pitEntry.closure;
                    
      if (this.verify == false) {
        
        currentClosure.upcall(Closure.UPCALL_CONTENT_UNVERIFIED, new UpcallInfo(this, pitEntry.interest, 0, data));
        continue;
      }
        
      
            
      
      var KeyFetchClosure = function KeyFetchClosure(content, closure, key, sig, wit) {
        this.data = content;  
        this.closure = closure;  
        this.keyName = key;  
            
        Closure.call(this);
      };
            
      var thisNDN = this;
      KeyFetchClosure.prototype.upcall = function(kind, upcallInfo) {
        if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
          console.log("In KeyFetchClosure.upcall: interest time out.");
          console.log(this.keyName.contentName.toUri());
        } 
        else if (kind == Closure.UPCALL_CONTENT) {
          var rsakey = new Key();
          rsakey.readDerPublicKey(upcallInfo.data.content);
          var verified = data.verify(rsakey);
                
          var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
          this.closure.upcall(flag, new UpcallInfo(thisNDN, null, 0, this.data));
                
          
          var keyEntry = new KeyStoreEntry(keylocator.keyName, rsakey, new Date().getTime());
          Face.addKeyEntry(keyEntry);
        } 
        else if (kind == Closure.UPCALL_CONTENT_BAD)
          console.log("In KeyFetchClosure.upcall: signature verification failed");
      };
            
      if (data.signedInfo && data.signedInfo.locator && data.signature) {
        if (LOG > 3) console.log("Key verification...");
        var sigHex = DataUtils.toHex(data.signature.signature).toLowerCase();
              
        var wit = null;
        if (data.signature.witness != null)
            
            currentClosure.upcall(Closure.UPCALL_CONTENT_BAD, new UpcallInfo(this, pitEntry.interest, 0, data));
          
        var keylocator = data.signedInfo.locator;
        if (keylocator.type == KeyLocatorType.KEYNAME) {
          if (LOG > 3) console.log("KeyLocator contains KEYNAME");
                
          if (keylocator.keyName.contentName.match(data.name)) {
            if (LOG > 3) console.log("Content is key itself");
                  
            var rsakey = new Key();
            rsakey.readDerPublicKey(data.content);
            var verified = data.verify(rsakey);
            var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
              
            currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, data));

            
          } 
          else {
            
            var keyEntry = Face.getKeyByName(keylocator.keyName);
            if (keyEntry) {
              
              if (LOG > 3) console.log("Local key cache hit");
              var rsakey = keyEntry.rsaKey;
              var verified = data.verify(rsakey);
              var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;

              
              currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, data));
            } 
            else {
              
              if (LOG > 3) console.log("Fetch key according to keylocator");
              var nextClosure = new KeyFetchClosure(data, currentClosure, keylocator.keyName, sigHex, wit);
              
              this.expressInterest(keylocator.keyName.contentName.getPrefix(4), nextClosure);
            }
          }
        } 
        else if (keylocator.type == KeyLocatorType.KEY) {
          if (LOG > 3) console.log("Keylocator contains KEY");
                
          var rsakey = new Key();
          rsakey.readDerPublicKey(keylocator.publicKey);
          var verified = data.verify(rsakey);
              
          var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
          
          currentClosure.upcall(Closure.UPCALL_CONTENT, new UpcallInfo(this, pitEntry.interest, 0, data));

          
          
        } 
        else {
          var cert = keylocator.certificate;
          console.log("KeyLocator contains CERT");
          console.log(cert);                
          
        }
      }
    }
  } 
};


Face.prototype.connectAndExecute = function(onConnected) 
{
  var hostAndPort = this.getHostAndPort();
  if (hostAndPort == null) {
    console.log('ERROR: No more hosts from getHostAndPort');
    this.host = null;
    return;
  }

  if (hostAndPort.host == this.host && hostAndPort.port == this.port) {
    console.log('ERROR: The host returned by getHostAndPort is not alive: ' + this.host + ":" + this.port);
    return;
  }
        
  this.host = hostAndPort.host;
  this.port = hostAndPort.port;   
  if (LOG>0) console.log("connectAndExecute: trying host from getHostAndPort: " + this.host);
    
  
  var interest = new Interest(new Name("/"));
  interest.interestLifetime = 4000; 

  var thisNDN = this;
  var timerID = setTimeout(function() {
    if (LOG>0) console.log("connectAndExecute: timeout waiting for host " + thisNDN.host);
      
      thisNDN.connectAndExecute(onConnected);
  }, 3000);
  
  this.reconnectAndExpressInterest(interest, new Face.ConnectClosure(this, onConnected, timerID));
};


Face.prototype.closeByTransport = function() 
{
  this.readyStatus = Face.CLOSED;
  this.onclose();
};

Face.ConnectClosure = function ConnectClosure(face, onConnected, timerID) 
{
  
  Closure.call(this);
    
  this.face = face;
  this.onConnected = onConnected;
  this.timerID = timerID;
};

Face.ConnectClosure.prototype.upcall = function(kind, upcallInfo) 
{
  if (!(kind == Closure.UPCALL_CONTENT ||
        kind == Closure.UPCALL_CONTENT_UNVERIFIED))
    
    return Closure.RESULT_ERR;
        
  
  clearTimeout(this.timerID);

    
  this.face.readyStatus = Face.OPENED;
  this.face.onopen();

  if (LOG>0) console.log("connectAndExecute: connected to host " + this.face.host);
  this.onConnected();

  return Closure.RESULT_OK;
};


var NDN = function NDN(settings) 
{
  
  Face.call(this, settings); 
}


NDN.prototype = new Face({ getTransport: function(){}, getHostAndPort: function(){} });

exports.NDN = NDN;

NDN.supported = Face.supported;
NDN.UNOPEN = Face.UNOPEN;
NDN.OPENED = Face.OPENED;
NDN.CLOSED = Face.CLOSED;
;console.log(exports)
module.exports = ndn;
