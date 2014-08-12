/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Wentao Shang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

// Library namespace
var ndn = ndn || {};

var exports = ndn;

var require = function(ignore) { return ndn; };

// Factory method to create node.js compatible buffer objects
var Buffer = function Buffer(data, format)
{
  var obj;

  if (typeof data == 'number')
    obj = new Uint8Array(data);
  else if (typeof data == 'string') {
    if (format == null || format == 'utf8') {
      var utf8 = Buffer.str2rstr_utf8(data);
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
  else if (typeof data == 'object' && data instanceof Uint8Array || Buffer.isBuffer(data)) {
    // The second argument is a boolean for "copy", default true.
    if (format == false)
      obj = data.subarray(0);
    else
      obj = new Uint8Array(data);
  }
  else if (typeof data == 'object' && data instanceof ArrayBuffer)
    // Copy.
    obj = new Uint8Array(data);
  else if (typeof data == 'object')
    // Assume component is a byte array.  We can't check instanceof Array because
    //   this doesn't work in JavaScript if the array comes from a different module.
    obj = new Uint8Array(data);
  else
    throw new Error('Buffer: unknown data type.');

  try {
    obj.__proto__ = Buffer.prototype;
  } catch(ex) {
    throw new Error("Buffer: Set obj.__proto__ exception: " + ex);
  }

  obj.__proto__.toString = function(encoding) {
    if (encoding == null || encoding == 'binary') {
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
      return new Buffer(this.subarray(begin, end), false);
    else
      return new Buffer(this.subarray(begin), false);
  };

  obj.__proto__.copy = function(target, targetStart) {
    if (targetStart !== undefined)
      target.set(this, targetStart);
    else
      target.set(this);
  };

  return obj;
};

Buffer.prototype = Uint8Array.prototype;

Buffer.isBuffer = function(obj)
{
  return typeof obj === 'object' && obj instanceof Buffer;
};

Buffer.concat = function(arrays)
{
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

Buffer.str2rstr_utf8 = function(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while (++i < input.length)
  {
    // Decode utf-16 surrogate pairs
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if (0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    // Encode output as utf-8
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

// Factory method to create hasher objects
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
    return new Buffer(this.md.digest(), 'hex');
  };

  return obj;
};

// Factory method to create RSA signer objects
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

    return new Buffer(signer.sign(), 'hex');
  };

  return obj;
};

// Factory method to create RSA verifier objects
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
  // TODO: Use a cryptographic random number generator.
  var result = new Buffer(size);
  for (var i = 0; i < size; ++i)
    result[i] = Math.floor(Math.random() * 256);
  return result;
};
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
associated documentation files (the "Software"), to deal in the Software without restriction, including 
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

code.google.com/p/crypto-js/wiki/License
*/
/**
 * CryptoJS core components.
 */
var CryptoJS = CryptoJS || (function (Math, undefined) {
    /**
     * CryptoJS namespace.
     */
    var C = {};

    /**
     * Library namespace.
     */
    var C_lib = C.lib = {};

    /**
     * Base object for prototypal inheritance.
     */
    var Base = C_lib.Base = (function () {
        function F() {}

        return {
            /**
             * Creates a new object that inherits from this object.
             *
             * @param {Object} overrides Properties to copy into the new object.
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         field: 'value',
             *
             *         method: function () {
             *         }
             *     });
             */
            extend: function (overrides) {
                // Spawn
                F.prototype = this;
                var subtype = new F();

                // Augment
                if (overrides) {
                    subtype.mixIn(overrides);
                }

                // Create default initializer
                if (!subtype.hasOwnProperty('init')) {
                    subtype.init = function () {
                        subtype.$super.init.apply(this, arguments);
                    };
                }

                // Initializer's prototype is the subtype object
                subtype.init.prototype = subtype;

                // Reference supertype
                subtype.$super = this;

                return subtype;
            },

            /**
             * Extends this object and runs the init method.
             * Arguments to create() will be passed to init().
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var instance = MyType.create();
             */
            create: function () {
                var instance = this.extend();
                instance.init.apply(instance, arguments);

                return instance;
            },

            /**
             * Initializes a newly created object.
             * Override this method to add some logic when your objects are created.
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         init: function () {
             *             // ...
             *         }
             *     });
             */
            init: function () {
            },

            /**
             * Copies properties into this object.
             *
             * @param {Object} properties The properties to mix in.
             *
             * @example
             *
             *     MyType.mixIn({
             *         field: 'value'
             *     });
             */
            mixIn: function (properties) {
                for (var propertyName in properties) {
                    if (properties.hasOwnProperty(propertyName)) {
                        this[propertyName] = properties[propertyName];
                    }
                }

                // IE won't copy toString using the loop above
                if (properties.hasOwnProperty('toString')) {
                    this.toString = properties.toString;
                }
            },

            /**
             * Creates a copy of this object.
             *
             * @return {Object} The clone.
             *
             * @example
             *
             *     var clone = instance.clone();
             */
            clone: function () {
                return this.init.prototype.extend(this);
            }
        };
    }());

    /**
     * An array of 32-bit words.
     *
     * @property {Array} words The array of 32-bit words.
     * @property {number} sigBytes The number of significant bytes in this word array.
     */
    var WordArray = C_lib.WordArray = Base.extend({
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of 32-bit words.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.create();
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
         */
        init: function (words, sigBytes) {
            words = this.words = words || [];

            if (sigBytes != undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 4;
            }
        },

        /**
         * Converts this word array to a string.
         *
         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
         *
         * @return {string} The stringified word array.
         *
         * @example
         *
         *     var string = wordArray + '';
         *     var string = wordArray.toString();
         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
         */
        toString: function (encoder) {
            return (encoder || Hex).stringify(this);
        },

        /**
         * Concatenates a word array to this word array.
         *
         * @param {WordArray} wordArray The word array to append.
         *
         * @return {WordArray} This word array.
         *
         * @example
         *
         *     wordArray1.concat(wordArray2);
         */
        concat: function (wordArray) {
            // Shortcuts
            var thisWords = this.words;
            var thatWords = wordArray.words;
            var thisSigBytes = this.sigBytes;
            var thatSigBytes = wordArray.sigBytes;

            // Clamp excess bits
            this.clamp();

            // Concat
            if (thisSigBytes % 4) {
                // Copy one byte at a time
                for (var i = 0; i < thatSigBytes; i++) {
                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                }
            } else if (thatWords.length > 0xffff) {
                // Copy one word at a time
                for (var i = 0; i < thatSigBytes; i += 4) {
                    thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
                }
            } else {
                // Copy all words at once
                thisWords.push.apply(thisWords, thatWords);
            }
            this.sigBytes += thatSigBytes;

            // Chainable
            return this;
        },

        /**
         * Removes insignificant bits.
         *
         * @example
         *
         *     wordArray.clamp();
         */
        clamp: function () {
            // Shortcuts
            var words = this.words;
            var sigBytes = this.sigBytes;

            // Clamp
            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
            words.length = Math.ceil(sigBytes / 4);
        },

        /**
         * Creates a copy of this word array.
         *
         * @return {WordArray} The clone.
         *
         * @example
         *
         *     var clone = wordArray.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone.words = this.words.slice(0);

            return clone;
        },

        /**
         * Creates a word array filled with random bytes.
         *
         * @param {number} nBytes The number of random bytes to generate.
         *
         * @return {WordArray} The random word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.random(16);
         */
        random: function (nBytes) {
            var words = [];
            for (var i = 0; i < nBytes; i += 4) {
                words.push((Math.random() * 0x100000000) | 0);
            }

            return new WordArray.init(words, nBytes);
        }
    });

    /**
     * Encoder namespace.
     */
    var C_enc = C.enc = {};

    /**
     * Hex encoding strategy.
     */
    var Hex = C_enc.Hex = {
        /**
         * Converts a word array to a hex string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The hex string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var hexChars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                hexChars.push((bite >>> 4).toString(16));
                hexChars.push((bite & 0x0f).toString(16));
            }

            return hexChars.join('');
        },

        /**
         * Converts a hex string to a word array.
         *
         * @param {string} hexStr The hex string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
         */
        parse: function (hexStr) {
            // Shortcut
            var hexStrLength = hexStr.length;

            // Convert
            var words = [];
            for (var i = 0; i < hexStrLength; i += 2) {
                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
            }

            return new WordArray.init(words, hexStrLength / 2);
        }
    };

    /**
     * Latin1 encoding strategy.
     */
    var Latin1 = C_enc.Latin1 = {
        /**
         * Converts a word array to a Latin1 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Latin1 string.
         *
         * @static
         *
         * @example
         *
         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var latin1Chars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                latin1Chars.push(String.fromCharCode(bite));
            }

            return latin1Chars.join('');
        },

        /**
         * Converts a Latin1 string to a word array.
         *
         * @param {string} latin1Str The Latin1 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
         */
        parse: function (latin1Str) {
            // Shortcut
            var latin1StrLength = latin1Str.length;

            // Convert
            var words = [];
            for (var i = 0; i < latin1StrLength; i++) {
                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
            }

            return new WordArray.init(words, latin1StrLength);
        }
    };

    /**
     * UTF-8 encoding strategy.
     */
    var Utf8 = C_enc.Utf8 = {
        /**
         * Converts a word array to a UTF-8 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-8 string.
         *
         * @static
         *
         * @example
         *
         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
         */
        stringify: function (wordArray) {
            try {
                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
            } catch (e) {
                throw new Error('Malformed UTF-8 data');
            }
        },

        /**
         * Converts a UTF-8 string to a word array.
         *
         * @param {string} utf8Str The UTF-8 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
         */
        parse: function (utf8Str) {
            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
        }
    };

    /**
     * Abstract buffered block algorithm template.
     *
     * The property blockSize must be implemented in a concrete subtype.
     *
     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
     */
    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
        /**
         * Resets this block algorithm's data buffer to its initial state.
         *
         * @example
         *
         *     bufferedBlockAlgorithm.reset();
         */
        reset: function () {
            // Initial values
            this._data = new WordArray.init();
            this._nDataBytes = 0;
        },

        /**
         * Adds new data to this block algorithm's buffer.
         *
         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
         *
         * @example
         *
         *     bufferedBlockAlgorithm._append('data');
         *     bufferedBlockAlgorithm._append(wordArray);
         */
        _append: function (data) {
            // Convert string to WordArray, else assume WordArray already
            if (typeof data == 'string') {
                data = Utf8.parse(data);
            }

            // Append
            this._data.concat(data);
            this._nDataBytes += data.sigBytes;
        },

        /**
         * Processes available data blocks.
         *
         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
         *
         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
         *
         * @return {WordArray} The processed data.
         *
         * @example
         *
         *     var processedData = bufferedBlockAlgorithm._process();
         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
         */
        _process: function (doFlush) {
            // Shortcuts
            var data = this._data;
            var dataWords = data.words;
            var dataSigBytes = data.sigBytes;
            var blockSize = this.blockSize;
            var blockSizeBytes = blockSize * 4;

            // Count blocks ready
            var nBlocksReady = dataSigBytes / blockSizeBytes;
            if (doFlush) {
                // Round up to include partial blocks
                nBlocksReady = Math.ceil(nBlocksReady);
            } else {
                // Round down to include only full blocks,
                // less the number of blocks that must remain in the buffer
                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
            }

            // Count words ready
            var nWordsReady = nBlocksReady * blockSize;

            // Count bytes ready
            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

            // Process blocks
            if (nWordsReady) {
                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                    // Perform concrete-algorithm logic
                    this._doProcessBlock(dataWords, offset);
                }

                // Remove processed words
                var processedWords = dataWords.splice(0, nWordsReady);
                data.sigBytes -= nBytesReady;
            }

            // Return processed words
            return new WordArray.init(processedWords, nBytesReady);
        },

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = bufferedBlockAlgorithm.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone._data = this._data.clone();

            return clone;
        },

        _minBufferSize: 0
    });

    /**
     * Abstract hasher template.
     *
     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
     */
    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
        /**
         * Configuration options.
         */
        cfg: Base.extend(),

        /**
         * Initializes a newly created hasher.
         *
         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
         *
         * @example
         *
         *     var hasher = CryptoJS.algo.SHA256.create();
         */
        init: function (cfg) {
            // Apply config defaults
            this.cfg = this.cfg.extend(cfg);

            // Set initial values
            this.reset();
        },

        /**
         * Resets this hasher to its initial state.
         *
         * @example
         *
         *     hasher.reset();
         */
        reset: function () {
            // Reset data buffer
            BufferedBlockAlgorithm.reset.call(this);

            // Perform concrete-hasher logic
            this._doReset();
        },

        /**
         * Updates this hasher with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {Hasher} This hasher.
         *
         * @example
         *
         *     hasher.update('message');
         *     hasher.update(wordArray);
         */
        update: function (messageUpdate) {
            // Append
            this._append(messageUpdate);

            // Update the hash
            this._process();

            // Chainable
            return this;
        },

        /**
         * Finalizes the hash computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The hash.
         *
         * @example
         *
         *     var hash = hasher.finalize();
         *     var hash = hasher.finalize('message');
         *     var hash = hasher.finalize(wordArray);
         */
        finalize: function (messageUpdate) {
            // Final message update
            if (messageUpdate) {
                this._append(messageUpdate);
            }

            // Perform concrete-hasher logic
            var hash = this._doFinalize();

            return hash;
        },

        blockSize: 512/32,

        /**
         * Creates a shortcut function to a hasher's object interface.
         *
         * @param {Hasher} hasher The hasher to create a helper for.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
         */
        _createHelper: function (hasher) {
            return function (message, cfg) {
                return new hasher.init(cfg).finalize(message);
            };
        },

        /**
         * Creates a shortcut function to the HMAC's object interface.
         *
         * @param {Hasher} hasher The hasher to use in this HMAC helper.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
         */
        _createHmacHelper: function (hasher) {
            return function (message, key) {
                return new C_algo.HMAC.init(hasher, key).finalize(message);
            };
        }
    });

    /**
     * Algorithm namespace.
     */
    var C_algo = C.algo = {};

    return C;
}(Math));
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
associated documentation files (the "Software"), to deal in the Software without restriction, including 
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

code.google.com/p/crypto-js/wiki/License
*/
(function (Math) {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;
    var Hasher = C_lib.Hasher;
    var C_algo = C.algo;

    // Initialization and round constants tables
    var H = [];
    var K = [];

    // Compute constants
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

    // Reusable object
    var W = [];

    /**
     * SHA-256 hash algorithm.
     */
    var SHA256 = C_algo.SHA256 = Hasher.extend({
        _doReset: function () {
            this._hash = new WordArray.init(H.slice(0));
        },

        _doProcessBlock: function (M, offset) {
            // Shortcut
            var H = this._hash.words;

            // Working variables
            var a = H[0];
            var b = H[1];
            var c = H[2];
            var d = H[3];
            var e = H[4];
            var f = H[5];
            var g = H[6];
            var h = H[7];

            // Computation
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

            // Intermediate hash value
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
            // Shortcuts
            var data = this._data;
            var dataWords = data.words;

            var nBitsTotal = this._nDataBytes * 8;
            var nBitsLeft = data.sigBytes * 8;

            // Add padding
            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
            data.sigBytes = dataWords.length * 4;

            // Hash final blocks
            this._process();

            // Return final computed hash
            return this._hash;
        },

        clone: function () {
            var clone = Hasher.clone.call(this);
            clone._hash = this._hash.clone();

            return clone;
        }
    });

    /**
     * Shortcut function to the hasher's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     *
     * @return {WordArray} The hash.
     *
     * @static
     *
     * @example
     *
     *     var hash = CryptoJS.SHA256('message');
     *     var hash = CryptoJS.SHA256(wordArray);
     */
    C.SHA256 = Hasher._createHelper(SHA256);

    /**
     * Shortcut function to the HMAC's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     * @param {WordArray|string} key The secret key.
     *
     * @return {WordArray} The HMAC.
     *
     * @static
     *
     * @example
     *
     *     var hmac = CryptoJS.HmacSHA256(message, key);
     */
    C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
}(Math));
// Copyright (c) 2003-2009  Tom Wu
// All Rights Reserved.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// See "jrsasig-THIRDPARTYLICENSE.txt" for details.

var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

// convert a base64 string to hex
function b64tohex(s) {
  var ret = ""
  var i;
  var k = 0; // b64 state, 0-3
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

// convert a base64 string to a byte/number array
function b64toBA(s) {
  //piggyback on b64tohex for now, optimize later
  var h = b64tohex(s);
  var i;
  var a = new Array();
  for(i = 0; 2*i < h.length; ++i) {
    a[i] = parseInt(h.substring(2*i,2*i+2),16);
  }
  return a;
}
// Copyright (c) 2003-2009  Tom Wu
// All Rights Reserved.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// See "jrsasig-THIRDPARTYLICENSE.txt" for details.

// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
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

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s,n) {
  if(n < s.length + 11) { // TODO: fix for utf-8
    alert("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
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
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

// PKCS#1 (OAEP) mask generation function
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

// PKCS#1 (OAEP) pad input string s to n bytes, and return a bigint
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

// "empty" RSA key constructor
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

// Set the public key fields N and e from hex strings
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

// Perform raw public operation on "x": return x^e (mod n)
function RSADoPublic(x) {
  return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
function RSAEncrypt(text) {
  var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 OAEP RSA encryption of "text" as an even-length hex string
function RSAEncryptOAEP(text, hash) {
  var m = oaep_pad(text, (this.n.bitLength()+7)>>3, hash);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
RSAKey.prototype.encryptOAEP = RSAEncryptOAEP;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;
// Copyright (c) 2003-2009  Tom Wu
// All Rights Reserved.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// See "jrsasig-THIRDPARTYLICENSE.txt" for details.

// Depends on rsa.js and jsbn2.js

// Version 1.1: support utf-8 decoding in pkcs1unpad2

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
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
    if(c < 128) { // utf-8 decode
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

// PKCS#1 (OAEP) mask generation function
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

// Undo PKCS#1 (OAEP) padding and, if valid, return the plaintext
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

// Set the private key fields N, e, and d from hex strings
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

// Set the private key fields N, e, d and CRT params from hex strings
function RSASetPrivateEx(N,E,D,P,Q,DP,DQ,C) {
  //alert("RSASetPrivateEx called");
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

// Generate a new random private key B bits long, using public expt E
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
    var p1 = this.p.subtract(BigInteger.ONE);	// p1 = p - 1
    var q1 = this.q.subtract(BigInteger.ONE);	// q1 = q - 1
    var phi = p1.multiply(q1);
    if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
      this.n = this.p.multiply(this.q);	// this.n = p * q
      this.d = ee.modInverse(phi);	// this.d = 
      this.dmp1 = this.d.mod(p1);	// this.dmp1 = d mod (p - 1)
      this.dmq1 = this.d.mod(q1);	// this.dmq1 = d mod (q - 1)
      this.coeff = this.q.modInverse(this.p);	// this.coeff = (q ^ -1) mod p
      break;
    }
  }
}

// Perform raw private operation on "x": return x^d (mod n)
function RSADoPrivate(x) {
  if(this.p == null || this.q == null)
    return x.modPow(this.d, this.n);

  // TODO: re-calculate any missing CRT params
  var xp = x.mod(this.p).modPow(this.dmp1, this.p); // xp=cp?
  var xq = x.mod(this.q).modPow(this.dmq1, this.q); // xq=cq?

  while(xp.compareTo(xq) < 0)
    xp = xp.add(this.p);
  // NOTE:
  // xp.subtract(xq) => cp -cq
  // xp.subtract(xq).multiply(this.coeff).mod(this.p) => (cp - cq) * u mod p = h
  // xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq) => cq + (h * q) = M
  return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
function RSADecrypt(ctext) {
  var c = parseBigInt(ctext, 16);
  var m = this.doPrivate(c);
  if(m == null) return null;
  return pkcs1unpad2(m, (this.n.bitLength()+7)>>3);
}

// Return the PKCS#1 OAEP RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
function RSADecryptOAEP(ctext, hash) {
  var c = parseBigInt(ctext, 16);
  var m = this.doPrivate(c);
  if(m == null) return null;
  return oaep_unpad(m, (this.n.bitLength()+7)>>3, hash);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is a Base64-encoded string and the output is a plain string.
//function RSAB64Decrypt(ctext) {
//  var h = b64tohex(ctext);
//  if(h) return this.decrypt(h); else return null;
//}

// protected
RSAKey.prototype.doPrivate = RSADoPrivate;

// public
RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.decrypt = RSADecrypt;
RSAKey.prototype.decryptOAEP = RSADecryptOAEP;
//RSAKey.prototype.b64_decrypt = RSAB64Decrypt;
/*! crypto-1.0.4.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * crypto.js - Cryptographic Algorithm Provider class
 *
 * Copyright (c) 2013 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name crypto-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.4 (2013-Mar-28)
 * @since 2.2
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's class library name space
 * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
/**
 * kjur's cryptographic algorithm provider library name space
 * <p>
 * This namespace privides following crytpgrahic classes.
 * <ul>
 * <li>{@link KJUR.crypto.MessageDigest} - Java JCE(cryptograhic extension) style MessageDigest class</li>
 * <li>{@link KJUR.crypto.Signature} - Java JCE(cryptograhic extension) style Signature class</li>
 * <li>{@link KJUR.crypto.Util} - cryptographic utility functions and properties</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.crypto
 * @namespace
 */
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * static object for cryptographic function utilities
 * @name KJUR.crypto.Util
 * @class static object for cryptographic function utilities
 * @property {Array} DIGESTINFOHEAD PKCS#1 DigestInfo heading hexadecimal bytes for each hash algorithms
 * @description
 */
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

    /**
     * get hexadecimal DigestInfo
     * @name getDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @return {String} hexadecimal string DigestInfo ASN.1 structure
     */
    this.getDigestInfoHex = function(hHash, alg) {
	if (typeof this.DIGESTINFOHEAD[alg] == "undefined")
	    throw "alg not supported in Util.DIGESTINFOHEAD: " + alg;
	return this.DIGESTINFOHEAD[alg] + hHash;
    };

    /**
     * get PKCS#1 padded hexadecimal DigestInfo
     * @name getPaddedDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @param {Integer} keySize key bit length (ex. 1024)
     * @return {String} hexadecimal string of PKCS#1 padded DigestInfo
     */
    this.getPaddedDigestInfoHex = function(hHash, alg, keySize) {
	var hDigestInfo = this.getDigestInfoHex(hHash, alg);
	var pmStrLen = keySize / 4; // minimum PM length

	if (hDigestInfo.length + 22 > pmStrLen) // len(0001+ff(*8)+00+hDigestInfo)=22
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

    /**
     * get hexadecimal SHA1 hash of string
     * @name sha1
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha1 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha1', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal SHA256 hash of string
     * @name sha256
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha256 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal SHA512 hash of string
     * @name sha512
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha512 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal MD5 hash of string
     * @name md5
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.md5 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'md5', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal RIPEMD160 hash of string
     * @name ripemd160
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.ripemd160 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'ripemd160', 'prov':'cryptojs'});
        return md.digestString(s);
    };
};

/**
 * MessageDigest class which is very similar to java.security.MessageDigest class
 * @name KJUR.crypto.MessageDigest
 * @class MessageDigest class which is very similar to java.security.MessageDigest class
 * @param {Array} params parameters for constructor
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>md5 - cryptojs</li>
 * <li>sha1 - cryptojs</li>
 * <li>sha224 - cryptojs</li>
 * <li>sha256 - cryptojs</li>
 * <li>sha384 - cryptojs</li>
 * <li>sha512 - cryptojs</li>
 * <li>ripemd160 - cryptojs</li>
 * <li>sha256 - sjcl (NEW from crypto.js 1.0.4)</li>
 * </ul>
 * @example
 * // CryptoJS provider sample
 * &lt;script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/core.js"&gt;&lt;/script&gt;
 * &lt;script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/sha1.js"&gt;&lt;/script&gt;
 * &lt;script src="crypto-1.0.js"&gt;&lt;/script&gt;
 * var md = new KJUR.crypto.MessageDigest({alg: "sha1", prov: "cryptojs"});
 * md.updateString('aaa')
 * var mdHex = md.digest()
 *
 * // SJCL(Stanford JavaScript Crypto Library) provider sample
 * &lt;script src="http://bitwiseshiftleft.github.io/sjcl/sjcl.js"&gt;&lt;/script&gt;
 * &lt;script src="crypto-1.0.js"&gt;&lt;/script&gt;
 * var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "sjcl"}); // sjcl supports sha256 only
 * md.updateString('aaa')
 * var mdHex = md.digest()
 */
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

    /**
     * set hash algorithm and provider
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} alg hash algorithm name
     * @param {String} prov provider name
     * @description
     * @example
     * // for SHA1
     * md.setAlgAndProvider('sha1', 'cryptojs');
     * // for RIPEMD160
     * md.setAlgAndProvider('ripemd160', 'cryptojs');
     */
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

    /**
     * update digest by specified string
     * @name updateString
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} str string to update
     * @description
     * @example
     * md.updateString('New York');
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * update digest by specified hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * completes hash calculation and returns hash result
     * @name digest
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @description
     * @example
     * md.digest()
     */
    this.digest = function() {
	throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @name digestString
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
     */
    this.digestString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using hexadecimal string, then completes the digest computation
     * @name digestHex
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
     */
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


/**
 * Signature class which is very similar to java.security.Signature class
 * @name KJUR.crypto.Signature
 * @class Signature class which is very similar to java.security.Signature class
 * @param {Array} params parameters for constructor
 * @property {String} state Current state of this signature object whether 'SIGN', 'VERIFY' or null
 * @description
 * <br/>
 * As for params of constructor's argument, it can be specify following attributes:
 * <ul>
 * <li>alg - signature algorithm name (ex. {MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD160}withRSA)</li>
 * <li>provider - currently 'cryptojs/jsrsa' only</li>
 * <li>prvkeypem - PEM string of signer's private key. If this specified, no need to call initSign(prvKey).</li>
 * </ul>
 * <h4>SUPPORTED ALGORITHMS AND PROVIDERS</h4>
 * Signature class supports {MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD160}
 * withRSA algorithm in 'cryptojs/jsrsa' provider.
 * <h4>EXAMPLES</h4>
 * @example
 * // signature generation
 * var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA", "prov": "cryptojs/jsrsa"});
 * sig.initSign(prvKey);
 * sig.updateString('aaa');
 * var hSigVal = sig.sign();
 *
 * // signature validation
 * var sig2 = new KJUR.crypto.Signature({"alg": "SHA1withRSA", "prov": "cryptojs/jsrsa"});
 * sig2.initVerifyByCertificatePEM(cert)
 * sig.updateString('aaa');
 * var isValid = sig2.verify(hSigVal);
 */
KJUR.crypto.Signature = function(params) {
    var prvKey = null; // RSAKey for signing
    var pubKey = null; // RSAKey for verifying

    var md = null; // KJUR.crypto.MessageDigest object
    var sig = null;
    var algName = null;
    var provName = null;
    var algProvName = null;
    var mdAlgName = null;
    var pubkeyAlgName = null;
    var state = null;

    var sHashHex = null; // hex hash value for hex
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

    /**
     * set signature algorithm and provider
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} alg signature algorithm name
     * @param {String} prov provider name
     * @description
     * @example
     * md.setAlgAndProvider('SHA1withRSA', 'cryptojs/jsrsa');
     */
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
		//alert(hHashFromDI + "\n" + this.sHashHex);
		return (hHashFromDI == this.sHashHex);
	    };
	}
    };

    /**
     * Initialize this object for verifying with a public key
     * @name initVerifyByPublicKey
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {RSAKey} rsaPubKey RSAKey object of public key
     * @since 1.0.2
     * @description
     * @example
     * sig.initVerifyByPublicKey(prvKey)
     */
    this.initVerifyByPublicKey = function(rsaPubKey) {
	throw "initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Initialize this object for verifying with a certficate
     * @name initVerifyByCertificatePEM
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} certPEM PEM formatted string of certificate
     * @since 1.0.2
     * @description
     * @example
     * sig.initVerifyByCertificatePEM(certPEM)
     */
    this.initVerifyByCertificatePEM = function(certPEM) {
	throw "initVerifyByCertificatePEM(certPEM) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Initialize this object for signing
     * @name initSign
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {RSAKey} prvKey RSAKey object of private key
     * @description
     * @example
     * sig.initSign(prvKey)
     */
    this.initSign = function(prvKey) {
	throw "initSign(prvKey) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a string
     * @name updateString
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to use for the update
     * @description
     * @example
     * sig.updateString('aaa')
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} hex hexadecimal string to use for the update
     * @description
     * @example
     * sig.updateHex('1f2f3f')
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Returns the signature bytes of all data updates as a hexadecimal string
     * @name sign
     * @memberOf KJUR.crypto.Signature
     * @function
     * @return the signature bytes as a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.sign()
     */
    this.sign = function() {
	throw "sign() not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signString
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signString('aaa')
     */
    this.signString = function(str) {
	throw "digestString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using hexadecimal string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signHex
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} hex hexadecimal string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signHex('1fdc33')
     */
    this.signHex = function(hex) {
	throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * verifies the passed-in signature.
     * @name verify
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to final update
     * @return {Boolean} true if the signature was verified, otherwise false
     * @description
     * @example
     * var isValid = sig.verify('1fbcefdca4823a7(snip)')
     */
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

/*! rsapem-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// rsa-pem.js - adding function for reading/writing PKCS#1 PEM private key
//              to RSAKey class.
//
// version: 1.1.1 (2013-Apr-12)
//
// Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license/
// 
//
// Depends on:
//
//
//
// _RSApem_pemToBase64(sPEM)
//
//   removing PEM header, PEM footer and space characters including
//   new lines from PEM formatted RSA private key string.
//

/**
 * @fileOverview
 * @name rsapem-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.1
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */
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

/**
 * read RSA private key from a ASN.1 hexadecimal string
 * @name readPrivateKeyFromASN1HexString
 * @memberOf RSAKey#
 * @function
 * @param {String} keyHex ASN.1 hexadecimal string of PKCS#1 private key.
 * @since 1.1.1
 */
function _rsapem_readPrivateKeyFromASN1HexString(keyHex) {
  var a = _rsapem_getHexValueArrayOfChildrenFromHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
}

/**
 * read PKCS#1 private key from a string
 * @name readPrivateKeyFromPEMString
 * @memberOf RSAKey#
 * @function
 * @param {String} keyPEM string of PKCS#1 private key.
 */
function _rsapem_readPrivateKeyFromPEMString(keyPEM) {
  var keyB64 = _rsapem_pemToBase64(keyPEM);
  var keyHex = b64tohex(keyB64) // depends base64.js
  var a = _rsapem_getHexValueArrayOfChildrenFromHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
}

RSAKey.prototype.readPrivateKeyFromPEMString = _rsapem_readPrivateKeyFromPEMString;
RSAKey.prototype.readPrivateKeyFromASN1HexString = _rsapem_readPrivateKeyFromASN1HexString;
/*! rsasign-1.2.2.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// rsa-sign.js - adding signing functions to RSAKey class.
//
//
// version: 1.2.2 (13 May 2013)
//
// Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license/
//
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
 * @fileOverview
 * @name rsasign-1.2.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.2.2
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

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
_RSASIGN_HASHHEXFUNC['sha1'] =      function(s){return KJUR.crypto.Util.sha1(s);};
_RSASIGN_HASHHEXFUNC['sha256'] =    function(s){return KJUR.crypto.Util.sha256(s);}
_RSASIGN_HASHHEXFUNC['sha512'] =    function(s){return KJUR.crypto.Util.sha512(s);}
_RSASIGN_HASHHEXFUNC['md5'] =       function(s){return KJUR.crypto.Util.md5(s);};
_RSASIGN_HASHHEXFUNC['ripemd160'] = function(s){return KJUR.crypto.Util.ripemd160(s);};

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

function _rsasign_signStringWithSHA1(s) {
    return _rsasign_signString.call(this, s, 'sha1');
}

function _rsasign_signStringWithSHA256(s) {
    return _rsasign_signString.call(this, s, 'sha256');
}

// PKCS#1 (PSS) mask generation function
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

/**
 * sign for a message string with RSA private key by PKCS#1 PSS signing.<br/>
 * @name signStringPSS
 * @memberOf RSAKey#
 * @function
 * @param {String} s message string to be signed.
 * @param {String} hashAlg hash algorithm name for signing.<br/>
 * @return returns hexadecimal string of signature value.
 */
function _rsasign_signStringPSS(s, hashAlg, sLen) {
    var hashFunc = _RSASIGN_HASHRAWFUNC[hashAlg];
    var mHash = hashFunc(s);
    var hLen = mHash.length;
    var emBits = this.n.bitLength() - 1;
    var emLen = Math.ceil(emBits / 8);
    var i;

    if (sLen === -1) {
        sLen = hLen; // same has hash length
    } else if ((sLen === -2) || (sLen === undefined)) {
        sLen = emLen - hLen - 2; // maximum
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
 * verifies a sigature for a message string with RSA public key by PKCS#1 PSS sign.<br/>
 * @name verifyStringPSS
 * @memberOf RSAKey#
 * @function
 * @param {String} sMsg message string to be verified.
 * @param {String} hSig hexadecimal string of siganture.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0
 */
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
        sLen = hLen; // same has hash length
    } else if ((sLen === -2) || (sLen === undefined)) {
        sLen = emLen - hLen - 2; // maximum
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

/**
 * @name RSAKey
 * @class key of RSA public key algorithm
 * @description Tom Wu's RSA Key class and extension
 */
/*! asn1hex-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// asn1hex.js - Hexadecimal represented ASN.1 string library
//
// version: 1.1 (09-May-2012)
//
// Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license/
//
// Depends on:
//

// MEMO:
//   f('3082025b02...', 2) ... 82025b ... 3bytes
//   f('020100', 2) ... 01 ... 1byte
//   f('0203001...', 2) ... 03 ... 1byte
//   f('02818003...', 2) ... 8180 ... 2bytes
//   f('3080....0000', 2) ... 80 ... -1
//
//   Requirements:
//   - ASN.1 type octet length MUST be 1. 
//     (i.e. ASN.1 primitives like SET, SEQUENCE, INTEGER, OCTETSTRING ...)
//   - 

/**
 * @fileOverview
 * @name asn1hex-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.1
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * get byte length for ASN.1 L(length) bytes
 * @name getByteLengthOfL_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return byte length for ASN.1 L(length) bytes
 */
function _asnhex_getByteLengthOfL_AtObj(s, pos) {
  if (s.substring(pos + 2, pos + 3) != '8') return 1;
  var i = parseInt(s.substring(pos + 3, pos + 4));
  if (i == 0) return -1; 		// length octet '80' indefinite length
  if (0 < i && i < 10) return i + 1;	// including '8?' octet;
  return -2;				// malformed format
}


/**
 * get hexadecimal string for ASN.1 L(length) bytes
 * @name getHexOfL_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return {String} hexadecimal string for ASN.1 L(length) bytes
 */
function _asnhex_getHexOfL_AtObj(s, pos) {
  var len = _asnhex_getByteLengthOfL_AtObj(s, pos);
  if (len < 1) return '';
  return s.substring(pos + 2, pos + 2 + len * 2);
}

//
//   getting ASN.1 length value at the position 'idx' of
//   hexa decimal string 's'.
//
//   f('3082025b02...', 0) ... 82025b ... ???
//   f('020100', 0) ... 01 ... 1
//   f('0203001...', 0) ... 03 ... 3
//   f('02818003...', 0) ... 8180 ... 128
/**
 * get integer value of ASN.1 length for ASN.1 data
 * @name getIntOfL_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return ASN.1 L(length) integer value
 */
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

/**
 * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
 * @name getStartPosOfV_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 */
function _asnhex_getStartPosOfV_AtObj(s, pos) {
  var l_len = _asnhex_getByteLengthOfL_AtObj(s, pos);
  if (l_len < 0) return l_len;
  return pos + (l_len + 1) * 2;
}

/**
 * get hexadecimal string of ASN.1 V(value)
 * @name getHexOfV_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return {String} hexadecimal string of ASN.1 value.
 */
function _asnhex_getHexOfV_AtObj(s, pos) {
  var pos1 = _asnhex_getStartPosOfV_AtObj(s, pos);
  var len = _asnhex_getIntOfL_AtObj(s, pos);
  return s.substring(pos1, pos1 + len * 2);
}

/**
 * get hexadecimal string of ASN.1 TLV at
 * @name getHexOfTLV_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return {String} hexadecimal string of ASN.1 TLV.
 * @since 1.1
 */
function _asnhex_getHexOfTLV_AtObj(s, pos) {
  var hT = s.substr(pos, 2);
  var hL = _asnhex_getHexOfL_AtObj(s, pos);
  var hV = _asnhex_getHexOfV_AtObj(s, pos);
  return hT + hL + hV;
}

/**
 * get next sibling starting index for ASN.1 object string
 * @name getPosOfNextSibling_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} pos string index
 * @return next sibling starting index for ASN.1 object string
 */
function _asnhex_getPosOfNextSibling_AtObj(s, pos) {
  var pos1 = _asnhex_getStartPosOfV_AtObj(s, pos);
  var len = _asnhex_getIntOfL_AtObj(s, pos);
  return pos1 + len * 2;
}

/**
 * get array of indexes of child ASN.1 objects
 * @name getPosArrayOfChildren_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} s hexadecimal string of ASN.1 DER encoded data
 * @param {Number} start string index of ASN.1 object
 * @return {Array of Number} array of indexes for childen of ASN.1 objects
 */
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

/**
 * get string index of nth child object of ASN.1 object refered by h, idx
 * @name getNthChildIndex_AtObj
 * @memberOf ASN1HEX
 * @function
 * @param {String} h hexadecimal string of ASN.1 DER encoded data
 * @param {Number} idx start string index of ASN.1 object
 * @param {Number} nth for child
 * @return {Number} string index of nth child.
 * @since 1.1
 */
function _asnhex_getNthChildIndex_AtObj(h, idx, nth) {
  var a = _asnhex_getPosArrayOfChildren_AtObj(h, idx);
  return a[nth];
}

// ========== decendant methods ==============================

/**
 * get string index of nth child object of ASN.1 object refered by h, idx
 * @name getDecendantIndexByNthList
 * @memberOf ASN1HEX
 * @function
 * @param {String} h hexadecimal string of ASN.1 DER encoded data
 * @param {Number} currentIndex start string index of ASN.1 object
 * @param {Array of Number} nthList array list of nth
 * @return {Number} string index refered by nthList
 * @since 1.1
 */
function _asnhex_getDecendantIndexByNthList(h, currentIndex, nthList) {
  if (nthList.length == 0) {
    return currentIndex;
  }
  var firstNth = nthList.shift();
  var a = _asnhex_getPosArrayOfChildren_AtObj(h, currentIndex);
  return _asnhex_getDecendantIndexByNthList(h, a[firstNth], nthList);
}

/**
 * get hexadecimal string of ASN.1 TLV refered by current index and nth index list.
 * @name getDecendantHexTLVByNthList
 * @memberOf ASN1HEX
 * @function
 * @param {String} h hexadecimal string of ASN.1 DER encoded data
 * @param {Number} currentIndex start string index of ASN.1 object
 * @param {Array of Number} nthList array list of nth
 * @return {Number} hexadecimal string of ASN.1 TLV refered by nthList
 * @since 1.1
 */
function _asnhex_getDecendantHexTLVByNthList(h, currentIndex, nthList) {
  var idx = _asnhex_getDecendantIndexByNthList(h, currentIndex, nthList);
  return _asnhex_getHexOfTLV_AtObj(h, idx);
}

/**
 * get hexadecimal string of ASN.1 V refered by current index and nth index list.
 * @name getDecendantHexVByNthList
 * @memberOf ASN1HEX
 * @function
 * @param {String} h hexadecimal string of ASN.1 DER encoded data
 * @param {Number} currentIndex start string index of ASN.1 object
 * @param {Array of Number} nthList array list of nth
 * @return {Number} hexadecimal string of ASN.1 V refered by nthList
 * @since 1.1
 */
function _asnhex_getDecendantHexVByNthList(h, currentIndex, nthList) {
  var idx = _asnhex_getDecendantIndexByNthList(h, currentIndex, nthList);
  return _asnhex_getHexOfV_AtObj(h, idx);
}

// ========== class definition ==============================

/**
 * ASN.1 DER encoded hexadecimal string utility class
 * @class ASN.1 DER encoded hexadecimal string utility class
 * @author Kenji Urushima
 * @version 1.1 (09 May 2012)
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 * @since 1.1
 */
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
/*! x509-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
// 
// x509.js - X509 class to read subject public key from certificate.
//
// version: 1.1 (10-May-2012)
//
// Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
//
// Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license
//
//
// Depends:
//   base64.js
//   rsa.js
//   asn1hex.js

/**
 * @fileOverview
 * @name x509-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.1
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

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

// NOTE: privateKeyUsagePeriod field of X509v2 not supported.
// NOTE: v1 and v3 supported
function _x509_getSubjectPublicKeyInfoPosFromCertHex(hCert) {
  var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
  var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pTbsCert); 
  if (a.length < 1) return -1;
  if (hCert.substring(a[0], a[0] + 10) == "a003020102") { // v3
    if (a.length < 6) return -1;
    return a[6];
  } else {
    if (a.length < 5) return -1;
    return a[5];
  }
}

// NOTE: Without BITSTRING encapsulation.
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

// ===== get basic fields from hex =====================================
/**
 * get hexadecimal string of serialNumber field of certificate.<br/>
 * @name getSerialNumberHex
 * @memberOf X509#
 * @function
 */
function _x509_getSerialNumberHex() {
  return ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 1]);
}

/**
 * get hexadecimal string of issuer field of certificate.<br/>
 * @name getIssuerHex
 * @memberOf X509#
 * @function
 */
function _x509_getIssuerHex() {
  return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]);
}

/**
 * get string of issuer field of certificate.<br/>
 * @name getIssuerString
 * @memberOf X509#
 * @function
 */
function _x509_getIssuerString() {
  return _x509_hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]));
}

/**
 * get hexadecimal string of subject field of certificate.<br/>
 * @name getSubjectHex
 * @memberOf X509#
 * @function
 */
function _x509_getSubjectHex() {
  return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]);
}

/**
 * get string of subject field of certificate.<br/>
 * @name getSubjectString
 * @memberOf X509#
 * @function
 */
function _x509_getSubjectString() {
  return _x509_hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]));
}

/**
 * get notBefore field string of certificate.<br/>
 * @name getNotBefore
 * @memberOf X509#
 * @function
 */
function _x509_getNotBefore() {
  var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 0]);
  s = s.replace(/(..)/g, "%$1");
  s = decodeURIComponent(s);
  return s;
}

/**
 * get notAfter field string of certificate.<br/>
 * @name getNotAfter
 * @memberOf X509#
 * @function
 */
function _x509_getNotAfter() {
  var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 1]);
  s = s.replace(/(..)/g, "%$1");
  s = decodeURIComponent(s);
  return s;
}

// ===== read certificate =====================================

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

// ===== read certificate =====================================


/**
 * read PEM formatted X.509 certificate from string.<br/>
 * @name readCertPEM
 * @memberOf X509#
 * @function
 * @param {String} sCertPEM string for PEM formatted X.509 certificate
 */
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

/**
 * X.509 certificate class.<br/>
 * @class X.509 certificate class
 * @property {RSAKey} subjectPublicKeyRSA Tom Wu's RSAKey object
 * @property {String} subjectPublicKeyRSA_hN hexadecimal string for modulus of RSA public key
 * @property {String} subjectPublicKeyRSA_hE hexadecimal string for public exponent of RSA public key
 * @property {String} hex hexacedimal string for X.509 certificate.
 * @author Kenji Urushima
 * @version 1.0.1 (08 May 2012)
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 */
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

// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// See "jrsasig-THIRDPARTYLICENSE.txt" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
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
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
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
else { // Mozilla/Netscape seems to prefer am3
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

// Digit conversions
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

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
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

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
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

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
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

// (protected) r = this >> n
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

// (protected) r = this - a
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

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
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

// (protected) r = this^2, r != this (HAC 14.16)
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

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
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
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
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
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
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
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
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

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
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

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
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

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// See "jrsasig-THIRDPARTYLICENSE.txt" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
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

// (protected) convert from radix string
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

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
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

// (protected) r = this op a (bitwise)
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

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
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

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
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

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
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

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
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

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
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

  // precomputation
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
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
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

// (public) gcd(this,a) (HAC 14.54)
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

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
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

// (public) test primality with certainty >= 1-.5^t
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

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
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

// protected
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

// public
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

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)
/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * The Log class holds the global static variable LOG.
 */
var Log = function Log()
{
}

exports.Log = Log;

/**
 * LOG is the level for logging debugging statements.  0 means no log messages.
 * @type Number
 */
Log.LOG = 0;
/**
 * This class contains all NDNx tags
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */


var NDNProtocolDTags = {

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
   Interest : 26,  /* 20090915 */
   Key : 27,
   KeyLocator : 28,
   KeyName : 29,
   Length : 30,
   Link : 31,
   LinkAuthenticator : 32,
   NameComponentCount : 33,  /* DeprecatedInInterest */
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
   Data : 64,  /* 20090915 */
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
/**
 * This class represents NDNTime Objects
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var LOG = require('../log.js').Log.LOG;

/**
 * @constructor
 */
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
/**
 * This is the closure class for use in expressInterest to re express with exponential falloff.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Closure = require('../closure.js').Closure;

/**
 * Create a new ExponentialReExpressClosure where upcall responds to UPCALL_INTEREST_TIMED_OUT
 *   by expressing the interest again with double the interestLifetime. If the interesLifetime goes
 *   over maxInterestLifetime, then call callerClosure.upcall with UPCALL_INTEREST_TIMED_OUT.
 * When upcall is not UPCALL_INTEREST_TIMED_OUT, just call callerClosure.upcall.
 * @constructor
 * @param {Closure} callerClosure
 * @param {Object} settings if not null, an associative array with the following defaults:
 * {
 *   maxInterestLifetime: 16000 // milliseconds
 * }
 */
var ExponentialReExpressClosure = function ExponentialReExpressClosure(callerClosure, settings)
{
  // Inherit from Closure.
  Closure.call(this);

  this.callerClosure = callerClosure;
  settings = (settings || {});
  this.maxInterestLifetime = (settings.maxInterestLifetime || 16000);
};

exports.ExponentialReExpressClosure = ExponentialReExpressClosure;

/**
 * Wrap this.callerClosure to responds to UPCALL_INTEREST_TIMED_OUT
 *   by expressing the interest again as described in the constructor.
 */
ExponentialReExpressClosure.prototype.upcall = function(kind, upcallInfo)
{
  try {
    if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
      var interestLifetime = upcallInfo.interest.getInterestLifetimeMilliseconds();
      if (interestLifetime == null)
        return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);

      var nextInterestLifetime = interestLifetime * 2;
      if (nextInterestLifetime > this.maxInterestLifetime)
        return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);

      var nextInterest = upcallInfo.interest.clone();
      nextInterest.setInterestLifetimeMilliseconds(nextInterestLifetime);
      // TODO: Use expressInterest with callbacks, not Closure.
      upcallInfo.face.expressInterest(nextInterest.getName(), this, nextInterest);
      return Closure.RESULT_OK;
    }
    else
      return this.callerClosure.upcall(kind, upcallInfo);
  } catch (ex) {
    console.log("ExponentialReExpressClosure.upcall exception: " + ex);
    return Closure.RESULT_ERR;
  }
};
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * A Blob holds an immutable byte array implemented as a Buffer.  This should be
 * treated like a string which is a pointer to an immutable string. (It is OK to
 * pass a pointer to the string because the new owner can’t change the bytes of
 * the string.)  Blob does not inherit from Buffer. Instead you must call buf()
 * to get the byte array which reminds you that you should not change the
 * contents.  Also remember that buf() can return null.
 * @param {Blob|Buffer|Array<number>} value (optional) If value is a Blob, take
 * another pointer to the Buffer without copying. If value is a Buffer or byte
 * array, copy to create a new Buffer.  If omitted, buf() will return null.
 * @param {boolean} copy (optional) (optional) If true, copy the contents of
 * value into a new Buffer.  If false, just use the existing value without
 * copying. If omitted, then copy the contents (unless value is already a Blob).
 * IMPORTANT: If copy is false, if you keep a pointer to the value then you must
 * treat the value as immutable and promise not to change it.
 */
var Blob = function Blob(value, copy)
{
  if (copy == null)
    copy = true;

  if (value == null)
    this.buffer = null;
  else if (typeof value === 'object' && value instanceof Blob)
    // Use the existing buffer.  Don't need to check for copy.
    this.buffer = value.buffer;
  else {
    if (typeof value === 'string')
      // Convert from a string to utf-8 byte encoding.
      this.buffer = new Buffer(value, 'utf8');
    else {
      if (copy)
        // We are copying, so just make another Buffer.
        this.buffer = new Buffer(value);
      else {
        if (Buffer.isBuffer(value))
          // We can use as-is.
          this.buffer = value;
        else
          // We need a Buffer, so copy.
          this.buffer = new Buffer(value);
      }
    }
  }

  // Set the length to be "JavaScript-like".
  this.length = this.buffer != null ? this.buffer.length : 0;
};

exports.Blob = Blob;

/**
 * Return the length of the immutable byte array.
 * @returns {number} The length of the array.  If buf() is null, return 0.
 */
Blob.prototype.size = function()
{
  if (this.buffer != null)
    return this.buffer.length;
  else
    return 0;
};

/**
 * Return the immutable byte array.  DO NOT change the contents of the Buffer.
 * If you need to change it, make a copy.
 * @returns {Buffer} The Buffer holding the immutable byte array, or null.
 */
Blob.prototype.buf = function()
{
  return this.buffer;
};

/**
 * Return true if the array is null, otherwise false.
 * @returns {boolean} True if the array is null.
 */
Blob.prototype.isNull = function()
{
  return this.buffer == null;
};

/**
 * Return the hex representation of the bytes in the byte array.
 * @returns {string} The hex string.
 */
Blob.prototype.toHex = function()
{
  if (this.buffer == null)
    return "";
  else
    return this.buffer.toString('hex');
};

/**
 * Check if the value of this Blob equals the other blob.
 * @param {Blob} other The other Blob to check.
 * @returns {boolean} if this isNull and other isNull or if the bytes of this
 * blob equal the bytes of the other.
 */
Blob.prototype.equals = function(other)
{
  if (this.isNull())
    return other.isNull();
  else if (other.isNull())
    return false;
  else {
    if (this.buffer.length != other.buffer.length)
      return false;

    for (var i = 0; i < this.buffer.length; ++i) {
      if (this.buffer[i] != other.buffer[i])
        return false;
    }

    return true;
  }
};/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('./blob.js').Blob;

/**
 * A SignedBlob extends Blob to keep the offsets of a signed portion (e.g., the
 * bytes of Data packet). This inherits from Blob, including Blob.size and Blob.buf.
 * @param {Blob|Buffer|Array<number>} value (optional) If value is a Blob, take
 * another pointer to the Buffer without copying. If value is a Buffer or byte
 * array, copy to create a new Buffer.  If omitted, buf() will return null.
 * @param {number} signedPortionBeginOffset (optional) The offset in the
 * encoding of the beginning of the signed portion. If omitted, set to 0.
 * @param {number} signedPortionEndOffset (optional) The offset in the encoding
 * of the end of the signed portion. If omitted, set to 0.
 */
var SignedBlob = function SignedBlob(value, signedPortionBeginOffset, signedPortionEndOffset)
{
  // Call the base constructor.
  Blob.call(this, value);

  if (this.buffer == null) {
    this.signedPortionBeginOffset = 0;
    this.signedPortionEndOffset = 0;
  }
  else if (typeof value === 'object' && value instanceof SignedBlob) {
    // Copy the SignedBlob, allowing override for offsets.
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

/**
 * Return the length of the signed portion of the immutable byte array.
 * @returns {number} The length of the signed portion.  If signedBuf() is null,
 * return 0.
 */
SignedBlob.prototype.signedSize = function()
{
  if (this.signedBuffer != null)
    return this.signedBuffer.length;
  else
    return 0;
};

/**
 * Return a the signed portion of the immutable byte array.
 * @returns {Buffer} A slice into the Buffer which is the signed portion.
 * If the pointer to the array is null, return null.
 */
SignedBlob.prototype.signedBuf = function()
{
  if (this.signedBuffer != null)
    return this.signedBuffer;
  else
    return null;
};

/**
 * Return the offset in the array of the beginning of the signed portion.
 * @returns {number} The offset in the array.
 */
SignedBlob.prototype.getSignedPortionBeginOffset = function()
{
  return this.signedPortionBeginOffset;
};

/**
 * Return the offset in the array of the end of the signed portion.
 * @returns {number} The offset in the array.
 */
SignedBlob.prototype.getSignedPortionEndOffset = function()
{
  return this.signedPortionEndOffset;
};
/**
 * Encapsulate a Buffer and support dynamic reallocation.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * Create a DynamicBuffer where this.array is a Buffer of size length.
 * To access the array, use this.array or call slice.
 * @constructor
 * @param {number} length the initial length of the array.  If null, use a default.
 */
var DynamicBuffer = function DynamicBuffer(length)
{
  if (!length)
    length = 16;

  this.array = new Buffer(length);
};

exports.DynamicBuffer = DynamicBuffer;

/**
 * Ensure that this.array has the length, reallocate and copy if necessary.
 * Update the length of this.array which may be greater than length.
 * @param {number} length The minimum length for the array.
 */
DynamicBuffer.prototype.ensureLength = function(length)
{
  if (this.array.length >= length)
    return;

  // See if double is enough.
  var newLength = this.array.length * 2;
  if (length > newLength)
    // The needed length is much greater, so use it.
    newLength = length;

  var newArray = new Buffer(newLength);
  this.array.copy(newArray);
  this.array = newArray;
};

/**
 * Copy the value to this.array at offset, reallocating if necessary.
 * @param {Buffer} value The buffer to copy.
 * @param {number} offset The offset in the buffer to start copying into.
 */
DynamicBuffer.prototype.copy = function(value, offset)
{
  this.ensureLength(value.length + offset);

  if (Buffer.isBuffer(value))
    value.copy(this.array, offset);
  else
    // Need to make value a Buffer to copy.
    new Buffer(value).copy(this.array, offset);
};

/**
 * Ensure that this.array has the length. If necessary, reallocate the array
 *   and shift existing data to the back of the new array.
 * Update the length of this.array which may be greater than length.
 * @param {number} length The minimum length for the array.
 */
DynamicBuffer.prototype.ensureLengthFromBack = function(length)
{
  if (this.array.length >= length)
    return;

  // See if double is enough.
  var newLength = this.array.length * 2;
  if (length > newLength)
    // The needed length is much greater, so use it.
    newLength = length;

  var newArray = new Buffer(newLength);
  // Copy to the back of newArray.
  this.array.copy(newArray, newArray.length - this.array.length);
  this.array = newArray;
};

/**
 * First call ensureLengthFromBack to make sure the bytearray has
 * offsetFromBack bytes, then copy value into the array starting
 * offsetFromBack bytes from the back of the array.
 * @param {Buffer} value The buffer to copy.
 * @param {offsetFromBack} offset The offset from the back of the array to start
 * copying.
 */
DynamicBuffer.prototype.copyFromBack = function(value, offsetFromBack)
{
  this.ensureLengthFromBack(offsetFromBack);

  if (Buffer.isBuffer(value))
    value.copy(this.array, this.array.length - offsetFromBack);
  else
    // Need to make value a Buffer to copy.
    new Buffer(value).copy(this.array, this.array.length - offsetFromBack);
};

/**
 * Return this.array.slice(begin, end);
 * @param {number} begin The begin index for the slice.
 * @param {number} end The end index for the slice.
 * @returns {Buffer} The buffer slice.
 */
DynamicBuffer.prototype.slice = function(begin, end)
{
  return this.array.slice(begin, end);
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * A ChangeCounter keeps a target object whose change count is tracked by a
 * local change count.  You can set to a new target which updates the local
 * change count, and you can call checkChanged to check if the target (or one of
 * the target's targets) has been changed. The target object must have a method
 * getChangeCount.
 *
 * Create a new ChangeCounter to track the given target.  This sets the local
 * change counter to target.getChangeCount().
 * @param {object} target The target to track, as an object with the method
 * getChangeCount().
 * @constructor
 */
var ChangeCounter = function ChangeCounter(target)
{
  this.target = target;
  this.changeCount = target.getChangeCount();
};

exports.ChangeCounter = ChangeCounter;

/**
 * Get the target object. If the target is changed, then checkChanged will
 * detect it.
 * @returns {object} The target, as an object with the method
 * getChangeCount().
 */
ChangeCounter.prototype.get = function()
{
  return this.target;
};

/**
 * Set the target to the given target. This sets the local change counter to
 * target.getChangeCount().
 * @param {object} target The target to track, as an object with the method
 * getChangeCount().
 */
ChangeCounter.prototype.set = function(target)
{
  this.target = target;
  this.changeCount = target.getChangeCount();
};

/**
 * If the target's change count is different than the local change count, then 
 * update the local change count and return true. Otherwise return false, 
 * meaning that the target has not changed. This is useful since the target (or 
 * one of the target's targets) may be changed and you need to find out.
 * @returns {boolean} True if the change count has been updated, false if not.
 */
ChangeCounter.prototype.checkChanged = function()
{
  targetChangeCount = this.target.getChangeCount();
  if (this.changeCount != targetChangeCount) {
    this.changeCount = targetChangeCount;
    return true;
  }
  else
    return false;
};
/**
 * This class contains utilities to help parse the data
 *
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * A DataUtils has static methods for converting data.
 * @constructor
 */
var DataUtils = function DataUtils()
{
};

exports.DataUtils = DataUtils;

/*
 * NOTE THIS IS CURRENTLY NOT BEING USED
 *
 */

DataUtils.keyStr = "ABCDEFGHIJKLMNOP" +
                   "QRSTUVWXYZabcdef" +
                   "ghijklmnopqrstuv" +
                   "wxyz0123456789+/" +
                   "=";

/**
 * Raw String to Base 64
 */
DataUtils.stringtoBase64 = function stringtoBase64(input)
{
   //input = escape(input);
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

/**
 * Base 64 to Raw String
 */
DataUtils.base64toString = function base64toString(input)
{
  var output = "";
  var chr1, chr2, chr3 = "";
  var enc1, enc2, enc3, enc4 = "";
  var i = 0;

  // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
  var base64test = /[^A-Za-z0-9\+\/\=]/g;
  /* Test for invalid characters. */
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

/**
 * Buffer to Hex String
 */
DataUtils.toHex = function(buffer)
{
  return buffer.toString('hex');
};

/**
 * Raw string to hex string.
 */
DataUtils.stringToHex = function(args)
{
  var ret = "";
  for (var i = 0; i < args.length; ++i) {
    var value = args.charCodeAt(i);
    ret += (value < 16 ? "0" : "") + value.toString(16);
  }
  return ret;
};

/**
 * Buffer to raw string.
 */
DataUtils.toString = function(buffer)
{
  return buffer.toString('binary');
};

/**
 * Hex String to Buffer.
 */
DataUtils.toNumbers = function(str)
{
  return new Buffer(str, 'hex');
};

/**
 * Hex String to raw string.
 */
DataUtils.hexToRawString = function(str)
{
  if (typeof str =='string') {
  var ret = "";
  str.replace(/(..)/g, function(s) {
    ret += String.fromCharCode(parseInt(s, 16));
  });
  return ret;
  }
};

/**
 * Raw String to Buffer.
 */
DataUtils.toNumbersFromString = function(str)
{
  return new Buffer(str, 'binary');
};

/**
 * If value is a string, then interpret it as a raw string and convert to
 * a Buffer. Otherwise assume it is a Buffer or array type and just return it.
 * @param {string|any} value
 * @returns {Buffer}
 */
DataUtils.toNumbersIfString = function(value)
{
  if (typeof value === 'string')
    return new Buffer(value, 'binary');
  else
    return value;
};

/**
 * Encode str as utf8 and return as Buffer.
 */
DataUtils.stringToUtf8Array = function(str)
{
  return new Buffer(str, 'utf8');
};

/**
 * arrays is an array of Buffer. Return a new Buffer which is the concatenation of all.
 */
DataUtils.concatArrays = function(arrays)
{
  return Buffer.concat(arrays);
};

// TODO: Take Buffer and use TextDecoder when available.
DataUtils.decodeUtf8 = function(utftext)
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

/**
 * Return true if a1 and a2 are the same length with equal elements.
 */
DataUtils.arraysEqual = function(a1, a2)
{
  // A simple sanity check that it is an array.
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

/**
 * Convert the big endian Buffer to an unsigned int.
 * Don't check for overflow.
 */
DataUtils.bigEndianToUnsignedInt = function(bytes)
{
  var result = 0;
  for (var i = 0; i < bytes.length; ++i) {
    result <<= 8;
    result += bytes[i];
  }
  return result;
};

/**
 * Convert the int value to a new big endian Buffer and return.
 * If value is 0 or negative, return new Buffer(0).
 */
DataUtils.nonNegativeIntToBigEndian = function(value)
{
  value = Math.round(value);
  if (value <= 0)
    return new Buffer(0);

  // Assume value is not over 64 bits.
  var size = 8;
  var result = new Buffer(size);
  var i = 0;
  while (value != 0) {
    ++i;
    result[size - i] = value & 0xff;
    value >>= 8;
  }
  return result.slice(size - i, size);
};

/**
 * Modify array to randomly shuffle the elements.
 */
DataUtils.shuffle = function(array)
{
  for (var i = array.length - 1; i >= 1; --i) {
    // j is from 0 to i.
    var j = Math.floor(Math.random() * (i + 1));
    var temp = array[i];
    array[i] = array[j];
    array[j] = temp;
  }
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * Create a new DecodingException wrapping the given error object.
 * Call with: throw new DecodingException(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
function DecodingException(error)
{
  this.message = error.message;
  // Copy lineNumber, etc. from where new Error was called.
  for (var prop in error)
      this[prop] = error[prop];
}
DecodingException.prototype = new Error();
DecodingException.prototype.name = "DecodingException";

exports.DecodingException = DecodingException;
/**
 * This class is used to encode ndnb binary elements (blob, type/value pairs).
 *
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var LOG = require('../log.js').Log.LOG;

var NDNProtocolDTags = require('../util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var DynamicBuffer = require('../util/dynamic-buffer.js').DynamicBuffer;
var DataUtils = require('./data-utils.js').DataUtils;
var LOG = require('../log.js').Log.LOG;

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
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); // 0x80
var BYTE_MASK = 0xFF;
var LONG_BYTES = 8;
var LONG_BITS = 64;

var bits_11 = 0x0000007FF;
var bits_18 = 0x00003FFFF;
var bits_32 = 0x0FFFFFFFF;

/**
 * @constructor
 */
var BinaryXMLEncoder = function BinaryXMLEncoder(initiaLength)
{
  if (!initiaLength)
    initiaLength = 16;

  this.ostream = new DynamicBuffer(initiaLength);
  this.offset = 0;
  this.CODEC_NAME = "Binary";
};

exports.BinaryXMLEncoder = BinaryXMLEncoder;

/**
 * Encode utf8Content as utf8 and write to the output buffer as a UDATA.
 * @param {string} utf8Content The string to convert to utf8.
 */
BinaryXMLEncoder.prototype.writeUString = function(utf8Content)
{
  this.encodeUString(utf8Content, XML_UDATA);
};

BinaryXMLEncoder.prototype.writeBlob = function(
    /*Buffer*/ binaryContent)
{
  if (LOG >3) console.log(binaryContent);

  this.encodeBlob(binaryContent, binaryContent.length);
};

/**
 * Write an element start header using DTAG with the tag to the output buffer.
 * @param {number} tag The DTAG tag.
 */
BinaryXMLEncoder.prototype.writeElementStartDTag = function(tag)
{
  this.encodeTypeAndVal(XML_DTAG, tag);
};

/**
 * @deprecated Use writeElementStartDTag.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLEncoder.prototype.writeStartElement = function(
  /*String*/ tag,
  /*TreeMap<String,String>*/ attributes)
{
  /*Long*/ var dictionaryVal = tag; //stringToTag(tag);

  if (null == dictionaryVal)
    this.encodeUString(tag, XML_TAG);
  else
    this.encodeTypeAndVal(XML_DTAG, dictionaryVal);

  if (null != attributes)
    this.writeAttributes(attributes);
};

/**
 * Write an element close to the output buffer.
 */
BinaryXMLEncoder.prototype.writeElementClose = function()
{
  this.ostream.ensureLength(this.offset + 1);
  this.ostream.array[this.offset] = XML_CLOSE;
  this.offset += 1;
};

/**
 * @deprecated Use writeElementClose.
 */
BinaryXMLEncoder.prototype.writeEndElement = function()
{
  this.writeElementClose();
};

/**
 * @deprecated Binary XML string tags and attributes are not used by any NDN encodings and support is not maintained in the code base.
 */
BinaryXMLEncoder.prototype.writeAttributes = function(/*TreeMap<String,String>*/ attributes)
{
  if (null == attributes)
    return;

  // the keySet of a TreeMap is sorted.

  for (var i = 0; i< attributes.length;i++) {
    var strAttr = attributes[i].k;
    var strValue = attributes[i].v;

    var dictionaryAttr = stringToTag(strAttr);
    if (null == dictionaryAttr)
      // not in dictionary, encode as attr
      // compressed format wants length of tag represented as length-1
      // to save that extra bit, as tag cannot be 0 length.
      // encodeUString knows to do that.
      this.encodeUString(strAttr, XML_ATTR);
    else
      this.encodeTypeAndVal(XML_DATTR, dictionaryAttr);

    // Write value
    this.encodeUString(strValue);
  }
};

//returns a string
stringToTag = function(/*long*/ tagVal)
{
  if (tagVal >= 0 && tagVal < NDNProtocolDTagsStrings.length)
    return NDNProtocolDTagsStrings[tagVal];
  else if (tagVal == NDNProtocolDTags.NDNProtocolDataUnit)
    return NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT;

  return null;
};

//returns a Long
tagToString =  function(/*String*/ tagName)
{
  // the slow way, but right now we don't care.... want a static lookup for the forward direction
  for (var i = 0; i < NDNProtocolDTagsStrings.length; ++i) {
    if (null != NDNProtocolDTagsStrings[i] && NDNProtocolDTagsStrings[i] == tagName)
      return i;
  }

  if (NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT == tagName)
    return NDNProtocolDTags.NDNProtocolDataUnit;

  return null;
};

/**
 * Write an element start header using DTAG with the tag to the output buffer, then the content as explained below,
 * then an element close.
 * @param {number} tag The DTAG tag.
 * @param {number|string|Buffer} content If contentis a number, convert it to a string and call writeUString.  If content is a string,
 * call writeUString.  Otherwise, call writeBlob.
 */
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

/**
 * @deprecated Use writeDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 * If Content is a string, then encode as utf8 and write UDATA.
 */
BinaryXMLEncoder.prototype.writeElement = function(
    //long
    tag,
    //byte[]
    Content,
    //TreeMap<String, String>
    attributes)
{
  this.writeStartElement(tag, attributes);
  // Will omit if 0-length

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
    //int
    type,
    //long
    val)
{
  if (LOG > 4) console.log('Encoding type '+ type+ ' and value '+ val);

  if (LOG > 4) console.log('OFFSET IS ' + this.offset);

  if (type > XML_UDATA || type < 0 || val < 0)
    throw new Error("Tag and value must be positive, and tag valid.");

  // Encode backwards. Calculate how many bytes we need:
  var numEncodingBytes = this.numEncodingBytes(val);
  this.ostream.ensureLength(this.offset + numEncodingBytes);

  // Bottom 4 bits of val go in last byte with tag.
  this.ostream.array[this.offset + numEncodingBytes - 1] =
    //(byte)
      (BYTE_MASK &
          (((XML_TT_MASK & type) |
           ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
           XML_TT_NO_MORE); // set top bit for last byte
  val = val >>> XML_TT_VAL_BITS;

  // Rest of val goes into preceding bytes, 7 bits per byte, top bit
  // is "more" flag.
  var i = this.offset + numEncodingBytes - 2;
  while (0 != val && i >= this.offset) {
    this.ostream.array[i] = //(byte)
        (BYTE_MASK & (val & XML_REG_VAL_MASK)); // leave top bit unset
    val = val >>> XML_REG_VAL_BITS;
    --i;
  }

  if (val != 0)
    throw new Error("This should not happen: miscalculated encoding");

  this.offset+= numEncodingBytes;

  return numEncodingBytes;
};

/**
 * Encode ustring as utf8.
 */
BinaryXMLEncoder.prototype.encodeUString = function(
    //String
    ustring,
    //byte
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
    //Buffer
    blob,
    //int
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
    //long
    x)
{
  if (x <= ENCODING_LIMIT_1_BYTE) return (1);
  if (x <= ENCODING_LIMIT_2_BYTES) return (2);
  if (x <= ENCODING_LIMIT_3_BYTES) return (3);

  var numbytes = 1;

  // Last byte gives you XML_TT_VAL_BITS
  // Remainder each give you XML_REG_VAL_BITS
  x = x >>> XML_TT_VAL_BITS;
  while (x != 0) {
        numbytes++;
    x = x >>> XML_REG_VAL_BITS;
  }
  return (numbytes);
};

/**
 * Write an element start header using DTAG with the tag to the output buffer, then the dateTime
   * as a big endian BLOB converted to 4096 ticks per second, then an element close.
 * @param {number} tag The DTAG tag.
 * @param {NDNTime} dateTime
 */
BinaryXMLEncoder.prototype.writeDateTimeDTagElement = function(tag, dateTime)
{
  //parse to hex
  var binarydate =  Math.round((dateTime.msec/1000) * 4096).toString(16)  ;
  if (binarydate.length % 2 == 1)
    binarydate = '0' + binarydate;

  this.writeDTagElement(tag, DataUtils.toNumbers(binarydate));
};

/**
 * @deprecated Use writeDateTimeDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLEncoder.prototype.writeDateTime = function(
    //String
    tag,
    //NDNTime
    dateTime)
{
  //parse to hex
  var binarydate =  Math.round((dateTime.msec/1000) * 4096).toString(16)  ;
  if (binarydate.length % 2 == 1)
    binarydate = '0' + binarydate;

  this.writeElement(tag, DataUtils.toNumbers(binarydate));
};

// This does not update this.offset.
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
    //Buffer
    blob)
{
  if (LOG > 4) console.log('GOING TO WRITE A BLOB');

  this.ostream.copy(blob, this.offset);
};

BinaryXMLEncoder.prototype.getReducedOstream = function()
{
  return this.ostream.slice(0, this.offset);
};
/**
 * This class is used to decode ndnb binary elements (blob, type/value pairs).
 *
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var NDNProtocolDTags = require('../util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var NDNTime = require('../util/ndn-time.js').NDNTime;
var DataUtils = require('./data-utils.js').DataUtils;
var DecodingException = require('./decoding-exception.js').DecodingException;
var LOG = require('../log.js').Log.LOG;

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
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); // 0x80
var BYTE_MASK = 0xFF;
var LONG_BYTES = 8;
var LONG_BITS = 64;

var bits_11 = 0x0000007FF;
var bits_18 = 0x00003FFFF;
var bits_32 = 0x0FFFFFFFF;



//returns a string
tagToString = function(/*long*/ tagVal)
{
  if (tagVal >= 0 && tagVal < NDNProtocolDTagsStrings.length) {
    return NDNProtocolDTagsStrings[tagVal];
  }
  else if (tagVal == NDNProtocolDTags.NDNProtocolDataUnit) {
    return NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT;
  }

  return null;
};

//returns a Long
stringToTag =  function(/*String*/ tagName)
{
  // the slow way, but right now we don't care.... want a static lookup for the forward direction
  for (var i=0; i < NDNProtocolDTagsStrings.length; ++i) {
    if (null != NDNProtocolDTagsStrings[i] && NDNProtocolDTagsStrings[i] == tagName)
      return i;
  }
  if (NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT == tagName) {
    return NDNProtocolDTags.NDNProtocolDataUnit;
  }

  return null;
};

/**
 * @constructor
 */
var BinaryXMLDecoder = function BinaryXMLDecoder(input)
{
  var MARK_LEN=512;
  var DEBUG_MAX_LEN =  32768;

  this.input = input;
  this.offset = 0;
  // peekDTag sets and checks this, and readElementStartDTag uses it to avoid reading again.
  this.previouslyPeekedDTagStartOffset = -1;
};

exports.BinaryXMLDecoder = BinaryXMLDecoder;

/**
 * Decode the header from the input starting at its position, expecting the type to be DTAG and the value to be expectedTag.
   * Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 */
BinaryXMLDecoder.prototype.readElementStartDTag = function(expectedTag)
{
  if (this.offset == this.previouslyPeekedDTagStartOffset) {
    // peekDTag already decoded this DTag.
    if (this.previouslyPeekedDTag != expectedTag)
      throw new DecodingException(new Error("Did not get the expected DTAG " + expectedTag + ", got " + this.previouslyPeekedDTag));

    // Fast forward past the header.
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

/**
 * @deprecated Use readElementStartDTag. Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readStartElement = function(
    //String
    startTag,
    //TreeMap<String, String>
    attributes)
{
  //TypeAndVal
  var tv = this.decodeTypeAndVal();

  if (null == tv)
    throw new DecodingException(new Error("Expected start element: " + startTag + " got something not a tag."));

  //String
  var decodedTag = null;

  if (tv.type() == XML_TAG) {
    // Tag value represents length-1 as tags can never be empty.
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

  // DKS: does not read attributes out of stream if caller doesn't
  // ask for them. Should possibly peek and skip over them regardless.
  // TODO: fix this
  if (null != attributes)
    readAttributes(attributes);
};

/**
 * @deprecated Binary XML string tags and attributes are not used by any NDN encodings and support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readAttributes = function(
  // array of [attributeName, attributeValue]
  attributes)
{
  if (null == attributes)
    return;

  try {
    // Now need to get attributes.
    //TypeAndVal
    var nextTV = this.peekTypeAndVal();

    while (null != nextTV && (XML_ATTR == nextTV.type() || XML_DATTR == nextTV.type())) {
      // Decode this attribute. First, really read the type and value.
      //this.TypeAndVal
      var thisTV = this.decodeTypeAndVal();

      //String
      var attributeName = null;
      if (XML_ATTR == thisTV.type()) {
        // Tag value represents length-1 as attribute names cannot be empty.
        var valval ;
        if (typeof thisTV.val() == 'string')
          valval = (parseInt(thisTV.val())) + 1;
        else
          valval = (thisTV.val())+ 1;

        attributeName = this.decodeUString(valval);
      }
      else if (XML_DATTR == thisTV.type()) {
        // DKS TODO are attributes same or different dictionary?
        attributeName = tagToString(thisTV.val());
        if (null == attributeName)
          throw new DecodingException(new Error("Unknown DATTR value" + thisTV.val()));
      }

      // Attribute values are always UDATA
      //String
      var attributeValue = this.decodeUString();

      attributes.push([attributeName, attributeValue]);
      nextTV = this.peekTypeAndVal();
    }
  }
  catch (e) {
    throw new DecodingException(new Error("readStartElement", e));
  }
};

/**
 * @deprecated Use peekDTag.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.peekStartElementAsString = function()
{
  //String
  var decodedTag = null;
  var previousOffset = this.offset;
  try {
    // Have to distinguish genuine errors from wrong tags. Could either use
    // a special exception subtype, or redo the work here.
    //this.TypeAndVal
    var tv = this.decodeTypeAndVal();

    if (null != tv) {
      if (tv.type() == XML_TAG) {
        // Tag value represents length-1 as tags can never be empty.
        var valval ;
        if (typeof tv.val() == 'string')
          valval = (parseInt(tv.val())) + 1;
        else
          valval = (tv.val())+ 1;

        decodedTag = this.decodeUString(valval);
      }
      else if (tv.type() == XML_DTAG)
        decodedTag = tagToString(tv.val());
    } // else, not a type and val, probably an end element. rewind and return false.
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

/**
 * Decode the header from the input starting at its position, and if it is a DTAG where the value is the expectedTag,
 * then set return true.  Do not update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @returns {boolean} True if the tag is the expected tag, otherwise false.
 */
BinaryXMLDecoder.prototype.peekDTag = function(expectedTag)
{
  if (this.offset == this.previouslyPeekedDTagStartOffset)
    // We already decoded this DTag.
    return this.previouslyPeekedDTag == expectedTag;
  else {
    // First check if it is an element close (which cannot be the expected tag).
    if (this.input[this.offset] == XML_CLOSE)
      return false;

    var saveOffset = this.offset;
    var typeAndValue = this.decodeTypeAndVal();
    // readElementStartDTag will use this to fast forward.
    this.previouslyPeekedDTagEndOffset = this.offset;
    // Restore the position.
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

/**
 * @deprecated Use peekDTag.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.peekStartElement = function(
    //String
    startTag)
{
  //String
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

/**
 * @deprecated Use peekDTag.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.peekStartElementAsLong = function()
{
  //Long
  var decodedTag = null;
  var previousOffset = this.offset;

  try {
    // Have to distinguish genuine errors from wrong tags. Could either use
    // a special exception subtype, or redo the work here.
    //this.TypeAndVal
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

        // Tag value represents length-1 as tags can never be empty.
        //String
        var strTag = this.decodeUString(valval);

        decodedTag = stringToTag(strTag);
      }
      else if (tv.type() == XML_DTAG)
        decodedTag = tv.val();
    } // else, not a type and val, probably an end element. rewind and return false.

  }
  catch (e) {
  }
  finally {
    try {
      //this.input.reset();
      this.offset = previousOffset;
    } catch (e) {
      Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
      throw new Error("Cannot reset stream! " + e.getMessage(), e);
    }
  }

  return decodedTag;
};

/**
 * Decode the header from the input starting its offset, expecting the type to be DTAG and the value to be expectedTag.
 * Then read one item of any type (presumably BLOB, UDATA, TAG or ATTR) and return a
 * Buffer. However, if allowNull is true, then the item may be absent.
 * Finally, read the element close.  Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @param {boolean} allowNull True if the binary item may be missing.
 * @returns {Buffer} A Buffer which is a slice on the data inside the input buffer. However,
 * if allowNull is true and the binary data item is absent, then return null.
 */
BinaryXMLDecoder.prototype.readBinaryDTagElement = function(expectedTag, allowNull)
{
  this.readElementStartDTag(expectedTag);
  return this.readBlob(allowNull);
};

/**
 * @deprecated Use readBinaryDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readBinaryElement = function(
    //long
    startTag,
    //TreeMap<String, String>
    attributes,
    //boolean
    allowNull)
{
  this.readStartElement(startTag, attributes);
  return this.readBlob(allowNull);
};

/**
 * Read one byte from the input starting at its offset, expecting it to be the element close.
 * Update the input's offset.
 */
BinaryXMLDecoder.prototype.readElementClose = function()
{
  var next = this.input[this.offset++];
  if (next != XML_CLOSE)
    throw new DecodingException(new Error("Expected end element, got: " + next));
};

/**
 * @deprecated Use readElementClose.
 */
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

//String
BinaryXMLDecoder.prototype.readUString = function()
{
  //String
  var ustring = this.decodeUString();
  this.readElementClose();
  return ustring;
};

/**
 * Read a blob as well as the end element. Returns a Buffer (or null for missing blob).
 * If the blob is missing and allowNull is false (default), throw an exception.  Otherwise,
 *   just read the end element and return null.
 */
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

/**
 * Decode the header from the input starting at its offset, expecting the type to be
 * DTAG and the value to be expectedTag.  Then read one item, parse it as an unsigned
 * big endian integer in 4096 ticks per second, and convert it to and NDNTime object.
 * Finally, read the element close.  Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @returns {NDNTime} The dateTime value.
 */
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

/**
 * @deprecated Use readDateTimeDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readDateTime = function(
  //long
  startTag)
{
  var byteTimestamp = this.readBinaryElement(startTag);
  byteTimestamp = DataUtils.toHex(byteTimestamp);
  byteTimestamp = parseInt(byteTimestamp, 16);

  var lontimestamp = (byteTimestamp/ 4096) * 1000;

  if (LOG > 4) console.log('DECODED DATE WITH VALUE');
  if (LOG > 4) console.log(lontimestamp);

  //NDNTime
  var timestamp = new NDNTime(lontimestamp);
  if (null == timestamp)
    throw new DecodingException(new Error("Cannot parse timestamp: " + DataUtils.printHexBytes(byteTimestamp)));

  return timestamp;
};

BinaryXMLDecoder.prototype.decodeTypeAndVal = function()
{

  /*int*/ var type = -1;
  /*long*/ var val = 0;
  /*boolean*/ var more = true;

  do {
    var next = this.input[this.offset ];
    if (next == null)
      // Quit the loop.
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

//TypeAndVal
BinaryXMLDecoder.prototype.peekTypeAndVal = function()
{
  //TypeAndVal
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

//Buffer
BinaryXMLDecoder.prototype.decodeBlob = function(
    //int
    blobLength)
{
  if (null == blobLength) {
    //TypeAndVal
    var tv = this.decodeTypeAndVal();

    var valval ;
    if (typeof tv.val() == 'string')
      valval = (parseInt(tv.val()));
    else
      valval = (tv.val());

    return this.decodeBlob(valval);
  }

  //Buffer
  var bytes = new Buffer(this.input.slice(this.offset, this.offset+ blobLength));
  this.offset += blobLength;

  return bytes;
};

//String
BinaryXMLDecoder.prototype.decodeUString = function(
    //int
    byteLength)
{
  if (null == byteLength) {
    var tempStreamPosition = this.offset;

    //TypeAndVal
    var tv = this.decodeTypeAndVal();

    if (LOG > 4) console.log('TV is '+tv);
    if (LOG > 4) console.log(tv);

    if (LOG > 4) console.log('Type of TV is '+typeof tv);

    // if we just have closers left, will get back null
    if (null == tv || XML_UDATA != tv.type()) {
      this.offset = tempStreamPosition;
      return "";
    }

    return this.decodeUString(tv.val());
  }
  else {
    //Buffer
    var stringBytes = this.decodeBlob(byteLength);

    // TODO: Should this parse as UTF8?
    return DataUtils.toString(stringBytes);
  }
};

//OBject containg a pair of type and value
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

/**
 * Decode the header from the input starting its offset, expecting the type to be DTAG and the value to be expectedTag.
 * Then read one UDATA item, parse it as a decimal integer and return the integer. Finally, read the element close.  Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @returns {number} The parsed integer.
 */
BinaryXMLDecoder.prototype.readIntegerDTagElement = function(expectedTag)
{
  return parseInt(this.readUTF8DTagElement(expectedTag));
};

/**
 * @deprecated Use readIntegerDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readIntegerElement = function(
  //String
  startTag)
{
  //String
  if (LOG > 4) console.log('READING INTEGER '+ startTag);
  if (LOG > 4) console.log('TYPE OF '+ typeof startTag);

  var strVal = this.readUTF8Element(startTag);

  return parseInt(strVal);
};

/**
 * Decode the header from the input starting its offset, expecting the type to be DTAG and the value to be expectedTag.
 * Then read one UDATA item and return a string. Finally, read the element close.  Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @returns {string} The UDATA string.
 */
BinaryXMLDecoder.prototype.readUTF8DTagElement = function(expectedTag)
{
  this.readElementStartDTag(expectedTag);
  return this.readUString();;
};

/**
 * @deprecated Use readUTF8DTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readUTF8Element = function(
    //String
    startTag,
    //TreeMap<String, String>
    attributes)
{
  //throws Error where name == "DecodingException"

  // can't use getElementText, can't get attributes
  this.readStartElement(startTag, attributes);
  //String
  var strElementText = this.readUString();
  return strElementText;
};

/**
 * Set the offset into the input, used for the next read.
 * @param {number} offset The new offset.
 */
BinaryXMLDecoder.prototype.seek = function(offset)
{
  this.offset = offset;
};
/**
 * This class uses BinaryXMLDecoder to follow the structure of a ndnb binary element to
 * determine its end.
 *
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var BinaryXMLDecoder = require('./binary-xml-decoder.js').BinaryXMLDecoder;
var DynamicBuffer = require('../util/dynamic-buffer.js').DynamicBuffer;

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
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); // 0x80

/**
 * @constructor
 */
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

/**
 * Continue scanning input starting from this.offset.  If found the end of the element
 *   which started at offset 0 then return true, else false.
 * If this returns false, you should read more into input and call again.
 * You have to pass in input each time because the array could be reallocated.
 * This throws an exception for badly formed ndnb.
 */
BinaryXMLStructureDecoder.prototype.findElementEnd = function(
  // Buffer
  input)
{
  if (this.gotElementEnd)
    // Someone is calling when we already got the end.
    return true;

  var decoder = new BinaryXMLDecoder(input);

  while (true) {
    if (this.offset >= input.length)
      // All the cases assume we have some input.
      return false;

    switch (this.state) {
      case BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE:
        // First check for XML_CLOSE.
        if (this.headerLength == 0 && input[this.offset] == XML_CLOSE) {
          ++this.offset;
          // Close the level.
          --this.level;
          if (this.level == 0) {
            // Finished.
            this.gotElementEnd = true;
            return true;
          }
          if (this.level < 0)
            throw new Error("BinaryXMLStructureDecoder: Unexpected close tag at offset " + (this.offset - 1));

          // Get ready for the next header.
          this.startHeader();
          break;
        }

        var startingHeaderLength = this.headerLength;
        while (true) {
          if (this.offset >= input.length) {
            // We can't get all of the header bytes from this input. Save in headerBuffer.
            this.useHeaderBuffer = true;
            var nNewBytes = this.headerLength - startingHeaderLength;
            this.headerBuffer.copy(input.slice(this.offset - nNewBytes, nNewBytes), startingHeaderLength);

            return false;
          }
          var headerByte = input[this.offset++];
          ++this.headerLength;
          if (headerByte & XML_TT_NO_MORE)
            // Break and read the header.
            break;
        }

        var typeAndVal;
        if (this.useHeaderBuffer) {
          // Copy the remaining bytes into headerBuffer.
          nNewBytes = this.headerLength - startingHeaderLength;
          this.headerBuffer.copy(input.slice(this.offset - nNewBytes, nNewBytes), startingHeaderLength);

          typeAndVal = new BinaryXMLDecoder(this.headerBuffer.array).decodeTypeAndVal();
        }
        else {
          // We didn't have to use the headerBuffer.
          decoder.seek(this.offset - this.headerLength);
          typeAndVal = decoder.decodeTypeAndVal();
        }

        if (typeAndVal == null)
          throw new Error("BinaryXMLStructureDecoder: Can't read header starting at offset " +
                          (this.offset - this.headerLength));

        // Set the next state based on the type.
        var type = typeAndVal.t;
        if (type == XML_DATTR)
          // We already consumed the item. READ_HEADER_OR_CLOSE again.
          // ndnb has rules about what must follow an attribute, but we are just scanning.
          this.startHeader();
        else if (type == XML_DTAG || type == XML_EXT) {
          // Start a new level and READ_HEADER_OR_CLOSE again.
          ++this.level;
          this.startHeader();
        }
        else if (type == XML_TAG || type == XML_ATTR) {
          if (type == XML_TAG)
            // Start a new level and read the tag.
            ++this.level;
          // Minimum tag or attribute length is 1.
          this.nBytesToRead = typeAndVal.v + 1;
          this.state = BinaryXMLStructureDecoder.READ_BYTES;
          // ndnb has rules about what must follow an attribute, but we are just scanning.
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
          // Need more.
          this.offset += nRemainingBytes;
          this.nBytesToRead -= nRemainingBytes;
          return false;
        }
        // Got the bytes.  Read a new header or close.
        this.offset += this.nBytesToRead;
        this.startHeader();
        break;

      default:
        // We don't expect this to happen.
        throw new Error("BinaryXMLStructureDecoder: Unrecognized state " + this.state);
    }
  }
};

/**
 * Set the state to READ_HEADER_OR_CLOSE and set up to start reading the header
 */
BinaryXMLStructureDecoder.prototype.startHeader = function()
{
  this.headerLength = 0;
  this.useHeaderBuffer = false;
  this.state = BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE;
};

/**
 *  Set the offset into the input, used for the next read.
 */
BinaryXMLStructureDecoder.prototype.seek = function(offset)
{
  this.offset = offset;
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * The Tlv class has static type codes for the NDN-TLV wire format.
 * @constructor
 */
var Tlv = function Tlv()
{
};

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

Tlv.ContentType_Default = 0;
Tlv.ContentType_Link =    1;
Tlv.ContentType_Key =     2;

Tlv.NfdCommand_ControlResponse = 101;
Tlv.NfdCommand_StatusCode =      102;
Tlv.NfdCommand_StatusText =      103;

Tlv.ControlParameters_ControlParameters =   104;
Tlv.ControlParameters_FaceId =              105;
Tlv.ControlParameters_Uri =                 114;
Tlv.ControlParameters_LocalControlFeature = 110;
Tlv.ControlParameters_Origin =              111;
Tlv.ControlParameters_Cost =                106;
Tlv.ControlParameters_Flags =               108;
Tlv.ControlParameters_Strategy =            107;
Tlv.ControlParameters_ExpirationPeriod =    109;
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var DynamicBuffer = require('../../util/dynamic-buffer.js').DynamicBuffer;

/**
 * Create a new TlvEncoder with an initialCapacity for the encoding buffer.
 * @constructor
 * @param {number} initialCapacity (optional) The initial capacity of the
 * encoding buffer. If omitted, use a default value.
 */
var TlvEncoder = function TlvEncoder(initialCapacity)
{
  initialCapacity = initialCapacity || 16;
  this.output = new DynamicBuffer(initialCapacity);
  // length is the number of bytes that have been written to the back of
  //  this.output.array.
  this.length = 0;
};

exports.TlvEncoder = TlvEncoder;

/**
 * Get the number of bytes that have been written to the output.  You can
 * save this number, write sub TLVs, then subtract the new length from this
 * to get the total length of the sub TLVs.
 * @returns {number} The number of bytes that have been written to the output.
 */
TlvEncoder.prototype.getLength = function()
{
  return this.length;
};

/**
 * Encode varNumber as a VAR-NUMBER in NDN-TLV and write it to this.output just
 * before this.length from the back.  Advance this.length.
 * @param {number} varNumber The non-negative number to encode.
 */
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

/**
 * Encode the type and length as VAR-NUMBER and write to this.output just before
 * this.length from the back.  Advance this.length.
 * @param {number} type The type of the TLV.
 * @param {number} length The non-negative length of the TLV.
 */
TlvEncoder.prototype.writeTypeAndLength = function(type, length)
{
  // Write backwards.
  this.writeVarNumber(length);
  this.writeVarNumber(type);
};

/**
 * Write value as a non-negative integer and write it to this.output just before
 * this.length from the back. Advance this.length.
 * @param {number} value The non-negative integer to encode.
 */
TlvEncoder.prototype.writeNonNegativeInteger = function(value)
{
  if (value < 0)
    throw new Error("TLV integer value may not be negative");

  // JavaScript doesn't distinguish int from float, so round.
  value = Math.round(value);

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
};

/**
 * Write the type, then the length of the encoded value then encode value as a
 * non-negative integer and write it to this.output just before this.length from
 * the back. Advance this.length.
 * @param {number} type The type of the TLV.
 * @param {number} value The non-negative integer to encode.
 */
TlvEncoder.prototype.writeNonNegativeIntegerTlv = function(type, value)
{
  // Write backwards.
  var saveNBytes = this.length;
  this.writeNonNegativeInteger(value);
  this.writeTypeAndLength(type, this.length - saveNBytes);
};

/**
 * If value is negative or null then do nothing, otherwise call
 * writeNonNegativeIntegerTlv.
 * @param {number} type The type of the TLV.
 * @param {number} value If negative or None do nothing, otherwise the integer
 *   to encode.
 */
TlvEncoder.prototype.writeOptionalNonNegativeIntegerTlv = function(type, value)
{
  if (value != null && value >= 0)
    this.writeNonNegativeIntegerTlv(type, value);
};

/**
 * Write the type, then the length of the buffer then the buffer value to
 * this.output just before this.length from the back. Advance this.length.
 * @param {number} type The type of the TLV.
 * @param {Buffer} value The byte array with the bytes of the blob.  If value is
    null, then just write the type and length 0.
 */
TlvEncoder.prototype.writeBlobTlv = function(type, value)
{
  if (value == null) {
    this.writeTypeAndLength(type, 0);
    return;
  }

  // Write backwards, starting with the blob array.
  this.length += value.length;
  this.output.copyFromBack(value, this.length);

  this.writeTypeAndLength(type, value.length);
};

/**
 * If the byte array is null or zero length then do nothing, otherwise call
 * writeBlobTlv.
 * @param {number} type The type of the TLV.
 * @param {Buffer} value If null or zero length do nothing, otherwise the byte
 * array with the bytes of the blob.
 */
TlvEncoder.prototype.writeOptionalBlobTlv = function(type, value)
{
  if (value != null && value.length > 0)
    this.writeBlobTlv(type, value);
};

/**
 * Get a slice of the encoded bytes.
 * @returns {Buffer} A slice backed by the encoding Buffer.
 */
TlvEncoder.prototype.getOutput = function()
{
  return this.output.array.slice(this.output.array.length - this.length);
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var DecodingException = require('../decoding-exception.js').DecodingException;

/**
 * Create a new TlvDecoder for decoding the input in the NDN-TLV wire format.
 * @constructor
 * @param {Buffer} input The buffer with the bytes to decode.
 */
var TlvDecoder = function TlvDecoder(input)
{
  this.input = input;
  this.offset = 0;
};

exports.TlvDecoder = TlvDecoder;

/**
 * Decode VAR-NUMBER in NDN-TLV and return it. Update offset.
 * @returns {number} The decoded VAR-NUMBER.
 */
TlvDecoder.prototype.readVarNumber = function()
{
  // Assume array values are in the range 0 to 255.
  var firstOctet = this.input[this.offset];
  this.offset += 1;
  if (firstOctet < 253)
    return firstOctet;
  else
    return this.readExtendedVarNumber(firstOctet);
};

/**
 * A private function to do the work of readVarNumber, given the firstOctet
 * which is >= 253.
 * @param {number} firstOctet The first octet which is >= 253, used to decode
 * the remaining bytes.
 * @returns {number} The decoded VAR-NUMBER.
 */
TlvDecoder.prototype.readExtendedVarNumber = function(firstOctet)
{
  var result;
  // This is a private function so we know firstOctet >= 253.
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

/**
 * Decode the type and length from this's input starting at offset, expecting
 * the type to be expectedType and return the length. Update offset.  Also make
 * sure the decoded length does not exceed the number of bytes remaining in the
 * input.
 * @param {number} expectedType The expected type.
 * @returns {number} The length of the TLV.
 * @throws DecodingException if (did not get the expected TLV type or the TLV length
 * exceeds the buffer length.
 */
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

/**
 * Decode the type and length from the input starting at offset, expecting the
 * type to be expectedType.  Update offset.  Also make sure the decoded length
 * does not exceed the number of bytes remaining in the input. Return the offset
 * of the end of this parent TLV, which is used in decoding optional nested
 * TLVs. After reading all nested TLVs, call finishNestedTlvs.
 * @param {number} expectedType The expected type.
 * @returns {number} The offset of the end of the parent TLV.
 * @throws DecodingException if did not get the expected TLV type or the TLV
 * length exceeds the buffer length.
 */
TlvDecoder.prototype.readNestedTlvsStart = function(expectedType)
{
  return this.readTypeAndLength(expectedType) + this.offset;
};

/**
 * Call this after reading all nested TLVs to skip any remaining unrecognized
 * TLVs and to check if the offset after the final nested TLV matches the
 * endOffset returned by readNestedTlvsStart.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @throws DecodingException if the TLV length does not equal the total length
 * of the nested TLVs.
 */
TlvDecoder.prototype.finishNestedTlvs = function(endOffset)
{
  // We expect offset to be endOffset, so check this first.
  if (this.offset == endOffset)
    return;

  // Skip remaining TLVs.
  while (this.offset < endOffset) {
    // Skip the type VAR-NUMBER.
    this.readVarNumber();
    // Read the length and update offset.
    var length = this.readVarNumber();
    this.offset += length;

    if (this.offset > this.input.length)
      throw new DecodingException("TLV length exceeds the buffer length");
  }

  if (this.offset != endOffset)
    throw new DecodingException
      ("TLV length does not equal the total length of the nested TLVs");
};

/**
 * Decode the type from this's input starting at offset, and if it is the
 * expectedType, then return true, else false.  However, if this's offset is
 * greater than or equal to endOffset, then return false and don't try to read
 * the type. Do not update offset.
 * @param {number} expectedType The expected type.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @returns {boolean} true if the type of the next TLV is the expectedType,
 *  otherwise false.
 */
TlvDecoder.prototype.peekType = function(expectedType, endOffset)
{
  if (this.offset >= endOffset)
    // No more sub TLVs to look at.
    return false;
  else {
    var saveOffset = this.offset;
    var type = this.readVarNumber();
    // Restore offset.
    this.offset = saveOffset;

    return type == expectedType;
  }
};

/**
 * Decode a non-negative integer in NDN-TLV and return it. Update offset by
 * length.
 * @param {number} length The number of bytes in the encoded integer.
 * @returns {number} The integer.
 * @throws DecodingException if length is an invalid length for a TLV
 * non-negative integer.
 */
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

/**
 * Decode the type and length from this's input starting at offset, expecting
 * the type to be expectedType. Then decode a non-negative integer in NDN-TLV
 * and return it.  Update offset.
 * @param {number} expectedType The expected type.
 * @returns {number} The integer.
 * @throws DecodingException if did not get the expected TLV type or can't
 * decode the value.
 */
TlvDecoder.prototype.readNonNegativeIntegerTlv = function(expectedType)
{
  var length = this.readTypeAndLength(expectedType);
  return this.readNonNegativeInteger(length);
};

/**
 * Peek at the next TLV, and if it has the expectedType then call
 * readNonNegativeIntegerTlv and return the integer.  Otherwise, return null.
 * However, if this's offset is greater than or equal to endOffset, then return
 * null and don't try to read the type.
 * @param {number} expectedType The expected type.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @returns {number} The integer or null if the next TLV doesn't have the
 * expected type.
 */
TlvDecoder.prototype.readOptionalNonNegativeIntegerTlv = function
  (expectedType, endOffset)
{
  if (this.peekType(expectedType, endOffset))
    return this.readNonNegativeIntegerTlv(expectedType);
  else
    return null;
};

/**
 * Decode the type and length from this's input starting at offset, expecting
 * the type to be expectedType. Then return an array of the bytes in the value.
 * Update offset.
 * @param {number} expectedType The expected type.
 * @returns {Buffer} The bytes in the value as a slice on the buffer.  This is
 * not a copy of the bytes in the input buffer.  If you need a copy, then you
 * must make a copy of the return value.
 * @throws DecodingException if did not get the expected TLV type.
 */
TlvDecoder.prototype.readBlobTlv = function(expectedType)
{
  var length = this.readTypeAndLength(expectedType);
  var result = this.input.slice(this.offset, this.offset + length);

  // readTypeAndLength already checked if length exceeds the input buffer.
  this.offset += length;
  return result;
};

/**
 * Peek at the next TLV, and if it has the expectedType then call readBlobTlv
 * and return the value.  Otherwise, return null. However, if this's offset is
 * greater than or equal to endOffset, then return null and don't try to read
 * the type.
 * @param {number} expectedType The expected type.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @returns {Buffer} The bytes in the value as a slice on the buffer or null if
 * the next TLV doesn't have the expected type.  This is not a copy of the bytes
 * in the input buffer.  If you need a copy, then you must make a copy of the
 * return value.
 */
TlvDecoder.prototype.readOptionalBlobTlv = function(expectedType, endOffset)
{
  if (this.peekType(expectedType, endOffset))
    return this.readBlobTlv(expectedType);
  else
    return null;
};

/**
 * Peek at the next TLV, and if it has the expectedType then read a type and
 * value, ignoring the value, and return true. Otherwise, return false.
 * However, if this's offset is greater than or equal to endOffset, then return
 * false and don't try to read the type.
 * @param {number} expectedType The expected type.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @returns {boolean} true, or else false if the next TLV doesn't have the
 * expected type.
 */
TlvDecoder.prototype.readBooleanTlv = function(expectedType, endOffset)
{
  if (this.peekType(expectedType, endOffset)) {
    var length = this.readTypeAndLength(expectedType);
    // We expect the length to be 0, but update offset anyway.
    this.offset += length;
    return true;
  }
  else
    return false;
};

/**
 * Get the offset into the input, used for the next read.
 * @returns {number} The offset.
 */
TlvDecoder.prototype.getOffset = function()
{
  return this.offset;
};

/**
 * Set the offset into the input, used for the next read.
 * @param {number} offset The new offset.
 */
TlvDecoder.prototype.seek = function(offset)
{
  this.offset = offset;
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var TlvDecoder = require('./tlv-decoder.js').TlvDecoder;

/**
 * Create and initialize a TlvStructureDecoder.
 */
var TlvStructureDecoder = function TlvStructureDecoder()
{
  this.gotElementEnd = false;
  this.offset = 0;
  this.state = TlvStructureDecoder.READ_TYPE;
  this.headerLength = 0;
  this.useHeaderBuffer = false;
  // 8 bytes is enough to hold the extended bytes in the length encoding
  // where it is an 8-byte number.
  this.headerBuffer = new Buffer(8);
  this.nBytesToRead = 0;
};

exports.TlvStructureDecoder = TlvStructureDecoder;

TlvStructureDecoder.READ_TYPE =         0;
TlvStructureDecoder.READ_TYPE_BYTES =   1;
TlvStructureDecoder.READ_LENGTH =       2;
TlvStructureDecoder.READ_LENGTH_BYTES = 3;
TlvStructureDecoder.READ_VALUE_BYTES =  4;

/**
 * Continue scanning input starting from this.offset to find the element end.
 * If the end of the element which started at offset 0 is found, this returns
 * true and getOffset() is the length of the element.  Otherwise, this returns
 * false which means you should read more into input and call again.
 * @param {Buffer} input The input buffer. You have to pass in input each time
 * because the buffer could be reallocated.
 * @returns {boolean} true if found the element end, false if not.
 */
TlvStructureDecoder.prototype.findElementEnd = function(input)
{
  if (this.gotElementEnd)
    // Someone is calling when we already got the end.
    return true;

  var decoder = new TlvDecoder(input);

  while (true) {
    if (this.offset >= input.length)
      // All the cases assume we have some input. Return and wait for more.
      return false;

    if (this.state == TlvStructureDecoder.READ_TYPE) {
      var firstOctet = input[this.offset];
      this.offset += 1;
      if (firstOctet < 253)
        // The value is simple, so we can skip straight to reading the length.
        this.state = TlvStructureDecoder.READ_LENGTH;
      else {
        // Set up to skip the type bytes.
        if (firstOctet == 253)
          this.nBytesToRead = 2;
        else if (firstOctet == 254)
          this.nBytesToRead = 4;
        else
          // value == 255.
          this.nBytesToRead = 8;

        this.state = TlvStructureDecoder.READ_TYPE_BYTES;
      }
    }
    else if (this.state == TlvStructureDecoder.READ_TYPE_BYTES) {
      var nRemainingBytes = input.length - this.offset;
      if (nRemainingBytes < this.nBytesToRead) {
        // Need more.
        this.offset += nRemainingBytes;
        this.nBytesToRead -= nRemainingBytes;
        return false;
      }

      // Got the type bytes. Move on to read the length.
      this.offset += this.nBytesToRead;
      this.state = TlvStructureDecoder.READ_LENGTH;
    }
    else if (this.state == TlvStructureDecoder.READ_LENGTH) {
      var firstOctet = input[this.offset];
      this.offset += 1;
      if (firstOctet < 253) {
        // The value is simple, so we can skip straight to reading
        //  the value bytes.
        this.nBytesToRead = firstOctet;
        if (this.nBytesToRead == 0) {
          // No value bytes to read. We're finished.
          this.gotElementEnd = true;
          return true;
        }

        this.state = TlvStructureDecoder.READ_VALUE_BYTES;
      }
      else {
        // We need to read the bytes in the extended encoding of
        //  the length.
        if (firstOctet == 253)
          this.nBytesToRead = 2;
        else if (firstOctet == 254)
          this.nBytesToRead = 4;
        else
          // value == 255.
          this.nBytesToRead = 8;

        // We need to use firstOctet in the next state.
        this.firstOctet = firstOctet;
        this.state = TlvStructureDecoder.READ_LENGTH_BYTES;
      }
    }
    else if (this.state == TlvStructureDecoder.READ_LENGTH_BYTES) {
      var nRemainingBytes = input.length - this.offset;
      if (!this.useHeaderBuffer && nRemainingBytes >= this.nBytesToRead) {
        // We don't have to use the headerBuffer. Set nBytesToRead.
        decoder.seek(this.offset);

        this.nBytesToRead = decoder.readExtendedVarNumber(this.firstOctet);
        // Update this.offset to the decoder's offset after reading.
        this.offset = decoder.getOffset();
      }
      else {
        this.useHeaderBuffer = true;

        var nNeededBytes = this.nBytesToRead - this.headerLength;
        if (nNeededBytes > nRemainingBytes) {
          // We can't get all of the header bytes from this input.
          // Save in headerBuffer.
          if (this.headerLength + nRemainingBytes > this.headerBuffer.length)
            // We don't expect this to happen.
            throw new Error
              ("Cannot store more header bytes than the size of headerBuffer");
          input.slice(this.offset, this.offset + nRemainingBytes).copy
            (this.headerBuffer, this.headerLength);
          this.offset += nRemainingBytes;
          this.headerLength += nRemainingBytes;

          return false;
        }

        // Copy the remaining bytes into headerBuffer, read the
        //   length and set nBytesToRead.
        if (this.headerLength + nNeededBytes > this.headerBuffer.length)
          // We don't expect this to happen.
          throw new Error
            ("Cannot store more header bytes than the size of headerBuffer");
        input.slice(this.offset, this.offset + nNeededBytes).copy
          (this.headerBuffer, this.headerLength);
        this.offset += nNeededBytes;

        // Use a local decoder just for the headerBuffer.
        var bufferDecoder = new TlvDecoder(this.headerBuffer);
        // Replace nBytesToRead with the length of the value.
        this.nBytesToRead = bufferDecoder.readExtendedVarNumber(this.firstOctet);
      }

      if (this.nBytesToRead == 0) {
        // No value bytes to read. We're finished.
        this.gotElementEnd = true;
        return true;
      }

      // Get ready to read the value bytes.
      this.state = TlvStructureDecoder.READ_VALUE_BYTES;
    }
    else if (this.state == TlvStructureDecoder.READ_VALUE_BYTES) {
      nRemainingBytes = input.length - this.offset;
      if (nRemainingBytes < this.nBytesToRead) {
        // Need more.
        this.offset += nRemainingBytes;
        this.nBytesToRead -= nRemainingBytes;
        return false;
      }

      // Got the bytes. We're finished.
      this.offset += this.nBytesToRead;
      this.gotElementEnd = true;
      return true;
    }
    else
      // We don't expect this to happen.
      throw new Error("findElementEnd: unrecognized state");
  }
};

/**
 * Get the current offset into the input buffer.
 * @returns {number} The offset.
 */
TlvStructureDecoder.prototype.getOffset = function()
{
  return this.offset;
};

/**
 * Set the offset into the input, used for the next read.
 * @param {number} offset The new offset.
 */
TlvStructureDecoder.prototype.seek = function(offset)
{
  this.offset = offset;
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var TlvEncoder = require('./tlv/tlv-encoder.js').TlvEncoder;
var TlvDecoder = require('./tlv/tlv-decoder.js').TlvDecoder;
var Blob = require('../util/blob.js').Blob;

/**
 * ProtobufTlv has static methods to encode and decode an Protobuf Message o
 * bject as NDN-TLV. The Protobuf tag value is used as the TLV type code. A
 * Protobuf message is encoded/decoded as a nested TLV encoding. Protobuf types
 * uint32, uint64 and enum are encoded/decoded as TLV nonNegativeInteger. (It is
 * an error if an enum value is negative.) Protobuf types bytes and string are
 * encoded/decoded as TLV bytes. The Protobuf type bool is encoded/decoded as a
 * TLV boolean (a zero length value for True, omitted for False). Other Protobuf
 * types are an error.
 *
 * Protobuf has no "outer" message type, so you need to put your TLV message
 * inside an outer "typeless" message.
 */
var ProtobufTlv = function ProtobufTlv()
{
};

exports.ProtobufTlv = ProtobufTlv;

// Load ProtoBuf.Reflect.Message.Field dynamically so that protobufjs is optional.
ProtobufTlv._Field = null;
ProtobufTlv.establishField = function()
{
  if (ProtobufTlv._Field === null) {
    try {
      // Using protobuf.min.js in the browser.
      ProtobufTlv._Field = dcodeIO.ProtoBuf.Reflect.Message.Field;
    }
    catch (ex) {
      // Using protobufjs in node.
      ProtobufTlv._Field = require("protobufjs").Reflect.Message.Field;
    }
  }
}

/**
 * Encode the Protobuf message object as NDN-TLV. This calls
 * message.encodeAB() to ensure that all required fields are present and
 * raises an exception if not. (This does not use the result of toArrayBuffer().)
 * @param {ProtoBuf.Builder.Message} message The Protobuf message object.
 * @param {ProtoBuf.Reflect.T} descriptor The reflection descriptor for the
 * message. For example, if the message is of type "MyNamespace.MyMessage" then
 * the descriptor is builder.lookup("MyNamespace.MyMessage").
 * @returns {Blob} The encoded buffer in a Blob object.
 */
ProtobufTlv.encode = function(message, descriptor)
{
  ProtobufTlv.establishField();

  message.encodeAB();
  var encoder = new TlvEncoder();
  ProtobufTlv._encodeMessageValue(message, descriptor, encoder);
  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode the input as NDN-TLV and update the fields of the Protobuf message
 * object.
 * @param {ProtoBuf.Builder.Message} message The Protobuf message object. This
 * does not first clear the object.
 * @param {ProtoBuf.Reflect.T} descriptor The reflection descriptor for the
 * message. For example, if the message is of type "MyNamespace.MyMessage" then
 * the descriptor is builder.lookup("MyNamespace.MyMessage").
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 */
ProtobufTlv.decode = function(message, descriptor, input)
{
  ProtobufTlv.establishField();

  if (ProtobufTlv._Field === null) {
    if (dcodeIO)
      ProtobufTlv._Field = dcodeIO.ProtoBuf.Reflect.Message.Field;
    else
      ProtobufTlv._Field = require("protobufjs").Reflect.Message.Field;
  }

  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ?
                     input.buf() : input;

  var decoder = new TlvDecoder(decodeBuffer);
  ProtobufTlv._decodeMessageValue
    (message, descriptor, decoder, decodeBuffer.length);
};

ProtobufTlv._encodeMessageValue = function(message, descriptor, encoder)
{
  var fields = descriptor.getChildren(ProtobufTlv._Field);
  // Encode the fields backwards.
  for (var iField = fields.length - 1; iField >= 0; --iField) {
    var field = fields[iField];
    var tlvType = field.id;

    var values;
    if (field.repeated)
      values = message[field.name];
    else {
      if (message[field.name] != null)
        // Make a singleton list.
        values = [message[field.name]];
      else
        continue;
    }

    // Encode the values backwards.
    for (var iValue = values.length - 1; iValue >= 0; --iValue) {
      var value = values[iValue];

      if (field.type.name == "message") {
        var saveLength =  encoder.getLength();

        // Encode backwards.
        ProtobufTlv._encodeMessageValue(value, field.resolvedType, encoder);
        encoder.writeTypeAndLength(tlvType, encoder.getLength() - saveLength);
      }
      else if (field.type.name == "uint32" ||
               field.type.name == "uint64")
        encoder.writeNonNegativeIntegerTlv(tlvType, value);
      else if (field.type.name == "enum") {
        if (value < 0)
          throw new Error("ProtobufTlv::encode: ENUM value may not be negative");
        encoder.writeNonNegativeIntegerTlv(tlvType, value);
      }
      else if (field.type.name == "bytes")
        encoder.writeBlobTlv(tlvType, value.toBinary());
      else if (field.type.name == "string")
        // Use Blob to convert.
        encoder.writeBlobTlv(tlvType, new Blob(value, false).buf());
      else if (field.type.name == "bool") {
        if (value)
          encoder.writeTypeAndLength(tlvType, 0);
      }
      else
        throw new Error("ProtobufTlv::encode: Unknown field type");
    }
  }
};

ProtobufTlv._decodeMessageValue = function(message, descriptor, decoder, endOffset)
{
  var fields = descriptor.getChildren(ProtobufTlv._Field);
  for (var iField = 0; iField < fields.length; ++iField) {
    var field = fields[iField];
    var tlvType = field.id;

    if (!field.required && !decoder.peekType(tlvType, endOffset))
      continue;

    if (field.repeated) {
      while (decoder.peekType(tlvType, endOffset)) {
        if (field.type.name == "message") {
          var innerEndOffset = decoder.readNestedTlvsStart(tlvType);
          var value = new (field.resolvedType.build())();
          message.add(field.name, value);
          ProtobufTlv._decodeMessageValue
            (value, field.resolvedType, decoder, innerEndOffset);
          decoder.finishNestedTlvs(innerEndOffset);
        }
        else
          message.add
            (field.name,
             ProtobufTlv._decodeFieldValue(field, tlvType, decoder, endOffset));
      }
    }
    else {
      if (field.type.name == "message") {
        var innerEndOffset = decoder.readNestedTlvsStart(tlvType);
        var value = new (field.resolvedType.build())();
        message.set(field.name, value);
        ProtobufTlv._decodeMessageValue
          (value, field.resolvedType, decoder, innerEndOffset);
        decoder.finishNestedTlvs(innerEndOffset);
      }
      else
        message.set
          (field.name,
           ProtobufTlv._decodeFieldValue(field, tlvType, decoder, endOffset));
    }
  }
};

/**
 * This is a helper for _decodeMessageValue. Decode a single field and return
 * the value. Assume the field.type.name is not "message".
 */
ProtobufTlv._decodeFieldValue = function(field, tlvType, decoder, endOffset)
{
  if (field.type.name == "uint32" ||
      field.type.name == "uint64" ||
      field.type.name == "enum")
    return decoder.readNonNegativeIntegerTlv(tlvType);
  else if (field.type.name == "bytes")
    return decoder.readBlobTlv(tlvType);
  else if (field.type.name == "string")
    return decoder.readBlobTlv(tlvType).toString();
  else if (field.type.name == "bool")
    return decoder.readBooleanTlv(tlvType, endOffset);
  else
    throw new Error("ProtobufTlv.decode: Unknown field type");
};
/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * Create a WireFormat base class where the encode and decode methods throw an error. You should use a derived class like TlvWireFormat.
 * @constructor
 */
var WireFormat = function WireFormat() {
};

exports.WireFormat = WireFormat;

/**
 * Encode interest and return the encoding.  Your derived class should override.
 * @param {Interest} interest The Interest to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the signed
 * portion. The signed portion starts from the first name component and ends
 * just before the final name component (which is assumed to be a signature for
 * a signed interest).
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeInterest = function(interest)
{
  throw new Error("encodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode input as an interest and set the fields of the interest object.
 * Your derived class should override.
 * @param {Interest} interest The Interest object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeInterest = function(interest, input)
{
  throw new Error("decodeInterest is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode data and return the encoding and signed offsets. Your derived class
 * should override.
 * @param {Data} data The Data object to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the
 * signed portion.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeData = function(data)
{
  throw new Error("encodeData is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode input as a data packet, set the fields in the data object, and return
 * the signed offsets.  Your derived class should override.
 * @param {Data} data The Data object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeData = function(data, input)
{
  throw new Error("decodeData is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode controlParameters and return the encoding.  Your derived class should
 * override.
 * @param {ControlParameters} controlParameters The ControlParameters object to
 * encode.
 * @returns {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeControlParameters = function(controlParameters)
{
  throw new Error("encodeControlParameters is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode input as a controlParameters and set the fields of the
 * controlParameters object. Your derived class should override.
 * @param {ControlParameters} controlParameters The ControlParameters object
 * whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeControlParameters = function(controlParameters, input)
{
  throw new Error("decodeControlParameters is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode signature as a SignatureInfo and return the encoding. Your derived
 * class should override.
 * @param {Signature} signature An object of a subclass of Signature to encode.
 * @returns {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeSignatureInfo = function(signature)
{
  throw new Error("encodeSignatureInfo is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Decode signatureInfo as a signature info and signatureValue as the related
 * SignatureValue, and return a new object which is a subclass of Signature.
 * Your derived class should override.
 * @param {Buffer} signatureInfo The buffer with the signature info bytes to
 * decode.
 * @param {Buffer} signatureValue The buffer with the signature value to decode.
 * @returns {Signature} A new object which is a subclass of Signature.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.decodeSignatureInfoAndValue = function
  (signatureInfo, signatureValue)
{
  throw new Error("decodeSignatureInfoAndValue is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Encode the signatureValue in the Signature object as a SignatureValue (the
 * signature bits) and return the encoding. Your derived class should override.
 * @param {Signature} signature An object of a subclass of Signature with the
 * signature value to encode.
 * @returns {Blob} A Blob containing the encoding.
 * @throws Error This always throws an "unimplemented" error. The derived class should override.
 */
WireFormat.prototype.encodeSignatureValue = function(signature)
{
  throw new Error("encodeSignatureValue is unimplemented in the base WireFormat class.  You should use a derived class.");
};

/**
 * Set the static default WireFormat used by default encoding and decoding
 * methods.
 * @param wireFormat {WireFormat} An object of a subclass of WireFormat.
 */
WireFormat.setDefaultWireFormat = function(wireFormat)
{
  WireFormat.defaultWireFormat = wireFormat;
};

/**
 * Return the default WireFormat used by default encoding and decoding methods
 * which was set with setDefaultWireFormat.
 * @returns {WireFormat} An object of a subclass of WireFormat.
 */
WireFormat.getDefaultWireFormat = function()
{
  return WireFormat.defaultWireFormat;
};

// Invoke TlvWireFormat to set the default format.
// Since tlv-wire-format.js includes this file, put this at the bottom
// to avoid problems with cycles of require.
var TlvWireFormat = require('./tlv-wire-format.js').TlvWireFormat;
/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var DataUtils = require('./data-utils.js').DataUtils;
var BinaryXMLStructureDecoder = require('./binary-xml-structure-decoder.js').BinaryXMLStructureDecoder;
var Tlv = require('./tlv/tlv.js').Tlv;
var TlvStructureDecoder = require('./tlv/tlv-structure-decoder.js').TlvStructureDecoder;
var LOG = require('../log.js').Log.LOG;

/**
 * A ElementReader lets you call onReceivedData multiple times which uses a
 * BinaryXMLStructureDecoder or TlvStructureDecoder to detect the end of a
 * binary XML or TLV element and calls elementListener.onReceivedElement(element)
 * with the element.  This handles the case where a single call to
 * onReceivedData may contain multiple elements.
 * @constructor
 * @param {{onReceivedElement:function}} elementListener
 */
var ElementReader = function ElementReader(elementListener)
{
  this.elementListener = elementListener;
  this.dataParts = [];
  this.binaryXmlStructureDecoder = new BinaryXMLStructureDecoder();
  this.tlvStructureDecoder = new TlvStructureDecoder();
  this.useTlv = null;
};

exports.ElementReader = ElementReader;

ElementReader.prototype.onReceivedData = function(/* Buffer */ data)
{
  // Process multiple objects in the data.
  while (true) {
    if (this.dataParts.length == 0) {
      // This is the beginning of an element.  Check whether it is binaryXML or TLV.
      if (data.length <= 0)
        // Wait for more data.
        return;

      // The type codes for TLV Interest and Data packets are chosen to not
      //   conflict with the first byte of a binary XML packet, so we can
      //   just look at the first byte.
      if (data[0] == Tlv.Interest || data[0] == Tlv.Data || data[0] == 0x80)
        this.useTlv = true;
      else
        // Binary XML.
        this.useTlv = false;
    }

    var gotElementEnd;
    var offset;
    if (this.useTlv) {
      // Scan the input to check if a whole TLV object has been read.
      this.tlvStructureDecoder.seek(0);
      gotElementEnd = this.tlvStructureDecoder.findElementEnd(data);
      offset = this.tlvStructureDecoder.getOffset();
    }
    else {
      // Scan the input to check if a whole Binary XML object has been read.
      this.binaryXmlStructureDecoder.seek(0);
      gotElementEnd = this.binaryXmlStructureDecoder.findElementEnd(data);
      offset = this.binaryXmlStructureDecoder.offset;
    }

    if (gotElementEnd) {
      // Got the remainder of an object.  Report to the caller.
      this.dataParts.push(data.slice(0, offset));
      var element = DataUtils.concatArrays(this.dataParts);
      this.dataParts = [];
      try {
        this.elementListener.onReceivedElement(element);
      } catch (ex) {
          console.log("ElementReader: ignoring exception from onReceivedElement: " + ex);
      }

      // Need to read a new object.
      data = data.slice(offset, data.length);
      this.binaryXmlStructureDecoder = new BinaryXMLStructureDecoder();
      this.tlvStructureDecoder = new TlvStructureDecoder();
      if (data.length == 0)
        // No more data in the packet.
        return;

      // else loop back to decode.
    }
    else {
      // Save for a later call to concatArrays so that we only copy data once.
      this.dataParts.push(data);
      if (LOG > 3) console.log('Incomplete packet received. Length ' + data.length + '. Wait for more input.');
        return;
    }
  }
};
/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var DataUtils = require('../encoding/data-utils.js').DataUtils;
var BinaryXMLDecoder = require('../encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./ndn-protoco-id-tags.js').NDNProtocolDTags;
var Name = require('../name.js').Name;

/**
 * Create a context for getting the response from the name enumeration command, as neede by getComponents.
 * (To do name enumeration, call the static method NameEnumeration.getComponents.)
 * @param {Face} face The Face object for using expressInterest.
 * @param {function} onComponents The onComponents callback given to getComponents.
 */
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

/**
 * Use the name enumeration protocol to get the child components of the name prefix.
 * @param {Face} face The Face object for using expressInterest.
 * @param {Name} name The name prefix for finding the child components.
 * @param {function} onComponents On getting the response, this calls onComponents(components) where
 * components is an array of Buffer name components.  If there is no response, this calls onComponents(null).
 */
NameEnumeration.getComponents = function(face, prefix, onComponents)
{
  var command = new Name(prefix);
  // Add %C1.E.be
  command.add([0xc1, 0x2e, 0x45, 0x2e, 0x62, 0x65])

  var enumeration = new NameEnumeration(face, onComponents);
  face.expressInterest(command, enumeration.onData, enumeration.onTimeout);
};

/**
 * Parse the response from the name enumeration command and call this.onComponents.
 * @param {Data} data
 */
NameEnumeration.prototype.processData = function(data)
{
  try {
    if (!NameEnumeration.endsWithSegmentNumber(data.getName()))
      // We don't expect a name without a segment number.  Treat it as a bad packet.
      this.onComponents(null);
    else {
      var segmentNumber = data.getName().get(-1).toSegment();

      // Each time we get a segment, we put it in contentParts, so its length follows the segment numbers.
      var expectedSegmentNumber = this.contentParts.length;
      if (segmentNumber != expectedSegmentNumber)
        // Try again to get the expected segment.  This also includes the case where the first segment is not segment 0.
        this.face.expressInterest
          (data.getName().getPrefix(-1).addSegment(expectedSegmentNumber), this.onData, this.onTimeout);
      else {
        // Save the content and check if we are finished.
        this.contentParts.push(data.getContent().buf());

        if (data.getMetaInfo() != null && data.getMetaInfo().getFinalBlockID().getValue().size() > 0) {
          var finalSegmentNumber = data.getMetaInfo().getFinalBlockID().toSegment();
          if (segmentNumber == finalSegmentNumber) {
            // We are finished.  Parse and return the result.
            this.onComponents(NameEnumeration.parseComponents(Buffer.concat(this.contentParts)));
            return;
          }
        }

        // Fetch the next segment.
        this.face.expressInterest
          (data.getName().getPrefix(-1).addSegment(expectedSegmentNumber + 1), this.onData, this.onTimeout);
      }
    }
  } catch (ex) {
    console.log("NameEnumeration: ignoring exception: " + ex);
  }
};

/**
 * Just call onComponents(null).
 */
NameEnumeration.prototype.processTimeout = function()
{
  try {
    this.onComponents(null);
  } catch (ex) {
    console.log("NameEnumeration: ignoring exception: " + ex);
  }
};

/**
 * Parse the content as a name enumeration response and return an array of components.  This makes a copy of the component.
 * @param {Buffer} content The content to parse.
 * @returns {Array<Buffer>} The array of components.
 */
NameEnumeration.parseComponents = function(content)
{
  var components = [];
  var decoder = new BinaryXMLDecoder(content);

  decoder.readElementStartDTag(NDNProtocolDTags.Collection);

  while (decoder.peekDTag(NDNProtocolDTags.Link)) {
    decoder.readElementStartDTag(NDNProtocolDTags.Link);
    decoder.readElementStartDTag(NDNProtocolDTags.Name);

    components.push(new Buffer(decoder.readBinaryDTagElement(NDNProtocolDTags.Component)));

    decoder.readElementClose();
    decoder.readElementClose();
  }

  decoder.readElementClose();
  return components;
};

/**
 * Check if the last component in the name is a segment number.
 * TODO: Move to Name class.
 * @param {Name} name
 * @returns {Boolean} True if the name ends with a segment number, otherwise false.
 */
NameEnumeration.endsWithSegmentNumber = function(name) {
  return name.size() >= 1 &&
         name.get(-1).getValue().size() >= 1 &&
         name.get(-1).getValue().buf()[0] == 0;
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Name = require('../name.js').Name;

/**
 * A MemoryContentCache holds a set of Data packets and answers an Interest to
 * return the correct Data packet. The cache is periodically cleaned up to
 * remove each stale Data packet based on its FreshnessPeriod (if it has one).
 * @note This class is an experimental feature.  See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/memory-content-cache.html .
 *
 * Create a new MemoryContentCache to use the given Face.
 *
 * @param {Face} face The Face to use to call registerPrefix and which will call
 * the OnInterest callback.
 * @param {number} cleanupIntervalMilliseconds (optional) The interval
 * in milliseconds between each check to clean up stale content in the cache. If
 * omitted, use a default of 1000 milliseconds. If this is a large number, then
 * effectively the stale content will not be removed from the cache.
 */
var MemoryContentCache = function MemoryContentCache
  (face, cleanupIntervalMilliseconds)
{
  cleanupIntervalMilliseconds = (cleanupIntervalMilliseconds || 1000.0);

  this.face = face;
  this.cleanupIntervalMilliseconds = cleanupIntervalMilliseconds;
  this.nextCleanupTime = new Date().getTime() + cleanupIntervalMilliseconds;

  this.onDataNotFoundForPrefix = {}; /**< The map key is the prefix.toUri().
 *                                        The value is an OnInterest function. */
  this.noStaleTimeCache = []; /**< elements are MemoryContentCache.Content */
  this.staleTimeCache = [];   /**< elements are MemoryContentCache.StaleTimeContent */
  //StaleTimeContent::Compare contentCompare_;
  this.emptyComponent = new Name.Component();
};

exports.MemoryContentCache = MemoryContentCache;

/**
 * Call registerPrefix on the Face given to the constructor so that this
 * MemoryContentCache will answer interests whose name has the prefix.
 * @param {Name} prefix The Name for the prefix to register. This copies the Name.
 * @param {function} onRegisterFailed If this fails to register the prefix for
 * any reason, this calls onRegisterFailed(prefix) where prefix is the prefix
 * given to registerPrefix.
 * @param {function} onDataNotFound (optional) If a data packet is not found in
 * the cache, this calls onInterest(prefix, interest, transport) to forward the
 * interest. If omitted, this does not use it.
 * @param {ForwardingFlags} flags (optional) See Face.registerPrefix.
 * @param {WireFormat} wireFormat (optional) See Face.registerPrefix.
 */
MemoryContentCache.prototype.registerPrefix = function
  (prefix, onRegisterFailed, onDataNotFound, flags, wireFormat)
{
  if (onDataNotFound)
    this.onDataNotFoundForPrefix[prefix.toUri()] = onDataNotFound;
  var thisMemoryContentCache = this;
  this.face.registerPrefix
    (prefix,
     function(prefix, interest, transport)
       { thisMemoryContentCache.onInterest(prefix, interest, transport); },
     onRegisterFailed, flags, wireFormat);
};

/**
 * Add the Data packet to the cache so that it is available to use to answer
 * interests. If data.getFreshnessPeriod() is not null, set the staleness
 * time to now plus data.getFreshnessPeriod(), which is checked during cleanup
 * to remove stale content. This also checks if cleanupIntervalMilliseconds
 * milliseconds have passed and removes stale content from the cache.
 * @param {Data} data The Data packet object to put in the cache. This copies
 * the fields from the object.
 */
MemoryContentCache.prototype.add = function(data)
{
  this.doCleanup();

  if (data.getMetaInfo().getFreshnessPeriod() != null &&
      data.getMetaInfo().getFreshnessPeriod() >= 0.0) {
    // The content will go stale, so use staleTimeCache.
    var content = new MemoryContentCache.StaleTimeContent(data);
    // Insert into staleTimeCache, sorted on content.staleTimeMilliseconds.
    // Search from the back since we expect it to go there.
    var i = this.staleTimeCache.length - 1;
    while (i >= 0) {
      if (this.staleTimeCache[i].staleTimeMilliseconds <= content.staleTimeMilliseconds)
        break;
      --i;
    }
    // Element i is the greatest less than or equal to
    // content.staleTimeMilliseconds, so insert after it.
    this.staleTimeCache.splice(i + 1, 0, content);
  }
  else
    // The data does not go stale, so use noStaleTimeCache.
    this.noStaleTimeCache.push(new MemoryContentCache.Content(data));
}

/**
 * This is the OnInterest callback which is called when the library receives
 * an interest whose name has the prefix given to registerPrefix. First check
 * if cleanupIntervalMilliseconds milliseconds have passed and remove stale
 * content from the cache. Then search the cache for the Data packet, matching
 * any interest selectors including ChildSelector, and send the Data packet
 * to the transport. If no matching Data packet is in the cache, call
 * the callback in onDataNotFoundForPrefix (if defined).
 */
MemoryContentCache.prototype.onInterest = function(prefix, interest, transport)
{
  this.doCleanup();

  var selectedComponent = 0;
  var selectedEncoding = null;
  // We need to iterate over both arrays.
  var totalSize = this.staleTimeCache.length + this.noStaleTimeCache.length;
  for (var i = 0; i < totalSize; ++i) {
    var content;
    if (i < this.staleTimeCache.length)
      content = this.staleTimeCache[i];
    else
      // We have iterated over the first array. Get from the second.
      content = this.noStaleTimeCache[i - this.staleTimeCache.length];

    if (interest.matchesName(content.getName())) {
      if (interest.getChildSelector() < 0) {
        // No child selector, so send the first match that we have found.
        transport.send(content.getDataEncoding());
        return;
      }
      else {
        // Update selectedEncoding based on the child selector.
        var component;
        if (content.getName().size() > interest.getName().size())
          component = content.getName().get(interest.getName().size());
        else
          component = this.emptyComponent;

        var gotBetterMatch = false;
        if (selectedEncoding === null)
          // Save the first match.
          gotBetterMatch = true;
        else {
          if (interest.getChildSelector() == 0) {
            // Leftmost child.
            if (component.compare(selectedComponent) < 0)
              gotBetterMatch = true;
          }
          else {
            // Rightmost child.
            if (component.compare(selectedComponent) > 0)
              gotBetterMatch = true;
          }
        }

        if (gotBetterMatch) {
          selectedComponent = component;
          selectedEncoding = content.getDataEncoding();
        }
      }
    }
  }

  if (selectedEncoding !== null)
    // We found the leftmost or rightmost child.
    transport.send(selectedEncoding);
  else {
    // Call the onDataNotFound callback (if defined).
    var onDataNotFound = this.onDataNotFoundForPrefix[prefix.toUri()];
    if (onDataNotFound)
      // TODO: Include registeredPrefixId.
      onDataNotFound(prefix, interest, transport);
  }
};

/**
 * Check if now is greater than nextCleanupTime and, if so, remove stale
 * content from staleTimeCache and reset nextCleanupTime based on
 * cleanupIntervalMilliseconds. Since add(Data) does a sorted insert into
 * staleTimeCache, the check for stale data is quick and does not require
 * searching the entire staleTimeCache.
 */
MemoryContentCache.prototype.doCleanup = function()
{
  var now = new Date().getTime();
  if (now >= this.nextCleanupTime) {
    // staleTimeCache is sorted on staleTimeMilliseconds, so we only need to
    // erase the stale entries at the front, then quit.
    while (this.staleTimeCache.length > 0 && this.staleTimeCache[0].isStale(now))
      this.staleTimeCache.shift();

    this.nextCleanupTime = now + this.cleanupIntervalMilliseconds;
  }
};

/**
 * Content is a private class to hold the name and encoding for each entry
 * in the cache. This base class is for a Data packet without a FreshnessPeriod.
 *
 * Create a new Content entry to hold data's name and wire encoding.
 * @param {Data} data The Data packet whose name and wire encoding are copied.
 */
MemoryContentCache.Content = function MemoryContentCacheContent(data)
{
  // Allow an undefined data so that StaleTimeContent can set the prototype.
  if (data) {
    // Copy the name.
    this.name = new Name(data.getName());
    // wireEncode returns the cached encoding if available.
    this.dataEncoding = data.wireEncode().buf();
  }
};

MemoryContentCache.Content.prototype.getName = function() { return this.name; };

MemoryContentCache.Content.prototype.getDataEncoding = function() { return this.dataEncoding; };

/**
 * StaleTimeContent extends Content to include the staleTimeMilliseconds for
 * when this entry should be cleaned up from the cache.
 *
 * Create a new StaleTimeContent to hold data's name and wire encoding as well
 * as the staleTimeMilliseconds which is now plus
 * data.getMetaInfo().getFreshnessPeriod().
 * @param {Data} data The Data packet whose name and wire encoding are copied.
 */
MemoryContentCache.StaleTimeContent = function MemoryContentCacheStaleTimeContent
  (data)
{
  // Call the base constructor.
  MemoryContentCache.Content.call(this, data);

  // Set up staleTimeMilliseconds which is The time when the content becomse
  // stale in milliseconds according to new Date().getTime().
  this.staleTimeMilliseconds = new Date().getTime() +
    data.getMetaInfo().getFreshnessPeriod();
};

MemoryContentCache.StaleTimeContent.prototype = new MemoryContentCache.Content();
MemoryContentCache.StaleTimeContent.prototype.name = "StaleTimeContent";

/**
 * Check if this content is stale.
 * @param {number} nowMilliseconds The current time in milliseconds from
 * new Date().getTime().
 * @returns {boolean} true if this interest is stale, otherwise false.
 */
MemoryContentCache.StaleTimeContent.prototype.isStale = function(nowMilliseconds)
{
  return this.staleTimeMilliseconds <= nowMilliseconds;
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * Transport is a base class for specific transport classes such as TcpTransport.
 */
var Transport = function Transport()
{
};

exports.Transport = Transport;

/**
 * Transport.ConnectionInfo is a base class for connection information used by
 * subclasses of Transport.
 */
Transport.ConnectionInfo = function TransportConnectionInfo()
{
};/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Wentao Shang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var ElementReader = require('../encoding/element-reader.js').ElementReader;
var LOG = require('../log.js').Log.LOG;
var Transport = require('./transport.js').Transport;

/**
 * @constructor
 */
var WebSocketTransport = function WebSocketTransport()
{
  // Call the base constructor.
  Transport.call(this);

  if (!WebSocket)
    throw new Error("WebSocket support is not available on this platform.");

  this.ws = null;
  this.connectionInfo = null; // Read by Face.
  this.elementReader = null;
  this.defaultGetConnectionInfo = Face.makeShuffledHostGetConnectionInfo
    (["A.ws.ndn.ucla.edu", "B.ws.ndn.ucla.edu", "C.ws.ndn.ucla.edu", "D.ws.ndn.ucla.edu",
      "E.ws.ndn.ucla.edu", "F.ws.ndn.ucla.edu", "G.ws.ndn.ucla.edu", "H.ws.ndn.ucla.edu",
      "I.ws.ndn.ucla.edu", "J.ws.ndn.ucla.edu", "K.ws.ndn.ucla.edu", "L.ws.ndn.ucla.edu",
      "M.ws.ndn.ucla.edu", "N.ws.ndn.ucla.edu"],
     9696,
     function(host, port) { return new WebSocketTransport.ConnectionInfo(host, port); });
};

WebSocketTransport.prototype = new Transport();
WebSocketTransport.prototype.name = "WebSocketTransport";

exports.WebSocketTransport = WebSocketTransport;

/**
 * Create a new WebSocketTransport.ConnectionInfo which extends
 * Transport.ConnectionInfo to hold the host and port info for the WebSocket
 * connection.
 * @param {string} host The host for the connection.
 * @param {number} port (optional) The port number for the connection. If
 * omitted, use 9696.
 */
WebSocketTransport.ConnectionInfo = function WebSocketTransportConnectionInfo
  (host, port)
{
  // Call the base constructor.
  Transport.ConnectionInfo .call(this);

  port = (port !== undefined ? port : 9696);

  this.host = host;
  this.port = port;
};

WebSocketTransport.ConnectionInfo.prototype = new Transport.ConnectionInfo();
WebSocketTransport.ConnectionInfo.prototype.name = "WebSocketTransport.ConnectionInfo";

/**
 * Check if the fields of this WebSocketTransport.ConnectionInfo equal the other
 * WebSocketTransport.ConnectionInfo.
 * @param {WebSocketTransport.ConnectionInfo} The other object to check.
 * @returns {boolean} True if the objects have equal fields, false if not.
 */
WebSocketTransport.ConnectionInfo.prototype.equals = function(other)
{
  if (other == null || other.host == undefined || other.port == undefined)
    return false;
  return this.host == other.host && this.port == other.port;
};

WebSocketTransport.ConnectionInfo.prototype.toString = function()
{
  return "{ host: " + this.host + ", port: " + this.port + " }";
};

/**
 * Connect to a WebSocket according to the info in connectionInfo. Listen on
 * the port to read an entire packet element and call
 * elementListener.onReceivedElement(element). Note: this connect method
 * previously took a Face object which is deprecated and renamed as the method
 * connectByFace.
 * @param {WebSocketTransport.ConnectionInfo} connectionInfo A
 * WebSocketTransport.ConnectionInfo with the host and port.
 * @param {object} elementListener The elementListener with function
 * onReceivedElement which must remain valid during the life of this object.
 * @param {function} onopenCallback Once connected, call onopenCallback().
 * @param {type} onclosedCallback If the connection is closed by the remote host,
 * call onclosedCallback().
 * @returns {undefined}
 */
WebSocketTransport.prototype.connect = function
  (connectionInfo, elementListener, onopenCallback, onclosedCallback)
{
  this.close();

  this.ws = new WebSocket('ws://' + connectionInfo.host + ':' + connectionInfo.port);
  if (LOG > 0) console.log('ws connection created.');
    this.connectionInfo = connectionInfo;

  this.ws.binaryType = "arraybuffer";

  this.elementReader = new ElementReader(elementListener);
  var self = this;
  this.ws.onmessage = function(ev) {
    var result = ev.data;
    //console.log('RecvHandle called.');

    if (result == null || result == undefined || result == "") {
      console.log('INVALID ANSWER');
    }
    else if (result instanceof ArrayBuffer) {
      var bytearray = new Buffer(result);

      if (LOG > 3) console.log('BINARY RESPONSE IS ' + bytearray.toString('hex'));

      try {
        // Find the end of the binary XML element and call face.onReceivedElement.
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
    // Face.registerPrefix will fetch the ndndid when needed.

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

    onclosedCallback();
  }
};

/**
 * @deprecated This is deprecated. You should not call Transport.connect
 * directly, since it is called by Face methods.
 */
WebSocketTransport.prototype.connectByFace = function(face, onopenCallback)
{
  this.connect
    (face.connectionInfo, face, onopenCallback,
     function() { face.closeByTransport(); });
};

/**
 * Send the Uint8Array data.
 */
WebSocketTransport.prototype.send = function(data)
{
  if (this.ws != null) {
    // If we directly use data.buffer to feed ws.send(),
    // WebSocket may end up sending a packet with 10000 bytes of data.
    // That is, WebSocket will flush the entire buffer
    // regardless of the offset of the Uint8Array. So we have to create
    // a new Uint8Array buffer with just the right size and copy the
    // content from binaryInterest to the new buffer.
    //    ---Wentao
    var bytearray = new Uint8Array(data.length);
    bytearray.set(data);
    this.ws.send(bytearray.buffer);
    if (LOG > 3) console.log('ws.send() returned.');
  }
  else
    console.log('WebSocket connection is not established.');
};

/**
 * Close the connection.
 */
WebSocketTransport.prototype.close = function()
{
  if (this.ws != null)
    delete this.ws;
}

/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

// The Face constructor uses TcpTransport by default which is not available in the browser, so override to WebSocketTransport.
exports.TcpTransport = ndn.WebSocketTransport;
/**
 * Provide the callback closure for the async communication methods in the Face class.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * This is a port of Closure.py from PyNDN, written by:
 * Derek Kulinski <takeda@takeda.tk>
 * Jeff Burke <jburke@ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * A subclass of Closure is passed to expressInterest and registerPrefix.
 * @deprecated You should use the forms of expressInterest and registerPrefix which use callbacks instead of Closure.
 * @constructor
 */
var Closure = function Closure()
{
  // I don't think storing Face's closure is needed
  // and it creates a reference loop, as of now both
  // of those variables are never set -- Derek
  //
  // Use instance variables to return data to callback
  this.ndn_data = null;  // this holds the ndn_closure
  this.ndn_data_dirty = false;
};

exports.Closure = Closure;

// Upcall result
Closure.RESULT_ERR               = -1; // upcall detected an error
Closure.RESULT_OK                =  0; // normal upcall return
Closure.RESULT_REEXPRESS         =  1; // reexpress the same interest again
Closure.RESULT_INTEREST_CONSUMED =  2; // upcall claims to consume interest
Closure.RESULT_VERIFY            =  3; // force an unverified result to be verified
Closure.RESULT_FETCHKEY          =  4; // get the key in the key locator and re-call the interest
                                       //   with the key available in the local storage

// Upcall kind
Closure.UPCALL_FINAL              = 0; // handler is about to be deregistered
Closure.UPCALL_INTEREST           = 1; // incoming interest
Closure.UPCALL_CONSUMED_INTEREST  = 2; // incoming interest, someone has answered
Closure.UPCALL_CONTENT            = 3; // incoming verified content
Closure.UPCALL_INTEREST_TIMED_OUT = 4; // interest timed out
Closure.UPCALL_CONTENT_UNVERIFIED = 5; // content that has not been verified
Closure.UPCALL_CONTENT_BAD        = 6; // verification failed

/**
 * Override this in your subclass.
 * If you're getting strange errors in upcall()
 * check your code whether you're returning a value.
 */
Closure.prototype.upcall = function(kind, upcallInfo)
{
  //dump('upcall ' + this + " " + kind + " " + upcallInfo + "\n");
  return Closure.RESULT_OK;
};

/**
 * An UpcallInfo is passed to Closure.upcall.
 * @constructor
 */
var UpcallInfo = function UpcallInfo(face, interest, matchedComps, data)
{
  this.face = face;  // Face object (not used)
  this.ndn = face;   // deprecated
  this.interest = interest;  // Interest object
  this.matchedComps = matchedComps;  // int
  this.data = data;  // Data
  this.contentObject = data; // deprecated.  Include for backward compatibility.
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
/**
 * This class represents PublisherPublicKeyDigest Objects
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var LOG = require('./log.js').Log.LOG;

/**
 * @constructor
 */
var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(pkd)
{
  this.PUBLISHER_ID_LEN = 512/8;
  this.publisherPublicKeyDigest = pkd;

  this.changeCount = 0;
};

exports.PublisherPublicKeyDigest = PublisherPublicKeyDigest;

PublisherPublicKeyDigest.prototype.from_ndnb = function(decoder)
{
  this.publisherPublicKeyDigest = decoder.readBinaryDTagElement(this.getElementLabel());

  if (LOG > 4) console.log('Publisher public key digest is ' + this.publisherPublicKeyDigest);

  if (null == this.publisherPublicKeyDigest)
    throw new Error("Cannot parse publisher key digest.");

  //TODO check if the length of the PublisherPublicKeyDigest is correct (Security reason)

  if (this.publisherPublicKeyDigest.length != this.PUBLISHER_ID_LEN) {
    if (LOG > 0)
      console.log('LENGTH OF PUBLISHER ID IS WRONG! Expected ' + this.PUBLISHER_ID_LEN + ", got " + this.publisherPublicKeyDigest.length);

    //this.publisherPublicKeyDigest = new PublisherPublicKeyDigest(this.PublisherPublicKeyDigest).PublisherKeyDigest;
  }
  ++this.changeCount;
};

PublisherPublicKeyDigest.prototype.to_ndnb= function(encoder)
{
  //TODO Check that the ByteArray for the key is present
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

/**
 * Get the change count, which is incremented each time this object is changed.
 * @returns {number} The change count.
 */
PublisherPublicKeyDigest.prototype.getChangeCount = function()
{
  return this.changeCount;
};
/**
 * This class represents Publisher and PublisherType Objects
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var NDNProtocolDTagsStrings = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTagsStrings;
var DecodingException = require('./encoding/decoding-exception.js').DecodingException;

/**
 * @constructor
 */
var PublisherType = function PublisherType(tag)
{
  this.KEY = NDNProtocolDTags.PublisherPublicKeyDigest;
  this.CERTIFICATE = NDNProtocolDTags.PublisherCertificateDigest;
  this.ISSUER_KEY = NDNProtocolDTags.PublisherIssuerKeyDigest;
  this.ISSUER_CERTIFICATE = NDNProtocolDTags.PublisherIssuerCertificateDigest;

  this.Tag = tag;
};

/**
 * @constructor
 */
var PublisherID = function PublisherID()
{
  this.PUBLISHER_ID_DIGEST_ALGORITHM = "SHA-256";
  this.PUBLISHER_ID_LEN = 256/8;

  //TODO, implement publisherID creation and key creation

  //TODO implement generatePublicKeyDigest
  this.publisherID =null;//= generatePublicKeyDigest(key);//ByteArray

  //TODO implement generate key
  //CryptoUtil.generateKeyID(PUBLISHER_ID_DIGEST_ALGORITHM, key);
  this.publisherType = null;//isIssuer ? PublisherType.ISSUER_KEY : PublisherType.KEY;//publisher Type

  this.changeCount = 0;
};

exports.PublisherID = PublisherID;

PublisherID.prototype.from_ndnb = function(decoder)
{
  // We have a choice here of one of 4 binary element types.
  var nextTag = PublisherID.peekAndGetNextDTag(decoder);

  this.publisherType = new PublisherType(nextTag);

  if (nextTag < 0)
    throw new Error("Invalid publisher ID, got unexpected type");

  this.publisherID = decoder.readBinaryDTagElement(nextTag);
  if (null == this.publisherID)
    throw new DecodingException(new Error("Cannot parse publisher ID of type : " + nextTag + "."));
  ++this.changeCount;
};

PublisherID.prototype.to_ndnb = function(encoder)
{
  if (!this.validate())
    throw new Error("Cannot encode " + this.getClass().getName() + ": field values missing.");

  encoder.writeDTagElement(this.getElementLabel(), this.publisherID);
};

/**
 * Peek the next DTag in the decoder and return it if it is a PublisherID DTag.
 * @param {BinaryXMLDecoder} decoder The BinaryXMLDecoder with the input to decode.
 * @returns {number} The PublisherID DTag or -1 if it is not one of them.
 */
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

PublisherID.peek = function(/* XMLDecoder */ decoder)
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

/**
 * Get the change count, which is incremented each time this object is changed.
 * @returns {number} The change count.
 */
PublisherID.prototype.getChangeCount = function()
{
  return this.changeCount;
};
/**
 * This class represents a Name as an array of components where each is a byte array.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui, Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('./util/blob.js').Blob;
var DataUtils = require('./encoding/data-utils.js').DataUtils;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var LOG = require('./log.js').Log.LOG;

/**
 * Create a new Name from components.
 *
 * @constructor
 * @param {string|Name|Array<string|Array<number>|ArrayBuffer|Buffer|Name>} components if a string, parse it as a URI.  If a Name, add a deep copy of its components.
 * Otherwise it is an array of components which are appended according to Name.append, so
 * convert each and store it as an array of Buffer.  If a component is a string, encode as utf8.
 */
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

  this.changeCount = 0;
};

exports.Name = Name;

/**
 *
 * @constructor
 * Create a new Name.Component with a copy of the given value.
 * @param {Name.Component|String|Array<number>|ArrayBuffer|Buffer} value If the value is a string, encode it as utf8 (but don't unescape).
 */
Name.Component = function NameComponent(value)
{
  if (typeof value === 'string')
    this.value = DataUtils.stringToUtf8Array(value);
  else if (typeof value === 'object' && value instanceof Name.Component)
    this.value = new Buffer(value.value);
  else if (typeof value === 'object' && value instanceof Blob) {
    if (value.isNull())
      this.value = new Buffer(0);
    else
      this.value = new Buffer(value.buf());
  }
  else if (Buffer.isBuffer(value))
    this.value = new Buffer(value);
  else if (typeof value === 'object' && typeof ArrayBuffer !== 'undefined' &&  value instanceof ArrayBuffer) {
    // Make a copy.  Don't use ArrayBuffer.slice since it isn't always supported.
    this.value = new Buffer(new ArrayBuffer(value.byteLength));
    this.value.set(new Buffer(value));
  }
  else if (typeof value === 'object')
    // Assume value is a byte array.  We can't check instanceof Array because
    //   this doesn't work in JavaScript if the array comes from a different module.
    this.value = new Buffer(value);
  else if (!value)
    this.value = new Buffer(0);
  else
    throw new Error("Name.Component constructor: Invalid type");
}

/**
 * Get the component value.
 * @returns {Blob} The component value.
 */
Name.Component.prototype.getValue = function()
{
  // For temporary backwards compatibility, leave this.value as a Buffer but return a Blob.
  return new Blob(this.value, false);
}

/**
 * @deprecated Use getValue. This method returns a Buffer which is the former
 * behavior of getValue, and should only be used while updating your code.
 */
Name.Component.prototype.getValueAsBuffer = function()
{
  return this.value;
};

/**
 * Convert this component value to a string by escaping characters according to the NDN URI Scheme.
 * This also adds "..." to a value with zero or more ".".
 * @returns {string} The escaped string.
 */
Name.Component.prototype.toEscapedString = function()
{
  return Name.toEscapedString(this.value);
};

/**
 * Interpret this name component as a network-ordered number and return an integer.
 * @returns {number} The integer number.
 */
Name.Component.prototype.toNumber = function()
{
  return DataUtils.bigEndianToUnsignedInt(this.value);
};

/**
 * Interpret this name component as a network-ordered number with a marker and 
 * return an integer.
 * @param {number} marker The required first byte of the component.
 * @returns {number} The integer number.
 * @throws Error If the first byte of the component does not equal the marker.
 */
Name.Component.prototype.toNumberWithMarker = function(marker)
{
  if (this.value.length == 0 || this.value[0] != marker)
    throw new Error("Name component does not begin with the expected marker");

  return DataUtils.bigEndianToUnsignedInt(this.value.slice(1));
};

/**
 * Interpret this name component as a segment number according to NDN name
 * conventions (a network-ordered number where the first byte is the marker 0x00).
 * @returns {number} The integer segment number.
 * @throws Error If the first byte of the component is not the expected marker.
 */
Name.Component.prototype.toSegment = function()
{
  return this.toNumberWithMarker(0x00);
};

/**
 * Interpret this name component as a version number according to NDN name 
 * conventions (a network-ordered number where the first byte is the marker 0xFD).  
 * Note that this returns the exact number from the component without converting 
 * it to a time representation.
 * @returns {number} The integer version number.
 * @throws Error If the first byte of the component is not the expected marker.
 */
Name.Component.prototype.toVersion = function()
{
  return this.toNumberWithMarker(0xFD);
};

/**
 * Create a component whose value is the marker appended with the 
 * network-ordered encoding of the number. Note: if the number is zero, no bytes 
 * are used for the number - the result will have only the marker.
 * @param {number} number
 * @param {number} marker
 * @returns {Name.Component}
 */
Name.Component.fromNumberWithMarker = function(number, marker)
{
  var bigEndian = DataUtils.nonNegativeIntToBigEndian(number);
  // Put the marker byte in front.
  var value = new Buffer(bigEndian.length + 1);
  value[0] = marker;
  bigEndian.copy(value, 1);

  return new Name.Component(value);
};

/**
 * Check if this is the same component as other.
 * @param {Name.Component} other The other Component to compare with.
 * @returns {Boolean} true if the components are equal, otherwise false.
 */
Name.Component.prototype.equals = function(other)
{
  return DataUtils.arraysEqual(this.value, other.value);
};

/**
 * Compare this to the other Component using NDN canonical ordering.
 * @param {Name.Component} other The other Component to compare with.
 * @returns {number} 0 if they compare equal, -1 if this comes before other in
 * the canonical ordering, or 1 if this comes after other in the canonical
 * ordering.
 *
 * @see http://named-data.net/doc/0.2/technical/CanonicalOrder.html
 */
Name.Component.prototype.compare = function(other)
{
  return Name.Component.compareBuffers(this.value, other.value);
};

/**
 * Do the work of Name.Component.compare to compare the component buffers.
 * @param {Buffer} component1
 * @param {Buffer} component2
 * @returns {number} 0 if they compare equal, -1 if component1 comes before
 * component2 in the canonical ordering, or 1 if component1 comes after
 * component2 in the canonical ordering.
 */
Name.Component.compareBuffers = function(component1, component2)
{
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

/**
 * @deprecated Use toUri.
 */
Name.prototype.getName = function()
{
  return this.toUri();
};

/** Parse uri as a URI and return an array of Buffer components.
 */
Name.createNameArray = function(uri)
{
  uri = uri.trim();
  if (uri.length <= 0)
    return [];

  var iColon = uri.indexOf(':');
  if (iColon >= 0) {
    // Make sure the colon came before a '/'.
    var iFirstSlash = uri.indexOf('/');
    if (iFirstSlash < 0 || iColon < iFirstSlash)
      // Omit the leading protocol such as ndn:
      uri = uri.substr(iColon + 1, uri.length - iColon - 1).trim();
  }

  if (uri[0] == '/') {
    if (uri.length >= 2 && uri[1] == '/') {
      // Strip the authority following "//".
      var iAfterAuthority = uri.indexOf('/', 2);
      if (iAfterAuthority < 0)
        // Unusual case: there was only an authority.
        return [];
      else
        uri = uri.substr(iAfterAuthority + 1, uri.length - iAfterAuthority - 1).trim();
    }
    else
      uri = uri.substr(1, uri.length - 1).trim();
  }

  var array = uri.split('/');

  // Unescape the components.
  for (var i = 0; i < array.length; ++i) {
    var value = Name.fromEscapedString(array[i]);

    if (value.isNull()) {
      // Ignore the illegal componenent.  This also gets rid of a trailing '/'.
      array.splice(i, 1);
      --i;
      continue;
    }
    else
      array[i] = new Name.Component(value);
  }

  return array;
};

/**
 * Parse the uri according to the NDN URI Scheme and set the name with the
 * components.
 * @param {string} uri The URI string.
 */
Name.prototype.set = function(uri)
{
  this.components = Name.createNameArray(uri);
  ++this.changeCount;
};

Name.prototype.from_ndnb = function(/*XMLDecoder*/ decoder)
{
  decoder.readElementStartDTag(this.getElementLabel());

  this.components = [];

  while (decoder.peekDTag(NDNProtocolDTags.Component))
    this.append(decoder.readBinaryDTagElement(NDNProtocolDTags.Component));

  decoder.readElementClose();
  ++this.changeCount;
};

/**
 * Encode this name to the encoder.
 * @param {BinaryXMLEncoder} encoder The encoder to receive the encoding.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
Name.prototype.to_ndnb = function(encoder)
{
  if (this.components == null)
    throw new Error("CANNOT ENCODE EMPTY CONTENT NAME");

  encoder.writeElementStartDTag(this.getElementLabel());
  var signedPortionBeginOffset = encoder.offset;
  var signedPortionEndOffset;

  var count = this.size();
  if (count == 0)
    // There is no "final component", so set signedPortionEndOffset arbitrarily.
    signedPortionEndOffset = signedPortionBeginOffset;
  else {
    for (var i = 0; i < count; i++) {
      if (i == count - 1)
        // We will begin the final component.
        signedPortionEndOffset = encoder.offset;

      encoder.writeDTagElement
        (NDNProtocolDTags.Component, this.components[i].getValue().buf());
    }
  }

  encoder.writeElementClose();

  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

Name.prototype.getElementLabel = function()
{
  return NDNProtocolDTags.Name;
};

/**
 * Convert the component to a Buffer and append to this Name.
 * Return this Name object to allow chaining calls to add.
 * @param {Name.Component|String|Array<number>|ArrayBuffer|Buffer|Name} component If a component is a string, encode as utf8 (but don't unescape).
 * @returns {Name}
 */
Name.prototype.append = function(component)
{
  if (typeof component == 'object' && component instanceof Name) {
    var components;
    if (component == this)
      // special case, when we need to create a copy
      components = this.components.slice(0, this.components.length);
    else
      components = component.components;

    for (var i = 0; i < components.length; ++i)
      this.components.push(new Name.Component(components[i]));
  }
  else
    // Just use the Name.Component constructor.
    this.components.push(new Name.Component(component));

  ++this.changeCount;
  return this;
};

/**
 * @deprecated Use append.
 */
Name.prototype.add = function(component)
{
  return this.append(component);
};

/**
 * Clear all the components.
 */
Name.prototype.clear = function()
{
  this.components = [];
  ++this.changeCount;
};

/**
 * Return the escaped name string according to "NDNx URI Scheme".
 * @returns {String}
 */
Name.prototype.toUri = function()
{
  if (this.size() == 0)
    return "/";

  var result = "";

  for (var i = 0; i < this.size(); ++i)
    result += "/"+ Name.toEscapedString(this.components[i].getValue().buf());

  return result;
};

/**
 * @deprecated Use toUri.
 */
Name.prototype.to_uri = function()
{
  return this.toUri();
};

/**
 * Append a component with the encoded segment number.
 * @param {number} segment The segment number.
 * @returns {Name} This name so that you can chain calls to append.
 */
Name.prototype.appendSegment = function(segment)
{
  return this.append(Name.Component.fromNumberWithMarker(segment, 0x00));
};

/**
 * Append a component with the encoded version number.
 * Note that this encodes the exact value of version without converting from a
 * time representation.
 * @param {number} version The version number.
 * @returns {Name} This name so that you can chain calls to append.
 */
Name.prototype.appendVersion = function(version)
{
  return this.append(Name.Component.fromNumberWithMarker(segment, 0xFD));
};

/**
 * @deprecated Use appendSegment.
 */
Name.prototype.addSegment = function(number)
{
  return this.appendSegment(number);
};

/**
 * Get a new name, constructed as a subset of components.
 * @param {number} iStartComponent The index if the first component to get.
 * @param {number} (optional) nComponents The number of components starting at iStartComponent.  If omitted,
 * return components starting at iStartComponent until the end of the name.
 * @returns {Name} A new name.
 */
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

/**
 * Return a new Name with the first nComponents components of this Name.
 * @param {number} nComponents The number of prefix components.  If nComponents is -N then return the prefix up
 * to name.size() - N. For example getPrefix(-1) returns the name without the final component.
 * @returns {Name} A new name.
 */
Name.prototype.getPrefix = function(nComponents)
{
  if (nComponents < 0)
    return this.getSubName(0, this.components.length + nComponents);
  else
    return this.getSubName(0, nComponents);
};

/**
 * @deprecated Use getPrefix(-nComponents).
 */
Name.prototype.cut = function(nComponents)
{
  return new Name(this.components.slice(0, this.components.length - nComponents));
};

/**
 * Return the number of name components.
 * @returns {number}
 */
Name.prototype.size = function()
{
  return this.components.length;
};

/**
 * Get a Name Component by index number.
 * @param {Number} i The index of the component, starting from 0.  However, if i is negative, return the component
 * at size() - (-i).
 * @returns {Name.Component}
 */
Name.prototype.get = function(i)
{
  if (i >= 0) {
    if (i >= this.components.length)
      throw new Error("Name.get: Index is out of bounds");

    return new Name.Component(this.components[i]);
  }
  else {
    // Negative index.
    if (i < -this.components.length)
      throw new Error("Name.get: Index is out of bounds");

    return new Name.Component(this.components[this.components.length - (-i)]);
  }
};

/**
 * @deprecated Use size().
 */
Name.prototype.getComponentCount = function()
{
  return this.components.length;
};

/**
 * @deprecated To get just the component value array, use get(i).getValue().buf().
 */
Name.prototype.getComponent = function(i)
{
  return new Buffer(this.components[i].getValue().buf());
};

/**
 * The "file name" in a name is the last component that isn't blank and doesn't start with one of the
 *   special marker octets (for version, etc.).  Return the index in this.components of
 *   the file name, or -1 if not found.
 */
Name.prototype.indexOfFileName = function()
{
  for (var i = this.size() - 1; i >= 0; --i) {
    var component = this.components[i].getValue().buf();
    if (component.length <= 0)
      continue;

    if (component[0] == 0 || component[0] == 0xC0 || component[0] == 0xC1 ||
        (component[0] >= 0xF5 && component[0] <= 0xFF))
      continue;

    return i;
  }

  return -1;
};

/**
 * Compare this to the other Name using NDN canonical ordering.  If the first 
 * components of each name are not equal, this returns -1 if the first comes 
 * before the second using the NDN canonical ordering for name components, or 1 
 * if it comes after. If they are equal, this compares the second components of 
 * each name, etc.  If both names are the same up to the size of the shorter 
 * name, this returns -1 if the first name is shorter than the second or 1 if it 
 * is longer. For example, std::sort gives: /a/b/d /a/b/cc /c /c/a /bb .  This 
 * is intuitive because all names with the prefix /a are next to each other.  
 * But it may be also be counter-intuitive because /c comes before /bb according 
 * to NDN canonical ordering since it is shorter.
 * @param {Name} other The other Name to compare with.
 * @returns {boolean} If they compare equal, -1 if *this comes before other in
 * the canonical ordering, or 1 if *this comes after other in the canonical
 * ordering.
 *
 * @see http://named-data.net/doc/0.2/technical/CanonicalOrder.html
 */
Name.prototype.compare = function(other)
{
  for (var i = 0; i < this.size() && i < other.size(); ++i) {
    var comparison = this.components[i].compare(other.components[i]);
    if (comparison == 0)
      // The components at this index are equal, so check the next components.
      continue;

    // Otherwise, the result is based on the components at this index.
    return comparison;
  }

  // The components up to min(this.size(), other.size()) are equal, so the
  // shorter name is less.
  if (this.size() < other.size())
    return -1;
  else if (this.size() > other.size())
    return 1;
  else
    return 0;
};

/**
 * Return true if this Name has the same components as name.
 */
Name.prototype.equals = function(name)
{
  if (this.components.length != name.components.length)
    return false;

  // Start from the last component because they are more likely to differ.
  for (var i = this.components.length - 1; i >= 0; --i) {
    if (!this.components[i].equals(name.components[i]))
      return false;
  }

  return true;
};

/**
 * @deprecated Use equals.
 */
Name.prototype.equalsName = function(name)
{
  return this.equals(name);
};

/**
 * Find the last component in name that has a ContentDigest and return the digest value as Buffer,
 *   or null if not found.  See Name.getComponentContentDigestValue.
 */
Name.prototype.getContentDigestValue = function()
{
  for (var i = this.size() - 1; i >= 0; --i) {
    var digestValue = Name.getComponentContentDigestValue(this.components[i]);
    if (digestValue != null)
      return digestValue;
  }

  return null;
};

/**
 * If component is a ContentDigest, return the digest value as a Buffer slice (don't modify!).
 * If not a ContentDigest, return null.
 * A ContentDigest component is Name.ContentDigestPrefix + 32 bytes + Name.ContentDigestSuffix.
 */
Name.getComponentContentDigestValue = function(component)
{
  if (typeof component == 'object' && component instanceof Name.Component)
    component = component.getValue().buf();

  var digestComponentLength = Name.ContentDigestPrefix.length + 32 + Name.ContentDigestSuffix.length;
  // Check for the correct length and equal ContentDigestPrefix and ContentDigestSuffix.
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

// Meta GUID "%C1.M.G%C1" + ContentDigest with a 32 byte BLOB.
Name.ContentDigestPrefix = new Buffer([0xc1, 0x2e, 0x4d, 0x2e, 0x47, 0xc1, 0x01, 0xaa, 0x02, 0x85]);
Name.ContentDigestSuffix = new Buffer([0x00]);


/**
 * Return value as an escaped string according to "NDNx URI Scheme".
 * We can't use encodeURIComponent because that doesn't encode all the characters we want to.
 * @param {Buffer|Name.Component} component The value or Name.Component to escape.
 * @returns {string} The escaped string.
 */
Name.toEscapedString = function(value)
{
  if (typeof value == 'object' && value instanceof Name.Component)
    value = value.getValue().buf();
  else if (typeof value === 'object' && value instanceof Blob)
    value = value.buf();

  var result = "";
  var gotNonDot = false;
  for (var i = 0; i < value.length; ++i) {
    if (value[i] != 0x2e) {
      gotNonDot = true;
      break;
    }
  }
  if (!gotNonDot) {
    // Special case for component of zero or more periods.  Add 3 periods.
    result = "...";
    for (var i = 0; i < value.length; ++i)
      result += ".";
  }
  else {
    for (var i = 0; i < value.length; ++i) {
      var x = value[i];
      // Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
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

/**
 * Make a blob value by decoding the escapedString according to "NDNx URI Scheme".
 * If escapedString is "", "." or ".." then return null, which means to skip the component in the name.
 * @param {string} escapedString The escaped string to decode.
 * @returns {Blob} The unescaped Blob value. If the escapedString is not a valid
 * escaped component, then the Blob isNull().
 */
Name.fromEscapedString = function(escapedString)
{
  var value = unescape(escapedString.trim());

  if (value.match(/[^.]/) == null) {
    // Special case for value of only periods.
    if (value.length <= 2)
      // Zero, one or two periods is illegal.  Ignore this componenent to be
      //   consistent with the C implementation.
      return new Blob();
    else
      // Remove 3 periods.
      return new Blob
        (DataUtils.toNumbersFromString(value.substr(3, value.length - 3)), false);
  }
  else
    return new Blob(DataUtils.toNumbersFromString(value), false);
};

/**
 * @deprecated Use fromEscapedString. This method returns a Buffer which is the former
 * behavior of fromEscapedString, and should only be used while updating your code.
 */
Name.fromEscapedStringAsBuffer = function(escapedString)
{
  return Name.fromEscapedString(escapedString).buf();
};

/**
 * Return true if the N components of this name are the same as the first N components of the given name.
 * @param {Name} name The name to check.
 * @returns {Boolean} true if this matches the given name.  This always returns true if this name is empty.
 */
Name.prototype.match = function(name)
{
  var i_name = this.components;
  var o_name = name.components;

  // This name is longer than the name we are checking it against.
  if (i_name.length > o_name.length)
    return false;

  // Check if at least one of given components doesn't match.
  for (var i = 0; i < i_name.length; ++i) {
    if (!i_name[i].equals(o_name[i]))
      return false;
  }

  return true;
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @returns {number} The change count.
 */
Name.prototype.getChangeCount = function()
{
  return this.changeCount;
};
/**
 * This class represents Key Objects
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var DataUtils = require('./encoding/data-utils.js').DataUtils;
var LOG = require('./log.js').Log.LOG;

/**
 * @constructor
 */
/**
 * Key
 */
var Key = function Key()
{
  this.publicKeyDer = null;     // Buffer
  this.publicKeyDigest = null;  // Buffer
  this.publicKeyPem = null;     // String
  this.privateKeyPem = null;    // String
};

exports.Key = Key;

/**
 * Helper functions to read Key fields
 * TODO: generateRSA()
 */

Key.prototype.publicToDER = function()
{
  return this.publicKeyDer;  // Buffer
};

Key.prototype.privateToDER = function()
{
  // Remove the '-----XXX-----' from the beginning and the end of the key
  // and also remove any \n in the key string
  var lines = this.privateKeyPem.split('\n');
  priKey = "";
  for (var i = 1; i < lines.length - 1; i++)
    priKey += lines[i];

  return new Buffer(priKey, 'base64');
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

Key.prototype.readDerPublicKey = function(/*Buffer*/pub_der)
{
  if (LOG > 4) console.log("Encode DER public key:\n" + pub_der.toString('hex'));

  this.publicKeyDer = pub_der;

  var hash = require("crypto").createHash('sha256');
  hash.update(this.publicKeyDer);
  this.publicKeyDigest = new Buffer(DataUtils.toNumbersIfString(hash.digest()));

  var keyStr = pub_der.toString('base64');
  var keyPem = "-----BEGIN PUBLIC KEY-----\n";
  for (var i = 0; i < keyStr.length; i += 64)
  keyPem += (keyStr.substr(i, 64) + "\n");
  keyPem += "-----END PUBLIC KEY-----";
  this.publicKeyPem = keyPem;

  if (LOG > 4) console.log("Convert public key to PEM format:\n" + this.publicKeyPem);
};

/**
 * Load RSA key pair from PEM-encoded strings.
 * Will throw an Error if both 'pub' and 'pri' are null.
 */
Key.prototype.fromPemString = function(pub, pri)
{
  if (pub == null && pri == null)
    throw new Error('Cannot create Key object if both public and private PEM string is empty.');

  // Read public key
  if (pub != null) {
    this.publicKeyPem = pub;
    if (LOG > 4) console.log("Key.publicKeyPem: \n" + this.publicKeyPem);

    // Remove the '-----XXX-----' from the beginning and the end of the public key
    // and also remove any \n in the public key string
    var lines = pub.split('\n');
    pub = "";
    for (var i = 1; i < lines.length - 1; i++)
      pub += lines[i];
    this.publicKeyDer = new Buffer(pub, 'base64');
    if (LOG > 4) console.log("Key.publicKeyDer: \n" + this.publicKeyDer.toString('hex'));

    var hash = require("crypto").createHash('sha256');
    hash.update(this.publicKeyDer);
    this.publicKeyDigest = new Buffer(DataUtils.toNumbersIfString(hash.digest()));
    if (LOG > 4) console.log("Key.publicKeyDigest: \n" + this.publicKeyDigest.toString('hex'));
  }

  // Read private key
  if (pri != null) {
    this.privateKeyPem = pri;
    if (LOG > 4) console.log("Key.privateKeyPem: \n" + this.privateKeyPem);
  }
};

Key.prototype.fromPem = Key.prototype.fromPemString;

/**
 * Static method that create a Key object.
 * Parameter 'obj' is a JSON object that has two properties:
 *   pub: the PEM string for the public key
 *   pri: the PEM string for the private key
 * Will throw an Error if both obj.pub and obj.pri are null.
 */
Key.createFromPEM = function(obj)
{
    var key = new Key();
    key.fromPemString(obj.pub, obj.pri);
    return key;
};
/**
 * This class represents an NDN KeyLocator object.
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('./util/blob.js').Blob;
var Name = require('./name.js').Name;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var PublisherID = require('./publisher-id.js').PublisherID;
var LOG = require('./log.js').Log.LOG;

/**
 * KeyLocator
 */
var KeyLocatorType = {
  KEYNAME: 1,
  KEY_LOCATOR_DIGEST: 2,
  KEY: 3,
  CERTIFICATE: 4
};

exports.KeyLocatorType = KeyLocatorType;

/**
 * @constructor
 */
var KeyLocator = function KeyLocator(input,type)
{
  if (typeof input === 'object' && input instanceof KeyLocator) {
    // Copy from the input KeyLocator.
    this.type = input.type;
    this.keyName = new KeyName();
    if (input.keyName != null) {
      this.keyName.contentName = input.keyName.contentName == null ?
        null : new Name(input.keyName.contentName);
      this.keyName.publisherID = input.keyName.publisherID;
    }
    this.keyData = input.keyData == null ? null : new Buffer(input.keyData);
    this.publicKey = input.publicKey == null ? null : new Buffer(input.publicKey);
    this.certificate = input.certificate == null ? null : new Buffer(input.certificate);
  }
  else {
    this.type = type;
    this.keyName = new KeyName();

    if (type == KeyLocatorType.KEYNAME)
      this.keyName = input;
    else if (type == KeyLocatorType.KEY_LOCATOR_DIGEST)
      this.keyData = new Buffer(input);
    else if (type == KeyLocatorType.KEY) {
      this.keyData = new Buffer(input);
      // Set for backwards compatibility.
      this.publicKey = this.keyData;
    }
    else if (type == KeyLocatorType.CERTIFICATE) {
      this.keyData = new Buffer(input);
      // Set for backwards compatibility.
      this.certificate = this.keyData;
    }
  }
};

exports.KeyLocator = KeyLocator;

/**
 * Get the key locator type. If KeyLocatorType.KEYNAME, you may also
 * getKeyName().  If KeyLocatorType.KEY_LOCATOR_DIGEST, you may also
 * getKeyData() to get the digest.
 * @returns {number} The key locator type, or null if not specified.
 */
KeyLocator.prototype.getType = function() { return this.type; };

/**
 * Get the key name.  This is meaningful if getType() is KeyLocatorType.KEYNAME.
 * @returns {Name} The key name. If not specified, the Name is empty.
 */
KeyLocator.prototype.getKeyName = function()
{
  if (this.keyName == null)
    this.keyName = new KeyName();
  if (this.keyName.contentName == null)
    this.keyName.contentName = new Name();

  return this.keyName.contentName;
};

/**
 * Get the key data. If getType() is KeyLocatorType.KEY_LOCATOR_DIGEST, this is
 * the digest bytes. If getType() is KeyLocatorType.KEY, this is the DER
 * encoded public key. If getType() is KeyLocatorType.CERTIFICATE, this is the
 * DER encoded certificate.
 * @returns {Blob} The key data, or null if not specified.
 */
KeyLocator.prototype.getKeyData = function()
{
  // For temporary backwards compatibility, leave the fields as a Buffer but return a Blob.
  return new Blob(this.getKeyDataAsBuffer(), false);
};

/**
 * @deprecated Use getKeyData. This method returns a Buffer which is the former
 * behavior of getKeyData, and should only be used while updating your code.
 */
KeyLocator.prototype.getKeyDataAsBuffer = function()
{
  if (this.type == KeyLocatorType.KEY)
    return this.publicKey;
  else if (this.type == KeyLocatorType.CERTIFICATE)
    return this.certificate;
  else
    return this.keyData;
};

/**
 * Set the key locator type.  If KeyLocatorType.KEYNAME, you must also
 * setKeyName().  If KeyLocatorType.KEY_LOCATOR_DIGEST, you must also
 * setKeyData() to the digest.
 * @param {number} type The key locator type.  If null, the type is unspecified.
 */
KeyLocator.prototype.setType = function(type) { this.type = type; };

/**
 * Set key name to a copy of the given Name.  This is the name if getType()
 * is KeyLocatorType.KEYNAME.
 * @param {Name} name The key name which is copied.
 */
KeyLocator.prototype.setKeyName = function(name)
{
  if (this.keyName == null)
    this.keyName = new KeyName();

  this.keyName.contentName = typeof name === 'object' && name instanceof Name ?
                             new Name(name) : new Name();
};

/**
 * Set the key data to the given value. This is the digest bytes if getType() is
 * KeyLocatorType.KEY_LOCATOR_DIGEST.
 * @param {Blob} keyData A Blob with the key data bytes.
 */
KeyLocator.prototype.setKeyData = function(keyData)
{
  var value = keyData;
  if (value != null) {
    if (typeof value === 'object' && value instanceof Blob)
      value = new Buffer(value.buf());
    else
      // Make a copy.
      value = new Buffer(value);
  }

  this.keyData = value;
  // Set for backwards compatibility.
  this.publicKey = value;
  this.certificate = value;
};

/**
 * Clear the keyData and set the type to none.
 */
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
      // This is a DER-encoded SubjectPublicKeyInfo.

      //TODO FIX THIS, This should create a Key Object instead of keeping bytes

      this.publicKey =   encodedKey;//CryptoUtil.getPublicKey(encodedKey);
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

      /*
       * Certificates not yet working
       */

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
    // encodeSignedInfo already encoded this as the publisherPublicKeyDigest,
    //   so do nothing here.
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

/**
 * KeyName is only used by KeyLocator.
 * @constructor
 */
var KeyName = function KeyName()
{
  this.contentName = new Name();  //contentName
  this.publisherID = this.publisherID;  //publisherID
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

/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Key = require('../key.js').Key;

/**
 * @constructor
 */
var KeyManager = function KeyManager()
{
  // Public Key
    this.publicKey =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuAmnWYKE7E8G+hyy4TiT\n"	+
  "U7t91KyIGvglEeT6HWEkW4LKzXLO22a1jVS9+yP96I6vp7N5vpS1t7oXtgWuzkO+\n" +
  "O85u6gfbvwp+67zJe2I89eHO4dmNnP4fx/j7WcCUCyzZfbyW67h5IoouoBIdQge2\n" +
  "Xdvh9rFdex9UUhyjEZv5676zlcqlhz8xGBrJmQHsqpD9ijY1XhKBvoSIoQ0ZKkpm\n" +
  "wVk8QYM9PbjUqzSQBj4aYXS+BPV6aRudVvyDt2DBXp2FNP0CGrosCXKnSl4Yv8BY\n" +
  "p0k0RmFZDuJuntLb/XIvPEfMX5li7g3zHzAlIJIVSwT+FRkd3H5cECFSIZFUYIuS\n" +
  "QQIDAQAB\n" +
  "-----END PUBLIC KEY-----";
  // Private Key
    this.privateKey =
  "-----BEGIN RSA PRIVATE KEY-----\n" +
  "MIIEpQIBAAKCAQEAuAmnWYKE7E8G+hyy4TiTU7t91KyIGvglEeT6HWEkW4LKzXLO\n"	+
  "22a1jVS9+yP96I6vp7N5vpS1t7oXtgWuzkO+O85u6gfbvwp+67zJe2I89eHO4dmN\n" +
  "nP4fx/j7WcCUCyzZfbyW67h5IoouoBIdQge2Xdvh9rFdex9UUhyjEZv5676zlcql\n" +
  "hz8xGBrJmQHsqpD9ijY1XhKBvoSIoQ0ZKkpmwVk8QYM9PbjUqzSQBj4aYXS+BPV6\n" +
  "aRudVvyDt2DBXp2FNP0CGrosCXKnSl4Yv8BYp0k0RmFZDuJuntLb/XIvPEfMX5li\n" +
  "7g3zHzAlIJIVSwT+FRkd3H5cECFSIZFUYIuSQQIDAQABAoIBAQCKBftzfxavn6lM\n" +
  "5T8m+GZN0vzRBsBg8Z/jpsYKSLOayiHNKYCIPaSFpXuCIYEo6/JDJLB2xVLvwupL\n" +
  "gkGSwm2mrvCyJkihI38Cz6iQF6I+iia9bYrupgwxzsK7klm1c+J9kXXivYxj4hyL\n" +
  "wmoc/mnARMtYV7cTQvDbUEzgRQmPykWKBv6Y0SL1WprfiRfKIMwSqQk91ffj6whK\n" +
  "xBLAuUdseVBmo/ivLPq0a+wDrcvaJAxSB4eIwCHzAugkRA/NoK0vG3mra0lK5jvQ\n" +
  "rcNIuffxNAnresDVDTnYRc42etjePLAhlpeK/4sjYE/wPdeP8yzLHUg/hsSpAPIj\n" +
  "LXJNZqUBAoGBANxPmUQNf1lGHo/nLY3dVMD3+kYNnTUD8XwS81qdg8/dNyF8t+7D\n" +
  "OdJ1j7Itb+zGA1XXAGfTm6JoUG+eKKR2OSuyZcxygpOgzxAFanXKhTWZsKbG70xN\n" +
  "mX0sOAEhtTGsgFTEGEv977MwIlFa6n2bsp3Luj/AGmvNsOYvBDPXOklxAoGBANXZ\n" +
  "yXAaE7M5JALusLuEFxLGvWVz6TRdQ//c+FWvKrnh+nFlTlAPpDvlaPJJca8ViNev\n" +
  "xJ2UhGtbENXAqgwTYpnAi/yQD4dATViIveK6Pn4t12mpPAlkMbbMTR8jtp5l1oHc\n" +
  "hcwe8QuEOKuTX5+STpNGlWs+tsMb12mhCpc3eO3RAoGAMxjDE2WOA8afkACuMBkF\n" +
  "bzwUb+r4azNe7sf2aS3fRHaqMroabuYYoxdhHJItQ10pqN8U2P/bOO+4uCqWgo5o\n" +
  "9BmMQr7MSjEh1TVsW6V8/9GFhyjcl3XoA4Ad/SU0QTEhEofomrdqwMSJMRVFDZzu\n" +
  "8Gov6FlFx3sNbFW7Q8rHWgECgYEAq/TVz3iIgsLdvCXmosHSM9zvCpcr3FlqhmFO\n" +
  "pseVmaamVWxajnIlY6xSuRBpg5nTUWwas4Nq/1BYtyiXE+K6lFuJtOq6Mc145EoA\n" +
  "NkIAYkHGR0Y36m1QtGaPVQzImZHV7NJAHCR9Ov90+jIk4BErca1+FKB3IWhPzLYb\n" +
  "6ABJEyECgYEAthhzWSxPkqyiLl+2vnhdR3EEkvDX6MV6hGu4tDAf2A1Y0GSApyEa\n" +
  "SAA31hlxu5EgneLD7Ns2HMpIfQMydB5lcwKQc9g/tVI1eRzuk6Myi+2JmPEM2BLy\n" +
  "iX8yI+xnZlKDiZleQitCS4RQGz5HbXT70aYQIGxuvkQ/uf68jdrL6o8=\n" +
  "-----END RSA PRIVATE KEY-----";

  this.key = null;
};

/**
 * Return a Key object for the keys in this KeyManager.  This creates the Key on the first
 * call and returns a cached copy after that.
 * @returns {Key}
 */
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
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * Create a new SecurityException to report an exception from the security
 * library, wrapping the given error object.
 * Call with: throw new SecurityException(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
function SecurityException(error)
{
  this.message = error.message;
  // Copy lineNumber, etc. from where new Error was called.
  for (var prop in error)
      this[prop] = error[prop];
}
SecurityException.prototype = new Error();
SecurityException.prototype.name = "SecurityException";

exports.SecurityException = SecurityException;
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * This module defines constants used by the security library.
 */

/**
 * The KeyType integer is used by the Sqlite key storage, so don't change them.
 * Make these the same as ndn-cpp in case the Sqlite file is shared.
 * @constructor
 */
var KeyType = function KeyType()
{
}

exports.KeyType = KeyType;

KeyType.RSA = 0;
KeyType.AES = 1;
// KeyType.DSA
// KeyType.DES
// KeyType.RC4
// KeyType.RC2
KeyType.EC = 2;

var KeyClass = function KeyClass()
{
};

exports.KeyClass = KeyClass;

KeyClass.PUBLIC = 1;
KeyClass.PRIVATE = 2;
KeyClass.SYMMETRIC = 3;

var DigestAlgorithm = function DigestAlgorithm()
{
};

exports.DigestAlgorithm = DigestAlgorithm;

DigestAlgorithm.SHA256 = 1;
// DigestAlgorithm.MD2
// DigestAlgorithm.MD5
// DigestAlgorithm.SHA1

var EncryptMode = function EncryptMode()
{
};

exports.EncryptMode = EncryptMode;

EncryptMode.DEFAULT = 1;
EncryptMode.CFB_AES = 2;
// EncryptMode.CBC_AES
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var SecurityException = require('../security-exception.js').SecurityException;
var KeyType = require('../security-types.js').KeyType;

/**
 * A PublicKey holds an encoded public key for use by the security library.
 * Create a new PublicKey with the given values.
 * @param {number} keyType The integer from KeyType, such as KeyType.RSA.
 * @param {Blob} keyDer The blob of the PublicKeyInfo in terms of DER.
 */
var PublicKey = function PublicKey(keyType, keyDer)
{
  this.keyType = keyType;
  this.keyDer = keyDer;
};

exports.PublicKey = PublicKey;

/**
 * Encode the public key into DER.
 * @returns {DerNode} The encoded DER syntax tree.
 */
PublicKey.prototype.toDer = function()
{
  throw new Error("PublicKey.toDer is not implemented");
};

/**
 * Decode the public key from the DER blob.
 * @param {number} keyType The integer from KeyType, such as KeyType.RSA.
 * @param {Blob} keyDer The DER blob.
 * @returns {PublicKey} The decoded public key.
 */
PublicKey.fromDer = function(keyType, keyDer)
{
  if (keyType == KeyType.RSA) {
    // TODO: Make sure we can decode the public key DER.
  }
  else
    throw new SecurityException(new Error
      ("PublicKey::fromDer: Unrecognized keyType"));

  return new PublicKey(keyType, keyDer);
};

/**
 * 
 * @param {number} digestAlgorithm (optional) The integer from DigestAlgorithm, 
 * such as DigestAlgorithm.SHA256. If omitted, use DigestAlgorithm.SHA256 .
 * @returns {Blob} The digest value.
 */
PublicKey.prototype.getDigest = function(digestAlgorithm)
{
  throw new Error("PublicKey.getDigest is not implemented");
};

/**
 * Get the key type.
 * @returns {number} The key type as an int from KeyType.
 */
PublicKey.prototype.getKeyType = function()
{
  return this.keyType;
};

/**
 * Get the raw bytes of the public key in DER format.
 * @returns {Blob} The public key DER.
 */
PublicKey.prototype.getKeyDer = function()
{
  return this.keyDer;
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var IdentityCertificate = function IdentityCertificate()
{
};

exports.IdentityCertificate = IdentityCertificate;

/**
 * Get the public key name from the full certificate name.
 * @param {Name} certificateName The full certificate name.
 * @returns {Name} The related public key name.
 */
IdentityCertificate.certificateNameToPublicKeyName = function(certificateName)
{
  var i = certificateName.size() - 1;
  var idString = "ID-CERT";
  while (i >= 0) {
    if (certificateName.get(i).toEscapedString() == idString)
      break;
    i -= 1;
  }

  var tmpName = certificateName.getSubName(0, i);
  var keyString = "KEY";
  for (var i = 0; i < tmpName.size(); ++i) {
    if (tmpName.get(i).toEscapedString() == keyString)
      break;
  }

  return tmpName.getSubName(0, i).append
    (tmpName.getSubName(i + 1, tmpName.size() - i - 1));
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Name = require('../../name.js').Name;
var SecurityException = require('../security-exception.js').SecurityException;

/**
 * IdentityStorage is a base class for the storage of identity, public keys and
 * certificates. Private keys are stored in PrivateKeyStorage.
 * This is an abstract base class.  A subclass must implement the methods.
 * @constructor
 */
var IdentityStorage = function IdentityStorage()
{
};

exports.IdentityStorage = IdentityStorage;

/**
 * Check if the specified identity already exists.
 * @param {Name} identityName The identity name.
 * @returns {boolean} true if the identity exists, otherwise false.
 */
IdentityStorage.prototype.doesIdentityExist = function(identityName)
{
  throw new Error("IdentityStorage.doesIdentityExist is not implemented");
};

/**
 * Add a new identity. An exception will be thrown if the identity already exists.
 * @param {Name} identityName The identity name to be added.
 */
IdentityStorage.prototype.addIdentity = function(identityName)
{
  throw new Error("IdentityStorage.addIdentity is not implemented");
};

/**
 * Revoke the identity.
 * @returns {boolean} true if the identity was revoked, false if not.
 */
IdentityStorage.prototype.revokeIdentity = function()
{
  throw new Error("IdentityStorage.revokeIdentity is not implemented");
};

/**
 * Generate a name for a new key belonging to the identity.
 * @param {Name} identityName The identity name.
 * @param {boolean} useKsk If true, generate a KSK name, otherwise a DSK name.
 * @returns {Name} The generated key name.
 */
IdentityStorage.prototype.getNewKeyName = function(identityName, useKsk)
{
  var ti = new Date().getTime();
  // Get the number of seconds.
  var seconds = "" + Math.floor(ti / 1000.0);

  var keyIdStr;
  if (useKsk)
    keyIdStr = "KSK-" + seconds;
  else
    keyIdStr = "DSK-" + seconds;

  var keyName = new Name(identityName).append(keyIdStr);

  if (this.doesKeyExist(keyName))
    throw new SecurityException(new Error("Key name already exists"));

  return keyName;
};

/**
 * Check if the specified key already exists.
 * @param {Name} keyName The name of the key.
 * @returns {boolean} true if the key exists, otherwise false.
 */
IdentityStorage.prototype.doesKeyExist = function(keyName)
{
  throw new Error("IdentityStorage.doesKeyExist is not implemented");
};

/**
 * Add a public key to the identity storage.
 * @param {Name} keyName The name of the public key to be added.
 * @param {number} keyType Type of the public key to be added from KeyType, such
 * as KeyType.RSA..
 * @param {Blob} publicKeyDer A blob of the public key DER to be added.
 */
IdentityStorage.prototype.addKey = function(keyName, keyType, publicKeyDer)
{
  throw new Error("IdentityStorage.addKey is not implemented");
};

/**
 * Get the public key DER blob from the identity storage.
 * @param {Name} keyName The name of the requested public key.
 * @returns {Blob} The DER Blob.  If not found, return a Blob with a null pointer.
 */
IdentityStorage.prototype.getKey = function(keyName)
{
  throw new Error("IdentityStorage.getKey is not implemented");
};

/**
 * Get the KeyType of the public key with the given keyName.
 * @param {Name} keyName The name of the requested public key.
 * @returns {number} The KeyType, for example KEY_TYPE_RSA.
 */
IdentityStorage.prototype.getKeyType = function(keyName)
{
  throw new Error("IdentityStorage.getKeyType is not implemented");
};

/**
 * Activate a key.  If a key is marked as inactive, its private part will not be
 * used in packet signing.
 * @param {Name} keyName name of the key
 */
IdentityStorage.prototype.activateKey = function(keyName)
{
  throw new Error("IdentityStorage.activateKey is not implemented");
};

/**
 * Deactivate a key. If a key is marked as inactive, its private part will not
 * be used in packet signing.
 * @param {Name} keyName name of the key
 */
IdentityStorage.prototype.deactivateKey = function(keyName)
{
  throw new Error("IdentityStorage.deactivateKey is not implemented");
};

/**
 * Check if the specified certificate already exists.
 * @param {Name} certificateName The name of the certificate.
 * @returns {boolean} true if the certificate exists, otherwise false.
 */
IdentityStorage.prototype.doesCertificateExist = function(certificateName)
{
  throw new Error("IdentityStorage.doesCertificateExist is not implemented");
};

/**
 * Add a certificate to the identity storage.
 * @param {IdentityCertificate} certificate The certificate to be added.  This
 * makes a copy of the certificate.
 */
IdentityStorage.prototype.addCertificate = function(certificate)
{
  throw new Error("IdentityStorage.addCertificate is not implemented");
};

/**
 * Get a certificate from the identity storage.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {boolean} allowAny (optional) If false, only a valid certificate will
 * be returned, otherwise validity is disregarded. If omitted, allowAny is false.
 * @returns {Data} The requested certificate.  If not found, return a shared_ptr
 * with a null pointer.
 */
IdentityStorage.prototype.getCertificate = function(certificateName, allowAny)
{
  throw new Error("IdentityStorage.getCertificate is not implemented");
};

/*****************************************
 *           Get/Set Default             *
 *****************************************/

/**
 * Get the default identity.
 * @returns {Name} The name of default identity.
 * @throws SecurityException if the default identity is not set.
 */
IdentityStorage.prototype.getDefaultIdentity = function()
{
  throw new Error("IdentityStorage.getDefaultIdentity is not implemented");
};

/**
 * Get the default key name for the specified identity.
 * @param {Name} identityName The identity name.
 * @returns {Name} The default key name.
 * @throws SecurityException if the default key name for the identity is not set.
 */
IdentityStorage.prototype.getDefaultKeyNameForIdentity = function(identityName)
{
  throw new Error("IdentityStorage.getDefaultKeyNameForIdentity is not implemented");
};

/**
 * Get the default certificate name for the specified identity.
 * @param {Name} identityName The identity name.
 * @returns {Name} The default certificate name.
 * @throws SecurityException if the default key name for the identity is not
 * set or the default certificate name for the key name is not set.
 */
IdentityStorage.prototype.getDefaultCertificateNameForIdentity = function
  (identityName)
{
  var keyName = this.getDefaultKeyNameForIdentity(identityName);
  return this.getDefaultCertificateNameForKey(keyName);
};

/**
 * Get the default certificate name for the specified key.
 * @param {Name} keyName The key name.
 * @returns {Name} The default certificate name.
 * @throws SecurityException if the default certificate name for the key name
 * is not set.
 */
IdentityStorage.prototype.getDefaultCertificateNameForKey = function(keyName)
{
  throw new Error("IdentityStorage.getDefaultCertificateNameForKey is not implemented");
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 */
IdentityStorage.prototype.setDefaultIdentity = function(identityName)
{
  throw new Error("IdentityStorage.setDefaultIdentity is not implemented");
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} identityNameCheck (optional) The identity name to check the
 * keyName.
 */
IdentityStorage.prototype.setDefaultKeyNameForIdentity = function
  (keyName, identityNameCheck)
{
  throw new Error("IdentityStorage.setDefaultKeyNameForIdentity is not implemented");
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} certificateName The certificate name.
 */
IdentityStorage.prototype.setDefaultCertificateNameForKey = function
  (keyName, certificateName)
{
  throw new Error("IdentityStorage.setDefaultCertificateNameForKey is not implemented");
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Data = require('../../data.js').Data;
var Name = require('../../name.js').Name;
var Blob = require('../../util/blob.js').Blob;
var KeyType = require('../security-types.js').KeyType;
var DataUtils = require('../../encoding/data-utils.js').DataUtils;
var SecurityException = require('../security-exception.js').SecurityException;
var IdentityStorage = require('./identity-storage.js').IdentityStorage;

/**
 * MemoryIdentityStorage extends IdentityStorage and implements its methods to
 * store identity, public key and certificate objects in memory. The application
 * must get the objects through its own means and add the objects to the
 * MemoryIdentityStorage object. To use permanent file-based storage, see
 * BasicIdentityStorage.
 * @constructor
 */
var MemoryIdentityStorage = function MemoryIdentityStorage()
{
  // Call the base constructor.
  IdentityStorage.call(this);

  // A list of name URI.
  this.identityStore = [];
  // The default identity in identityStore_, or "" if not defined.
  this.defaultIdentity = "";
  // The key is the keyName.toUri(). The value is the object
  //  {keyType, // number from KeyType
  //   keyDer   // Blob
  //  }.
  this.keyStore = {};
  // The key is the key is the certificateName.toUri(). The value is the
  //   encoded certificate.
  this.certificateStore = {};
};

MemoryIdentityStorage.prototype = new IdentityStorage();
MemoryIdentityStorage.prototype.name = "MemoryIdentityStorage";

exports.MemoryIdentityStorage = MemoryIdentityStorage;
/**
 * Check if the specified identity already exists.
 * @param {Name} identityName The identity name.
 * @returns {boolean} true if the identity exists, otherwise false.
 */
MemoryIdentityStorage.prototype.doesIdentityExist = function(identityName)
{
  return this.identityStore[identityName.toUri()] !== undefined;
};

/**
 * Add a new identity. An exception will be thrown if the identity already exists.
 * @param {Name} identityName The identity name to be added.
 */
MemoryIdentityStorage.prototype.addIdentity = function(identityName)
{
  var identityUri = identityName.toUri();
  if (this.identityStore.indexOf(identityUri) >= 0)
      throw new SecurityException(new Error
        ("Identity already exists: " + identityUri));

  this.identityStore.push(identityUri);
};

/**
 * Revoke the identity.
 * @returns {boolean} true if the identity was revoked, false if not.
 */
MemoryIdentityStorage.prototype.revokeIdentity = function()
{
  throw new Error("MemoryIdentityStorage.revokeIdentity is not implemented");
};

/**
 * Check if the specified key already exists.
 * @param {Name} keyName The name of the key.
 * @returns {boolean} true if the key exists, otherwise false.
 */
MemoryIdentityStorage.prototype.doesKeyExist = function(keyName)
{
  return this.keyStore[keyName.toUri()] !== undefined;
};

/**
 * Add a public key to the identity storage.
 * @param {Name} keyName The name of the public key to be added.
 * @param {number} keyType Type of the public key to be added from KeyType, such
 * as KeyType.RSA..
 * @param {Blob} publicKeyDer A blob of the public key DER to be added.
 */
MemoryIdentityStorage.prototype.addKey = function(keyName, keyType, publicKeyDer)
{
  var identityName = keyName.getSubName(0, keyName.size() - 1);

  if (!this.doesIdentityExist(identityName))
    this.addIdentity(identityName);

  if (this.doesKeyExist(keyName))
    throw new SecurityException(new Error
      ("A key with the same name already exists!"));

  this.keyStore[keyName.toUri()] =
    { keyType: keyType, keyDer: new Blob(publicKeyDer) };
};

/**
 * Get the public key DER blob from the identity storage.
 * @param {Name} keyName The name of the requested public key.
 * @returns {Blob} The DER Blob.  If not found, return a Blob with a null pointer.
 */
MemoryIdentityStorage.prototype.getKey = function(keyName)
{
  var keyNameUri = keyName.toUri();
  var entry = this.keyStore[keyNameUri];
  if (entry === undefined)
    // Not found.  Silently return a null Blob.
    return new Blob();

  return entry.keyDer;
};

/**
 * Get the KeyType of the public key with the given keyName.
 * @param {Name} keyName The name of the requested public key.
 * @returns {number} The KeyType, for example KEY_TYPE_RSA.
 */
MemoryIdentityStorage.prototype.getKeyType = function(keyName)
{
  var keyNameUri = keyName.toUri();
  var entry = this.keyStore[keyNameUri];
  if (entry === undefined)
    throw new SecurityException(new Error
      ("Cannot get public key type because the keyName doesn't exist"));

  return entry.keyType;
};

/**
 * Activate a key.  If a key is marked as inactive, its private part will not be
 * used in packet signing.
 * @param {Name} keyName name of the key
 */
MemoryIdentityStorage.prototype.activateKey = function(keyName)
{
  throw new Error("MemoryIdentityStorage.activateKey is not implemented");
};

/**
 * Deactivate a key. If a key is marked as inactive, its private part will not
 * be used in packet signing.
 * @param {Name} keyName name of the key
 */
MemoryIdentityStorage.prototype.deactivateKey = function(keyName)
{
  throw new Error("MemoryIdentityStorage.deactivateKey is not implemented");
};

/**
 * Check if the specified certificate already exists.
 * @param {Name} certificateName The name of the certificate.
 * @returns {boolean} true if the certificate exists, otherwise false.
 */
MemoryIdentityStorage.prototype.doesCertificateExist = function(certificateName)
{
  return this.certificateStore[certificateName.toUri()] !== undefined;
};

/**
 * Add a certificate to the identity storage.
 * @param {IdentityCertificate} certificate The certificate to be added.  This
 * makes a copy of the certificate.
 */
MemoryIdentityStorage.prototype.addCertificate = function(certificate)
{
  var certificateName = certificate.getName();
  var keyName = certificate.getPublicKeyName();

  if (!this.doesKeyExist(keyName))
    throw new SecurityException(new Error
      ("No corresponding Key record for certificate! " +
       keyName.toUri() + " " + certificateName.toUri()));

  // Check if the certificate already exists.
  if (this.doesCertificateExist(certificateName))
    throw new SecurityException(new Error
      ("Certificate has already been installed!"));

  // Check if the public key of the certificate is the same as the key record.
  var keyBlob = getKey(keyName);
  if (keyBlob.isNull() ||
      !DataUtils.arraysEqual(keyBlob.buf(),
        certificate.getPublicKeyInfo().getKeyDer().buf()))
    throw new SecurityException(new Error
      ("The certificate does not match the public key!"));

  // Insert the certificate.
  // wireEncode returns the cached encoding if available.
  this.certificateStore[certificateName.toUri()] = certificate.wireEncode();
};

/**
 * Get a certificate from the identity storage.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {boolean} allowAny (optional) If false, only a valid certificate will
 * be returned, otherwise validity is disregarded. If omitted, allowAny is false.
 * @returns {Data} The requested certificate.  If not found, return null.
 */
MemoryIdentityStorage.prototype.getCertificate = function(certificateName, allowAny)
{
  var certificateNameUri = certificateName.toUri();
  if (this.certificateStore[certificateNameUri] === undefined)
    // Not found.  Silently return null.
    return null;

  var data = new Data();
  data.wireDecode(this.certificateStore[certificateNameUri]);
  return data;
};

/*****************************************
 *           Get/Set Default             *
 *****************************************/

/**
 * Get the default identity.
 * @returns {Name} The name of default identity.
 * @throws SecurityException if the default identity is not set.
 */
MemoryIdentityStorage.prototype.getDefaultIdentity = function()
{
  if (this.defaultIdentity.length === 0)
    throw new SecurityException(new Error
      ("MemoryIdentityStorage.getDefaultIdentity: The default identity is not defined"));

  return new Name(this.defaultIdentity);
};

/**
 * Get the default key name for the specified identity.
 * @param {Name} identityName The identity name.
 * @returns {Name} The default key name.
 * @throws SecurityException if the default key name for the identity is not set.
 */
MemoryIdentityStorage.prototype.getDefaultKeyNameForIdentity = function
  (identityName)
{
  throw new Error("MemoryIdentityStorage.getDefaultKeyNameForIdentity is not implemented");
};

/**
 * Get the default certificate name for the specified key.
 * @param {Name} keyName The key name.
 * @returns {Name} The default certificate name.
 * @throws SecurityException if the default certificate name for the key name
 * is not set.
 */
MemoryIdentityStorage.prototype.getDefaultCertificateNameForKey = function(keyName)
{
  throw new Error("MemoryIdentityStorage.getDefaultCertificateNameForKey is not implemented");
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 */
MemoryIdentityStorage.prototype.setDefaultIdentity = function(identityName)
{
  var identityUri = identityName.toUri();
  if (this.identityStore[identityUri] !== undefined)
    this.defaultIdentity = identityUri;
  else
    // The identity doesn't exist, so clear the default.
    this.defaultIdentity = "";
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} identityNameCheck (optional) The identity name to check the
 * keyName.
 */
MemoryIdentityStorage.prototype.setDefaultKeyNameForIdentity = function
  (keyName, identityNameCheck)
{
  throw new Error("MemoryIdentityStorage.setDefaultKeyNameForIdentity is not implemented");
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} certificateName The certificate name.
 */
MemoryIdentityStorage.prototype.setDefaultCertificateNameForKey = function
  (keyName, certificateName)
{
  throw new Error("MemoryIdentityStorage.setDefaultCertificateNameForKey is not implemented");
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * PrivateKeyStorage is an abstract class which declares methods for working
 * with a private key storage. You should use a subclass.
 * @constructor
 */
var PrivateKeyStorage = function PrivateKeyStorage()
{
};

exports.PrivateKeyStorage = PrivateKeyStorage;

/**
 * Generate a pair of asymmetric keys.
 * @param {Name} keyName The name of the key pair.
 * @param {number} keyType (optional) The type of the key pair, e.g. KeyType.RSA.
 * If omitted, use KeyType.RSA.
 * @param {number} keySize (optional) The size of the key pair. If omitted, use
 * 2048.
 */
PrivateKeyStorage.prototype.generateKeyPair = function(keyName, keyType, keySize)
{
  throw new Error("PrivateKeyStorage.generateKeyPair is not implemented");
};

/**
 * Get the public key
 * @param {Name} keyName The name of public key.
 * @returns {PublicKey} The public key.
 */
PrivateKeyStorage.prototype.getPublicKey = function(keyName)
{
  throw new Error("PrivateKeyStorage.getPublicKey is not implemented");
};

/**
 * Fetch the private key for keyName and sign the data, returning a signature Blob.
 * @param {Buffer} data Pointer to the input byte array.
 * @param {Name} keyName The name of the signing key.
 * @param {number} digestAlgorithm (optional) The digest algorithm from
 * DigestAlgorithm, such as DigestAlgorithm.SHA256. If omitted, use
 * DigestAlgorithm.SHA256.
 * @returns {Blob} The signature, or a isNull() Blob if signing fails.
 */
PrivateKeyStorage.prototype.sign = function(data, keyName, digestAlgorithm)
{
  throw new Error("PrivateKeyStorage.sign is not implemented");
};

/**
 * Decrypt data.
 * @param {Name} keyName The name of the decrypting key.
 * @param {Buffer} data The byte to be decrypted.
 * @param {boolean} isSymmetric (optional) If true symmetric encryption is used,
 * otherwise asymmetric encryption is used. If omitted, use asymmetric
 * encryption.
 * @returns {Blob} The decrypted data.
 */
PrivateKeyStorage.prototype.decrypt = function(keyName, data, isSymmetric)
{
  throw new Error("PrivateKeyStorage.decrypt is not implemented");
};

/**
 * Encrypt data.
 * @param {Name} keyName The name of the encrypting key.
 * @param {Buffer} data The byte to be encrypted.
 * @param {boolean} isSymmetric (optional) If true symmetric encryption is used,
 * otherwise asymmetric encryption is used. If omitted, use asymmetric
 * encryption.
 * @returns {Blob} The encrypted data.
 */
PrivateKeyStorage.prototype.encrypt = function(keyName, data, isSymmetric)
{
  throw new Error("PrivateKeyStorage.encrypt is not implemented");
};

/**
 * @brief Generate a symmetric key.
 * @param {Name} keyName The name of the key.
 * @param {number} keyType (optional) The type of the key from KeyType, e.g.
 * KeyType.AES. If omitted, use KeyType.AES.
 * @param {number} keySize (optional) The size of the key. If omitted, use 256.
 */
PrivateKeyStorage.prototype.generateKey = function(keyName, keyType, keySize)
{
  throw new Error("PrivateKeyStorage.generateKey is not implemented");
};

/**
 * Check if a particular key exists.
 * @param {Name} keyName The name of the key.
 * @param {number} keyClass The class of the key, e.g. KeyClass.PUBLIC,
 * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
 * @returns {boolean} True if the key exists, otherwise false.
 */
PrivateKeyStorage.prototype.doesKeyExist = function(keyName, keyClass)
{
  throw new Error("PrivateKeyStorage.doesKeyExist is not implemented");
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('../../util/blob.js').Blob;
var SecurityException = require('../security-exception.js').SecurityException;
var PublicKey = require('../certificate/public-key.js').PublicKey;
var KeyClass = require('../security-types.js').KeyClass;
var DigestAlgorithm = require('../security-types.js').DigestAlgorithm;
var DataUtils = require('../../encoding/data-utils.js').DataUtils;
var PrivateKeyStorage = require('./private-key-storage.js').PrivateKeyStorage;

/**
 * MemoryPrivateKeyStorage class extends PrivateKeyStorage to implement private
 * key storage in memory.
 * @constructor
 */
var MemoryPrivateKeyStorage = function MemoryPrivateKeyStorage()
{
  // Call the base constructor.
  PrivateKeyStorage.call(this);

  // The key is the keyName.toUri(). The value is security.certificate.PublicKey.
  this.publicKeyStore = {};
  // The key is the keyName.toUri(). The value is the object
  //  {keyType,     // number from KeyType
  //   privateKey   // The PEM-encoded private key.
  //  }.
  this.privateKeyStore = {};
};

MemoryPrivateKeyStorage.prototype = new PrivateKeyStorage();
MemoryPrivateKeyStorage.prototype.name = "MemoryPrivateKeyStorage";

exports.MemoryPrivateKeyStorage = MemoryPrivateKeyStorage;

/**
 * Set the public key for the keyName.
 * @param {Name} keyName The key name.
 * @param {number} keyType The KeyType, such as KeyType.RSA.
 * @param {Buffer} publicKeyDer The public key DER byte array.
 */
MemoryPrivateKeyStorage.prototype.setPublicKeyForKeyName = function
  (keyName, keyType, publicKeyDer)
{
  this.publicKeyStore[keyName.toUri()] = PublicKey.fromDer(
    keyType, new Blob(publicKeyDer, true));
};

/**
 * Set the private key for the keyName.
 * @param {Name} keyName The key name.
 * @param {number} keyType The KeyType, such as KeyType.RSA.
 * @param {Buffer} privateKeyDer The private key DER byte array.
 */
MemoryPrivateKeyStorage.prototype.setPrivateKeyForKeyName = function
  (keyName, keyType, privateKeyDer)
{
  // Encode the DER as PEM.
  var keyBase64 = privateKeyDer.toString('base64');
  var keyPem = "-----BEGIN RSA PRIVATE KEY-----\n";
  for (var i = 0; i < keyBase64.length; i += 64)
    keyPem += (keyBase64.substr(i, 64) + "\n");
  keyPem += "-----END RSA PRIVATE KEY-----";

  this.privateKeyStore[keyName.toUri()] =
    { keyType: keyType, privateKey: keyPem };
};

/**
 * Set the public and private key for the keyName.
 * @param {Name} keyName The key name.
 * @param {number} keyType The KeyType, such as KeyType.RSA.
 * @param {Buffer} publicKeyDer The public key DER byte array.
 * @param {Buffer} privateKeyDer The private key DER byte array.
 */
MemoryPrivateKeyStorage.prototype.setKeyPairForKeyName = function
  (keyName, keyType, publicKeyDer, privateKeyDer)
{
  this.setPublicKeyForKeyName(keyName, keyType, publicKeyDer);
  this.setPrivateKeyForKeyName(keyName, keyType, privateKeyDer);
};

/**
 * Get the public key
 * @param {Name} keyName The name of public key.
 * @returns {PublicKey} The public key.
 */
MemoryPrivateKeyStorage.prototype.getPublicKey = function(keyName)
{
  var keyNameUri = keyName.toUri();
  var publicKey = this.publicKeyStore[keyNameUri];
  if (publicKey === undefined)
    throw new SecurityException(new Error
      ("MemoryPrivateKeyStorage: Cannot find public key " + keyName.toUri()));

  return publicKey;
};

/**
 * Fetch the private key for keyName and sign the data, returning a signature Blob.
 * @param {Buffer} data Pointer to the input byte array.
 * @param {Name} keyName The name of the signing key.
 * @param {number} digestAlgorithm (optional) The digest algorithm from
 * DigestAlgorithm, such as DigestAlgorithm.SHA256. If omitted, use
 * DigestAlgorithm.SHA256.
 * @returns {Blob} The signature, or a isNull() Blob if signing fails.
 */
MemoryPrivateKeyStorage.prototype.sign = function(data, keyName, digestAlgorithm)
{
  if (digestAlgorithm == null)
    digestAlgorithm = DigestAlgorithm.SHA256;

  if (digestAlgorithm != DigestAlgorithm.SHA256)
    return new Blob();

  // Find the private key.
  var keyUri = keyName.toUri();
  var privateKey = this.privateKeyStore[keyUri];
  if (privateKey === undefined)
    throw new SecurityException(new Error
      ("MemoryPrivateKeyStorage: Cannot find private key " + keyUri));

  var rsa = require("crypto").createSign('RSA-SHA256');
  rsa.update(data);

  var signature = new Buffer
    (DataUtils.toNumbersIfString(rsa.sign(privateKey.privateKey)));
  return new Blob(signature, false);
};

/**
 * Check if a particular key exists.
 * @param {Name} keyName The name of the key.
 * @param {number} keyClass The class of the key, e.g. KeyClass.PUBLIC,
 * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
 * @returns {boolean} True if the key exists, otherwise false.
 */
MemoryPrivateKeyStorage.prototype.doesKeyExist = function(keyName, keyClass)
{
  var keyUri = keyName.toUri();
  if (keyClass == KeyClass.PUBLIC)
    return this.publicKeyStore[keyUri] !== undefined;
  else if (keyClass == KeyClass.PRIVATE)
    return this.privateKeyStore[keyUri] !== undefined;
  else
    // KeyClass.SYMMETRIC not implemented yet.
    return false ;
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Name = require('../../name.js').Name;
var Data = require('../../data.js').Data;
var Sha256WithRsaSignature = require('../../sha256-with-rsa-signature.js').Sha256WithRsaSignature;
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType;
var WireFormat = require('../../encoding/wire-format.js').WireFormat;
var SecurityException = require('../security-exception.js').SecurityException;

/**
 * An IdentityManager is the interface of operations related to identity, keys,
 * and certificates.
 *
 * Create a new IdentityManager to use the given IdentityStorage and
 * PrivateKeyStorage.
 * @param {IdentityStorage} identityStorage An object of a subclass of
 * IdentityStorage.
 * @param {PrivateKeyStorage} privateKeyStorage An object of a subclass of
 * PrivateKeyStorage.
 * @constructor
 */
var IdentityManager = function IdentityManager
  (identityStorage, privateKeyStorage)
{
  this.identityStorage = identityStorage;
  this.privateKeyStorage = privateKeyStorage;
};

exports.IdentityManager = IdentityManager;

/**
 * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
 * identity and a self-signed certificate of the KSK.
 * @param {Name} identityName The name of the identity.
 * @returns {Name} The key name of the auto-generated KSK of the identity.
 */
IdentityManager.prototype.createIdentity = function(identityName)
{
  throw new Error("IdentityManager.createIdentity is not implemented");
};

/**
 * Get the default identity.
 * @returns {Name} The name of default identity.
 * @throws SecurityException if the default identity is not set.
 */
IdentityManager.prototype.getDefaultIdentity = function()
{
  return this.identityStorage.getDefaultIdentity();
};

/**
 * Generate a pair of RSA keys for the specified identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk (optional) true for generating a Key-Signing-Key (KSK),
 * false for a Data-Signing-Key (DSK). If omitted, generate a Data-Signing-Key.
 * @param {number} keySize (optional) The size of the key. If omitted, use a
 * default secure key size.
 * @returns {Name} The generated key name.
 */
IdentityManager.prototype.generateRSAKeyPair = function
  (identityName, isKsk, keySize)
{
  throw new Error("IdentityManager.generateRSAKeyPair is not implemented");
};

/**
 * Set a key as the default key of an identity.
 * @param {Name} keyName The name of the key.
 * @param {Name} identityName (optional) the name of the identity. If not
 * specified, the identity name is inferred from the keyName.
 */
IdentityManager.prototype.setDefaultKeyForIdentity = function
  (keyName, identityName)
{
  if (identityName == null)
    identityName = new Name();
  this.identityStorage.setDefaultKeyNameForIdentity(keyName, identityName);
};

/**
 * Get the default key for an identity.
 * @param {Name} identityName The name of the identity.
 * @returns {Name} The default key name.
 * @throws SecurityException if the default key name for the identity is not set.
 */
IdentityManager.prototype.getDefaultKeyNameForIdentity = function(identityName)
{
  return this.identityStorage.getDefaultKeyNameForIdentity(identityName);
};

/**
 * Generate a pair of RSA keys for the specified identity and set it as default
 * key for the identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk (optional) true for generating a Key-Signing-Key (KSK),
 * false for a Data-Signing-Key (DSK). If omitted, generate a Data-Signing-Key.
 * @param {number} keySize (optional) The size of the key. If omitted, use a
 * default secure key size.
 * @returns {Name} The generated key name.
 */
IdentityManager.prototype.generateRSAKeyPairAsDefault = function
  (identityName, isKsk, keySize)
{
  throw new Error("IdentityManager.generateRSAKeyPairAsDefault is not implemented");
};

/**
 * Get the public key with the specified name.
 * @param {Name} keyName The name of the key.
 * @returns {PublicKey} The public key.
 */
IdentityManager.prototype.getPublicKey = function(keyName)
{
  return PublicKey.fromDer
    (this.identityStorage.getKeyType(keyName),
     this.identityStorage.getKey(keyName));
};

// TODO: Add two versions of createIdentityCertificate.

/**
 * Add a certificate into the public key identity storage.
 * @param {IdentityCertificate} certificate The certificate to to added. This
 * makes a copy of the certificate.
 */
IdentityManager.prototype.addCertificate = function(certificate)
{
  this.identityStorage.addCertificate(certificate);
};

/**
 * Set the certificate as the default for its corresponding key.
 * @param {IdentityCertificate} certificate The certificate.
 */
IdentityManager.prototype.setDefaultCertificateForKey = function(certificate)
{
  var keyName = certificate.getPublicKeyName();

  if (!this.identityStorage.doesKeyExist(keyName))
      throw new SecurityException(new Error
        ("No corresponding Key record for certificate!"));

  this.identityStorage.setDefaultCertificateNameForKey
    (keyName, certificate.getName());
};

/**
 * Add a certificate into the public key identity storage and set the
 * certificate as the default for its corresponding identity.
 * @param {IdentityCertificate} certificate The certificate to be added. This
 * makes a copy of the certificate.
 */
IdentityManager.prototype.addCertificateAsIdentityDefault = function(certificate)
{
  this.identityStorage.addCertificate(certificate);
  var keyName = certificate.getPublicKeyName();
  this.setDefaultKeyForIdentity(keyName);
  this.setDefaultCertificateForKey(certificate);
};

/**
 * Add a certificate into the public key identity storage and set the
 * certificate as the default of its corresponding key.
 * @param {IdentityCertificate} certificate The certificate to be added.  This makes a copy of the certificate.
 */
IdentityManager.prototype.addCertificateAsDefault = function(certificate)
{
  this.identityStorage.addCertificate(certificate);
  this.setDefaultCertificateForKey(certificate);
};

/**
 * Get a certificate with the specified name.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} the requested certificate which is valid.
 */
IdentityManager.prototype.getCertificate = function(certificateName)
{
  return new IdentityCertificate
    (this.identityStorage.getCertificate(certificateName, false));
};

/**
 * Get a certificate even if the certificate is not valid anymore.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} the requested certificate.
 */
IdentityManager.prototype.getAnyCertificate = function(certificateName)
{
  return new IdentityCertificate
    (this.identityStorage.getCertificate(certificateName, true));
};

/**
 * Get the default certificate name for the specified identity, which will be
 * used when signing is performed based on identity.
 * @param {Name} identityName The name of the specified identity.
 * @returns {Name} The requested certificate name.
 * @throws SecurityException if the default key name for the identity is not
 * set or the default certificate name for the key name is not set.
 */
IdentityManager.prototype.getDefaultCertificateNameForIdentity = function
  (identityName)
{
  return this.identityStorage.getDefaultCertificateNameForIdentity(identityName);
};

/**
 * Get the default certificate name of the default identity, which will be used when signing is based on identity and
 * the identity is not specified.
 * @returns {Name} The requested certificate name.
 * @throws SecurityException if the default identity is not set or the default
 * key name for the identity is not set or the default certificate name for
 * the key name is not set.
 */
IdentityManager.prototype.getDefaultCertificateName = function()
{
  return this.identityStorage.getDefaultCertificateNameForIdentity
    (this.getDefaultIdentity());
};

/**
 * Sign the byte array data based on the certificate name.
 * @param {Buffer} target If this is a Data object, wire encode for signing,
 * update its signature and key locator field and wireEncoding. If it is an
 * array, sign it and return a Signature object.
 * @param {Name} certificateName The Name identifying the certificate which
 * identifies the signing key.
 * @param {WireFormat} (optional) The WireFormat for calling encodeData, or
 * WireFormat.getDefaultWireFormat() if omitted.
 * @returns {Signature} The generated signature.
 */
IdentityManager.prototype.signByCertificate = function
  (target, certificateName, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (target instanceof Data) {
    var data = target;
    var keyName = IdentityManager.certificateNameToPublicKeyName(certificateName);

    // For temporary usage, we support RSA + SHA256 only, but will support more.
    data.setSignature(new Sha256WithRsaSignature());
    // Get a pointer to the clone which Data made.
    var signature = data.getSignature();
    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));

    // Set an empty signature so that we can encode.
    signature.setSignature(new Buffer(1));
    // Encode once to get the signed portion.
    var encoding = data.wireEncode(wireFormat);

    signature.setSignature(this.privateKeyStorage.sign
      (encoding.signedBuf(), keyName));

    // Encode again to include the signature.
    data.wireEncode(wireFormat);
  }
  else {
    var keyName = IdentityManager.certificateNameToPublicKeyName(certificateName);

    // For temporary usage, we support RSA + SHA256 only, but will support more.
    var signature = new Sha256WithRsaSignature();

    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));

    signature.setSignature(this.privateKeyStorage.sign(target, keyName));

    return signature;
  }
};

/**
 * Generate a self-signed certificate for a public key.
 * @param {Name} keyName The name of the public key.
 * @returns {IdentityCertificate} The generated certificate.
 */
IdentityManager.prototype.selfSign = function(keyName)
{
  throw new Error("IdentityManager.selfSign is not implemented");
};

/**
 * Get the public key name from the full certificate name.
 *
 * @param {Name} certificateName The full certificate name.
 * @returns {Name} The related public key name.
 * TODO: Move this to IdentityCertificate
 */
IdentityManager.certificateNameToPublicKeyName = function(certificateName)
{
  var i = certificateName.size() - 1;
  var idString = "ID-CERT";
  while (i >= 0) {
    if (certificateName.get(i).toEscapedString() == idString)
      break;
    --i;
  }

  var tmpName = certificateName.getSubName(0, i);
  var keyString = "KEY";
  i = 0;
  while (i < tmpName.size()) {
    if (tmpName.get(i).toEscapedString() == keyString)
      break;
    ++i;
  }

  return tmpName.getSubName(0, i).append(tmpName.getSubName
    (i + 1, tmpName.size() - i - 1));
};/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * A ValidationRequest is used to return information from
 * PolicyManager.checkVerificationPolicy.
 *
 * Create a new ValidationRequest with the given values.
 * @param {Interest} interest An interest for fetching more data.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(data).
 * @param {boolean} retry
 * @param {number} stepCount  The number of verification steps that have been
 * done, used to track the verification progress.
 * @constructor
 */
var ValidationRequest = function ValidationRequest
  (interest, onVerified, onVerifyFailed, retry, stepCount)
{
  this.interest = interest;
  this.onVerified = onVerified;
  this.onVerifyFailed = onVerifyFailed;
  this.retry = retry;
  this.stepCount = stepCount;
};

exports.ValidationRequest = ValidationRequest;
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * A PolicyManager is an abstract base class to represent the policy for
 * verifying data packets. You must create an object of a subclass.
 * @constructor
 */
var PolicyManager = function PolicyManager()
{
};

exports.PolicyManager = PolicyManager;

/**
 * Check if the received data packet or signed interest can escape from
 * verification and be trusted as valid.
 * Your derived class should override.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True if the data or interest does not need to be verified
 * to be trusted as valid, otherwise false.
 */
PolicyManager.prototype.skipVerifyAndTrust = function(dataOrInterest)
{
  throw new Error("PolicyManager.skipVerifyAndTrust is not implemented");
};

/**
 * Check if this PolicyManager has a verification rule for the received data
 * packet or signed interest.
 * Your derived class should override.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True if the data or interest must be verified, otherwise
 * false.
 */
PolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  throw new Error("PolicyManager.requireVerify is not implemented");
};

/**
 * Check whether the received data packet complies with the verification policy,
 * and get the indication of the next verification step.
 * Your derived class should override.
 *
 * @param {Data|Interest} dataOrInterest The Data object or interest with the
 * signature to check.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(data).
 * @param {WireFormat} wireFormat
 * @returns {ValidationRequest} The indication of next verification step, or
 * null if there is no further step.
 */
PolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onVerifyFailed, wireFormat)
{
  throw new Error("PolicyManager.checkVerificationPolicy is not implemented");
};

/**
 * Check if the signing certificate name and data name satisfy the signing
 * policy.
 * Your derived class should override.
 *
 * @param {Name} dataName The name of data to be signed.
 * @param {Name} certificateName The name of signing certificate.
 * @returns {boolean} True if the signing certificate can be used to sign the
 * data, otherwise false.
 */
PolicyManager.prototype.checkSigningPolicy = function(dataName, certificateName)
{
  throw new Error("PolicyManager.checkSigningPolicy is not implemented");
};

/**
 * Infer the signing identity name according to the policy. If the signing
 * identity cannot be inferred, return an empty name.
 * Your derived class should override.
 *
 * @param {Name} dataName The name of data to be signed.
 * @returns {Name} The signing identity or an empty name if cannot infer.
 */
PolicyManager.prototype.inferSigningIdentity = function(dataName)
{
  throw new Error("PolicyManager.inferSigningIdentity is not implemented");
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Name = require('../../name.js').Name;
var PolicyManager = require('./policy-manager.js').PolicyManager;

/**
 * @constructor
 */
var NoVerifyPolicyManager = function NoVerifyPolicyManager()
{
  // Call the base constructor.
  PolicyManager.call(this);
};

NoVerifyPolicyManager.prototype = new PolicyManager();
NoVerifyPolicyManager.prototype.name = "NoVerifyPolicyManager";

exports.NoVerifyPolicyManager = NoVerifyPolicyManager;

/**
 * Override to always skip verification and trust as valid.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True.
 */
NoVerifyPolicyManager.prototype.skipVerifyAndTrust = function(dataOrInterest)
{
  return true;
};

/**
 * Override to return false for no verification rule for the received data or
 * signed interest.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} False.
 */
NoVerifyPolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  return false;
};

/**
 * Override to call onVerified(data) and to indicate no further verification
 * step.
 *
 * @param {Data|Interest} dataOrInterest The Data object or interest with the
 * signature to check.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {function} onVerified This does override to call
 * onVerified(dataOrInterest).
 * @param {function} onVerifyFailed Override to ignore this.
 * @param {WireFormat} wireFormat
 * @returns {ValidationRequest} null for no further step for looking up a
 * certificate chain.
 */
NoVerifyPolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onVerifyFailed, wireFormat)
{
  onVerified(dataOrInterest);
  return null;
};

/**
 * Override to always indicate that the signing certificate name and data name
 * satisfy the signing policy.
 *
 * @param {Name} dataName The name of data to be signed.
 * @param {Name} certificateName The name of signing certificate.
 * @returns {boolean} True to indicate that the signing certificate can be used
 * to sign the data.
 */
NoVerifyPolicyManager.prototype.checkSigningPolicy = function
  (dataName, certificateName)
{
  return true;
};

/**
 * Override to indicate that the signing identity cannot be inferred.
 *
 * @param {Name} dataName The name of data to be signed.
 * @returns {Name} An empty name because cannot infer.
 */
NoVerifyPolicyManager.prototype.inferSigningIdentity = function(dataName)
{
  return new Name();
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Name = require('../../name.js').Name;
var Data = require('../../data.js').Data;
var DataUtils = require('../../encoding/data-utils.js').DataUtils;
var IdentityCertificate = require('../certificate/identity-certificate.js').IdentityCertificate;
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType;
var SecurityException = require('../security-exception.js').SecurityException;
var WireFormat = require('../../encoding/wire-format.js').WireFormat;
var PolicyManager = require('./policy-manager.js').PolicyManager;

/**
 * A SelfVerifyPolicyManager implements a PolicyManager to use the public key
 * DER in the data packet's KeyLocator (if available) or look in the
 * IdentityStorage for the public key with the name in the KeyLocator (if
 * available) and use it to verify the data packet, without searching a
 * certificate chain.  If the public key can't be found, the verification fails.
 *
 * @param {IdentityStorage} identityStorage (optional) The IdentityStorage for
 * looking up the public key. This object must remain valid during the life of
 * this SelfVerifyPolicyManager. If omitted, then don't look for a public key
 * with the name in the KeyLocator and rely on the KeyLocator having the full
 * public key DER.
 * @constructor
 */
var SelfVerifyPolicyManager = function SelfVerifyPolicyManager(identityStorage)
{
  // Call the base constructor.
  PolicyManager.call(this);

  this.identityStorage = identityStorage;
};

SelfVerifyPolicyManager.prototype = new PolicyManager();
SelfVerifyPolicyManager.prototype.name = "SelfVerifyPolicyManager";

exports.SelfVerifyPolicyManager = SelfVerifyPolicyManager;

/**
 * Never skip verification.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} False.
 */
SelfVerifyPolicyManager.prototype.skipVerifyAndTrust = function(dataOrInterest)
{
  return false;
};

/**
 * Always return true to use the self-verification rule for the received data.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True.
 */
SelfVerifyPolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  return true;
};

/**
 * Use the public key DER in the KeyLocator (if available) or look in the
 * IdentityStorage for the public key with the name in the KeyLocator (if
 * available) and use it to verify the data packet.  If the public key can't
   * be found, call onVerifyFailed.
 *
 * @param {Data|Interest} dataOrInterest The Data object or interest with the
 * signature to check.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(data).
 * @param {WireFormat} wireFormat
 * @returns {ValidationRequest} null for no further step for looking up a
 * certificate chain.
 */
SelfVerifyPolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onVerifyFailed, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (dataOrInterest instanceof Data) {
    var data = dataOrInterest;
    // wireEncode returns the cached encoding if available.
    if (this.verify(data.getSignature(), data.wireEncode()))
      onVerified(data);
    else
      onVerifyFailed(data);
  }
  else if (dataOrInterest instanceof Interest) {
    var interest = dataOrInterest;
    // Decode the last two name components of the signed interest
    var signature = wireFormat.decodeSignatureInfoAndValue
      (interest.getName().get(-2).getValue().buf(),
       interest.getName().get(-1).getValue().buf());

    // wireEncode returns the cached encoding if available.
    if (this.verify(signature, interest.wireEncode()))
      onVerified(interest);
    else
      onVerifyFailed(interest);
  }
  else
    throw new SecurityException(new Error
      ("checkVerificationPolicy: unrecognized type for dataOrInterest"));

  // No more steps, so return a None.
  return null;
};

/**
 * Override to always indicate that the signing certificate name and data name
 * satisfy the signing policy.
 *
 * @param {Name} dataName The name of data to be signed.
 * @param {Name} certificateName The name of signing certificate.
 * @returns {boolean} True to indicate that the signing certificate can be used
 * to sign the data.
 */
SelfVerifyPolicyManager.prototype.checkSigningPolicy = function
  (dataName, certificateName)
{
  return true;
};

/**
 * Override to indicate that the signing identity cannot be inferred.
 *
 * @param {Name} dataName The name of data to be signed.
 * @returns {Name} An empty name because cannot infer.
 */
SelfVerifyPolicyManager.prototype.inferSigningIdentity = function(dataName)
{
  return new Name();
};

/**
 * Check the type of signatureInfo to get the KeyLocator. Use the public key
 * DER in the KeyLocator (if available) or look in the IdentityStorage for the
 * public key with the name in the KeyLocator (if available) and use it to
 * verify the signedBlob. If the public key can't be found, return false.
 * (This is a generalized method which can verify both a Data packet and an
 * interest.)
 * @param {Signature} signatureInfo An object of a subclass of Signature, e.g.
 * Sha256WithRsaSignature.
 * @param {SignedBlob} signedBlob the SignedBlob with the signed portion to
 * verify.
 * @returns {boolean} True if the signature is verified, false if failed.
 */
SelfVerifyPolicyManager.prototype.verify = function(signatureInfo, signedBlob)
{
  var signature = signatureInfo;
  /*
  if (!signature)
    throw new SecurityException(new Error
      ("SelfVerifyPolicyManager: Signature is not Sha256WithRsaSignature.");
  */

  if (signature.getKeyLocator().getType() == KeyLocatorType.KEY)
    // Use the public key DER directly.
    return SelfVerifyPolicyManager.verifySha256WithRsaSignature
      (signature, signedBlob, signature.getKeyLocator().getKeyData());
  else if (signature.getKeyLocator().getType() == KeyLocatorType.KEYNAME &&
           this.identityStorage != null) {
    // Assume the key name is a certificate name.
    var publicKeyDer = this.identityStorage.getKey
      (IdentityCertificate.certificateNameToPublicKeyName
       (signature.getKeyLocator().getKeyName()));
    if (publicKeyDer.isNull())
      // Can't find the public key with the name.
      return false;

    return SelfVerifyPolicyManager.verifySha256WithRsaSignature
      (signature, signedBlob, publicKeyDer);
  }
  else
    // Can't find a key to verify.
    return false;
};

// The first time verify is called, it sets this to determine if a signature
//   buffer needs to be converted to a string for the crypto verifier.
SelfVerifyPolicyManager.verifyUsesString = null;

/**
 * Verify the RSA signature on the SignedBlob using the given public key.
 * TODO: Move this general verification code to a more central location.
 * @param signature {Sha256WithRsaSignature} The Sha256WithRsaSignature.
 * @param signedBlob {SignedBlob} the SignedBlob with the signed portion to
 * verify.
 * @param publicKeyDer {Blob} The DER-encoded public key used to verify the
 * signature.
 * @returns true if the signature verifies, false if not.
 */
SelfVerifyPolicyManager.verifySha256WithRsaSignature = function
  (signature, signedBlob, publicKeyDer)
{
  if (SelfVerifyPolicyManager.verifyUsesString === null) {
    var hashResult = require("crypto").createHash('sha256').digest();
    // If the hash result is a string, we assume that this is a version of
    //   crypto where verify also uses a string signature.
    SelfVerifyPolicyManager.verifyUsesString = (typeof hashResult === 'string');
  }

  // The crypto verifier requires a PEM-encoded public key.
  var keyBase64 = publicKeyDer.buf().toString('base64');
  var keyPem = "-----BEGIN PUBLIC KEY-----\n";
  for (var i = 0; i < keyBase64.length; i += 64)
    keyPem += (keyBase64.substr(i, 64) + "\n");
  keyPem += "-----END PUBLIC KEY-----";

  var verifier = require('crypto').createVerify('RSA-SHA256');
  verifier.update(signedBlob.signedBuf());
  var signatureBytes = Data.verifyUsesString ?
    DataUtils.toString(signature.getSignature().buf()) :
    signature.getSignature().buf();
  return verifier.verify(keyPem, signatureBytes);
};
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Name = require('../name.js').Name;
var Interest = require('../interest.js').Interest;
var Data = require('../data.js').Data;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature;
var WireFormat = require('../encoding/wire-format.js').WireFormat;
var Tlv = require('../encoding/tlv/tlv.js').Tlv;
var TlvEncoder = require('../encoding/tlv/tlv-encoder.js').TlvEncoder;
var SecurityException = require('./security-exception.js').SecurityException;

/**
 * A KeyChain provides a set of interfaces to the security library such as
 * identity management, policy configuration and packet signing and verification.
 * Note: This class is an experimental feature. See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/key-chain.html .
 *
 * Create a new KeyChain with the given IdentityManager and PolicyManager.
 * @param {IdentityManager} identityManager An object of a subclass of
 * IdentityManager.
 * @param {PolicyManager} policyManager An object of a subclass of
 * PolicyManager.
 * @constructor
 */
var KeyChain = function KeyChain(identityManager, policyManager)
{
  this.identityManager = identityManager;
  this.policyManager = policyManager;
  this.encryptionManager = null;
  this.face = null;
  this.maxSteps = 100;
};

exports.KeyChain = KeyChain;

/*****************************************
 *          Identity Management          *
 *****************************************/

/**
 * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
 * identity and a self-signed certificate of the KSK.
 * @param {Name} identityName The name of the identity.
 * @returns {Name} The key name of the auto-generated KSK of the identity.
 */
KeyChain.prototype.createIdentity = function(identityName)
{
  return this.identityManager.createIdentity(identityName);
};

/**
 * Get the default identity.
 * @returns {Name} The name of default identity.
 * @throws SecurityException if the default identity is not set.
 */
KeyChain.prototype.getDefaultIdentity = function()
{
  return this.identityManager.getDefaultIdentity();
};

/**
 * Get the default certificate name of the default identity.
 * @returns {Name} The requested certificate name.
 * @throws SecurityException if the default identity is not set or the default
 * key name for the identity is not set or the default certificate name for
 * the key name is not set.
 */
KeyChain.prototype.getDefaultCertificateName = function()
{
  return this.identityManager.getDefaultCertificateName();
};

/**
 * Generate a pair of RSA keys for the specified identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk (optional) true for generating a Key-Signing-Key (KSK),
 * false for a Data-Signing-Key (DSK). If omitted, generate a Data-Signing-Key.
 * @param {number} keySize (optional) The size of the key. If omitted, use a
 * default secure key size.
 * @returns {Name} The generated key name.
 */
KeyChain.prototype.generateRSAKeyPair = function(identityName, isKsk, keySize)
{
  return this.identityManager.generateRSAKeyPair(identityName, isKsk, keySize);
};

/**
 * Set a key as the default key of an identity.
 * @param {Name} keyName The name of the key.
 * @param {Name} identityName (optional) the name of the identity. If not
 * specified, the identity name is inferred from the keyName.
 */
KeyChain.prototype.setDefaultKeyForIdentity = function(keyName, identityName)
{
  if (identityName == null)
    identityName = new Name();
  return this.identityManager.setDefaultKeyForIdentity(keyName, identityName);
};

/**
 * Generate a pair of RSA keys for the specified identity and set it as default
 * key for the identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk (optional) true for generating a Key-Signing-Key (KSK),
 * false for a Data-Signing-Key (DSK). If omitted, generate a Data-Signing-Key.
 * @param {number} keySize (optional) The size of the key. If omitted, use a
 * default secure key size.
 * @returns {Name} The generated key name.
 */
KeyChain.prototype.generateRSAKeyPairAsDefault = function
  (identityName, isKsk, keySize)
{
  return this.identityManager.generateRSAKeyPairAsDefault
    (identityName, isKsk, keySize);
};

/**
 * Create a public key signing request.
 * @param {Name} keyName The name of the key.
 * @returns {Blob} The signing request data.
 */
KeyChain.prototype.createSigningRequest = function(keyName)
{
  return this.identityManager.getPublicKey(keyName).getKeyDer();
};

/**
 * Install an identity certificate into the public key identity storage.
 * @param {IdentityCertificate} certificate The certificate to to added.
 */
KeyChain.prototype.installIdentityCertificate = function(certificate)
{
  this.identityManager.addCertificate(certificate);
};

/**
 * Set the certificate as the default for its corresponding key.
 * @param {IdentityCertificate} certificate The certificate.
 */
KeyChain.prototype.setDefaultCertificateForKey = function(certificate)
{
  this.identityManager.setDefaultCertificateForKey(certificate);
};

/**
 * Get a certificate with the specified name.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {Certificate} The requested certificate which is valid.
 */
KeyChain.prototype.getCertificate = function(certificateName)
{
  return this.identityManager.getCertificate(certificateName);
};

/**
 * Get a certificate even if the certificate is not valid anymore.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {Certificate} The requested certificate.
 */
KeyChain.prototype.getAnyCertificate = function(certificateName)
{
  return this.identityManager.getAnyCertificate(certificateName);
};

/**
 * Get an identity certificate with the specified name.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} The requested certificate which is valid.
 */
KeyChain.prototype.getIdentityCertificate = function(certificateName)
{
  return this.identityManager.getCertificate(certificateName);
};

/**
 * Get an identity certificate even if the certificate is not valid anymore.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} The requested certificate.
 */
KeyChain.prototype.getAnyIdentityCertificate = function(certificateName)
{
  return this.identityManager.getAnyCertificate(certificateName);
};

/**
 * Revoke a key.
 * @param {Name} keyName The name of the key that will be revoked.
 */
KeyChain.prototype.revokeKey = function(keyName)
{
  //TODO: Implement
};

/**
 * Revoke a certificate.
 * @param {Name} certificateName The name of the certificate that will be
 * revoked.
 */
KeyChain.prototype.revokeCertificate = function(certificateName)
{
  //TODO: Implement
};

/**
 * Get the identity manager given to or created by the constructor.
 * @returns {IdentityManager} The identity manager.
 */
KeyChain.prototype.getIdentityManager = function()
{ 
  return this.identityManager;
};

/*****************************************
 *           Policy Management           *
 *****************************************/

/**
 * Get the policy manager given to or created by the constructor.
 * @returns {PolicyManager} The policy manager.
 */
KeyChain.prototype.getPolicyManager = function()
{ 
  return this.policyManager;
};

/*****************************************
 *              Sign/Verify              *
 *****************************************/

/**
 * Sign the target. If it is a Data or Interest object, set its signature. If it
 * is an array, return a signature object.
 * @param {Data|Interest|Buffer} target If this is a Data object, wire encode for
 * signing, update its signature and key locator field and wireEncoding. If this
 * is an Interest object, wire encode for signing, append a SignatureInfo to the
 * Interest name, sign the name components and append a final name component
 * with the signature bits. If it is an array, sign it and return a Signature
 * object.
 * @param {Name} certificateName The certificate name of the key to use for
 * signing.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 */
KeyChain.prototype.sign = function(target, certificateName, wireFormat)
{
  if (target instanceof Interest)
    this.signInterest(target, certificateName, wireFormat);
  else if (target instanceof Data)
    this.identityManager.signByCertificate(target, certificateName, wireFormat);
  else
    return this.identityManager.signByCertificate(target, certificateName);
};

/**
 * Append a SignatureInfo to the Interest name, sign the name components and
 * append a final name component with the signature bits.
 * @param {Interest} interest The Interest object to be signed. This appends
 * name components of SignatureInfo and the signature bits.
 * @param {Name} certificateName The certificate name of the key to use for
 * signing.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 */
KeyChain.prototype.signInterest = function(interest, certificateName, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  // TODO: Handle signature algorithms other than Sha256WithRsa.
  var signature = new Sha256WithRsaSignature();
  signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
  signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));

  // Append the encoded SignatureInfo.
  interest.getName().append(wireFormat.encodeSignatureInfo(signature));

  // Append an empty signature so that the "signedPortion" is correct.
  interest.getName().append(new Name.Component());
  // Encode once to get the signed portion.
  var encoding = interest.wireEncode(wireFormat);
  var signedSignature = this.sign(encoding.buf(), certificateName);

  // Remove the empty signature and append the real one.
  var encoder = new TlvEncoder(256);
  encoder.writeBlobTlv
    (Tlv.SignatureValue, signedSignature.getSignature().buf());
  interest.setName(interest.getName().getPrefix(-1).append
    (wireFormat.encodeSignatureValue(signedSignature)));
};

/**
 * Sign the target. If it is a Data object, set its signature. If it is an
 * array, return a signature object.
 * @param {Data|Buffer} target If this is a Data object, wire encode for
 * signing, update its signature and key locator field and wireEncoding. If it
 * is an array, sign it and return a Signature object.
 * @param identityName (optional) The identity name for the key to use for
 * signing.  If omitted, infer the signing identity from the data packet name.
 * @param wireFormat (optional) A WireFormat object used to encode the input. If
 * omitted, use WireFormat getDefaultWireFormat().
 */
KeyChain.prototype.signByIdentity = function(target, identityName, wireFormat)
{
  if (identityName == null)
    identityName = new Name();

  if (target instanceof Data) {
    var signingCertificateName;
    if (identityName.size() == 0) {
      var inferredIdentity = this.policyManager.inferSigningIdentity
        (data.getName());
      if (inferredIdentity.size() == 0)
        signingCertificateName = this.identityManager.getDefaultCertificateName();
      else
        signingCertificateName =
          this.identityManager.getDefaultCertificateNameForIdentity
            (inferredIdentity);
    }
    else
      signingCertificateName =
        this.identityManager.getDefaultCertificateNameForIdentity(identityName);

    if (signingCertificateName.size() == 0)
      throw new SecurityException(new Error
        ("No qualified certificate name found!"));

    if (!this.policyManager.checkSigningPolicy
         (data.getName(), signingCertificateName))
      throw new SecurityException(new Error
        ("Signing Cert name does not comply with signing policy"));

    this.identityManager.signByCertificate
      (data, signingCertificateName, wireFormat);
  }
  else {
    var signingCertificateName =
      this.identityManager.getDefaultCertificateNameForIdentity(identityName);

    if (signingCertificateName.size() == 0)
      throw new SecurityException(new Error
        ("No qualified certificate name found!"));

    return this.identityManager.signByCertificate(array, signingCertificateName);
  }
};

/**
 * Check the signature on the Data object and call either onVerify or 
 * onVerifyFailed. We use callback functions because verify may fetch
 * information to check the signature.
 * @param {Data} data The Data object with the signature to check.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(data).
 * @param {number} stepCount
 */
KeyChain.prototype.verifyData = function
  (data, onVerified, onVerifyFailed, stepCount)
{
  if (this.policyManager.requireVerify(data)) {
    var nextStep = this.policyManager.checkVerificationPolicy
      (data, stepCount, onVerified, onVerifyFailed);
    if (nextStep != null) {
      var thisKeyChain = this;
      this.face.expressInterest
        (nextStep.interest,
         function(callbackInterest, callbackData) {
           thisKeyChain.onCertificateData(callbackInterest, callbackData, nextStep);
         },
         function(callbackInterest) {
           thisKeyChain.onCertificateInterestTimeout
             (callbackInterest, nextStep.retry, onVerifyFailed, data, nextStep);
         });
    }
  }
  else if (this.policyManager.skipVerifyAndTrust(data))
    onVerified(data);
  else
    onVerifyFailed(data);
};

/**
 * Check the signature on the signed interest and call either onVerify or
 * onVerifyFailed. We use callback functions because verify may fetch
 * information to check the signature.
 * @param {Interest} interest The interest with the signature to check.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(data).
 */
KeyChain.prototype.verifyInterest = function
  (interest, onVerified, onVerifyFailed, stepCount, wireFormat)
{
  throw new Error("KeyChain.verifyInterest is not implemented");
};

/*****************************************
 *           Encrypt/Decrypt             *
 *****************************************/

/**
 * Generate a symmetric key.
 * @param {Name} keyName The name of the generated key.
 * @param {number} keyType (optional) The type of the key from KeyType, e.g.
 * KeyType.AES.
 */
KeyChain.prototype.generateSymmetricKey = function(keyName, keyType)
{
  this.encryptionManager.createSymmetricKey(keyName, keyType);
};

/**
 * Encrypt a byte array.
 * @param {Name} keyName The name of the encrypting key.
 * @param {Buffer} data The byte array that will be encrypted.
 * @param {boolean} useSymmetric (optional) If true then symmetric encryption is
 * used, otherwise asymmetric encryption is used. If omitted, use symmetric
 * encryption.
 * @param encryptMode (optional) The encryption mode from EncryptMode. If
 * omitted, use EncryptMode.DEFAULT.
 * @returns {Blob} The encrypted data as an immutable Blob.
 */
KeyChain.prototype.encrypt = function(keyName, data, useSymmetric, encryptMode)
{
  return this.encryptionManager.encrypt(keyName, data, useSymmetric, encryptMode);
}

/**
 * Decrypt a byte array.
 * @param {Name} keyName The name of the decrypting key.
 * @param {Buffer} data The byte array that will be decrypted.
 * @param {boolean} useSymmetric (optional) If true then symmetric encryption is
 * used, otherwise asymmetric encryption is used. If omitted, use symmetric
 * encryption.
 * @param encryptMode (optional) The encryption mode from EncryptMode. If
 * omitted, use EncryptMode.DEFAULT.
 * @returns {Blob} The decrypted data as an immutable Blob.
 */
KeyChain.prototype.decrypt = function(keyName, data, useSymmetric, encryptMode)
{
   return this.encryptionManager.decrypt
     (keyName, data, useSymmetric, encryptMode);
};

/**
 * Set the Face which will be used to fetch required certificates.
 * @param {Face} face A pointer to the Face object.
 */
KeyChain.prototype.setFace = function(face)
{ 
  this.face = face;
};

KeyChain.prototype.onCertificateData = function(interest, data, nextStep)
{
  // Try to verify the certificate (data) according to the parameters in nextStep.
  this.verifyData
    (data, nextStep.onVerified, nextStep.onVerifyFailed, nextStep.stepCount);
};

KeyChain.prototype.onCertificateInterestTimeout = function
  (interest, retry, onVerifyFailed, data, nextStep)
{
  if (retry > 0) {
    // Issue the same expressInterest as in verifyData except decrement retry.
    var thisKeyChain = this;
    this.face.expressInterest
      (interest,
       function(callbackInterest, callbackData) {
         thisKeyChain.onCertificateData(callbackInterest, callbackData, nextStep);
       },
       function(callbackInterest) {
         thisKeyChain.onCertificateInterestTimeout
           (callbackInterest, retry - 1, onVerifyFailed, data, nextStep);
       });
  }
  else
    onVerifyFailed(data);
};
/**
 * This class represents an NDN Data MetaInfo object.
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var Blob = require('./util/blob.js').Blob;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var KeyLocator = require('./key-locator.js').KeyLocator;
var KeyLocatorType = require('./key-locator.js').KeyLocatorType;
var Name = require('./name.js').Name;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;
var NDNTime = require('./util/ndn-time.js').NDNTime;
var globalKeyManager = require('./security/key-manager.js').globalKeyManager;
var LOG = require('./log.js').Log.LOG;

var ContentType = {
  BLOB:0,
  // ContentType DATA is deprecated.  Use ContentType.BLOB .
  DATA:0,
  LINK:1,
  KEY: 2,
  // ContentType ENCR, GONE and NACK are not supported in NDN-TLV encoding and are deprecated.
  ENCR:3,
  GONE:4,
  NACK:5
};

exports.ContentType = ContentType;

/**
 * Create a new MetaInfo with the optional values.
 * @constructor
 */
var MetaInfo = function MetaInfo(publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockID, skipSetFields)
{
  if (typeof publisherOrMetaInfo === 'object' &&
      publisherOrMetaInfo instanceof MetaInfo) {
    // Copy values.
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
    this.publisher = publisherOrMetaInfo; //publisherPublicKeyDigest
    this.timestamp = timestamp; // NDN Time
    this.type = type == null || type < 0 ? ContentType.BLOB : type; // ContentType
    this.locator = locator == null ? new KeyLocator() : new KeyLocator(locator);
    this.freshnessSeconds = freshnessSeconds; // Integer
    this.finalBlockID = finalBlockID; //byte array

    if (!skipSetFields)
      this.setFields();
  }

  this.changeCount = 0;
};

exports.MetaInfo = MetaInfo;

/**
 * Get the content type.
 * @returns {number} The content type as an int from ContentType.
 */
MetaInfo.prototype.getType = function()
{
  return this.type;
};

/**
 * Get the freshness period.
 * @returns {number} The freshness period in milliseconds, or null if not
 * specified.
 */
MetaInfo.prototype.getFreshnessPeriod = function()
{
  // Use attribute freshnessSeconds for backwards compatibility.
  if (this.freshnessSeconds == null || this.freshnessSeconds < 0)
    return null;
  else
    // Convert to milliseconds.
    return this.freshnessSeconds * 1000.0;
};

/**
 * Get the final block ID.
 * @returns {Name.Component} The final block ID as a Name.Component. If the
 * Name.Component getValue().size() is 0, then the final block ID is not specified.
 */
MetaInfo.prototype.getFinalBlockID = function()
{
  // For backwards-compatibility, leave this.finalBlockID as a Buffer but return a Name.Component.
  return new Name.Component(new Blob(this.finalBlockID, true));
};

/**
 * @deprecated Use getFinalBlockID. This method returns a Buffer which is the former
 * behavior of getFinalBlockID, and should only be used while updating your code.
 */
MetaInfo.prototype.getFinalBlockIDAsBuffer = function()
{
  return this.finalBlockID;
};

/**
 * Set the content type.
 * @param {number} type The content type as an int from ContentType.  If null,
 * this uses ContentType.BLOB.
 */
MetaInfo.prototype.setType = function(type)
{
  this.type = type == null || type < 0 ? ContentType.BLOB : type;
  ++this.changeCount;
};

/**
 * Set the freshness period.
 * @param {type} freshnessPeriod The freshness period in milliseconds, or null
 * for not specified.
 */
MetaInfo.prototype.setFreshnessPeriod = function(freshnessPeriod)
{
  // Use attribute freshnessSeconds for backwards compatibility.
  if (freshnessPeriod == null || freshnessPeriod < 0)
    this.freshnessSeconds = null;
  else
    // Convert from milliseconds.
    this.freshnessSeconds = freshnessPeriod / 1000.0;
  ++this.changeCount;
};

MetaInfo.prototype.setFinalBlockID = function(finalBlockID)
{
  // TODO: finalBlockID should be a Name.Component, not Buffer.
  if (finalBlockID == null)
    this.finalBlockID = null;
  else if (typeof finalBlockID === 'object' && finalBlockID instanceof Blob)
    this.finalBlockID = finalBlockID.buf();
  else if (typeof finalBlockID === 'object' && finalBlockID instanceof Name.Component)
    this.finalBlockID = finalBlockID.getValue().buf();
  else
    this.finalBlockID = new Buffer(finalBlockID);
  ++this.changeCount;
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

  //DATA
  this.type = ContentType.BLOB;

  if (LOG > 4) console.log('PUBLIC KEY TO WRITE TO DATA PACKET IS ');
  if (LOG > 4) console.log(key.publicToDER().toString('hex'));

  this.locator = new KeyLocator(key.getKeyID(), KeyLocatorType.KEY_LOCATOR_DIGEST);
  ++this.changeCount;
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

    //TODO Implement type of Key Reading
    if (null == this.type)
      throw new Error("Cannot parse signedInfo type: bytes.");
  }
  else
    this.type = ContentType.DATA; // default

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
  ++this.changeCount;
};

/**
 * Encode this MetaInfo in ndnb, using the given keyLocator instead of the
 * locator in this object.
 * @param {BinaryXMLEncoder} encoder The encoder.
 * @param {KeyLocator} keyLocator The key locator to use (from
 * Data.getSignatureOrMetaInfoKeyLocator).
 */
MetaInfo.prototype.to_ndnb = function(encoder, keyLocator)  {
  if (!this.validate())
    throw new Error("Cannot encode : field values missing.");

  encoder.writeElementStartDTag(this.getElementLabel());

  if (null != this.publisher) {
    // We have a publisherPublicKeyDigest, so use it.
    if (LOG > 3) console.log('ENCODING PUBLISHER KEY' + this.publisher.publisherPublicKeyDigest);
    this.publisher.to_ndnb(encoder);
  }
  else {
    if (null != keyLocator &&
        keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
        !keyLocator.getKeyData().isNull() &&
        keyLocator.getKeyData().size() > 0)
      // We have a TLV-style KEY_LOCATOR_DIGEST, so encode as the
      //   publisherPublicKeyDigest.
      encoder.writeDTagElement
        (NDNProtocolDTags.PublisherPublicKeyDigest, keyLocator.getKeyData().buf());
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
  // We don't do partial matches any more, even though encoder/decoder
  // is still pretty generous.
  if (null == this.timestamp)
    return false;
  return true;
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @returns {number} The change count.
 */
MetaInfo.prototype.getChangeCount = function()
{
  return this.changeCount;
};

/**
 * @deprecated Use new MetaInfo.
 */
var SignedInfo = function SignedInfo(publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockID)
{
  // Call the base constructor.
  MetaInfo.call(this, publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockID);
}

// Set skipSetFields true since we only need the prototype functions.
SignedInfo.prototype = new MetaInfo(null, null, null, null, null, null, true);

exports.SignedInfo = SignedInfo;
/**
 * This class represents an NDN Data Signature object.
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('./util/blob.js').Blob;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var KeyLocator = require('./key-locator.js').KeyLocator;
var LOG = require('./log.js').Log.LOG;

/**
 * Create a new Sha256WithRsaSignature object, possibly copying values from
 * another object.
 *
 * @param {Sha256WithRsaSignature} value (optional) If value is a
 * Sha256WithRsaSignature, copy its values.  If value is omitted, the keyLocator
 * is the default with unspecified values and the signature is unspecified.
 * @constructor
 */
var Sha256WithRsaSignature = function Sha256WithRsaSignature(value)
{
  if (typeof value === 'object' && value instanceof Sha256WithRsaSignature) {
    // Copy the values.
    this.keyLocator = new KeyLocator(value.keyLocator);
    this.signature = value.signature;
    // witness is deprecated.
    this.witness = value.witness;
    // digestAlgorithm is deprecated.
    this.digestAlgorithm = value.digestAlgorithm;
  }
  else {
    this.keyLocator = new KeyLocator();
    this.signature = null;
    // witness is deprecated.
    this.witness = null;
    // digestAlgorithm is deprecated.
    this.digestAlgorithm = null;
  }
};

exports.Sha256WithRsaSignature = Sha256WithRsaSignature;

/**
 * Create a new Sha256WithRsaSignature which is a copy of this object.
 * @returns {Sha256WithRsaSignature} A new object which is a copy of this object.
 */
Sha256WithRsaSignature.prototype.clone = function()
{
  return new Sha256WithRsaSignature(this);
};

/**
 * Get the key locator.
 * @returns {KeyLocator} The key locator.
 */
Sha256WithRsaSignature.prototype.getKeyLocator = function()
{
  return this.keyLocator;
};

/**
 * Get the data packet's signature bytes.
 * @returns {Blob} The signature bytes. If not specified, the value isNull().
 */
Sha256WithRsaSignature.prototype.getSignature = function()
{
  // For backwards-compatibility, leave this.signature as a Buffer but return a Blob.
  return new Blob(this.signature, false);
};

/**
 * @deprecated Use getSignature. This method returns a Buffer which is the former
 * behavior of getSignature, and should only be used while updating your code.
 */
Sha256WithRsaSignature.prototype.getSignatureAsBuffer = function()
{
  return this.signature;
};

/**
 * Set the key locator to a copy of the given keyLocator.
 * @param {KeyLocator} keyLocator The KeyLocator to copy.
 */
Sha256WithRsaSignature.prototype.setKeyLocator = function(keyLocator)
{
  this.keyLocator = typeof keyLocator === 'object' && keyLocator instanceof KeyLocator ?
                    new KeyLocator(keyLocator) : new KeyLocator();
};

/**
 * Set the data packet's signature bytes.
 * @param {Blob} signature
 */
Sha256WithRsaSignature.prototype.setSignature = function(signature)
{
  if (signature == null)
    this.signature = null;
  else if (typeof signature === 'object' && signature instanceof Blob)
    this.signature = new Buffer(signature.buf());
  else
    this.signature = new Buffer(signature);
};

Sha256WithRsaSignature.prototype.from_ndnb = function(decoder)
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

  //FORCE TO READ A SIGNATURE

  if (LOG > 4) console.log('SIGNATURE FOUND');
  this.signature = decoder.readBinaryDTagElement(NDNProtocolDTags.SignatureBits);

  decoder.readElementClose();
};

Sha256WithRsaSignature.prototype.to_ndnb = function(encoder)
{
  if (!this.validate())
    throw new Error("Cannot encode: field values missing.");

  encoder.writeElementStartDTag(this.getElementLabel());

  if (null != this.digestAlgorithm && !this.digestAlgorithm.equals(NDNDigestHelper.DEFAULT_DIGEST_ALGORITHM))
    encoder.writeDTagElement(NDNProtocolDTags.DigestAlgorithm, OIDLookup.getDigestOID(this.DigestAlgorithm));

  if (null != this.witness)
    // needs to handle null witness
    encoder.writeDTagElement(NDNProtocolDTags.Witness, this.witness);

  encoder.writeDTagElement(NDNProtocolDTags.SignatureBits, this.signature);

  encoder.writeElementClose();
};

Sha256WithRsaSignature.prototype.getElementLabel = function() { return NDNProtocolDTags.Signature; };

Sha256WithRsaSignature.prototype.validate = function()
{
  return this.getSignature().size() > 0;
};

/**
 * Note: This Signature class is not the same as the base Signature class of
 * the Common Client Libraries API. It is a deprecated name for
 * Sha256WithRsaSignature. In the future, after we remove this deprecated class,
 * we may implement the CCL version of Signature.
 * @deprecated Use new Sha256WithRsaSignature.
 */
var Signature = function Signature
  (witnessOrSignatureObject, signature, digestAlgorithm)
{
  if (typeof witnessOrSignatureObject === 'object' &&
      witnessOrSignatureObject instanceof Sha256WithRsaSignature)
    // Call the base copy constructor.
    Sha256WithRsaSignature.call(this, witnessOrSignatureObject);
  else {
    // Call the base default constructor.
    Sha256WithRsaSignature.call(this);

    // Set the given fields (if supplied).
    if (witnessOrSignatureObject != null)
      // witness is deprecated.
      this.witness = witnessOrSignatureObject;
    if (signature != null)
      this.signature = signature;
    if (digestAlgorithm != null)
      // digestAlgorithm is deprecated.
      this.digestAlgorithm = digestAlgorithm;
  }
}

Signature.prototype = new Sha256WithRsaSignature();

exports.Signature = Signature;
/**
 * This class represents an NDN Data object.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('./util/blob.js').Blob;
var SignedBlob = require('./util/signed-blob.js').SignedBlob;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var DataUtils = require('./encoding/data-utils.js').DataUtils;
var Name = require('./name.js').Name;
var Sha256WithRsaSignature = require('./sha256-with-rsa-signature.js').Sha256WithRsaSignature;
var MetaInfo = require('./meta-info.js').MetaInfo;
var KeyLocator = require('./key-locator.js').KeyLocator;
var globalKeyManager = require('./security/key-manager.js').globalKeyManager;
var WireFormat = require('./encoding/wire-format.js').WireFormat;

/**
 * Create a new Data with the optional values.  There are 2 forms of constructor:
 * new Data([name] [, content]);
 * new Data(name, metaInfo [, content]);
 *
 * @constructor
 * @param {Name} name
 * @param {MetaInfo} metaInfo
 * @param {Buffer} content
 */
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

  // Use signedInfo instead of metaInfo for backward compatibility.
  this.signedInfo = typeof metaInfo === 'object' && metaInfo instanceof MetaInfo ?
       new MetaInfo(metaInfo) : new MetaInfo();

  if (typeof content === 'string')
    this.content = DataUtils.toNumbersFromString(content);
  else if (typeof content === 'object' && content instanceof Blob)
    this.content = content.buf();
  else
    this.content = content;

  this.signature = new Sha256WithRsaSignature();

  this.wireEncoding = SignedBlob();
};

exports.Data = Data;

/**
 * Get the data packet's name.
 * @returns {Name} The name.
 */
Data.prototype.getName = function()
{
  return this.name;
};

/**
 * Get the data packet's meta info.
 * @returns {MetaInfo} The meta info.
 */
Data.prototype.getMetaInfo = function()
{
  return this.signedInfo;
};

/**
 * Get the data packet's signature object.
 * @returns {Signature} The signature object.
 */
Data.prototype.getSignature = function()
{
  return this.signature;
};

/**
 * Get the data packet's content.
 * @returns {Blob} The data packet content as a Blob.
 */
Data.prototype.getContent = function()
{
  // For temporary backwards compatibility, leave this.content as a Buffer but return a Blob.
  return new Blob(this.content, false);
};

/**
 * @deprecated Use getContent. This method returns a Buffer which is the former
 * behavior of getContent, and should only be used while updating your code.
 */
Data.prototype.getContentAsBuffer = function()
{
  return this.content;
};

/**
 * Set name to a copy of the given Name.
 * @param {Name} name The Name which is copied.
 * @returns {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setName = function(name)
{
  this.name = typeof name === 'object' && name instanceof Name ?
    new Name(name) : new Name();

  // The object has changed, so the wireEncoding is invalid.
  this.wireEncoding = SignedBlob();
  return this;
};

/**
 * Set metaInfo to a copy of the given MetaInfo.
 * @param {MetaInfo} metaInfo The MetaInfo which is copied.
 * @returns {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setMetaInfo = function(metaInfo)
{
  this.signedInfo = typeof metaInfo === 'object' && metaInfo instanceof MetaInfo ?
    new MetaInfo(metaInfo) : new MetaInfo();

  // The object has changed, so the wireEncoding is invalid.
  this.wireEncoding = SignedBlob();
  return this;
};

/**
 * Set the signature to a copy of the given signature.
 * @param {Signature} signature The signature object which is cloned.
 * @returns {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setSignature = function(signature)
{
  this.signature = typeof signature === 'object' && signature instanceof Sha256WithRsaSignature ?
    signature.clone() : new Sha256WithRsaSignature();

  // The object has changed, so the wireEncoding is invalid.
  this.wireEncoding = SignedBlob();
  return this;
};

/**
 * Set the content to the given value.
 * @param {type} content The array this is copied.
 * @returns {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setContent = function(content)
{
  if (typeof content === 'string')
    this.content = DataUtils.toNumbersFromString(content);
  else if (typeof content === 'object' && content instanceof Blob)
    this.content = content.buf();
  else
    this.content = new Buffer(content);

  // The object has changed, so the wireEncoding is invalid.
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
    // Need to encode to set wireEncoding.
    // Set an initial empty signature so that we can encode.
    this.getSignature().setSignature(new Buffer(128));
    this.wireEncode(wireFormat);
  }

  var rsa = require("crypto").createSign('RSA-SHA256');
  rsa.update(this.wireEncoding.signedBuf());

  var sig = new Buffer
    (DataUtils.toNumbersIfString(rsa.sign(globalKeyManager.privateKey)));
  this.signature.setSignature(sig);
};

// The first time verify is called, it sets this to determine if a signature
//   buffer needs to be converted to a string for the crypto verifier.
Data.verifyUsesString = null;
Data.prototype.verify = function(/*Key*/ key)
{
  if (key == null || key.publicKeyPem == null)
    throw new Error('Cannot verify Data without a public key.');

  if (Data.verifyUsesString == null) {
    var hashResult = require("crypto").createHash('sha256').digest();
    // If the has result is a string, we assume that this is a version of
    //   crypto where verify also uses a string signature.
    Data.verifyUsesString = (typeof hashResult === 'string');
  }

  if (this.wireEncoding == null || this.wireEncoding.isNull())
    // Need to encode to set wireEncoding.
    this.wireEncode();
  var verifier = require('crypto').createVerify('RSA-SHA256');
  verifier.update(this.wireEncoding.signedBuf());
  var signatureBytes = Data.verifyUsesString ?
    DataUtils.toString(this.signature.getSignature().buf()) : this.signature.getSignature().buf();
  return verifier.verify(key.publicKeyPem, signatureBytes);
};

Data.prototype.getElementLabel = function() { return NDNProtocolDTags.Data; };

/**
 * Encode this Data for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @returns {SignedBlob} The encoded buffer in a SignedBlob object.
 */
Data.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  var result = wireFormat.encodeData(this);
  // TODO: Implement setDefaultWireEncoding with getChangeCount support.
  this.wireEncoding = new SignedBlob
    (result.encoding, result.signedPortionBeginOffset,
     result.signedPortionEndOffset);
  return this.wireEncoding;
};

/**
 * Decode the input using a particular wire format and update this Data.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Data.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ?
                     input.buf() : input;
  var result = wireFormat.decodeData(this, decodeBuffer);
  // TODO: Implement setDefaultWireEncoding with getChangeCount support.
  // In the Blob constructor, set copy true, but if input is already a Blob, it
  //   won't copy.
  this.wireEncoding = new SignedBlob
    (new Blob(input, true), result.signedPortionBeginOffset,
     result.signedPortionEndOffset);
};

/**
 * If getSignature() has a key locator, return it.  Otherwise, use
 * the key locator from getMetaInfo() for backward compatibility and print
 * a warning to console.log that the key locator has moved to the Signature
 * object.  If neither has a key locator, return an empty key locator.
 * When we stop supporting the key locator in MetaInfo, this function is not
 * necessary and we will just use the key locator in the Signature.
 * @returns {KeyLocator} The key locator to use.
 */
Data.prototype.getSignatureOrMetaInfoKeyLocator = function()
{
  if (this.signature != null && this.signature.getKeyLocator() != null &&
      this.signature.getKeyLocator().getType() != null &&
      this.signature.getKeyLocator().getType() >= 0)
    // The application is using the key locator in the correct object.
    return this.signature.getKeyLocator();

  if (this.signedInfo != null && this.signedInfo.locator != null &&
      this.signedInfo.locator.getType() != null &&
      this.signedInfo.locator.getType() >= 0) {
    console.log("WARNING: Temporarily using the key locator found in the MetaInfo - expected it in the Signature object.");
    console.log("WARNING: In the future, the key locator in the Signature object will not be supported.");
    return this.signedInfo.locator;
  }

  // Return the empty key locator from the Signature object if possible.
  if (this.signature != null && this.signature.getKeyLocator() != null)
    return this.signature.getKeyLocator();
  else
    return new KeyLocator();
}

// Since binary-xml-wire-format.js includes this file, put these at the bottom to avoid problems with cycles of require.
var BinaryXmlWireFormat = require('./encoding/binary-xml-wire-format.js').BinaryXmlWireFormat;

/**
 * @deprecated Use BinaryXmlWireFormat.decodeData.
 */
Data.prototype.from_ndnb = function(/*XMLDecoder*/ decoder)
{
  BinaryXmlWireFormat.decodeData(this, decoder);
};

/**
 * @deprecated Use BinaryXmlWireFormat.encodeData.
 */
Data.prototype.to_ndnb = function(/*XMLEncoder*/ encoder)
{
  BinaryXmlWireFormat.encodeData(this, encoder);
};

/**
 * @deprecated Use wireEncode.  If you need binary XML, use
 * wireEncode(BinaryXmlWireFormat.get()).
 */
Data.prototype.encode = function(wireFormat)
{
  wireFormat = (wireFormat || BinaryXmlWireFormat.get());
  return wireFormat.encodeData(this).buf();
};

/**
 * @deprecated Use wireDecode.  If you need binary XML, use
 * wireDecode(input, BinaryXmlWireFormat.get()).
 */
Data.prototype.decode = function(input, wireFormat)
{
  wireFormat = (wireFormat || BinaryXmlWireFormat.get());
  wireFormat.decodeData(this, input);
};

/**
 * @deprecated Use new Data.
 */
var ContentObject = function ContentObject(name, signedInfo, content)
{
  // Call the base constructor.
  Data.call(this, name, signedInfo, content);
}

ContentObject.prototype = new Data();

exports.ContentObject = ContentObject;
/**
 * This class represents an Interest Exclude.
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Name = require('./name.js').Name;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var DataUtils = require('./encoding/data-utils.js').DataUtils;
var Blob = require('./util/blob.js').Blob;

/**
 * Create a new Exclude.
 * @constructor
 * @param {Array<Name.Component|Buffer|Exclude.ANY>} values (optional) An array where each element is either a Name.Component, Buffer component or Exclude.ANY.
 */
var Exclude = function Exclude(values)
{
  this.values = [];

  if (typeof values === 'object' && values instanceof Exclude)
    // Copy the exclude.
    this.values = values.values.slice(0);
  else if (values) {
    // Set the changeCount now since append expects it.
    this.changeCount = 0;
    for (var i = 0; i < values.length; ++i) {
      if (values[i] == Exclude.ANY)
        this.appendAny();
      else
        this.appendComponent(values[i]);
    }
  }

  this.changeCount = 0;
};

exports.Exclude = Exclude;

Exclude.ANY = "*";

/**
 * Get the number of entries.
 * @returns {number} The number of entries.
 */
Exclude.prototype.size = function() { return this.values.length; };

/**
 * Get the entry at the given index.
 * @param {number} i The index of the entry, starting from 0.
 * @returns {Exclude.ANY|Name.Component} Exclude.ANY or a Name.Component.
 */
Exclude.prototype.get = function(i) { return this.values[i]; };

/**
 * Append an Exclude.ANY element.
 * @returns This Exclude so that you can chain calls to append.
 */
Exclude.prototype.appendAny = function()
{
  this.values.push(Exclude.ANY);
  ++this.changeCount;
  return this;
};

/**
 * Append a component entry, copying from component.
 * @param {Name.Component|Buffer} component
 * @returns This Exclude so that you can chain calls to append.
 */
Exclude.prototype.appendComponent = function(component)
{
  this.values.push(new Name.Component(component));
  ++this.changeCount;
  return this;
};

/**
 * Clear all the entries.
 */
Exclude.prototype.clear = function()
{
  ++this.changeCount;
  this.values = [];
};

Exclude.prototype.from_ndnb = function(/*XMLDecoder*/ decoder)
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
      // Skip the Bloom and treat it as Any.
      decoder.readBinaryDTagElement(NDNProtocolDTags.Bloom);
      this.appendAny();
    }
    else
      break;
  }

  decoder.readElementClose();
};

Exclude.prototype.to_ndnb = function(/*XMLEncoder*/ encoder)
{
  if (this.values == null || this.values.length == 0)
    return;

  encoder.writeElementStartDTag(NDNProtocolDTags.Exclude);

  // TODO: Do we want to order the components (except for ANY)?
  for (var i = 0; i < this.values.length; ++i) {
    if (this.values[i] == Exclude.ANY) {
      encoder.writeElementStartDTag(NDNProtocolDTags.Any);
      encoder.writeElementClose();
    }
    else
      encoder.writeDTagElement(NDNProtocolDTags.Component, this.values[i].getValue().buf());
  }

  encoder.writeElementClose();
};

/**
 * Return a string with elements separated by "," and Exclude.ANY shown as "*".
 */
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
      result += Name.toEscapedString(this.values[i].getValue().buf());
  }
  return result;
};

/**
 * Return true if the component matches any of the exclude criteria.
 */
Exclude.prototype.matches = function(/*Buffer*/ component)
{
  if (typeof component == 'object' && component instanceof Name.Component)
    component = component.getValue().buf();
  else if (typeof component === 'object' && component instanceof Blob)
    component = component.buf();

  for (var i = 0; i < this.values.length; ++i) {
    if (this.values[i] == Exclude.ANY) {
      var lowerBound = null;
      if (i > 0)
        lowerBound = this.values[i - 1];

      // Find the upper bound, possibly skipping over multiple ANY in a row.
      var iUpperBound;
      var upperBound = null;
      for (iUpperBound = i + 1; iUpperBound < this.values.length; ++iUpperBound) {
        if (this.values[iUpperBound] != Exclude.ANY) {
          upperBound = this.values[iUpperBound];
          break;
        }
      }

      // If lowerBound != null, we already checked component equals lowerBound on the last pass.
      // If upperBound != null, we will check component equals upperBound on the next pass.
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

        // Make i equal iUpperBound on the next pass.
        i = iUpperBound - 1;
      }
      else {
        if (lowerBound != null) {
            if (Exclude.compareComponents(component, lowerBound) > 0)
              return true;
        }
        else
          // this.values has only ANY.
          return true;
      }
    }
    else {
      if (DataUtils.arraysEqual(component, this.values[i].getValue().buf()))
        return true;
    }
  }

  return false;
};

/**
 * Return -1 if component1 is less than component2, 1 if greater or 0 if equal.
 * A component is less if it is shorter, otherwise if equal length do a byte comparison.
 */
Exclude.compareComponents = function(component1, component2)
{
  if (typeof component1 == 'object' && component1 instanceof Name.Component)
    component1 = component1.getValue().buf();
  if (typeof component2 == 'object' && component2 instanceof Name.Component)
    component2 = component2.getValue().buf();

  return Name.Component.compareBuffers(component1, component2);
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @returns {number} The change count.
 */
Exclude.prototype.getChangeCount = function()
{
  return this.changeCount;
};
/**
 * This class represents Interest Objects
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('./util/blob.js').Blob;
var Name = require('./name.js').Name;
var Exclude = require('./exclude.js').Exclude;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;
var KeyLocator = require('./key-locator.js').KeyLocator;
var WireFormat = require('./encoding/wire-format.js').WireFormat;

/**
 * Create a new Interest with the optional values.
 *
 * @constructor
 * @param {Name|Interest} nameOrInterest If this is an Interest, copy values from the interest and ignore the
 * other arguments.  Otherwise this is the optional name for the new Interest.
 * @param {number} minSuffixComponents
 * @param {number} maxSuffixComponents
 * @param {Buffer} publisherPublicKeyDigest
 * @param {Exclude} exclude
 * @param {number} childSelector
 * @param {number} answerOriginKind
 * @param {number} scope
 * @param {number} interestLifetimeMilliseconds in milliseconds
 * @param {Buffer} nonce
 */
var Interest = function Interest
   (nameOrInterest, minSuffixComponents, maxSuffixComponents, publisherPublicKeyDigest, exclude,
    childSelector, answerOriginKind, scope, interestLifetimeMilliseconds, nonce)
{
  if (typeof nameOrInterest === 'object' && nameOrInterest instanceof Interest) {
    // Special case: this is a copy constructor.  Ignore all but the first argument.
    var interest = nameOrInterest;
    if (interest.name)
      // Copy the name.
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
      // Copy.
      this.nonce = new Buffer(interest.nonce);
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
      // Copy and make sure it is a Buffer.
      this.nonce = new Buffer(nonce);
  }
};

exports.Interest = Interest;

Interest.RECURSIVE_POSTFIX = "*";

Interest.CHILD_SELECTOR_LEFT = 0;
Interest.CHILD_SELECTOR_RIGHT = 1;

Interest.ANSWER_NO_CONTENT_STORE = 0;
Interest.ANSWER_CONTENT_STORE = 1;
Interest.ANSWER_GENERATED = 2;
Interest.ANSWER_STALE = 4;    // Stale answer OK
Interest.MARK_STALE = 16;    // Must have scope 0.  Michael calls this a "hack"

Interest.DEFAULT_ANSWER_ORIGIN_KIND = Interest.ANSWER_CONTENT_STORE | Interest.ANSWER_GENERATED;

/**
 * Return true if this.name.match(name) and the name conforms to the interest selectors.
 * @param {Name} name
 * @returns {boolean}
 */
Interest.prototype.matchesName = function(/*Name*/ name)
{
  if (!this.name.match(name))
    return false;

  if (this.minSuffixComponents != null &&
      // Add 1 for the implicit digest.
      !(name.size() + 1 - this.name.size() >= this.minSuffixComponents))
    return false;
  if (this.maxSuffixComponents != null &&
      // Add 1 for the implicit digest.
      !(name.size() + 1 - this.name.size() <= this.maxSuffixComponents))
    return false;
  if (this.exclude != null && name.size() > this.name.size() &&
      this.exclude.matches(name.get(this.name.size())))
    return false;

  return true;
};

/**
 * @deprecated Use matchesName.
 */
Interest.prototype.matches_name = function(/*Name*/ name)
{
  return this.matchesName(name);
};

/**
 * Return a new Interest with the same fields as this Interest.
 */
Interest.prototype.clone = function()
{
  return new Interest
     (this.name, this.minSuffixComponents, this.maxSuffixComponents,
      this.publisherPublicKeyDigest, this.exclude, this.childSelector, this.answerOriginKind,
      this.scope, this.interestLifetime, this.nonce);
};

/**
 * Get the interest Name.
 * @returns {Name} The name.  The name size() may be 0 if not specified.
 */
Interest.prototype.getName = function() { return this.name; };

/**
 * Get the min suffix components.
 * @returns number} The min suffix components, or null if not specified.
 */
Interest.prototype.getMinSuffixComponents = function()
{
  return this.minSuffixComponents;
};

/**
 * Get the max suffix components.
 * @returns {number} The max suffix components, or null if not specified.
 */
Interest.prototype.getMaxSuffixComponents = function()
{
  return this.maxSuffixComponents;
};

/**
 * Get the interest key locator.
 * @returns {KeyLocator} The key locator. If its getType() is null,
 * then the key locator is not specified.
 */
Interest.prototype.getKeyLocator = function()
{
  return this.keyLocator;
};

/**
 * Get the exclude object.
 * @returns {Exclude} The exclude object. If the exclude size() is zero, then
 * the exclude is not specified.
 */
Interest.prototype.getExclude = function() { return this.exclude; };

/**
 * Get the child selector.
 * @returns {number} The child selector, or null if not specified.
 */
Interest.prototype.getChildSelector = function()
{
  return this.childSelector;
};

/**
 * @deprecated Use getMustBeFresh.
 */
Interest.prototype.getAnswerOriginKind = function()
{
  return this.answerOriginKind;
};

  /**
   * Return true if the content must be fresh.
   * @return true if must be fresh, otherwise false.
   */

/**
 * Get the must be fresh flag. If not specified, the default is true.
 * @returns {boolean} The must be fresh flag.
 */
Interest.prototype.getMustBeFresh = function()
{
  if (this.answerOriginKind == null || this.answerOriginKind < 0)
    return true;
  else
    return (this.answerOriginKind & Interest.ANSWER_STALE) == 0;
};

/**
 * Return the nonce value from the incoming interest.  If you change any of the
 * fields in this Interest object, then the nonce value is cleared.
 * @returns {Blob} The nonce. If not specified, the value isNull().
 */
Interest.prototype.getNonce = function()
{
  // For backwards-compatibility, leave this.nonce as a Buffer but return a Blob.
  return  new Blob(this.nonce, false);
};

/**
 * @deprecated Use getNonce. This method returns a Buffer which is the former
 * behavior of getNonce, and should only be used while updating your code.
 */
Interest.prototype.getNonceAsBuffer = function()
{
  return this.nonce;
};

/**
 * Get the interest scope.
 * @returns {number} The scope, or null if not specified.
 */
Interest.prototype.getScope = function() { return this.scope; };

/**
 * Get the interest lifetime.
 * @returns {number} The interest lifetime in milliseconds, or null if not
 * specified.
 */
Interest.prototype.getInterestLifetimeMilliseconds = function()
{
  return this.interestLifetime;
};

Interest.prototype.setName = function(name)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;

  this.name = typeof name === 'object' && name instanceof Name ?
              new Name(name) : new Name();
};

Interest.prototype.setMinSuffixComponents = function(minSuffixComponents)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;

  this.minSuffixComponents = minSuffixComponents;
};

Interest.prototype.setMaxSuffixComponents = function(maxSuffixComponents)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;

  this.maxSuffixComponents = maxSuffixComponents;
};

/**
 * Set this interest to use a copy of the given exclude object. Note: You can
 * also change this interest's exclude object modifying the object from
 * getExclude().
 * @param {Exclude} exclude The exlcude object that is copied.
 */
Interest.prototype.setExclude = function(exclude)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;

  this.exclude = typeof exclude === 'object' && exclude instanceof Exclude ?
                 new Exclude(exclude) : new Exclude();
};

Interest.prototype.setChildSelector = function(childSelector)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;

  this.childSelector = childSelector;
};

/**
 * @deprecated Use setMustBeFresh.
 */
Interest.prototype.setAnswerOriginKind = function(answerOriginKind)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;

  this.answerOriginKind = answerOriginKind;
};

/**
 * Set the MustBeFresh flag.
 * @param {boolean} mustBeFresh True if the content must be fresh, otherwise false.
 */
Interest.prototype.setMustBeFresh = function(mustBeFresh)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;

  if (this.answerOriginKind == null || this.answerOriginKind < 0) {
    // It is is already the default where MustBeFresh is true.
    if (!mustBeFresh)
      // Set answerOriginKind_ so that getMustBeFresh returns false.
      this.answerOriginKind = Interest.ANSWER_STALE;
  }
  else {
    if (mustBeFresh)
      // Clear the stale bit.
      this.answerOriginKind &= ~Interest.ANSWER_STALE;
    else
      // Set the stale bit.
      this.answerOriginKind |= Interest.ANSWER_STALE;
  }
};

Interest.prototype.setScope = function(scope)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;

  this.scope = scope;
};

Interest.prototype.setInterestLifetimeMilliseconds = function(interestLifetimeMilliseconds)
{
  // The object has changed, so the nonce is invalid.
  this.nonce = null;

  this.interestLifetime = interestLifetimeMilliseconds;
};

/**
 * @deprecated You should let the wire encoder generate a random nonce
 * internally before sending the interest.
 */
Interest.prototype.setNonce = function(nonce)
{
  if (nonce) {
    if (typeof nonce === 'object' && nonce instanceof Blob)
      this.nonce = nonce.buf();
    else
      // Copy and make sure it is a Buffer.
      this.nonce = new Buffer(nonce);
  }
  else
    this.nonce = null;
};

/**
 * Encode the name according to the "NDN URI Scheme".  If there are interest selectors, append "?" and
 * added the selectors as a query string.  For example "/test/name?ndn.ChildSelector=1".
 * @returns {string} The URI string.
 * @note This is an experimental feature.  See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/interest.html#interest-touri-method .
 */
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
    // Replace the first & with ?.
    result += "?" + selectors.substr(1);

  return result;
};

/**
 * Encode this Interest for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @returns {Blob} The encoded buffer in a Blob object.
 */
Interest.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  var result = wireFormat.encodeInterest(this);
  return result.encoding;
};

/**
 * Decode the input using a particular wire format and update this Interest.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Interest.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ?
                     input.buf() : input;
  wireFormat.decodeInterest(this, decodeBuffer);
};

// Since binary-xml-wire-format.js includes this file, put these at the bottom
// to avoid problems with cycles of require.
var BinaryXmlWireFormat = require('./encoding/binary-xml-wire-format.js').BinaryXmlWireFormat;

/**
 * @deprecated Use wireDecode(input, BinaryXmlWireFormat.get()).
 */
Interest.prototype.from_ndnb = function(/*XMLDecoder*/ decoder)
{
  BinaryXmlWireFormat.decodeInterest(this, decoder);
};

/**
 * @deprecated Use wireEncode(BinaryXmlWireFormat.get()).
 */
Interest.prototype.to_ndnb = function(/*XMLEncoder*/ encoder)
{
  BinaryXmlWireFormat.encodeInterest(this, encoder);
};

/**
 * @deprecated Use wireEncode.  If you need binary XML, use
 * wireEncode(BinaryXmlWireFormat.get()).
 */
Interest.prototype.encode = function(wireFormat)
{
  return this.wireEncode(BinaryXmlWireFormat.get()).buf();
};

/**
 * @deprecated Use wireDecode.  If you need binary XML, use
 * wireDecode(input, BinaryXmlWireFormat.get()).
 */
Interest.prototype.decode = function(input, wireFormat)
{
  this.wireDecode(input, BinaryXmlWireFormat.get())
};
/**
 * This class represents Face Instances
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;

/**
 * @constructor
 */
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

/**
 * Used by NetworkObject to decode the object from a network stream.
 */
FaceInstance.prototype.from_ndnb = function(
  //XMLDecoder
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
    //int
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

/**
 * Used by NetworkObject to encode the object to a network stream.
 */
FaceInstance.prototype.to_ndnb = function(
  //XMLEncoder
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

/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * A ForwardingFlags object holds the flags which specify how the forwarding daemon should forward an interest for
 * a registered prefix.  We use a separate ForwardingFlags object to retain future compatibility if the daemon forwarding
 * bits are changed, amended or deprecated.
 * Create a new ForwardingFlags with "active" and "childInherit" set and all other flags cleared.
 */
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

ForwardingFlags.ForwardingEntryFlags_ACTIVE         = 1;
ForwardingFlags.ForwardingEntryFlags_CHILD_INHERIT  = 2;
ForwardingFlags.ForwardingEntryFlags_ADVERTISE      = 4;
ForwardingFlags.ForwardingEntryFlags_LAST           = 8;
ForwardingFlags.ForwardingEntryFlags_CAPTURE       = 16;
ForwardingFlags.ForwardingEntryFlags_LOCAL         = 32;
ForwardingFlags.ForwardingEntryFlags_TAP           = 64;
ForwardingFlags.ForwardingEntryFlags_CAPTURE_OK   = 128;

ForwardingFlags.NfdForwardingFlags_CHILD_INHERIT = 1;
ForwardingFlags.NfdForwardingFlags_CAPTURE       = 2;

/**
 * Get an integer with the bits set according to the flags as used by the ForwardingEntry message.
 * @returns {number} An integer with the bits set.
 */
ForwardingFlags.prototype.getForwardingEntryFlags = function()
{
  var result = 0;

  if (this.active)
    result |= ForwardingFlags.ForwardingEntryFlags_ACTIVE;
  if (this.childInherit)
    result |= ForwardingFlags.ForwardingEntryFlags_CHILD_INHERIT;
  if (this.advertise)
    result |= ForwardingFlags.ForwardingEntryFlags_ADVERTISE;
  if (this.last)
    result |= ForwardingFlags.ForwardingEntryFlags_LAST;
  if (this.capture)
    result |= ForwardingFlags.ForwardingEntryFlags_CAPTURE;
  if (this.local)
    result |= ForwardingFlags.ForwardingEntryFlags_LOCAL;
  if (this.tap)
    result |= ForwardingFlags.ForwardingEntryFlags_TAP;
  if (this.captureOk)
    result |= ForwardingFlags.ForwardingEntryFlags_CAPTURE_OK;

  return result;
};

/**
 * Set the flags according to the bits in forwardingEntryFlags as used by the ForwardingEntry message.
 * @param {number} forwardingEntryFlags An integer with the bits set.
 */
ForwardingFlags.prototype.setForwardingEntryFlags = function(forwardingEntryFlags)
{
  this.active = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_ACTIVE) != 0);
  this.childInherit = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_CHILD_INHERIT) != 0);
  this.advertise = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_ADVERTISE) != 0);
  this.last = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_LAST) != 0);
  this.capture = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_CAPTURE) != 0);
  this.local = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_LOCAL) != 0);
  this.tap = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_TAP) != 0);
  this.captureOk = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_CAPTURE_OK) != 0);
};

/**
 * Get an integer with the bits set according to the NFD forwarding flags as
 * used in the ControlParameters of the command interest.
 * @returns {number} An integer with the bits set.
 */
ForwardingFlags.prototype.getNfdForwardingFlags = function()
{
  var result = 0;

  if (this.childInherit)
    result |= ForwardingFlags.NfdForwardingFlags_CHILD_INHERIT;
  if (this.capture)
    result |= ForwardingFlags.NfdForwardingFlags_CAPTURE;

  return result;
};

/**
 * Set the flags according to the NFD forwarding flags as used in the
 * ControlParameters of the command interest.
 * @param {number} nfdForwardingFlags An integer with the bits set.
 */
ForwardingFlags.prototype.setNfdForwardingFlags = function(nfdForwardingFlags)
{
  this.childInherit =
    ((nfdForwardingFlags & ForwardingFlags.NfdForwardingFlags_CHILD_INHERIT) != 0);
  this.capture =
    ((nfdForwardingFlags & ForwardingFlags.NfdForwardingFlags_CAPTURE) != 0);
};

/**
 * Get the value of the "active" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getActive = function() { return this.active; };

/**
 * Get the value of the "childInherit" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getChildInherit = function() { return this.childInherit; };

/**
 * Get the value of the "advertise" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getAdvertise = function() { return this.advertise; };

/**
 * Get the value of the "last" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getLast = function() { return this.last; };

/**
 * Get the value of the "capture" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getCapture = function() { return this.capture; };

/**
 * Get the value of the "local" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getLocal = function() { return this.local; };

/**
 * Get the value of the "tap" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getTap = function() { return this.tap; };

/**
 * Get the value of the "captureOk" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getCaptureOk = function() { return this.captureOk; };

/**
 * Set the value of the "active" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setActive = function(value) { this.active = value; };

/**
 * Set the value of the "childInherit" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setChildInherit = function(value) { this.childInherit = value; };

/**
 * Set the value of the "advertise" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setAdvertise = function(value) { this.advertise = value; };

/**
 * Set the value of the "last" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setLast = function(value) { this.last = value; };

/**
 * Set the value of the "capture" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setCapture = function(value) { this.capture = value; };

/**
 * Set the value of the "local" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setLocal = function(value) { this.local = value; };

/**
 * Set the value of the "tap" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setTap = function(value) { this.tap = value; };

/**
 * Set the value of the "captureOk" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setCaptureOk = function(value) { this.captureOk = value; };
/**
 * This class represents Forwarding Entries
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var ForwardingFlags = require('./forwarding-flags.js').ForwardingFlags;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;
var Name = require('./name.js').Name;

/**
 * Create a new ForwardingEntry with the optional arguments.
 * @constructor
 * @param {String} action
 * @param {Name} prefixName
 * @param {PublisherPublicKeyDigest} ndndId
 * @param {number} faceID
 * @param {number} flags
 * @param {number} lifetime in seconds
 */
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

ForwardingEntry.prototype.from_ndnb = function(
  //XMLDecoder
  decoder)
  //throws DecodingException
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
  //XMLEncoder
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
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var ForwardingFlags = require('./forwarding-flags.js').ForwardingFlags;
var Name = require('./name.js').Name;
var WireFormat = require('./encoding/wire-format.js').WireFormat;

/**
 * A ControlParameters which holds a Name and other fields for a
 * ControlParameters which is used, for example, in the command interest to
 * register a prefix with a forwarder.
 * @constructor
 */
var ControlParameters = function ControlParameters()
{
  this.name = new Name();
  this.faceId = null;
  // TODO: Add "Uri" string.
  this.localControlFeature = null;
  this.origin = null;
  this.cost = null;
  this.forwardingFlags = new ForwardingFlags();
  // TODO: Add "Strategy" name.
  this.expirationPeriod = null;
};

exports.ControlParameters = ControlParameters;

/**
 * Encode this ControlParameters for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @returns {Blob} The encoded buffer in a Blob object.
 */
ControlParameters.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return wireFormat.encodeControlParameters(this);
};

/**
 * Decode the input using a particular wire format and update this
 * ControlParameters.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
ControlParameters.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ?
                     input.buf() : input;
  wireFormat.decodeControlParameters(this, decodeBuffer);
};

/**
 * Get the name.
 * @returns {Name} The name.
 */
ControlParameters.prototype.getName = function()
{
  return this.name;
};

/**
 * Get the face ID.
 * @returns {number} The face ID, or null if not specified.
 */
ControlParameters.prototype.getFaceId = function()
{
  return this.faceId;
};

/**
 * Get the local control feature value.
 * @returns {number} The local control feature value, or null if not specified.
 */
ControlParameters.prototype.getLocalControlFeature = function()
{
  return this.localControlFeature;
};

/**
 * Get the origin value.
 * @returns {number} The origin value, or null if not specified.
 */
ControlParameters.prototype.getOrigin = function()
{
  return this.origin;
};

/**
 * Get the cost value.
 * @returns {number} The cost value, or null if not specified.
 */
ControlParameters.prototype.getCost = function()
{
  return this.cost;
};

/**
 * Get the ForwardingFlags object.
 * @returns {ForwardingFlags} The ForwardingFlags object.
 */
ControlParameters.prototype.getForwardingFlags = function()
{
  return this.forwardingFlags;
};

/**
 * Get the expiration period.
 * @returns {number} The expiration period in milliseconds, or null if not specified.
 */
ControlParameters.prototype.getExpirationPeriod = function()
{
  return this.expirationPeriod;
};

/**
 * Set the name to a copy of the given Name.
 * @param {Name} name The new Name to copy.
 */
ControlParameters.prototype.setName = function(name)
{
  this.name = typeof name === 'object' && name instanceof Name ?
              new Name(name) : new Name();
};

/**
 * Set the Face ID.
 * @param {number} faceId The new face ID, or null for not specified.
 */
ControlParameters.prototype.setFaceId = function(faceId)
{
  this.faceId = faceId;
};

/**
 * Set the local control feature value.
 * @param {number} localControlFeature The new local control feature value, or
 * null for not specified.
 */
ControlParameters.prototype.setLocalControlFeature = function(localControlFeature)
{
  this.localControlFeature = localControlFeature;
};

/**
 * Set the origin value.
 * @param {number} origin The new origin value, or null for not specified.
 */
ControlParameters.prototype.setOrigin = function(origin)
{
  this.origin = origin;
};

/**
 * Set the cost value.
 * @param {number} cost The new cost value, or null for not specified.
 */
ControlParameters.prototype.setCost = function(cost)
{
  this.cost = cost;
};

/**
 * Set the cost value.
 * @param {number} forwardingFlags The new cost value, or null for not specified.
 */
ControlParameters.prototype.setForwardingFlags = function(forwardingFlags)
{
  this.forwardingFlags =
    typeof forwardingFlags === 'object' && forwardingFlags instanceof ForwardingFlags ?
      new ForwardingFlags(forwardingFlags) : new ForwardingFlags();
};

/**
 * Set the expiration period.
 * @param {number} expirationPeriod The expiration period in milliseconds, or
 * null for not specified.
 */
ControlParameters.prototype.setExpirationPeriod = function(expirationPeriod)
{
  this.expirationPeriod = expirationPeriod;
};
/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('../util/blob.js').Blob;
var NDNProtocolDTags = require('../util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var BinaryXMLEncoder = require('./binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./binary-xml-decoder.js').BinaryXMLDecoder;
var WireFormat = require('./wire-format.js').WireFormat;
var Name = require('../name.js').Name;
var Exclude = require('../exclude.js').Exclude;
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature;
var MetaInfo = require('../meta-info.js').MetaInfo;
var PublisherPublicKeyDigest = require('../publisher-public-key-digest.js').PublisherPublicKeyDigest;
var DataUtils = require('./data-utils.js').DataUtils;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;

/**
 * A BinaryXmlWireFormat implements the WireFormat interface for encoding and decoding in binary XML.
 * @constructor
 */
var BinaryXmlWireFormat = function BinaryXmlWireFormat()
{
  // Inherit from WireFormat.
  WireFormat.call(this);
};

exports.BinaryXmlWireFormat = BinaryXmlWireFormat;

// Default object.
BinaryXmlWireFormat.instance = null;

/**
 * Encode interest as Binary XML and return the encoding.
 * @param {Interest} interest The Interest to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the signed
 * portion. The signed portion starts from the first name component and ends
 * just before the final name component (which is assumed to be a signature for
 * a signed interest).
 */
BinaryXmlWireFormat.prototype.encodeInterest = function(interest)
{
  var encoder = new BinaryXMLEncoder();
  var offsets = BinaryXmlWireFormat.encodeInterest(interest, encoder);
  return { encoding: new Blob(encoder.getReducedOstream(), false),
           signedPortionBeginOffset: offsets.signedPortionBeginOffset,
           signedPortionEndOffset: offsets.signedPortionEndOffset };
};

/**
 * Decode input as a Binary XML interest and set the fields of the interest object.
 * @param {Interest} interest The Interest object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 */
BinaryXmlWireFormat.prototype.decodeInterest = function(interest, input)
{
  var decoder = new BinaryXMLDecoder(input);
  BinaryXmlWireFormat.decodeInterest(interest, decoder);
};

/**
 * Encode data as Binary XML and return the encoding and signed offsets.
 * @param {Data} data The Data object to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the
 * signed portion.
 */
BinaryXmlWireFormat.prototype.encodeData = function(data)
{
  var encoder = new BinaryXMLEncoder(1500);
  var result = BinaryXmlWireFormat.encodeData(data, encoder);
  result.encoding = new Blob(encoder.getReducedOstream(), false);
  return result;
};

/**
 * @deprecated Use encodeData(data).
 */
BinaryXmlWireFormat.prototype.encodeContentObject = function(data)
{
  return this.encodeData(data);
};

/**
 * Decode input as a Binary XML data packet, set the fields in the data object, and return
 * the signed offsets.
 * @param {Data} data The Data object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 */
BinaryXmlWireFormat.prototype.decodeData = function(data, input)
{
  var decoder = new BinaryXMLDecoder(input);
  return BinaryXmlWireFormat.decodeData(data, decoder);
};

/**
 * @deprecated Use decodeData(data, input).
 */
BinaryXmlWireFormat.prototype.decodeContentObject = function(data, input)
{
  this.decodeData(data, input);
};

/**
 * Get a singleton instance of a BinaryXmlWireFormat.  Assuming that the default
 * wire format was set with
 * WireFormat.setDefaultWireFormat(BinaryXmlWireFormat.get()), you can check if
 * this is the default wire encoding with
 * if WireFormat.getDefaultWireFormat() == BinaryXmlWireFormat.get().
 * @returns {BinaryXmlWireFormat} The singleton instance.
 */
BinaryXmlWireFormat.get = function()
{
  if (BinaryXmlWireFormat.instance === null)
    BinaryXmlWireFormat.instance = new BinaryXmlWireFormat();
  return BinaryXmlWireFormat.instance;
};

/**
 * Encode the interest by calling the operations on the encoder.
 * @param {Interest} interest
 * @param {BinaryXMLEncoder} encoder
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
BinaryXmlWireFormat.encodeInterest = function(interest, encoder)
{
  encoder.writeElementStartDTag(NDNProtocolDTags.Interest);

  var offsets = interest.getName().to_ndnb(encoder);

  if (null != interest.getMinSuffixComponents())
    encoder.writeDTagElement(NDNProtocolDTags.MinSuffixComponents, interest.getMinSuffixComponents());

  if (null != interest.getMaxSuffixComponents())
    encoder.writeDTagElement(NDNProtocolDTags.MaxSuffixComponents, interest.getMaxSuffixComponents());

  if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
      !interest.getKeyLocator().getKeyData().isNull() &&
      interest.getKeyLocator().getKeyData().size() > 0)
    // There is a KEY_LOCATOR_DIGEST. Use this instead of the publisherPublicKeyDigest.
    encoder.writeDTagElement
      (NDNProtocolDTags.PublisherPublicKeyDigest,
       interest.getKeyLocator().getKeyData());
  else {
    if (null != interest.publisherPublicKeyDigest)
      interest.publisherPublicKeyDigest.to_ndnb(encoder);
  }

  if (null != interest.getExclude())
    interest.getExclude().to_ndnb(encoder);

  if (null != interest.getChildSelector())
    encoder.writeDTagElement(NDNProtocolDTags.ChildSelector, interest.getChildSelector());

  if (interest.DEFAULT_ANSWER_ORIGIN_KIND != interest.setAnswerOriginKind() && interest.setAnswerOriginKind()!=null)
    encoder.writeDTagElement(NDNProtocolDTags.AnswerOriginKind, interest.setAnswerOriginKind());

  if (null != interest.setScope())
    encoder.writeDTagElement(NDNProtocolDTags.Scope, interest.setScope());

  if (null != interest.getInterestLifetimeMilliseconds())
    encoder.writeDTagElement(NDNProtocolDTags.InterestLifetime,
                DataUtils.nonNegativeIntToBigEndian((interest.getInterestLifetimeMilliseconds() / 1000.0) * 4096));

  if (interest.getNonce().size() > 0)
    encoder.writeDTagElement(NDNProtocolDTags.Nonce, interest.getNonce());

  encoder.writeElementClose();
  return offsets;
};

/**
 * Use the decoder to place the result in interest.
 * @param {Interest} interest
 * @param {BinaryXMLDecoder} decoder
 */
BinaryXmlWireFormat.decodeInterest = function(interest, decoder)
{
  decoder.readElementStartDTag(NDNProtocolDTags.Interest);

  interest.setName(new Name());
  interest.getName().from_ndnb(decoder);

  if (decoder.peekDTag(NDNProtocolDTags.MinSuffixComponents))
    interest.setMinSuffixComponents(decoder.readIntegerDTagElement(NDNProtocolDTags.MinSuffixComponents));
  else
    interest.setMinSuffixComponents(null);

  if (decoder.peekDTag(NDNProtocolDTags.MaxSuffixComponents))
    interest.setMaxSuffixComponents(decoder.readIntegerDTagElement(NDNProtocolDTags.MaxSuffixComponents));
  else
    interest.setMaxSuffixComponents(null);

  // Initially clear the keyLocator.
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
    // We keep the deprecated publisherPublicKeyDigest for backwards
    //   compatibility.  Also set the key locator.
    interest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    interest.getKeyLocator().setKeyData
      (interest.publisherPublicKeyDigest.publisherPublicKeyDigest);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Exclude)) {
    interest.setExclude(new Exclude());
    interest.getExclude().from_ndnb(decoder);
  }
  else
    interest.setExclude(new Exclude());

  if (decoder.peekDTag(NDNProtocolDTags.ChildSelector))
    interest.setChildSelector(decoder.readIntegerDTagElement(NDNProtocolDTags.ChildSelector));
  else
    interest.setChildSelector(null);

  if (decoder.peekDTag(NDNProtocolDTags.AnswerOriginKind))
    interest.setAnswerOriginKind(decoder.readIntegerDTagElement(NDNProtocolDTags.AnswerOriginKind));
  else
    interest.setAnswerOriginKind(null);

  if (decoder.peekDTag(NDNProtocolDTags.Scope))
    interest.setScope(decoder.readIntegerDTagElement(NDNProtocolDTags.Scope));
  else
    interest.setScope(null);

  if (decoder.peekDTag(NDNProtocolDTags.InterestLifetime))
    interest.setInterestLifetimeMilliseconds(1000.0 * DataUtils.bigEndianToUnsignedInt
               (decoder.readBinaryDTagElement(NDNProtocolDTags.InterestLifetime)) / 4096);
  else
    interest.setInterestLifetimeMilliseconds(null);

  if (decoder.peekDTag(NDNProtocolDTags.Nonce))
    interest.setNonce(decoder.readBinaryDTagElement(NDNProtocolDTags.Nonce));
  else
    interest.setNonce(null);

  decoder.readElementClose();
};

/**
 * Encode the data by calling the operations on the encoder.
 * @param {Data} data
 * @param {BinaryXMLEncoder} encoder
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 */
BinaryXmlWireFormat.encodeData = function(data, encoder)
{
  //TODO verify name, MetaInfo and Signature is present
  encoder.writeElementStartDTag(data.getElementLabel());

  if (null != data.getSignature())
    data.getSignature().to_ndnb(encoder);

  var signedPortionBeginOffset = encoder.offset;

  if (null != data.getName())
    data.getName().to_ndnb(encoder);

  if (null != data.getMetaInfo())
    // Use getSignatureOrMetaInfoKeyLocator for the transition of moving
    //   the key locator from the MetaInfo to the Signauture object.
    data.getMetaInfo().to_ndnb(encoder, data.getSignatureOrMetaInfoKeyLocator());

  encoder.writeDTagElement(NDNProtocolDTags.Content, data.getContent().buf());

  var signedPortionEndOffset = encoder.offset;

  encoder.writeElementClose();

  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Use the decoder to place the result in data.
 * @param {Data} data
 * @param {BinaryXMLDecoder} decoder
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 */
BinaryXmlWireFormat.decodeData = function(data, decoder)
{
  // TODO VALIDATE THAT ALL FIELDS EXCEPT SIGNATURE ARE PRESENT
  decoder.readElementStartDTag(data.getElementLabel());

  if (decoder.peekDTag(NDNProtocolDTags.Signature)) {
    data.setSignature(new Sha256WithRsaSignature());
    data.getSignature().from_ndnb(decoder);
  }
  else
    data.setSignature(new Sha256WithRsaSignature());

  var signedPortionBeginOffset = decoder.offset;

  data.setName(new Name());
  data.getName().from_ndnb(decoder);

  if (decoder.peekDTag(NDNProtocolDTags.SignedInfo)) {
    data.setMetaInfo(new MetaInfo());
    data.getMetaInfo().from_ndnb(decoder);
    if (data.getMetaInfo().locator != null && data.getSignature() != null)
      // Copy the key locator pointer to the Signature object for the transition
      //   of moving the key locator from the MetaInfo to the Signature object.
      data.getSignature().setKeyLocator(data.getMetaInfo().locator);
  }
  else
    data.setMetaInfo(new MetaInfo());

  data.setContent(decoder.readBinaryDTagElement(NDNProtocolDTags.Content, true));

  var signedPortionEndOffset = decoder.offset;

  decoder.readElementClose();

  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};
/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var crypto = require('crypto');
var Blob = require('../util/blob.js').Blob;
var Tlv = require('./tlv/tlv.js').Tlv;
var TlvEncoder = require('./tlv/tlv-encoder.js').TlvEncoder;
var TlvDecoder = require('./tlv/tlv-decoder.js').TlvDecoder;
var WireFormat = require('./wire-format.js').WireFormat;
var Exclude = require('../exclude.js').Exclude;
var ContentType = require('../meta-info.js').ContentType;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature;
var ForwardingFlags = require('../forwarding-flags.js').ForwardingFlags;
var PublisherPublicKeyDigest = require('../publisher-public-key-digest.js').PublisherPublicKeyDigest;
var DecodingException = require('./decoding-exception.js').DecodingException;

/**
 * A Tlv0_1WireFormat implements the WireFormat interface for encoding and
 * decoding with the NDN-TLV wire format, version 0.1a2.
 * @constructor
 */
var Tlv0_1WireFormat = function Tlv0_1WireFormat()
{
  // Inherit from WireFormat.
  WireFormat.call(this);
};

Tlv0_1WireFormat.prototype = new WireFormat();
Tlv0_1WireFormat.prototype.name = "Tlv0_1WireFormat";

exports.Tlv0_1WireFormat = Tlv0_1WireFormat;

// Default object.
Tlv0_1WireFormat.instance = null;

/**
 * Encode the interest using NDN-TLV and return a Buffer.
 * @param {Interest} interest The Interest object to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the signed
 * portion. The signed portion starts from the first name component and ends
 * just before the final name component (which is assumed to be a signature for
 * a signed interest).
 */
Tlv0_1WireFormat.prototype.encodeInterest = function(interest)
{
  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds());
  encoder.writeOptionalNonNegativeIntegerTlv(Tlv.Scope, interest.getScope());

  // Encode the Nonce as 4 bytes.
  if (interest.getNonce().isNull() || interest.getNonce().size() == 0)
    // This is the most common case. Generate a nonce.
    encoder.writeBlobTlv(Tlv.Nonce, require("crypto").randomBytes(4));
  else if (interest.getNonce().size() < 4) {
    var nonce = Buffer(4);
    // Copy existing nonce bytes.
    interest.getNonce().buf().copy(nonce);

    // Generate random bytes for remaining bytes in the nonce.
    for (var i = interest.getNonce().size(); i < 4; ++i)
      nonce[i] = require("crypto").randomBytes(1)[0];

    encoder.writeBlobTlv(Tlv.Nonce, nonce);
  }
  else if (interest.getNonce().size() == 4)
    // Use the nonce as-is.
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf());
  else
    // Truncate.
    encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf().slice(0, 4));

  Tlv0_1WireFormat.encodeSelectors(interest, encoder);
  var tempOffsets = Tlv0_1WireFormat.encodeName(interest.getName(), encoder);
  var signedPortionBeginOffsetFromBack =
    encoder.getLength() - tempOffsets.signedPortionBeginOffset;
  var signedPortionEndOffsetFromBack =
    encoder.getLength() - tempOffsets.signedPortionEndOffset;

  encoder.writeTypeAndLength(Tlv.Interest, encoder.getLength() - saveLength);
  var signedPortionBeginOffset =
    encoder.getLength() - signedPortionBeginOffsetFromBack;
  var signedPortionEndOffset =
    encoder.getLength() - signedPortionEndOffsetFromBack;

  return { encoding: new Blob(encoder.getOutput(), false),
           signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Decode input as an NDN-TLV interest and set the fields of the interest
 * object.
 * @param {Interest} interest The Interest object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 */
Tlv0_1WireFormat.prototype.decodeInterest = function(interest, input)
{
  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
  Tlv0_1WireFormat.decodeName(interest.getName(), decoder);
  if (decoder.peekType(Tlv.Selectors, endOffset))
    Tlv0_1WireFormat.decodeSelectors(interest, decoder);
  // Require a Nonce, but don't force it to be 4 bytes.
  var nonce = decoder.readBlobTlv(Tlv.Nonce);
  interest.setScope(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.Scope, endOffset));
  interest.setInterestLifetimeMilliseconds
    (decoder.readOptionalNonNegativeIntegerTlv(Tlv.InterestLifetime, endOffset));

  // Set the nonce last because setting other interest fields clears it.
  interest.setNonce(nonce);

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode data as NDN-TLV and return the encoding and signed offsets.
 * @param {Data} data The Data object to encode.
 * @returns {object} An associative array with fields
 * (encoding, signedPortionBeginOffset, signedPortionEndOffset) where encoding
 * is a Blob containing the encoding, signedPortionBeginOffset is the offset in
 * the encoding of the beginning of the signed portion, and
 * signedPortionEndOffset is the offset in the encoding of the end of the
 * signed portion.
 */
Tlv0_1WireFormat.prototype.encodeData = function(data)
{
  var encoder = new TlvEncoder(1500);
  var saveLength = encoder.getLength();

  // Encode backwards.
  // TODO: The library needs to handle other signature types than
  //   SignatureSha256WithRsa.
  encoder.writeBlobTlv(Tlv.SignatureValue, data.getSignature().getSignature().buf());
  var signedPortionEndOffsetFromBack = encoder.getLength();

  // Use getSignatureOrMetaInfoKeyLocator for the transition of moving
  //   the key locator from the MetaInfo to the Signauture object.
  Tlv0_1WireFormat.encodeSignatureSha256WithRsaValue
    (data.getSignature(), encoder, data.getSignatureOrMetaInfoKeyLocator());
  encoder.writeBlobTlv(Tlv.Content, data.getContent().buf());
  Tlv0_1WireFormat.encodeMetaInfo(data.getMetaInfo(), encoder);
  Tlv0_1WireFormat.encodeName(data.getName(), encoder);
  var signedPortionBeginOffsetFromBack = encoder.getLength();

  encoder.writeTypeAndLength(Tlv.Data, encoder.getLength() - saveLength);
  var signedPortionBeginOffset =
    encoder.getLength() - signedPortionBeginOffsetFromBack;
  var signedPortionEndOffset = encoder.getLength() - signedPortionEndOffsetFromBack;

  return { encoding: new Blob(encoder.getOutput(), false),
           signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Decode input as an NDN-TLV data packet, set the fields in the data object,
 * and return the signed offsets.
 * @param {Data} data The Data object whose fields are updated.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion.
 */
Tlv0_1WireFormat.prototype.decodeData = function(data, input)
{
  var decoder = new TlvDecoder(input);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Data);
  var signedPortionBeginOffset = decoder.getOffset();

  Tlv0_1WireFormat.decodeName(data.getName(), decoder);
  Tlv0_1WireFormat.decodeMetaInfo(data.getMetaInfo(), decoder);
  data.setContent(decoder.readBlobTlv(Tlv.Content));
  Tlv0_1WireFormat.decodeSignatureInfo(data, decoder);
  if (data.getSignature() != null &&
      data.getSignature().getKeyLocator() != null &&
      data.getMetaInfo() != null)
    // Copy the key locator pointer to the MetaInfo object for the transition of
    //   moving the key locator from the MetaInfo to the Signature object.
    data.getMetaInfo().locator = data.getSignature().getKeyLocator();

  var signedPortionEndOffset = decoder.getOffset();
  // TODO: The library needs to handle other signature types than
  //   SignatureSha256WithRsa.
  data.getSignature().setSignature
    (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), true));

  decoder.finishNestedTlvs(endOffset);
  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

/**
 * Encode controlParameters as NDN-TLV and return the encoding.
 * @param {ControlParameters} controlParameters The ControlParameters object to
 * encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1WireFormat.prototype.encodeControlParameters = function(controlParameters)
{
  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_ExpirationPeriod,
     controlParameters.getExpirationPeriod());

  // TODO: Encode Strategy.

  var flags = controlParameters.getForwardingFlags().getNfdForwardingFlags();
  if (flags != new ForwardingFlags().getNfdForwardingFlags())
      // The flags are not the default value.
      encoder.writeNonNegativeIntegerTlv
        (Tlv.ControlParameters_Flags, flags);

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_Cost, controlParameters.getCost());
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_Origin, controlParameters.getOrigin());
  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.ControlParameters_LocalControlFeature,
     controlParameters.getLocalControlFeature());

  // TODO: Encode Uri.

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.FaceID, controlParameters.getFaceId());
  Tlv0_1WireFormat.encodeName(controlParameters.getName(), encoder);

  encoder.writeTypeAndLength
    (Tlv.ControlParameters_ControlParameters, encoder.getLength() - saveLength);

  return new Blob(encoder.getOutput(), false);
};

/**
 * Encode signature as a SignatureInfo and return the encoding.
 * @param {Signature} signature An object of a subclass of Signature to encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1WireFormat.prototype.encodeSignatureInfo = function(signature)
{
  var encoder = new TlvEncoder(256);
  // TODO: This assumes it is a Sha256WithRsaSignature.
  Tlv0_1WireFormat.encodeSignatureSha256WithRsaValue
    (signature, encoder, signature.getKeyLocator());
  
  return new Blob(encoder.getOutput(), false);
};

// SignatureHolder is used by decodeSignatureInfoAndValue.
Tlv0_1WireFormat.SignatureHolder = function Tlv0_1WireFormatSignatureHolder()
{
};

Tlv0_1WireFormat.SignatureHolder.prototype.setSignature = function(signature)
{
  this.signature = signature;
};

Tlv0_1WireFormat.SignatureHolder.prototype.getSignature = function()
{
  return this.signature;
};

/**
 * Decode signatureInfo as a signature info and signatureValue as the related
 * SignatureValue, and return a new object which is a subclass of Signature.
 * @param {Buffer} signatureInfo The buffer with the signature info bytes to
 * decode.
 * @param {Buffer} signatureValue The buffer with the signature value to decode.
 * @returns {Signature} A new object which is a subclass of Signature.
 */
Tlv0_1WireFormat.prototype.decodeSignatureInfoAndValue = function
  (signatureInfo, signatureValue)
{
  // Use a SignatureHolder to imitate a Data object for decodeSignatureInfo.
  var signatureHolder = new Tlv0_1WireFormat.SignatureHolder();
  var decoder = new TlvDecoder(signatureInfo);
  Tlv0_1WireFormat.decodeSignatureInfo(signatureHolder, decoder);

  decoder = TlvDecoder(signatureValue);
  // TODO: The library needs to handle other signature types than
  //   SignatureSha256WithRsa.
  signatureHolder.getSignature().setSignature
    (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), true));

  return signatureHolder.getSignature();
};

/**
 * Encode the signatureValue in the Signature object as a SignatureValue (the
 * signature bits) and return the encoding.
 * @param {Signature} signature An object of a subclass of Signature with the
 * signature value to encode.
 * @returns {Blob} A Blob containing the encoding.
 */
Tlv0_1WireFormat.prototype.encodeSignatureValue = function(signature)
{
  var encoder = new TlvEncoder(256);
  // TODO: This assumes it is a Sha256WithRsaSignature.
  encoder.writeBlobTlv(Tlv.SignatureValue, signature.getSignature().buf());

  return new Blob(encoder.getOutput(), false);
};

/**
 * Get a singleton instance of a Tlv1_0a2WireFormat.  To always use the
 * preferred version NDN-TLV, you should use TlvWireFormat.get().
 * @returns {Tlv0_1WireFormat} The singleton instance.
 */
Tlv0_1WireFormat.get = function()
{
  if (Tlv0_1WireFormat.instance === null)
    Tlv0_1WireFormat.instance = new Tlv0_1WireFormat();
  return Tlv0_1WireFormat.instance;
};

/**
 * Encode the name to the encoder.
 * @param {Name} name The name to encode.
 * @param {TlvEncoder} encoder The encoder to receive the encoding.
 * @returns {object} An associative array with fields
 * (signedPortionBeginOffset, signedPortionEndOffset) where
 * signedPortionBeginOffset is the offset in the encoding of the beginning of
 * the signed portion, and signedPortionEndOffset is the offset in the encoding
 * of the end of the signed portion. The signed portion starts from the first
 * name component and ends just before the final name component (which is
 * assumed to be a signature for a signed interest).
 */
Tlv0_1WireFormat.encodeName = function(name, encoder)
{
  var saveLength = encoder.getLength();

  // Encode the components backwards.
  var signedPortionEndOffsetFromBack;
  for (var i = name.size() - 1; i >= 0; --i) {
    encoder.writeBlobTlv(Tlv.NameComponent, name.get(i).getValue().buf());
    if (i == name.size() - 1)
      signedPortionEndOffsetFromBack = encoder.getLength();
  }

  var signedPortionBeginOffsetFromBack = encoder.getLength();
  encoder.writeTypeAndLength(Tlv.Name, encoder.getLength() - saveLength);

  var signedPortionBeginOffset =
    encoder.getLength() - signedPortionBeginOffsetFromBack;
  var signedPortionEndOffset;
  if (name.size() == 0)
    // There is no "final component", so set signedPortionEndOffset arbitrarily.
    signedPortionEndOffset = signedPortionBeginOffset;
  else
    signedPortionEndOffset = encoder.getLength() - signedPortionEndOffsetFromBack;

  return { signedPortionBeginOffset: signedPortionBeginOffset,
           signedPortionEndOffset: signedPortionEndOffset };
};

Tlv0_1WireFormat.decodeName = function(name, decoder)
{
  name.clear();

  var endOffset = decoder.readNestedTlvsStart(Tlv.Name);
  while (decoder.getOffset() < endOffset)
      name.append(decoder.readBlobTlv(Tlv.NameComponent));

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode the interest selectors.  If no selectors are written, do not output a
 * Selectors TLV.
 */
Tlv0_1WireFormat.encodeSelectors = function(interest, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (interest.getMustBeFresh())
    encoder.writeTypeAndLength(Tlv.MustBeFresh, 0);
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.ChildSelector, interest.getChildSelector());
  if (interest.getExclude().size() > 0)
    Tlv0_1WireFormat.encodeExclude(interest.getExclude(), encoder);

  if (interest.getKeyLocator().getType() != null)
    Tlv0_1WireFormat.encodeKeyLocator
      (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), encoder);
  else {
    // There is no keyLocator. If there is a publisherPublicKeyDigest, then
    //   encode as KEY_LOCATOR_DIGEST. (When we remove the deprecated
    //   publisherPublicKeyDigest, we don't need this.)
    if (null != interest.publisherPublicKeyDigest) {
      var savePublisherPublicKeyDigestLength = encoder.getLength();
      encoder.writeBlobTlv
        (Tlv.KeyLocatorDigest,
         interest.publisherPublicKeyDigest.publisherPublicKeyDigest);
      encoder.writeTypeAndLength
        (Tlv.PublisherPublicKeyLocator,
         encoder.getLength() - savePublisherPublicKeyDigestLength);
    }
  }

  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents());
  encoder.writeOptionalNonNegativeIntegerTlv(
    Tlv.MinSuffixComponents, interest.getMinSuffixComponents());

  // Only output the type and length if values were written.
  if (encoder.getLength() != saveLength)
    encoder.writeTypeAndLength(Tlv.Selectors, encoder.getLength() - saveLength);
};

Tlv0_1WireFormat.decodeSelectors = function(interest, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Selectors);

  interest.setMinSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MinSuffixComponents, endOffset));
  interest.setMaxSuffixComponents(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.MaxSuffixComponents, endOffset));

  // Initially set publisherPublicKeyDigest to none.
  interest.publisherPublicKeyDigest = null;
  if (decoder.peekType(Tlv.PublisherPublicKeyLocator, endOffset)) {
    Tlv0_1WireFormat.decodeKeyLocator
      (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), decoder);
    if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST) {
      // For backwards compatibility, also set the publisherPublicKeyDigest.
      interest.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
      interest.publisherPublicKeyDigest.publisherPublicKeyDigest =
        interest.getKeyLocator().getKeyData().buf();
    }
  }
  else
    interest.getKeyLocator().clear();

  if (decoder.peekType(Tlv.Exclude, endOffset))
    Tlv0_1WireFormat.decodeExclude(interest.getExclude(), decoder);
  else
    interest.getExclude().clear();

  interest.setChildSelector(decoder.readOptionalNonNegativeIntegerTlv
    (Tlv.ChildSelector, endOffset));
  interest.setMustBeFresh(decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset));

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1WireFormat.encodeExclude = function(exclude, encoder)
{
  var saveLength = encoder.getLength();

  // TODO: Do we want to order the components (except for ANY)?
  // Encode the entries backwards.
  for (var i = exclude.size() - 1; i >= 0; --i) {
    var entry = exclude.get(i);

    if (entry == Exclude.ANY)
      encoder.writeTypeAndLength(Tlv.Any, 0);
    else
      encoder.writeBlobTlv(Tlv.NameComponent, entry.getValue().buf());
  }

  encoder.writeTypeAndLength(Tlv.Exclude, encoder.getLength() - saveLength);
};

Tlv0_1WireFormat.decodeExclude = function(exclude, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Exclude);

  exclude.clear();
  while (true) {
    if (decoder.peekType(Tlv.NameComponent, endOffset))
      exclude.appendComponent(decoder.readBlobTlv(Tlv.NameComponent));
    else if (decoder.readBooleanTlv(Tlv.Any, endOffset))
      exclude.appendAny();
    else
      // Else no more entries.
      break;
  }

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1WireFormat.encodeKeyLocator = function(type, keyLocator, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  if (keyLocator.getType() != null) {
    if (keyLocator.getType() == KeyLocatorType.KEYNAME)
      Tlv0_1WireFormat.encodeName(keyLocator.getKeyName(), encoder);
    else if (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
             keyLocator.getKeyData().size() > 0)
      encoder.writeBlobTlv(Tlv.KeyLocatorDigest, keyLocator.getKeyData().buf());
    else
      throw new Error("Unrecognized KeyLocatorType " + keyLocator.getType());
  }

  encoder.writeTypeAndLength(type, encoder.getLength() - saveLength);
};

Tlv0_1WireFormat.decodeKeyLocator = function
  (expectedType, keyLocator, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(expectedType);

  keyLocator.clear();

  if (decoder.getOffset() == endOffset)
    // The KeyLocator is omitted, so leave the fields as none.
    return;

  if (decoder.peekType(Tlv.Name, endOffset)) {
    // KeyLocator is a Name.
    keyLocator.setType(KeyLocatorType.KEYNAME);
    Tlv0_1WireFormat.decodeName(keyLocator.getKeyName(), decoder);
  }
  else if (decoder.peekType(Tlv.KeyLocatorDigest, endOffset)) {
    // KeyLocator is a KeyLocatorDigest.
    keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    keyLocator.setKeyData(decoder.readBlobTlv(Tlv.KeyLocatorDigest));
  }
  else
    throw new DecodingException
      ("decodeKeyLocator: Unrecognized key locator type");

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Encode the signature object in TLV, using the given keyLocator instead of the
 * locator in this object.
 * @param {Sha256WithRsaSignature} signature The Sha256WithRsaSignature object to encode.
 * @param {TlvEncoder} encoder The encoder.
 * @param {KeyLocator} keyLocator The key locator to use (from
 * Data.getSignatureOrMetaInfoKeyLocator).
 */
Tlv0_1WireFormat.encodeSignatureSha256WithRsaValue = function
  (signature, encoder, keyLocator)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  Tlv0_1WireFormat.encodeKeyLocator(Tlv.KeyLocator, keyLocator, encoder);
  encoder.writeNonNegativeIntegerTlv
    (Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithRsa);

  encoder.writeTypeAndLength(Tlv.SignatureInfo, encoder.getLength() - saveLength);
};

Tlv0_1WireFormat.decodeSignatureInfo = function(data, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);

  var signatureType = decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
  // TODO: The library needs to handle other signature types than
  //     SignatureSha256WithRsa.
  if (signatureType == Tlv.SignatureType_SignatureSha256WithRsa) {
      data.setSignature(new Sha256WithRsaSignature());
      // Modify data's signature object because if we create an object
      //   and set it, then data will have to copy all the fields.
      var signatureInfo = data.getSignature();
      Tlv0_1WireFormat.decodeKeyLocator
        (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder);
  }
  else
      throw new DecodingException
       ("decodeSignatureInfo: unrecognized SignatureInfo type" + signatureType);

  decoder.finishNestedTlvs(endOffset);
};

Tlv0_1WireFormat.encodeMetaInfo = function(metaInfo, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  var finalBlockIdBuf = metaInfo.getFinalBlockID().getValue().buf();
  if (finalBlockIdBuf != null && finalBlockIdBuf.length > 0) {
    // FinalBlockId has an inner NameComponent.
    var finalBlockIdSaveLength = encoder.getLength();
    encoder.writeBlobTlv(Tlv.NameComponent, finalBlockIdBuf);
    encoder.writeTypeAndLength
      (Tlv.FinalBlockId, encoder.getLength() - finalBlockIdSaveLength);
  }

  encoder.writeOptionalNonNegativeIntegerTlv
    (Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod());
  if (metaInfo.getType() != ContentType.BLOB) {
    // Not the default, so we need to encode the type.
    if (metaInfo.getType() == ContentType.LINK ||
        metaInfo.getType() == ContentType.KEY)
      // The ContentType enum is set up with the correct integer for
      // each NDN-TLV ContentType.
      encoder.writeNonNegativeIntegerTlv(Tlv.ContentType, metaInfo.getType());
    else
      throw new Error("unrecognized TLV ContentType");
  }

  encoder.writeTypeAndLength(Tlv.MetaInfo, encoder.getLength() - saveLength);
};

Tlv0_1WireFormat.decodeMetaInfo = function(metaInfo, decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.MetaInfo);

  // The ContentType enum is set up with the correct integer for each
  // NDN-TLV ContentType.  If readOptionalNonNegativeIntegerTlv returns
  // None, then setType will convert it to BLOB.
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
/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var WireFormat = require('./wire-format.js').WireFormat;
var Tlv0_1WireFormat = require('./tlv-0_1-wire-format.js').Tlv0_1WireFormat;

/**
 * A TlvWireFormat extends WireFormat to override its methods to
 * implement encoding and decoding using the preferred implementation of NDN-TLV.
 * @constructor
 */
var TlvWireFormat = function TlvWireFormat()
{
  // Inherit from Tlv0_1WireFormat.
  Tlv0_1WireFormat.call(this);
};

TlvWireFormat.prototype = new Tlv0_1WireFormat();
TlvWireFormat.prototype.name = "TlvWireFormat";

exports.TlvWireFormat = TlvWireFormat;

// Default object.
TlvWireFormat.instance = null;

/**
 * Get a singleton instance of a TlvWireFormat.  Assuming that the default
 * wire format was set with WireFormat.setDefaultWireFormat(TlvWireFormat.get()),
 * you can check if this is the default wire encoding with
 * if WireFormat.getDefaultWireFormat() == TlvWireFormat.get().
 * @returns {TlvWireFormat} The singleton instance.
 */
TlvWireFormat.get = function()
{
  if (TlvWireFormat.instance === null)
    TlvWireFormat.instance = new TlvWireFormat();
  return TlvWireFormat.instance;
};

// On loading this module, make this the default wire format.
// This module will be loaded because WireFormat loads it.
WireFormat.setDefaultWireFormat(TlvWireFormat.get());
/**
 * This file contains utilities to help encode and decode NDN objects.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * author: Meki Cheraoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var DataUtils = require('./data-utils.js').DataUtils;
var BinaryXMLEncoder = require('./binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./binary-xml-decoder.js').BinaryXMLDecoder;
var Key = require('../key.js').Key;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;
var Interest = require('../interest.js').Interest;
var Data = require('../data.js').Data;
var FaceInstance = require('../face-instance.js').FaceInstance;
var ForwardingEntry = require('../forwarding-entry.js').ForwardingEntry;
var WireFormat = require('./wire-format.js').WireFormat;
var LOG = require('../log.js').Log.LOG;

/**
 * An EncodingUtils has static methods for encoding data.
 * @constructor
 */
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

/**
 * @deprecated Use EncodingUtils.encodeToHexData(data).
 */
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

/**
 * @deprecated Use EncodingUtils.decodeHexData(input).
 */
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

/**
 * Decode the Buffer array which holds SubjectPublicKeyInfo and return an RSAKey.
 */
EncodingUtils.decodeSubjectPublicKeyInfo = function(array)
{
  var hex = DataUtils.toHex(array).toLowerCase();
  var a = _x509_getPublicKeyHexArrayFromCertHex(hex, _x509_getSubjectPublicKeyPosFromCertHex(hex, 0));
  var rsaKey = new RSAKey();
  rsaKey.setPublic(a[0], a[1]);
  return rsaKey;
}

/**
 * Return a user friendly HTML string with the contents of data.
 * This also outputs to console.log.
 */
EncodingUtils.dataToHtml = function(/* Data */ data)
{
  var output ="";

  if (data == -1)
    output+= "NO CONTENT FOUND"
  else if (data == -2)
    output+= "CONTENT NAME IS EMPTY"
  else {
    if (data.getName() != null) {
      output+= "NAME: " + data.getName().toUri();

      output+= "<br />";
      output+= "<br />";
    }
    if (!data.getContent().isNull()) {
      output += "CONTENT(ASCII): "+ DataUtils.toString(data.getContent().buf());

      output+= "<br />";
      output+= "<br />";
    }
    if (!data.getContent().isNull()) {
      output += "CONTENT(hex): "+ data.getContent().toHex();

      output+= "<br />";
      output+= "<br />";
    }
    if (data.getSignature() != null && data.getSignature().digestAlgorithm != null) {
      output += "DigestAlgorithm (hex): "+ DataUtils.toHex(data.getSignature().digestAlgorithm);

      output+= "<br />";
      output+= "<br />";
    }
    if (data.getSignature() != null && data.getSignature().witness != null) {
      output += "Witness (hex): "+ DataUtils.toHex(data.getSignature().witness);

      output+= "<br />";
      output+= "<br />";
    }
    if (data.getSignature() != null && data.getSignature().getSignature() != null) {
      output += "Signature(hex): "+ data.getSignature().getSignature().toHex();

      output+= "<br />";
      output+= "<br />";
    }
    if (data.getMetaInfo() != null && data.getMetaInfo().publisher != null && data.getMetaInfo().publisher.publisherPublicKeyDigest != null) {
      output += "Publisher Public Key Digest(hex): "+ DataUtils.toHex(data.getMetaInfo().publisher.publisherPublicKeyDigest);

      output+= "<br />";
      output+= "<br />";
    }
    if (data.getMetaInfo() != null && data.getMetaInfo().timestamp != null) {
      var d = new Date();
      d.setTime(data.getMetaInfo().timestamp.msec);

      var bytes = [217, 185, 12, 225, 217, 185, 12, 225];

      output += "TimeStamp: "+d;
      output+= "<br />";
      output += "TimeStamp(number): "+ data.getMetaInfo().timestamp.msec;

      output+= "<br />";
    }
    if (data.getMetaInfo() != null && data.getMetaInfo().getFinalBlockID().getValue().size() > 0) {
      output += "FinalBlockID: "+ data.getMetaInfo().getFinalBlockID().getValue().toHex();
      output+= "<br />";
    }
    if (data.getMetaInfo() != null && data.getMetaInfo().locator != null && data.getMetaInfo().locator.getType()) {
      output += "keyLocator: ";
      if (data.getMetaInfo().locator.getType() == KeyLocatorType.KEY)
        output += "Key: " + DataUtils.toHex(data.getMetaInfo().locator.publicKey).toLowerCase() + "<br />";
      else if (data.getMetaInfo().locator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST)
        output += "KeyLocatorDigest: " + DataUtils.toHex(data.getMetaInfo().locator.getKeyData().buf()).toLowerCase() + "<br />";
      else if (data.getMetaInfo().locator.getType() == KeyLocatorType.CERTIFICATE)
        output += "Certificate: " + DataUtils.toHex(data.getMetaInfo().locator.certificate).toLowerCase() + "<br />";
      else if (data.getMetaInfo().locator.getType() == KeyLocatorType.KEYNAME)
        output += "KeyName: " + data.getMetaInfo().locator.keyName.contentName.to_uri() + "<br />";
      else
        output += "[unrecognized ndn_KeyLocatorType " + data.getMetaInfo().locator.getType() + "]<br />";
    }
  }

  return output;
};

/**
 * @deprecated Use return EncodingUtils.dataToHtml(data).
 */
EncodingUtils.contentObjectToHtml = function(data)
{
  return EncodingUtils.dataToHtml(data);
}

//
// Deprecated: For the browser, define these in the global scope.  Applications should access as member of EncodingUtils.
//

var encodeToHexInterest = function(interest) { return EncodingUtils.encodeToHexInterest(interest); }
var encodeToHexContentObject = function(data) { return EncodingUtils.encodeToHexData(data); }
var encodeForwardingEntry = function(data) { return EncodingUtils.encodeForwardingEntry(data); }
var decodeHexFaceInstance = function(input) { return EncodingUtils.decodeHexFaceInstance(input); }
var decodeHexInterest = function(input) { return EncodingUtils.decodeHexInterest(input); }
var decodeHexContentObject = function(input) { return EncodingUtils.decodeHexData(input); }
var decodeHexForwardingEntry = function(input) { return EncodingUtils.decodeHexForwardingEntry(input); }
var decodeSubjectPublicKeyInfo = function(input) { return EncodingUtils.decodeSubjectPublicKeyInfo(input); }
var contentObjectToHtml = function(data) { return EncodingUtils.dataToHtml(data); }

/**
 * @deprecated Use interest.wireEncode().
 */
function encodeToBinaryInterest(interest) { return interest.wireEncode().buf(); }
/**
 * @deprecated Use data.wireEncode().
 */
function encodeToBinaryContentObject(data) { return data.wireEncode().buf(); }
/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var WireFormat = require('../encoding/wire-format.js').WireFormat;
var TlvEncoder = require('../encoding/tlv/tlv-encoder.js').TlvEncoder;
var Blob = require('./blob.js').Blob;

/**
 * A CommandInterestGenerator keeps track of a timestamp and generates command
 * interests according to the NFD Signed Command Interests protocol:
 * http://redmine.named-data.net/projects/nfd/wiki/Command_Interests
 *
 * Create a new CommandInterestGenerator and initialize the timestamp to now.
 * @constructor
 */
var CommandInterestGenerator = function CommandInterestGenerator()
{
  this.lastTimestamp = Math.round(new Date().getTime());
};

exports.CommandInterestGenerator = CommandInterestGenerator;

/**
 * Append a timestamp component and a random value component to interest's name.
 * This ensures that the timestamp is greater than the timestamp used in the
 * previous call. Then use keyChain to sign the interest which appends a
 * SignatureInfo component and a component with the signature bits. If the
 * interest lifetime is not set, this sets it.
 * @param {Interest} interest The interest whose name is append with components.
 * @param {KeyChain} keyChain The KeyChain for calling sign.
 * @param {Name} certificateName The certificate name of the key to use for
 * signing.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode 
 * the SignatureInfo and to encode interest name for signing. If omitted, use
 * WireFormat.getDefaultWireFormat().
 */
CommandInterestGenerator.prototype.generate = function
  (interest, keyChain, certificateName, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  var timestamp = Math.round(new Date().getTime());
  while (timestamp <= this.lastTimestamp)
    timestamp += 1.0;

  // The timestamp is encoded as a TLV nonNegativeInteger.
  var encoder = new TlvEncoder(8);
  encoder.writeNonNegativeInteger(timestamp);
  interest.getName().append(new Blob(encoder.getOutput(), false));

  // The random value is a TLV nonNegativeInteger too, but we know it is 8
  // bytes, so we don't need to call the nonNegativeInteger encoder.
  interest.getName().append(new Blob(require("crypto").randomBytes(8), false));

  keyChain.sign(interest, certificateName, wireFormat);

  if (interest.getInterestLifetimeMilliseconds() == null ||
      interest.getInterestLifetimeMilliseconds() < 0)
    // The caller has not set the interest lifetime, so set it here.
    interest.setInterestLifetimeMilliseconds(1000.0);

  // We successfully signed the interest, so update the timestamp.
  this.lastTimestamp = timestamp;
};
/**
 * This class represents the top-level object for communicating with an NDN host.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cherkaoui, Jeff Thompson <jefft0@remap.ucla.edu>, Wentao Shang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var crypto = require('crypto');
var DataUtils = require('./encoding/data-utils.js').DataUtils;
var Name = require('./name.js').Name;
var Interest = require('./interest.js').Interest;
var Data = require('./data.js').Data;
var MetaInfo = require('./meta-info.js').MetaInfo;
var ForwardingEntry = require('./forwarding-entry.js').ForwardingEntry;
var ControlParameters = require('./control-parameters.js').ControlParameters;
var TlvWireFormat = require('./encoding/tlv-wire-format.js').TlvWireFormat;
var BinaryXmlWireFormat = require('./encoding/binary-xml-wire-format.js').BinaryXmlWireFormat;
var Tlv = require('./encoding/tlv/tlv.js').Tlv;
var TlvDecoder = require('./encoding/tlv/tlv-decoder.js').TlvDecoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var Key = require('./key.js').Key;
var KeyLocatorType = require('./key-locator.js').KeyLocatorType;
var globalKeyManager = require('./security/key-manager.js').globalKeyManager;
var ForwardingFlags = require('./forwarding-flags.js').ForwardingFlags;
var Closure = require('./closure.js').Closure;
var UpcallInfo = require('./closure.js').UpcallInfo;
var Transport = require('./transport/transport.js').Transport;
var TcpTransport = require('./transport/tcp-transport.js').TcpTransport;
var UnixTransport = require('./transport/unix-transport.js').UnixTransport;
var CommandInterestGenerator = require('./util/command-interest-generator.js').CommandInterestGenerator;
var fs = require('fs');
var LOG = require('./log.js').Log.LOG;

/**
 * Create a new Face with the given settings.
 * This throws an exception if Face.supported is false.
 * There are two forms of the constructor.  The first form takes the transport and connectionInfo:
 * Face(transport, connectionInfo).  The second form takes an optional settings object:
 * Face([settings]).
 * @constructor
 * @param {Transport} transport An object of a subclass of Transport to use for
 * communication.
 * @param {Transport.ConnectionInfo} connectionInfo This must be a ConnectionInfo
 * from the same subclass of Transport as transport. If omitted and transport is
 * a new UnixTransport() then attempt to create to the Unix socket for the local
 * forwarder.
 * @param {Object} settings (optional) An associative array with the following defaults:
 * {
 *   getTransport: function() { return new WebSocketTransport(); }, // If in the browser.
 *              OR function() { return new TcpTransport(); },       // If in Node.js.
 *              // If getTransport creates a UnixTransport and connectionInfo is null,
 *              // then connect to the local forwarder's Unix socket.
 *   getConnectionInfo: transport.defaultGetConnectionInfo, // a function, on each call it returns a new Transport.ConnectionInfo or null if there are no more hosts.
 *                                                          // If connectionInfo or host is not null, getConnectionInfo is ignored.
 *   connectionInfo: null,
 *   host: null, // If null and connectionInfo is null, use getConnectionInfo when connecting.
 *               // However, if connectionInfo is not null, use it instead.
 *   port: 9696, // If in the browser.
 *      OR 6363, // If in Node.js.
 *               // However, if connectionInfo is not null, use it instead.
 *   onopen: function() { if (LOG > 3) console.log("NDN connection established."); },
 *   onclose: function() { if (LOG > 3) console.log("NDN connection closed."); },
 *   verify: false // If false, don't verify and call upcall with Closure.UPCALL_CONTENT_UNVERIFIED.
 * }
 */
var Face = function Face(transportOrSettings, connectionInfo)
{
  if (!Face.supported)
    throw new Error("The necessary JavaScript support is not available on this platform.");

  var settings;
  if (typeof transportOrSettings == 'object' && transportOrSettings instanceof Transport) {
    this.getConnectionInfo = null;
    this.transport = transportOrSettings;
    this.connectionInfo = (connectionInfo || null);
    // Use defaults for other settings.
    settings = {};

    if (this.connectionInfo == null) {
      if (this.transport && this.transport.__proto__ &&
          this.transport.__proto__.name == "UnixTransport") {
        // Try to create the default connectionInfo for UnixTransport.
        var filePath = Face.getUnixSocketFilePathForLocalhost();
        if (filePath != null)
          this.connectionInfo = new UnixTransport.ConnectionInfo(filePath);
        else
          console.log
            ("Face constructor: Cannot determine the default Unix socket file path for UnixTransport");
        console.log("Using " + this.connectionInfo.toString());
      }
    }
  }
  else {
    settings = (transportOrSettings || {});
    // For the browser, browserify-tcp-transport.js replaces TcpTransport with WebSocketTransport.
    var getTransport = (settings.getTransport || function() { return new TcpTransport(); });
    this.transport = getTransport();
    this.getConnectionInfo = (settings.getConnectionInfo || this.transport.defaultGetConnectionInfo);

    this.connectionInfo = (settings.connectionInfo || null);
    if (this.connectionInfo == null) {
      var host = (settings.host !== undefined ? settings.host : null);

      if (this.transport && this.transport.__proto__ &&
          this.transport.__proto__.name == "UnixTransport") {
        // We are using UnixTransport on Node.js. There is no IP-style host and port.
        if (host != null)
          // Assume the host is the local Unix socket path.
          this.connectionInfo = new UnixTransport.ConnectionInfo(host);
        else {
          // If getConnectionInfo is not null, it will be used instead so no
          // need to set this.connectionInfo.
          if (this.getConnectionInfo == null) {
            var filePath = Face.getUnixSocketFilePathForLocalhost();
            if (filePath != null)
              this.connectionInfo = new UnixTransport.ConnectionInfo(filePath);
            else
              console.log
                ("Face constructor: Cannot determine the default Unix socket file path for UnixTransport");
          }
        }
      }
      else {
        if (host != null) {
          if (typeof WebSocketTransport != 'undefined')
            this.connectionInfo = new WebSocketTransport.ConnectionInfo
              (host, settings.port || 9696);
          else
            this.connectionInfo = new TcpTransport.ConnectionInfo
              (host, settings.port || 6363);
        }
      }
    }
  }

  // Deprecated: Set this.host and this.port for backwards compatibility.
  if (this.connectionInfo == null) {
    this.host = null;
    this.host = null;
  }
  else {
    this.host = this.connectionInfo.host;
    this.host = this.connectionInfo.port;
  }

  this.readyStatus = Face.UNOPEN;
  this.verify = (settings.verify !== undefined ? settings.verify : false);
  // Event handler
  this.onopen = (settings.onopen || function() { if (LOG > 3) console.log("Face connection established."); });
  this.onclose = (settings.onclose || function() { if (LOG > 3) console.log("Face connection closed."); });
  this.ndndid = null;
  // This is used by reconnectAndExpressInterest.
  this.onConnectedCallbacks = [];
  this.commandKeyChain = null;
  this.commandCertificateName = new Name();
  this.commandInterestGenerator = new CommandInterestGenerator();
};

exports.Face = Face;

Face.UNOPEN = 0;  // the Face is created but not opened yet
Face.OPEN_REQUESTED = 1;  // requested to connect but onopen is not called.
Face.OPENED = 2;  // connection to the forwarder opened
Face.CLOSED = 3;  // connection to the forwarder closed

/**
 * If the forwarder's Unix socket file path exists, then return the file path.
 * Otherwise return an empty string. This uses Node.js blocking file system
 * utilities.
 * @return The Unix socket file path to use, or an empty string.
 */
Face.getUnixSocketFilePathForLocalhost = function()
{
  var filePath = "/var/run/nfd.sock";
  if (fs.existsSync(filePath))
    return filePath;
  else {
    filePath = "/tmp/.ndnd.sock";
    if (fs.existsSync(filePath))
      return filePath;
    else
      return "";
  }
}

/**
 * Return true if necessary JavaScript support is available, else log an error and return false.
 */
Face.getSupported = function()
{
  try {
    var dummy = new Buffer(1).slice(0, 1);
  }
  catch (ex) {
    console.log("NDN not available: Buffer not supported. " + ex);
    return false;
  }

  return true;
};

Face.supported = Face.getSupported();

Face.ndndIdFetcher = new Name('/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY');

Face.prototype.createRoute = function(hostOrConnectionInfo, port)
{
  if (hostOrConnectionInfo instanceof Transport.ConnectionInfo)
    this.connectionInfo = hostOrConnectionInfo;
  else
    this.connectionInfo = new TcpTransport.ConnectionInfo(hostOrConnectionInfo, port);

  // Deprecated: Set this.host and this.port for backwards compatibility.
  this.host = this.connectionInfo.host;
  this.host = this.connectionInfo.port;
};

Face.KeyStore = new Array();

var KeyStoreEntry = function KeyStoreEntry(name, rsa, time)
{
  this.keyName = name;  // KeyName
  this.rsaKey = rsa;    // RSA key
  this.timeStamp = time;  // Time Stamp
};

Face.addKeyEntry = function(/* KeyStoreEntry */ keyEntry)
{
  var result = Face.getKeyByName(keyEntry.keyName);
  if (result == null)
    Face.KeyStore.push(keyEntry);
  else
    result = keyEntry;
};

Face.getKeyByName = function(/* KeyName */ name)
{
  var result = null;

  for (var i = 0; i < Face.KeyStore.length; i++) {
    if (Face.KeyStore[i].keyName.contentName.match(name.contentName)) {
      if (result == null || Face.KeyStore[i].keyName.contentName.size() > result.keyName.contentName.size())
        result = Face.KeyStore[i];
    }
  }

  return result;
};

Face.prototype.close = function()
{
  if (this.readyStatus != Face.OPENED)
    return;

  this.readyStatus = Face.CLOSED;
  this.transport.close();
};

// For fetching data
Face.PITTable = new Array();
Face.PITTableRemoveRequests = new Array();

/**
 * @constructor
 */
var PITEntry = function PITEntry(pendingInterestId, interest, closure)
{
  this.pendingInterestId = pendingInterestId;
  this.interest = interest;  // Interest
  this.closure = closure;    // Closure
  this.timerID = -1;  // Timer ID
};

PITEntry.lastPendingInterestId = 0;

/**
 * Get the next unique pending interest ID.
 *
 * @returns {number} The next pending interest ID.
 */
PITEntry.getNextPendingInterestId = function()
{
  ++PITEntry.lastPendingInterestId;
  return PITEntry.lastPendingInterestId;
};

/**
 * Return the entry from Face.PITTable where the name conforms to the interest selectors, and
 * the interest name is the longest that matches name.
 */

/**
 * Find all entries from Face.PITTable where the name conforms to the entry's
 * interest selectors, remove the entries from the table, cancel their timeout
 * timers and return them.
 * @param {Name} name The name to find the interest for (from the incoming data
 * packet).
 * @returns {Array<PITEntry>} The matching entries from Face.PITTable, or [] if
 * none are found.
 */
Face.extractEntriesForExpressedInterest = function(name)
{
  var result = [];

  // Go backwards through the list so we can erase entries.
  for (var i = Face.PITTable.length - 1; i >= 0; --i) {
    var entry = Face.PITTable[i];
    if (entry.interest.matchesName(name)) {
      // Cancel the timeout timer.
      clearTimeout(entry.timerID);

      result.push(entry);
      Face.PITTable.splice(i, 1);
    }
  }

  return result;
};

// For publishing data
Face.registeredPrefixTable = new Array();
Face.registeredPrefixRemoveRequests = new Array();

/**
 * @constructor
 */
var RegisteredPrefix = function RegisteredPrefix(registeredPrefixId, prefix, closure)
{
  this.registeredPrefixId = registeredPrefixId;
  this.prefix = prefix;        // String
  this.closure = closure;  // Closure
};

RegisteredPrefix.lastRegisteredPrefixId = 0;

/**
 * Get the next unique registered prefix ID.
 * @returns {number} The next registered prefix ID.
 */
RegisteredPrefix.getNextRegisteredPrefixId = function()
{
  ++RegisteredPrefix.lastRegisteredPrefixId;
  return RegisteredPrefix.lastRegisteredPrefixId;
};

/**
 * Find the first entry from Face.registeredPrefixTable where the entry prefix is the longest that matches name.
 * @param {Name} name The name to find the PrefixEntry for (from the incoming interest packet).
 * @returns {object} The entry from Face.registeredPrefixTable, or 0 if not found.
 */
function getEntryForRegisteredPrefix(name)
{
  var iResult = -1;

  for (var i = 0; i < Face.registeredPrefixTable.length; i++) {
    if (LOG > 3) console.log("Registered prefix " + i + ": checking if " + Face.registeredPrefixTable[i].prefix + " matches " + name);
    if (Face.registeredPrefixTable[i].prefix.match(name)) {
      if (iResult < 0 ||
          Face.registeredPrefixTable[i].prefix.size() > Face.registeredPrefixTable[iResult].prefix.size())
        // Update to the longer match.
        iResult = i;
    }
  }

  if (iResult >= 0)
    return Face.registeredPrefixTable[iResult];
  else
    return null;
}

/**
 * Return a function that selects a host at random from hostList and returns
 * makeConnectionInfo(host, port), and if no more hosts remain, return null.
 * @param {Array<string>} hostList An array of host names.
 * @param {number} port The port for the connection.
 * @param {function} makeConnectionInfo This calls makeConnectionInfo(host, port)
 * to make the Transport.ConnectionInfo. For example:
 * function(host, port) { return new TcpTransport.ConnectionInfo(host, port); }
 * @returns {function} A function which returns a Transport.ConnectionInfo.
 */
Face.makeShuffledHostGetConnectionInfo = function(hostList, port, makeConnectionInfo)
{
  // Make a copy.
  hostList = hostList.slice(0, hostList.length);
  DataUtils.shuffle(hostList);

  return function() {
    if (hostList.length == 0)
      return null;

    return makeConnectionInfo(hostList.splice(0, 1)[0], port);
  };
};

/**
 * Send the interest through the transport, read the entire response and call onData.
 * If the interest times out according to interest lifetime, call onTimeout (if not omitted).
 * There are two forms of expressInterest.  The first form takes the exact interest (including lifetime):
 * expressInterest(interest, onData [, onTimeout]).  The second form creates the interest from
 * a name and optional interest template:
 * expressInterest(name [, template], onData [, onTimeout]).
 * This also supports the deprecated form expressInterest(name, closure [, template]), but you should use the other forms.
 * @param {Interest} interest The Interest to send which includes the interest lifetime for the timeout.
 * @param {function} onData When a matching data packet is received, this calls onData(interest, data) where
 * interest is the interest given to expressInterest and data is the received
 * Data object. NOTE: You must not change the interest object - if you need to
 * change it then make a copy.
 * @param {function} onTimeout (optional) If the interest times out according to the interest lifetime,
 *   this calls onTimeout(interest) where:
 *   interest is the interest given to expressInterest.
 * @param {Name} name The Name for the interest. (only used for the second form of expressInterest).
 * @param {Interest} template (optional) If not omitted, copy the interest selectors from this Interest.
 * If omitted, use a default interest lifetime. (only used for the second form of expressInterest).
 * @returns {number} The pending interest ID which can be used with removePendingInterest.
 */
Face.prototype.expressInterest = function(interestOrName, arg2, arg3, arg4)
{
  // There are several overloaded versions of expressInterest, each shown inline below.

  // expressInterest(Name name, Closure closure);                      // deprecated
  // expressInterest(Name name, Closure closure,   Interest template); // deprecated
  if (arg2 && arg2.upcall && typeof arg2.upcall == 'function') {
    // Assume arg2 is the deprecated use with Closure.
    // The first argument is a name. Make the interest from the name and possible template.
    interest = new Interest(interestOrName);
    if (arg3) {
      var template = arg3;
      interest.setMinSuffixComponents(template.getMinSuffixComponents());
      interest.setMaxSuffixComponents(template.getMaxSuffixComponents());
      interest.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
      interest.setExclude(template.getExclude());
      interest.setChildSelector(template.getChildSelector());
      interest.getAnswerOriginKind(template.getAnswerOriginKind());
      interest.setScope(template.getScope());
      interest.setInterestLifetimeMilliseconds(template.getInterestLifetimeMilliseconds());
    }
    else
      interest.setInterestLifetimeMilliseconds(4000);   // default interest timeout value in milliseconds.

    return this.expressInterestWithClosure(interest, arg2);
  }

  var interest;
  var onData;
  var onTimeout;
  // expressInterest(Interest interest, function onData);
  // expressInterest(Interest interest, function onData, function onTimeout);
  if (typeof interestOrName == 'object' && interestOrName instanceof Interest) {
    // Just use a copy of the interest.
    interest = new Interest(interestOrName);
    onData = arg2;
    onTimeout = (arg3 ? arg3 : function() {});
  }
  else {
    // The first argument is a name. Make the interest from the name and possible template.
    interest = new Interest(interestOrName);
    // expressInterest(Name name, Interest template, function onData);
    // expressInterest(Name name, Interest template, function onData, function onTimeout);
    if (arg2 && typeof arg2 == 'object' && arg2 instanceof Interest) {
      var template = arg2;
      interest.setMinSuffixComponents(template.getMinSuffixComponents());
      interest.setMaxSuffixComponents(template.getMaxSuffixComponents());
      interest.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
      interest.setExclude(template.getExclude());
      interest.setChildSelector(template.getChildSelector());
      interest.getAnswerOriginKind(template.getAnswerOriginKind());
      interest.setScope(template.getScope());
      interest.setInterestLifetimeMilliseconds(template.getInterestLifetimeMilliseconds());

      onData = arg3;
      onTimeout = (arg4 ? arg4 : function() {});
    }
    // expressInterest(Name name, function onData);
    // expressInterest(Name name, function onData,   function onTimeout);
    else {
      interest.setInterestLifetimeMilliseconds(4000);   // default interest timeout
      onData = arg2;
      onTimeout = (arg3 ? arg3 : function() {});
    }
  }

  // Make a Closure from the callbacks so we can use expressInterestWithClosure.
  // TODO: Convert the PIT to use callbacks, not a closure.
  return this.expressInterestWithClosure(interest, new Face.CallbackClosure(onData, onTimeout));
};

Face.CallbackClosure = function FaceCallbackClosure(onData, onTimeout, onInterest, prefix, transport) {
  // Inherit from Closure.
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
    // Note: We never return INTEREST_CONSUMED because onInterest will send the result to the transport.
    this.onInterest(this.prefix, upcallInfo.interest, this.transport)

  return Closure.RESULT_OK;
};

/**
 * A private method to send the the interest to host:port, read the entire response and call
 * closure.upcall(Closure.UPCALL_CONTENT (or Closure.UPCALL_CONTENT_UNVERIFIED),
 *                 new UpcallInfo(this, interest, 0, data)).
 * @deprecated Use expressInterest with callback functions, not Closure.
 * @param {Interest} the interest, already processed with a template (if supplied).
 * @param {Closure} closure
 * @returns {number} The pending interest ID which can be used with removePendingInterest.
 */
Face.prototype.expressInterestWithClosure = function(interest, closure)
{
  var pendingInterestId = PITEntry.getNextPendingInterestId();

  if (this.connectionInfo == null) {
    if (this.getConnectionInfo == null)
      console.log('ERROR: connectionInfo is NOT SET');
    else {
      var thisFace = this;
      this.connectAndExecute(function() { 
        thisFace.reconnectAndExpressInterest(pendingInterestId, interest, closure);
      });
    }
  }
  else
    this.reconnectAndExpressInterest(pendingInterestId, interest, closure);

  return pendingInterestId;
};

/**
 * If the host and port are different than the ones in this.transport, then call
 *   this.transport.connect to change the connection (or connect for the first time).
 * Then call expressInterestHelper.
 */
Face.prototype.reconnectAndExpressInterest = function(pendingInterestId, interest, closure)
{
  var thisFace = this;
  if (!this.connectionInfo.equals(this.transport.connectionInfo) || this.readyStatus === Face.UNOPEN) {
    this.readyStatus = Face.OPEN_REQUESTED;
    this.onConnectedCallbacks.push
      (function() { thisFace.expressInterestHelper(pendingInterestId, interest, closure); });

    this.transport.connect
     (this.connectionInfo, this,
      function() {
        thisFace.readyStatus = Face.OPENED;

        // Execute each action requested while the connection was opening.
        while (thisFace.onConnectedCallbacks.length > 0) {
          try {
            thisFace.onConnectedCallbacks.shift()();
          } catch (ex) {
            console.log("Face.reconnectAndExpressInterest: ignoring exception from onConnectedCallbacks: " + ex);
          }
        }

        if (thisFace.onopen)
          // Call Face.onopen after success
          thisFace.onopen();
      },
      function() { thisFace.closeByTransport(); });
  }
  else {
    if (this.readyStatus === Face.OPEN_REQUESTED)
      // The connection is still opening, so add to the interests to express.
      this.onConnectedCallbacks.push
        (function() { thisFace.expressInterestHelper(pendingInterestId, interest, closure); });
    else if (this.readyStatus === Face.OPENED)
      this.expressInterestHelper(pendingInterestId, interest, closure);
    else
      throw new Error
        ("reconnectAndExpressInterest: unexpected connection is not opened");
  }
};

/**
 * Do the work of reconnectAndExpressInterest once we know we are connected.  Set the PITTable and call
 *   this.transport.send to send the interest.
 */
Face.prototype.expressInterestHelper = function(pendingInterestId, interest, closure)
{
  var binaryInterest = interest.wireEncode();
  var thisFace = this;
  //TODO: check local content store first
  if (closure != null) {
    var removeRequestIndex = -1;
    if (removeRequestIndex != null)
      removeRequestIndex = Face.PITTableRemoveRequests.indexOf(pendingInterestId);
    if (removeRequestIndex >= 0)
      // removePendingInterest was called with the pendingInterestId returned by
      //   expressInterest before we got here, so don't add a PIT entry.
      Face.PITTableRemoveRequests.splice(removeRequestIndex, 1);
    else {
      var pitEntry = new PITEntry(pendingInterestId, interest, closure);
      // TODO: This needs to be a single thread-safe transaction on a global object.
      Face.PITTable.push(pitEntry);
      closure.pitEntry = pitEntry;

      // Set interest timer.
      var timeoutMilliseconds = (interest.getInterestLifetimeMilliseconds() || 4000);
      var timeoutCallback = function() {
        if (LOG > 1) console.log("Interest time out: " + interest.getName().toUri());

        // Remove PIT entry from Face.PITTable, even if we add it again later to re-express
        //   the interest because we don't want to match it in the mean time.
        // TODO: Make this a thread-safe operation on the global PITTable.
        var index = Face.PITTable.indexOf(pitEntry);
        if (index >= 0)
          Face.PITTable.splice(index, 1);

        // Raise closure callback
        if (closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, new UpcallInfo(thisFace, interest, 0, null)) == Closure.RESULT_REEXPRESS) {
          if (LOG > 1) console.log("Re-express interest: " + interest.getName().toUri());
          pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
          Face.PITTable.push(pitEntry);
          thisFace.transport.send(binaryInterest.buf());
        }
      };

      pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
    }
  }

  this.transport.send(binaryInterest.buf());
};

/**
 * Remove the pending interest entry with the pendingInterestId from the pending
 * interest table. This does not affect another pending interest with a
 * different pendingInterestId, even if it has the same interest name.
 * If there is no entry with the pendingInterestId, do nothing.
 * @param {number} pendingInterestId The ID returned from expressInterest.
 */
Face.prototype.removePendingInterest = function(pendingInterestId)
{
  if (pendingInterestId == null)
    return;
  
  // Go backwards through the list so we can erase entries.
  // Remove all entries even though pendingInterestId should be unique.
  var count = 0;
  for (var i = Face.PITTable.length - 1; i >= 0; --i) {
    var entry = Face.PITTable[i];
    if (entry.pendingInterestId == pendingInterestId) {
      // Cancel the timeout timer.
      clearTimeout(entry.timerID);

      Face.PITTable.splice(i, 1);
      ++count;
    }
  }

  if (count == 0) {
    // The pendingInterestId was not found. Perhaps this has been called before
    //   the callback in expressInterest can add to the PIT. Add this
    //   removal request which will be checked before adding to the PIT.
    if (Face.PITTableRemoveRequests.indexOf(pendingInterestId) < 0)
      // Not already requested, so add the request.
      Face.PITTableRemoveRequests.push(pendingInterestId);
  }
};

/**
 * Set the KeyChain and certificate name used to sign command interests (e.g. 
 * for registerPrefix).
 * @param {KeyChain} keyChain The KeyChain object for signing interests, which 
 * must remain valid for the life of this Face. You must create the KeyChain 
 * object and pass it in. You can create a default KeyChain for your system with 
 * the default KeyChain constructor.
 * @param {Name} certificateName The certificate name for signing interests.
 * This makes a copy of the Name. You can get the default certificate name with
 * keyChain.getDefaultCertificateName() .
 */
Face.prototype.setCommandSigningInfo = function(keyChain, certificateName)
{
  this.commandKeyChain = keyChain;
  this.commandCertificateName = new Name(certificateName);
};

/**
 * Set the certificate name used to sign command interest (e.g. for
 * registerPrefix), using the KeyChain that was set with setCommandSigningInfo.
 * @param {Name} certificateName The certificate name for signing interest. This 
 * makes a copy of the Name.
 */
Face.prototype.setCommandCertificateName = function(certificateName)
{
  this.commandCertificateName = new Name(certificateName);
};

/**
 * Append a timestamp component and a random value component to interest's name. 
 * Then use the keyChain and certificateName from setCommandSigningInfo to sign 
 * the interest. If the interest lifetime is not set, this sets it.
 * @note This method is an experimental feature. See the API docs for more
 * detail at
 * http://named-data.net/doc/ndn-ccl-api/face.html#face-makecommandinterest-method .
 * @param {Interest} interest The interest whose name is appended with
 * components.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the SignatureInfo and to encode the interest name for signing.  If omitted,
 * use WireFormat.getDefaultWireFormat().
 */
Face.prototype.makeCommandInterest = function(interest, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  this.nodeMakeCommandInterest
    (interest, this.commandKeyChain, this.commandCertificateName, wireFormat);
};

/**
 * Append a timestamp component and a random value component to interest's name.
 * Then use the keyChain and certificateName from setCommandSigningInfo to sign
 * the interest. If the interest lifetime is not set, this sets it.
 * @param {Interest} interest The interest whose name is appended with
 * components.
 * @param {KeyChain} keyChain The KeyChain for calling sign.
 * @param {Name} certificateName The certificate name of the key to use for
 * signing.
 * @param {WireFormat} wireFormat A WireFormat object used to encode
 * the SignatureInfo and to encode the interest name for signing.
 */
Face.prototype.nodeMakeCommandInterest = function
  (interest, keyChain, certificateName, wireFormat)
{
  this.commandInterestGenerator.generate
    (interest, keyChain, certificateName, wireFormat);
};

/**
 * Register prefix with the connected NDN hub and call onInterest when a matching interest is received.
 * This uses the form:
 * registerPrefix(name, onInterest, onRegisterFailed [, flags]).
 * This also supports the deprecated form registerPrefix(name, closure [, intFlags]), but you should use the main form.
 * @param {Name} prefix The Name prefix.
 * @param {function} onInterest When an interest is received which matches the name prefix, this calls
 * onInterest(prefix, interest, transport) where:
 *   prefix is the prefix given to registerPrefix.
 *   interest is the received interest.
 *   transport The Transport with the connection which received the interest. You must encode a signed Data packet and send it using transport.send().
 * NOTE: You must not change the prefix object - if you need to change it then
 * make a copy.
 * @param {function} onRegisterFailed If register prefix fails for any reason,
 * this calls onRegisterFailed(prefix) where:
 *   prefix is the prefix given to registerPrefix.
 * @param {ForwardingFlags} flags (optional) The ForwardingFlags object for finer control of which interests are forward to the application.
 * If omitted, use the default flags defined by the default ForwardingFlags constructor.
 * @param {number} intFlags (optional) (only for the deprecated form of
 * registerPrefix) The integer NDNx flags for finer control of which interests
 * are forward to the application.
 * @returns {number} The registered prefix ID which can be used with
 * removeRegisteredPrefix.
 */
Face.prototype.registerPrefix = function(prefix, arg2, arg3, arg4)
{
  // There are several overloaded versions of registerPrefix, each shown inline below.

  // registerPrefix(Name prefix, Closure closure);            // deprecated
  // registerPrefix(Name prefix, Closure closure, int flags); // deprecated
  if (arg2 && arg2.upcall && typeof arg2.upcall == 'function') {
    // Assume arg2 is the deprecated use with Closure.
    if (arg3) {
      var flags;
      if (typeof flags === 'number') {
        // Assume this deprecated form is only called for NDNx.
        flags = new ForwardingFlags();
        flags.setForwardingEntryFlags(arg3);
      }
      else
        // Assume arg3 is already a ForwardingFlags.
        flags = arg3;
      return this.registerPrefixWithClosure(prefix, arg2, flags);
    }
    else
      return this.registerPrefixWithClosure(prefix, arg2, new ForwardingFlags());
  }

  // registerPrefix(Name prefix, function onInterest, function onRegisterFailed);
  // registerPrefix(Name prefix, function onInterest, function onRegisterFailed, ForwardingFlags flags);
  var onInterest = arg2;
  var onRegisterFailed = (arg3 ? arg3 : function() {});
  var flags = (arg4 ? arg4 : new ForwardingFlags());
  return this.registerPrefixWithClosure
    (prefix, new Face.CallbackClosure(null, null, onInterest, prefix, this.transport),
     flags, onRegisterFailed);
};

/**
 * A private method to register the prefix with the host, receive the data and call
 * closure.upcall(Closure.UPCALL_INTEREST, new UpcallInfo(this, interest, 0, null)).
 * @deprecated Use registerPrefix with callback functions, not Closure.
 * @param {Name} prefix
 * @param {Closure} closure
 * @param {ForwardingFlags} flags
 * @param {function} onRegisterFailed (optional) If called from the
 * non-deprecated registerPrefix, call onRegisterFailed(prefix) if registration
 * fails.
 * @returns {number} The registered prefix ID which can be used with
 * removeRegisteredPrefix.
 */
Face.prototype.registerPrefixWithClosure = function
  (prefix, closure, flags, onRegisterFailed)
{
  var registeredPrefixId = RegisteredPrefix.getNextRegisteredPrefixId();
  var thisFace = this;
  var onConnected = function() {
    // If we have an _ndndId, we know we already connected to NDNx.
    if (thisFace.ndndid != null || thisFace.commandKeyChain == null) {
      // Assume we are connected to a legacy NDNx server.

      if (thisFace.ndndid == null) {
        // Fetch ndndid first, then register.
        var interest = new Interest(Face.ndndIdFetcher);
        interest.setInterestLifetimeMilliseconds(4000);
        if (LOG > 3) console.log('Expressing interest for ndndid from ndnd.');
        thisFace.reconnectAndExpressInterest
          (null, interest, new Face.FetchNdndidClosure
           (thisFace, registeredPrefixId, prefix, closure, flags, onRegisterFailed));
      }
      else
        thisFace.registerPrefixHelper
          (registeredPrefixId, prefix, closure, flags, onRegisterFailed);
    }
    else
      // The application set the KeyChain for signing NFD interests.
      thisFace.nfdRegisterPrefix
        (registeredPrefixId, prefix, closure, flags, onRegisterFailed,
         thisFace.commandKeyChain, thisFace.commandCertificateName);
  };

  if (this.connectionInfo == null) {
    if (this.getConnectionInfo == null)
      console.log('ERROR: connectionInfo is NOT SET');
    else
      this.connectAndExecute(onConnected);
  }
  else
    onConnected();

  return registeredPrefixId;
};

/**
 * This is a closure to receive the Data for Face.ndndIdFetcher and call
 *   registerPrefixHelper(registeredPrefixId, prefix, callerClosure, flags).
 */
Face.FetchNdndidClosure = function FetchNdndidClosure
  (face, registeredPrefixId, prefix, callerClosure, flags, onRegisterFailed)
{
  // Inherit from Closure.
  Closure.call(this);

  this.face = face;
  this.registeredPrefixId = registeredPrefixId;
  this.prefix = prefix;
  this.callerClosure = callerClosure;
  this.flags = flags; // FOrwardingFlags
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
    // The upcall is not for us.  Don't expect this to happen.
    return Closure.RESULT_ERR;

  if (LOG > 3) console.log('Got ndndid from ndnd.');
  // Get the digest of the public key in the data packet content.
  var hash = require("crypto").createHash('sha256');
  hash.update(upcallInfo.data.getContent().buf());
  this.face.ndndid = new Buffer(DataUtils.toNumbersIfString(hash.digest()));
  if (LOG > 3) console.log(this.face.ndndid);

  this.face.registerPrefixHelper
    (this.registeredPrefixId, this.prefix, this.callerClosure, this.flags,
     this.onRegisterFailed);

  return Closure.RESULT_OK;
};

/**
 * This is a closure to receive the response Data packet from the register
 * prefix interest sent to the connected NDN hub. If this gets a bad response
 * or a timeout, call onRegisterFailed.
 */
Face.RegisterResponseClosure = function RegisterResponseClosure
  (face, prefix, callerClosure, onRegisterFailed, flags, wireFormat, isNfdCommand)
{
  // Inherit from Closure.
  Closure.call(this);

  this.face = face;
  this.prefix = prefix;
  this.callerClosure = callerClosure;
  this.onRegisterFailed = onRegisterFailed;
  this.flags = flags;
  this.wireFormat = wireFormat;
  this.isNfdCommand = isNfdCommand;
};

Face.RegisterResponseClosure.prototype.upcall = function(kind, upcallInfo)
{
  if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
    // We timed out waiting for the response.
    if (this.isNfdCommand) {
      // The application set the commandKeyChain, but we may be connected to NDNx.
      if (this.face.ndndid == null) {
        // Fetch ndndid first, then register.
        // Pass 0 for registeredPrefixId since the entry was already added to
        //   registeredPrefixTable_ on the first try.
        var interest = new Interest(Face.ndndIdFetcher);
        interest.setInterestLifetimeMilliseconds(4000);
        this.face.reconnectAndExpressInterest
          (null, interest, new Face.FetchNdndidClosure
           (this.face, 0, this.prefix, this.closure, this.flags, this.onRegisterFailed));
      }
      else
        // Pass 0 for registeredPrefixId since the entry was already added to
        //   registeredPrefixTable_ on the first try.
        this.face.registerPrefixHelper
          (0, this.prefix, this.closure, this.flags, this.onRegisterFailed);
    }
    else {
      // An NDNx command was sent because there is no commandKeyChain, so we
      //   can't try an NFD command. Or it was sent from this callback after
      //   trying an NFD command. Fail.
      if (this.onRegisterFailed)
        this.onRegisterFailed(this.prefix);
    }
    
    return Closure.RESULT_OK;
  }
  if (!(kind == Closure.UPCALL_CONTENT ||
        kind == Closure.UPCALL_CONTENT_UNVERIFIED))
    // The upcall is not for us.  Don't expect this to happen.
    return Closure.RESULT_ERR;

  if (this.isNfdCommand) {
    // Decode responseData->getContent() and check for a success code.
    // TODO: Move this into the TLV code.
    var statusCode;
    try {
        var decoder = new TlvDecoder(upcallInfo.data.getContent().buf());
        decoder.readNestedTlvsStart(Tlv.NfdCommand_ControlResponse);
        statusCode = decoder.readNonNegativeIntegerTlv(Tlv.NfdCommand_StatusCode);
    }
    catch (e) {
        // Error decoding the ControlResponse.
        if (this.onRegisterFailed)
          this.onRegisterFailed(this.prefix);
        return Closure.RESULT_OK;
    }

    // Status code 200 is "OK".
    if (statusCode != 200) {
      if (this.onRegisterFailed)
        this.onRegisterFailed(this.prefix);
    }

    // Otherwise, silently succeed.
  }
  else {
    var expectedName = new Name("/ndnx/.../selfreg");
    // Got a response. Do a quick check of expected name components.
    if (upcallInfo.data.getName().size() < 4 ||
        !upcallInfo.data.getName().get(0).equals(expectedName.get(0)) ||
        !upcallInfo.data.getName().get(2).equals(expectedName.get(2))) {
      this.onRegisterFailed(this.prefix);
      return Closure.RESULT_OK;
    }

    // Otherwise, silently succeed.
  }

  return Closure.RESULT_OK;
};

/**
 * Do the work of registerPrefix once we know we are connected with an ndndid.
 * @param {type} registeredPrefixId The
 * RegisteredPrefix.getNextRegisteredPrefixId() which registerPrefix got so it
 * could return it to the caller. If this is 0, then don't add to
 * registeredPrefixTable (assuming it has already been done).
 * @param {Name} prefix
 * @param {Closure} closure
 * @param {ForwardingFlags} flags
 * @param {function} onRegisterFailed
 * @returns {undefined}
 */
Face.prototype.registerPrefixHelper = function
  (registeredPrefixId, prefix, closure, flags, onRegisterFailed)
{
  var removeRequestIndex = -1;
  if (removeRequestIndex != null)
    removeRequestIndex = Face.registeredPrefixRemoveRequests.indexOf
      (registeredPrefixId);
  if (removeRequestIndex >= 0) {
    // removeRegisteredPrefix was called with the registeredPrefixId returned by
    //   registerPrefix before we got here, so don't add a registeredPrefixTable
    //   entry.
    Face.registeredPrefixRemoveRequests.splice(removeRequestIndex, 1);
    return;
  }

  // A ForwardingEntry is only used with NDNx.
  var fe = new ForwardingEntry
    ('selfreg', prefix, null, null, flags.getForwardingEntryFlags(), null);

  // Always encode as BinaryXml until we support TLV for ForwardingEntry.
  var encoder = new BinaryXMLEncoder();
  fe.to_ndnb(encoder);
  var bytes = encoder.getReducedOstream();

  var metaInfo = new MetaInfo();
  metaInfo.setFields();
  // Since we encode the register prefix message as BinaryXml, use the full
  //   public key in the key locator to make the legacy NDNx happy.
  metaInfo.locator.setType(KeyLocatorType.KEY);
  metaInfo.locator.setKeyData(globalKeyManager.getKey().publicToDER());

  var data = new Data(new Name(), metaInfo, bytes);
  // Always encode as BinaryXml until we support TLV for ForwardingEntry.
  data.sign(BinaryXmlWireFormat.get());
  var coBinary = data.wireEncode(BinaryXmlWireFormat.get());;

  var nodename = this.ndndid;
  var interestName = new Name(['ndnx', nodename, 'selfreg', coBinary]);

  var interest = new Interest(interestName);
  interest.setInterestLifetimeMilliseconds(4000.0);
  interest.setScope(1);
  if (LOG > 3) console.log('Send Interest registration packet.');

  if (registeredPrefixId != 0)
    Face.registeredPrefixTable.push
      (new RegisteredPrefix(registeredPrefixId, prefix, closure));

  this.reconnectAndExpressInterest
    (null, interest, new Face.RegisterResponseClosure
     (this, prefix, closure, onRegisterFailed, flags, BinaryXmlWireFormat.get(), false));
};

/**
 * Do the work of registerPrefix to register with NFD.
 * @param {number} registeredPrefixId The 
 * RegisteredPrefix.getNextRegisteredPrefixId() which registerPrefix got so it 
 * could return it to the caller. If this is 0, then don't add to 
 * registeredPrefixTable (assuming it has already been done).
 * @param {Name} prefix
 * @param {Closure} closure
 * @param {ForwardingFlags} flags
 * @param {function} onRegisterFailed
 * @param {KeyChain} commandKeyChain
 * @param {Name} commandCertificateName
 */
Face.prototype.nfdRegisterPrefix = function
  (registeredPrefixId, prefix, closure, flags, onRegisterFailed, commandKeyChain,
   commandCertificateName)
{
  var removeRequestIndex = -1;
  if (removeRequestIndex != null)
    removeRequestIndex = Face.registeredPrefixRemoveRequests.indexOf
      (registeredPrefixId);
  if (removeRequestIndex >= 0) {
    // removeRegisteredPrefix was called with the registeredPrefixId returned by
    //   registerPrefix before we got here, so don't add a registeredPrefixTable
    //   entry.
    Face.registeredPrefixRemoveRequests.splice(removeRequestIndex, 1);
    return;
  }

  if (commandKeyChain == null)
      throw new Error
        ("registerPrefix: The command KeyChain has not been set. You must call setCommandSigningInfo.");
  if (commandCertificateName.size() == 0)
      throw new Error
        ("registerPrefix: The command certificate name has not been set. You must call setCommandSigningInfo.");

  var controlParameters = new ControlParameters();
  controlParameters.setName(prefix);

  var commandInterest = new Interest(new Name("/localhost/nfd/rib/register"));
  // NFD only accepts TlvWireFormat packets.
  commandInterest.getName().append
    (controlParameters.wireEncode(TlvWireFormat.get()));
  this.nodeMakeCommandInterest
    (commandInterest, commandKeyChain, commandCertificateName,
     TlvWireFormat.get());
  // The interest is answered by the local host, so set a short timeout.
  commandInterest.setInterestLifetimeMilliseconds(2000.0);

  if (registeredPrefixId != 0)
      // Save the onInterest callback and send the registration interest.
      Face.registeredPrefixTable.push
        (new RegisteredPrefix(registeredPrefixId, prefix, closure));

  this.reconnectAndExpressInterest
    (null, commandInterest, new Face.RegisterResponseClosure
     (this, prefix, closure, onRegisterFailed, flags,
      TlvWireFormat.get(), true));
};

/**
 * Remove the registered prefix entry with the registeredPrefixId from the
 * registered prefix table. This does not affect another registered prefix with
 * a different registeredPrefixId, even if it has the same prefix name. If there
 * is no entry with the registeredPrefixId, do nothing.
 *
 * @param {number} registeredPrefixId The ID returned from registerPrefix.
 */
Face.prototype.removeRegisteredPrefix = function(registeredPrefixId)
{
  // Go backwards through the list so we can erase entries.
  // Remove all entries even though registeredPrefixId should be unique.
  var count = 0;
  for (var i = Face.registeredPrefixTable.length - 1; i >= 0; --i) {
    var entry = Face.registeredPrefixTable[i];
    if (entry.registeredPrefixId == registeredPrefixId) {
      Face.registeredPrefixTable.splice(i, 1);
      ++count;
    }
  }

  if (count == 0) {
    // The registeredPrefixId was not found. Perhaps this has been called before
    //   the callback in registerPrefix can add to the registeredPrefixTable. Add
    //   this removal request which will be checked before adding to the
    //   registeredPrefixTable.
    if (Face.registeredPrefixRemoveRequests.indexOf(registeredPrefixId) < 0)
      // Not already requested, so add the request.
      Face.registeredPrefixRemoveRequests.push(registeredPrefixId);
  }
};

/**
 * This is called when an entire binary XML element is received, such as a Data or Interest.
 * Look up in the PITTable and call the closure callback.
 */
Face.prototype.onReceivedElement = function(element)
{
  if (LOG > 3) console.log('Complete element received. Length ' + element.length + '. Start decoding.');
  // First, decode as Interest or Data.
  var interest = null;
  var data = null;
  // The type codes for TLV Interest and Data packets are chosen to not
  //   conflict with the first byte of a binary XML packet, so we can
  //   just look at the first byte.
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
    // Binary XML.
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

  // Now process as Interest or Data.
  if (interest !== null) {
    if (LOG > 3) console.log('Interest packet received.');

    var entry = getEntryForRegisteredPrefix(interest.getName());
    if (entry != null) {
      if (LOG > 3) console.log("Found registered prefix for " + interest.getName().toUri());
      var info = new UpcallInfo(this, interest, 0, null);
      var ret = entry.closure.upcall(Closure.UPCALL_INTEREST, info);
      if (ret == Closure.RESULT_INTEREST_CONSUMED && info.data != null)
        this.transport.send(info.data.wireEncode().buf());
    }
  }
  else if (data !== null) {
    if (LOG > 3) console.log('Data packet received.');

    var pendingInterests = Face.extractEntriesForExpressedInterest(data.getName());
    // Process each matching PIT entry (if any).
    for (var i = 0; i < pendingInterests.length; ++i) {
      var pitEntry = pendingInterests[i];
      var currentClosure = pitEntry.closure;

      if (this.verify == false) {
        // Pass content up without verifying the signature
        currentClosure.upcall(Closure.UPCALL_CONTENT_UNVERIFIED, new UpcallInfo(this, pitEntry.interest, 0, data));
        continue;
      }

      // Key verification

      // Recursive key fetching & verification closure
      var KeyFetchClosure = function KeyFetchClosure(content, closure, key, sig, wit) {
        this.data = content;  // unverified data packet object
        this.closure = closure;  // closure corresponding to the data
        this.keyName = key;  // name of current key to be fetched

        Closure.call(this);
      };

      var thisFace = this;
      KeyFetchClosure.prototype.upcall = function(kind, upcallInfo) {
        if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
          console.log("In KeyFetchClosure.upcall: interest time out.");
          console.log(this.keyName.contentName.toUri());
        }
        else if (kind == Closure.UPCALL_CONTENT) {
          var rsakey = new Key();
          rsakey.readDerPublicKey(upcallInfo.data.getContent().buf());
          var verified = data.verify(rsakey);

          var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
          this.closure.upcall(flag, new UpcallInfo(thisFace, null, 0, this.data));

          // Store key in cache
          var keyEntry = new KeyStoreEntry(keylocator.keyName, rsakey, new Date().getTime());
          Face.addKeyEntry(keyEntry);
        }
        else if (kind == Closure.UPCALL_CONTENT_BAD)
          console.log("In KeyFetchClosure.upcall: signature verification failed");
      };

      if (data.getMetaInfo() && data.getMetaInfo().locator && data.getSignature()) {
        if (LOG > 3) console.log("Key verification...");
        var sigHex = data.getSignature().getSignature().toHex();

        var wit = null;
        if (data.getSignature().witness != null)
            //SWT: deprecate support for Witness decoding and Merkle hash tree verification
            currentClosure.upcall(Closure.UPCALL_CONTENT_BAD, new UpcallInfo(this, pitEntry.interest, 0, data));

        var keylocator = data.getMetaInfo().locator;
        if (keylocator.getType() == KeyLocatorType.KEYNAME) {
          if (LOG > 3) console.log("KeyLocator contains KEYNAME");

          if (keylocator.keyName.contentName.match(data.getName())) {
            if (LOG > 3) console.log("Content is key itself");

            var rsakey = new Key();
            rsakey.readDerPublicKey(data.getContent().buf());
            var verified = data.verify(rsakey);
            var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;

            currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, data));

            // SWT: We don't need to store key here since the same key will be stored again in the closure.
          }
          else {
            // Check local key store
            var keyEntry = Face.getKeyByName(keylocator.keyName);
            if (keyEntry) {
              // Key found, verify now
              if (LOG > 3) console.log("Local key cache hit");
              var rsakey = keyEntry.rsaKey;
              var verified = data.verify(rsakey);
              var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;

              // Raise callback
              currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, data));
            }
            else {
              // Not found, fetch now
              if (LOG > 3) console.log("Fetch key according to keylocator");
              var nextClosure = new KeyFetchClosure(data, currentClosure, keylocator.keyName, sigHex, wit);
              // TODO: Use expressInterest with callbacks, not Closure.
              this.expressInterest(keylocator.keyName.contentName.getPrefix(4), nextClosure);
            }
          }
        }
        else if (keylocator.getType() == KeyLocatorType.KEY) {
          if (LOG > 3) console.log("Keylocator contains KEY");

          var rsakey = new Key();
          rsakey.readDerPublicKey(keylocator.publicKey);
          var verified = data.verify(rsakey);

          var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
          // Raise callback
          currentClosure.upcall(Closure.UPCALL_CONTENT, new UpcallInfo(this, pitEntry.interest, 0, data));

          // Since KeyLocator does not contain key name for this key,
          // we have no way to store it as a key entry in KeyStore.
        }
        else {
          var cert = keylocator.certificate;
          console.log("KeyLocator contains CERT");
          console.log(cert);
          // TODO: verify certificate
        }
      }
    }
  }
};

/**
 * Assume this.getConnectionInfo is not null.  This is called when
 * this.connectionInfo is null or its host is not alive.
 * Get a connectionInfo, connect, then execute onConnected().
 */
Face.prototype.connectAndExecute = function(onConnected)
{
  var connectionInfo = this.getConnectionInfo();
  if (connectionInfo == null) {
    console.log('ERROR: No more connectionInfo from getConnectionInfo');
    this.connectionInfo = null;
    // Deprecated: Set this.host and this.port for backwards compatibility.
    this.host = null;
    this.host = null;

    return;
  }

  if (connectionInfo.equals(this.connectionInfo)) {
    console.log
      ('ERROR: The host returned by getConnectionInfo is not alive: ' +
       this.connectionInfo.toString());
    return;
  }

  this.connectionInfo = connectionInfo;
  if (LOG>0) console.log("connectAndExecute: trying host from getConnectionInfo: " +
                         this.connectionInfo.toString());
  // Deprecated: Set this.host and this.port for backwards compatibility.
  this.host = this.connectionInfo.host;
  this.host = this.connectionInfo.port;

  // Fetch any content.
  var interest = new Interest(new Name("/"));
  interest.setInterestLifetimeMilliseconds(4000);

  var thisFace = this;
  var timerID = setTimeout(function() {
    if (LOG>0) console.log("connectAndExecute: timeout waiting for host " + thisFace.host);
      // Try again.
      thisFace.connectAndExecute(onConnected);
  }, 3000);

  this.reconnectAndExpressInterest(null, interest, new Face.ConnectClosure(this, onConnected, timerID));
};

/**
 * This is called by the Transport when the connection is closed by the remote host.
 */
Face.prototype.closeByTransport = function()
{
  this.readyStatus = Face.CLOSED;
  this.onclose();
};

Face.ConnectClosure = function ConnectClosure(face, onConnected, timerID)
{
  // Inherit from Closure.
  Closure.call(this);

  this.face = face;
  this.onConnected = onConnected;
  this.timerID = timerID;
};

Face.ConnectClosure.prototype.upcall = function(kind, upcallInfo)
{
  if (!(kind == Closure.UPCALL_CONTENT ||
        kind == Closure.UPCALL_CONTENT_UNVERIFIED))
    // The upcall is not for us.
    return Closure.RESULT_ERR;

  // The host is alive, so cancel the timeout and continue with onConnected().
  clearTimeout(this.timerID);

  if (LOG>0) console.log("connectAndExecute: connected to host " + this.face.host);
  this.onConnected();

  return Closure.RESULT_OK;
};

/**
 * @deprecated Use new Face.
 */
var NDN = function NDN(settings)
{
  // Call the base constructor.
  Face.call(this, settings);
}

// Use dummy functions so that the Face constructor will not try to set its own defaults.
NDN.prototype = new Face({ getTransport: function(){}, getConnectionInfo: function(){} });

exports.NDN = NDN;

NDN.supported = Face.supported;
NDN.UNOPEN = Face.UNOPEN;
NDN.OPEN_REQUESTED = Face.OPEN_REQUESTED;
NDN.OPENED = Face.OPENED;
NDN.CLOSED = Face.CLOSED;
