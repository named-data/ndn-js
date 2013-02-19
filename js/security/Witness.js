/** 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

var MerklePath = function MerkelPath() {
	this.index = null;  // int
	this.digestList = [];  // array of hex string
};

var Witness = function Witness() {
	this.oid = null;  // string
	this.path = new MerklePath();  // MerklePath
};

function parseOID(bytes, start, end) {
    var s, n = 0, bits = 0;
    for (var i = start; i < end; ++i) {
        var v = bytes[i];
        n = (n << 7) | (v & 0x7F);
        bits += 7;
        if (!(v & 0x80)) { // finished
            if (s == undefined)
                s = parseInt(n / 40) + "." + (n % 40);
            else
                s += "." + ((bits >= 31) ? "bigint" : n);
            n = bits = 0;
        }
        s += String.fromCharCode();
    }
    return s;
}

function parseInteger(bytes, start, end) {
    var n = 0;
    for (var i = start; i < end; ++i)
        n = (n << 8) | bytes[i];
    return n;
}

Witness.prototype.decode = function(/* Uint8Array */ witness) {
	/* The asn1.js decoder has some bug and 
	 * cannot decode certain kind of witness.
	 * So we use an alternative (and dirty) hack
	 * to read witness from byte streams
	 *      ------Wentao
	 */
	/*
	var wit = DataUtils.toHex(witness).toLowerCase();
	try {
		var der = Hex.decode(wit);
		var asn1 = ASN1.decode(der);
	}
	catch (e) {
		console.log(e);
		console.log(wit);
	}
	//console.log(asn1.toPrettyString());
	
	this.oid = asn1.sub[0].sub[0].content();  // OID
	//console.log(this.oid);
	this.path.index = asn1.sub[1].sub[0].sub[0].content();  // index
	//console.log(this.path.index);
	for (i = 0; i < asn1.sub[1].sub[0].sub[1].sub.length; i++) {
		pos = asn1.sub[1].sub[0].sub[1].sub[i].stream.pos;
		str = wit.substring(2 * pos + 4, 2 * pos + 68);
		this.path.digestList.push(str);  // digest hex string
		//console.log(str);
	}
	*/
	
	// FIXME: Need to be fixed to support arbitrary ASN1 encoding,
	// But do we really nned that????  -------Wentao
	
	// The structure of Witness is fixed as follows:
	// SEQUENCE  (2 elem)
	//   SEQUENCE  (1 elem)
	//     OBJECT IDENTIFIER  1.2.840.113550.11.1.2.2
	//   OCTET STRING  (1 elem)
	//     SEQUENCE  (2 elem)
	//       INTEGER  index
	//       SEQUENCE  (n elem)
	//         OCTET STRING(32 byte) 345FB4B5E9A1D2FF450ECA87EB87601683027A1A...
	//         OCTET STRING(32 byte) DBCEE5B7A6C2B851B029324197DDBD9A655723DC...
	//         OCTET STRING(32 byte) 4C79B2D256E4CD657A27F01DCB51AC3C56A24E71...
	//         OCTET STRING(32 byte) 7F7FB169604A87EAC94378F0BDB4FC5D5899AB88...
	//         ......
	// Hence we can follow this structure to extract witness fields at fixed level
	// Tag numbers for ASN1:
	//    SEQUENCE            0x10
	//    OCT STRING          0x04
	//    INTEGER             0x02
	//    OBJECT IDENTIFIER   0x06
	var i = 0;
	var step = 0;  // count of sequence tag
	while (i < witness.length) {
		var len = 0;
		
		if (witness[i] == 0x30) {
			// Sequence (constructed)
			// There is no primitive sequence in Witness
			if ((witness[i + 1] & 0x80) != 0) {
				len = witness[i+1] & 0x7F;
			}
			step++;
		} else if (witness[i] == 0x06) {
			// Decode OID
			len = witness[i+1];  // XXX: OID will not be longer than 127 bytes
			this.oid = parseOID(witness, i + 2, i + 2 + len);
			//console.log(this.oid);
		} else if (witness[i] == 0x02) {
			// Decode node index
			len = witness[i+1];  // XXX: index will not be longer than 127 bytes
			this.path.index = parseInteger(witness, i + 2, i + 2 + len);
			//console.log(this.path.index);
		} else if (witness[i] == 0x04) {
			if ((witness[i + 1] & 0x80) != 0) {
				len = witness[i+1] & 0x7F;
			}
			if (step == 4) {
				// Start to decode digest hex string
				len = witness[i+1];  // XXX: digest hex should always be 32 bytes
				var str = DataUtils.toHex(witness.subarray(i + 2, i + 2 + len));
				this.path.digestList.push(str);  // digest hex string
				//console.log(str);
			}
		}
		i = i + 2 + len;
	}
};
