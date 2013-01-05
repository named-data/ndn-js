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

Witness.prototype.decode = function(/* Uint8Array */ witness) {
	var wit = DataUtils.toHex(witness).toLowerCase();
	var der = Hex.decode(wit);
	var asn1 = ASN1.decode(der);
	//console.log(asn1.toPrettyString());
	
	this.oid = asn1.sub[0].sub[0].content();  // OID
	this.path.index = asn1.sub[1].sub[0].sub[0].content();  // index
	for (i = 0; i < asn1.sub[1].sub[0].sub[1].sub.length; i++) {
		pos = asn1.sub[1].sub[0].sub[1].sub[i].stream.pos;
		str = wit.substring(2 * pos + 4, 2 * pos + 68);
		this.path.digestList.push(str);  // digest hex string
	}
};
