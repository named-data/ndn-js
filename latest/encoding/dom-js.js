var sax = require("./sax");
var strict = true;

/**
 * Really simple XML DOM implementation based on sax that works with Strings.
 * 
 * If you have an XML string and want a DOM this utility is convenient.
 * 
 * var domjs = new DomJS();
 * domjs.parse(xmlString, function(err, dom) {
 * 	
 * });
 * 
 * If you want to compile C there are versions based on libxml2
 * and jsdom is full featured but complicated.
 * 
 * This is "lightweight" meaning really simple and serves my purpose, it does not support namespaces or all
 * of the features of XML 1.0  it just takes a string and returns a JavaScript object graph. 
 * 
 * There are only three types of object supported Element, Text and Comment.
 * 
 * e.g.
 * 
 * take  <xml><elem att="val1"/><elem att="val1"/><elem att="val1"/></xml>
 * 
 * return 	{ name : "xml",
 * 			  attributes : {}
 * 			  children [
 * 				{ name : "elem", attributes : {att:'val1'}, children [] },
 * 				{ name : "elem", attributes : {att:'val1'}, children [] },
 * 				{ name : "elem", attributes : {att:'val1'}, children [] }
 * 			  ]
 * 			}
 * 
 * The object returned can be serialized back out with obj.toXml();
 * 
 * 
 * @constructor DomJS
 */
DomJS = function() {
	this.root = null;
	this.stack = new Array();
	this.currElement = null;
	this.error = false;
};

DomJS.prototype.parse = function(string, cb) {
	if (typeof string != 'string') {
		cb(true, 'Data is not a string');
		return;
	}
	var self = this;
	parser = sax.parser(strict);

	parser.onerror = function (err) {
		self.error = true;
		cb(true, err);
	};
	parser.ontext = function (text) {
		if (self.currElement == null) {
			// console.log("Content in the prolog " + text);
			return;
		}
		var textNode = new Text(text);
		self.currElement.children.push(textNode);
	};
	parser.onopencdata = function () {
		var cdataNode = new CDATASection();
		self.currElement.children.push(cdataNode);
	};
	parser.oncdata = function (data) {
		var cdataNode = self.currElement.children[self.currElement.children.length - 1];
		cdataNode.appendData(data);
	};
	// do nothing on parser.onclosecdata	
	parser.onopentag = function (node) {
		var elem = new Element(node.name, node.attributes);
		if (self.root == null) {
			self.root = elem;
		}
		if (self.currElement != null) {
			self.currElement.children.push(elem);
		}
		self.currElement = elem;
		self.stack.push(self.currElement);
	};
	parser.onclosetag = function (node) {
		self.stack.pop();
		self.currElement = self.stack[self.stack.length - 1 ];// self.stack.peek(); 
	};
	parser.oncomment = function (comment) {
		if (self.currElement == null) {
			//console.log("Comments in the prolog discarded " + comment);
			return;
		}		
		var commentNode = new Comment(comment);
		self.currElement.children.push(commentNode);
	};

	parser.onend = function () {
		if ( self.error == false) {
			cb(false, self.root);
		}
	};

	parser.write(string).close();	
};

DomJS.prototype.reset = function() {
	this.root = null;
	this.stack = new Array();
	this.currElement = null;
	this.error = false;	
};

var escape = function(string) {
	return string.replace(/&/g, '&amp;').replace(/>/g, '&gt;').replace(/</g, '&lt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
};


Element = function(name, attributes, children ) {
	this.name = name;
	this.attributes = attributes || [];
	this.children = children || [];
}
Element.prototype.toXml = function(sb) {
	if (typeof sb == 'undefined') {
		sb = {buf:''}; // Strings are pass by value in JS it seems
	}
	sb.buf += '<' + this.name;
	for (att in this.attributes) {

		sb.buf += ' ' + att + '="' + escape(this.attributes[att]) + '"';
	}
	if (this.children.length != 0) {
		sb.buf += '>';
		for (var i = 0 ; i < this.children.length ; i++) {
			this.children[i].toXml(sb);
		}
		sb.buf += '</' + this.name + '>';
	}
	else {
		sb.buf += '/>';
	}
	return sb.buf;
};
Element.prototype.firstChild = function() {
	if ( this.children.length > 0) {
		return this.children[0];	
	}
	return null;
};	
Element.prototype.text = function() {
	if ( this.children.length > 0) {
		if (typeof this.children[0].text == 'string') {
			return this.children[0].text;
		};	
	}
	return null;
};

Text = function(data){
	this.text = data;
};
Text.prototype.toXml = function(sb) {
	sb.buf += escape(this.text);
};

Comment = function(comment) {
	this.comment = comment;
};
Comment.prototype.toXml = function(sb) {
	sb.buf += '<!--' + this.comment + '-->';
};

CDATASection = function(data){
	this.text = data || '';
};
CDATASection.prototype.toXml = function(sb) {
	sb.buf += '<![CDATA[' + this.text + ']]>';
};
CDATASection.prototype.appendData = function(data) {
	this.text += data;
};




