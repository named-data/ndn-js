/**
 * Simple xml 2 javascript object parser based on sax.js
 * 
 * https://github.com/emberfeather/node-xml2object
 */
var emitter = require('events').EventEmitter;
var fs = require('fs');
var sax = require('./sax');
var util = require('util');

var xml2object  = function(xmlFile, elements) {
	elements = elements || [];
	
	this._hasStarted = false;

	var self = this;
	var currentObject;
	var inObject = false;
	var inObjectName;
	var ancestors = [];

	this.fileStream = fs.createReadStream(xmlFile);
	this.saxStream = sax.createStream(true);

	this.saxStream.on("opentag", function (args) {
		if(!inObject) {
			// If we are not in an object and not tracking the element
			// then we don't need to do anything
			if (elements.indexOf(args.name) < 0) {
				return;
			}

			// Start tracking a new object
			inObject = true;
			inObjectName = args.name;

			currentObject = {};
		}

		if (!(args.name in currentObject)) {
			currentObject[args.name] = args.attributes;
		} else if (!util.isArray(currentObject[args.name])) {
			// Put the existing object in an array.
			var newArray = [currentObject[args.name]];
			
			// Add the new object to the array.
			newArray.push(args.attributes);
			
			// Point to the new array.
			currentObject[args.name] = newArray;
		} else {
			// An array already exists, push the attributes on to it.
			currentObject[args.name].push(args.attributes);
		}

		// Store the current (old) parent.
		ancestors.push(currentObject);

		// We are now working with this object, so it becomes the current parent.
		if (currentObject[args.name] instanceof Array) {
			// If it is an array, get the last element of the array.
			currentObject = currentObject[args.name][currentObject[args.name].length - 1];
		} else {
			// Otherwise, use the object itself.
			currentObject = currentObject[args.name];
		}
	});

	this.saxStream.on("text", function (data) {
		if(!inObject) {
			return;
		}

		data = data.trim();

		if (!data.length) {
			return;
		}

		currentObject['$t'] = (currentObject['$t'] || "") + data;
	});

	this.saxStream.on("closetag", function (name) {
		if(!inObject) {
			return;
		}

		if(inObject && inObjectName === name) {
			// Finished building the object
			self.emit('object', name, currentObject);

			inObject = false;
			ancestors = [];

			return;
		}

		if(ancestors.length) {
			var ancestor = ancestors.pop();
			var keys = Object.keys(currentObject);

			if (keys.length == 1 && '$t' in currentObject) {
				// Convert the text only objects into just the text
				if (ancestor[name] instanceof Array) {
					ancestor[name].push(ancestor[name].pop()['$t']);
				} else {
					ancestor[name] = currentObject['$t'];
				}
			} else if (!keys.length) {
				// Remove empty keys
				delete ancestor[name];
			}

			currentObject = ancestor;
		} else {
			currentObject = {};
		}
	});

	// Rebroadcast the error and keep going
	this.saxStream.on("error", function (e) {
		this.emit('error', e);

		// clear the error and resume
		this._parser.error = null;
		this._parser.resume();
	});

	// Rebroadcast the end of the file read
	this.fileStream.on("end", function() {
		self.emit("end");
	});
};

util.inherits(xml2object, emitter);

xml2object.prototype.start = function() {
	// Can only start once
	if(this._hasStarted) {
		return;
	}

	this._hasStarted = true;

	this.emit('start');

	// Start the streaming!
	this.fileStream.pipe(this.saxStream);
};


//TEST///////////////////////////////////////////////////////////////////////////////
//var xml2object = require('xml2object');

// Create a new xml parser with an array of xml elements to look for
/*var parser = new xml2object('./src/encoding/ContentObject1.xml', [ 'ContentObject' ]);

// Bind to the object event to work with the objects found in the XML file
parser.on('object', function(name, obj) {
    console.log('Found an object: %s', name);
    console.log(obj);
});

// Bind to the file end event to tell when the file is done being streamed
parser.on('end', function(name, obj) {
    console.log('Finished parsing xml!');
});

// Start parsing the XML
parser.start();*/