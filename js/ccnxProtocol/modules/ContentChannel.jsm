/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 */

var EXPORTED_SYMBOLS = ["ContentChannel"];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
  
/** Create an nsIChannel where asyncOpen calls requestContent(contentListener).  When the content
	is available, call contentListener.onReceivedContent(content, contentType, contentCharset).  
    The content is sent	to the listener passed to asyncOpen.
 */
function ContentChannel(uri, requestContent) {
	this.requestContent = requestContent;

	this.done = false;

	this.name = uri;
	this.loadFlags = 0;
	this.loadGroup = null;
	this.status = 200;

	// We don't know these yet.
	this.contentLength = -1;
	this.contentType = null;
	this.contentCharset = null;
	this.URI = uri;
	this.originalURI = uri;
	this.owner = null;
	this.notificationCallback = null;
	this.securityInfo = null;
}

ContentChannel.prototype = {
	QueryInterface: function(aIID) {
		if (aIID.equals(Ci.nsISupports))
			return this;
		
		if (aIID.equals(Ci.nsIRequest))
			return this;
		
		if (aIID.equals(Ci.nsIChannel))
			return this;
		
		throw Cr.NS_ERROR_NO_INTERFACE;
	},
	
	isPending: function() {
		return !this.done;
	},
	
	cancel: function(aStatus){
		this.status = aStatus;
		this.done   = true;
	},
	
	suspend: function(aStatus){
		this.status = aStatus;
	},
	
	resume: function(aStatus){
		this.status = aStatus;
	},
	
	open: function() {
		throw Cr.NS_ERROR_NOT_IMPLEMENTED;
	},
	
	asyncOpen: function(aListener, aContext) {
		var thisContentChannel = this;
		var contentListener = {
			onReceivedContent : function(content, contentType, contentCharset) {
				thisContentChannel.contentLength = content.length;
				thisContentChannel.contentType = contentType;
				thisContentChannel.contentCharset = contentCharset;
				
				// Call aListener immediately to send all the content.
				aListener.onStartRequest(thisContentChannel, aContext);

				var pipe = Cc["@mozilla.org/pipe;1"].createInstance(Ci.nsIPipe);
				pipe.init(true, true, 0, 0, null);
				pipe.outputStream.write(content, content.length);
				pipe.outputStream.close();
				
				aListener.onDataAvailable(thisContentChannel, aContext, pipe.inputStream, 0, content.length);
				
				thisContentChannel.done = true;
				aListener.onStopRequest(thisContentChannel, aContext, thisContentChannel.status);
			}
		};
		
		this.requestContent(contentListener);
	}
};
