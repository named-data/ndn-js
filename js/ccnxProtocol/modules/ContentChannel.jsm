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
	is available, call contentListener.onReceivedContent(content, contentType, contentCharset),  
    which sends the content	to the listener passed to asyncOpen and returns after calling its
    onStopRequest.
 */
function ContentChannel(uri, requestContent) {
	this.requestContent = requestContent;

	this.done = false;

	this.name = uri.spec;
    // This is set by the caller of asyncOpen.
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
        try {
            var thisContentChannel = this;
            
    		var threadManager = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager);
			var callingThread = threadManager.currentThread; 
            
            var contentListener = {
                onReceivedContent : function(content, contentType, contentCharset) {
                    thisContentChannel.contentLength = content.length;
                    thisContentChannel.contentType = contentType;
                    thisContentChannel.contentCharset = contentCharset;
				
                    var pipe = Cc["@mozilla.org/pipe;1"].createInstance(Ci.nsIPipe);
                    pipe.init(true, true, 0, 0, null);
                    pipe.outputStream.write(content, content.length);
                    pipe.outputStream.close();
				
                    // nsIChannel requires us to call aListener on its calling thread.
                    // Set dispatch flags to 1 to wait for it to finish.
					callingThread.dispatch({
						run: function() { 				
                            aListener.onStartRequest(thisContentChannel, aContext);
                            aListener.onDataAvailable(thisContentChannel, aContext, 
                                pipe.inputStream, 0, content.length);
				
                            thisContentChannel.done = true;
                            aListener.onStopRequest(thisContentChannel, aContext, 
                                thisContentChannel.status);
						}
					}, 1);
                }
            };
		
            this.requestContent(contentListener);
        } catch (ex) {
            dump("ContentChannel.asyncOpen exception: " + ex + "\n");
        }
	}
};
