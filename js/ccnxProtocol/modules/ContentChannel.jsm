/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 */

var EXPORTED_SYMBOLS = ["ContentChannel"];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
  
/* Create an nsIChannel for returning content to the caller of asyncOpen. 
 * For requestContent detail, see asyncOpen.
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
            
    // Save the mostRecentWindow from the moment of creating the channel.
    var wm = Cc["@mozilla.org/appshell/window-mediator;1"].getService(Ci.nsIWindowMediator);
    this.mostRecentWindow = wm.getMostRecentWindow("navigator:browser");
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
	}
};

/*  Call requestContent(contentListener).  When the content is available, you should call 
 *  contentListener.onReceivedContent(content, contentType, contentCharset, uri), 
 *  which sends the content	aListener.  If uri is not null, update this.URI and if this.loadFlags
 *  LOAD_INITIAL_DOCUMENT_URI bit is set, then update the URL bar of the mostRecentWindow.
 *  (Note that the caller of asyncOpen sets this.loadFlags.)
 */
ContentChannel.prototype.asyncOpen = function(aListener, aContext) {
    try {
        var thisContentChannel = this;
            
		var threadManager = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager);
		var callingThread = threadManager.currentThread; 
            
        var contentListener = {
            onReceivedContent : function(content, contentType, contentCharset, uri) {
                if (uri)
                    thisContentChannel.URI = uri;
                thisContentChannel.contentLength = content.length;
                thisContentChannel.contentType = contentType;
                thisContentChannel.contentCharset = contentCharset;
				
                var pipe = Cc["@mozilla.org/pipe;1"].createInstance(Ci.nsIPipe);
                pipe.init(true, true, 0, 0, null);
                pipe.outputStream.write(content, content.length);
                pipe.outputStream.close();
				
                // nsIChannel requires us to call aListener on its calling thread.
                // Set dispatch flags to 0 to return immediately.
				callingThread.dispatch({
					run: function() { 				
                        aListener.onStartRequest(thisContentChannel, aContext);
                        // Load flags bit 19 "LOAD_INITIAL_DOCUMENT_URI" means this channel is
                        //   for the main window with the URL bar.
                        if (uri && thisContentChannel.loadFlags & (1<<19))
                            // aListener.onStartRequest may set the URL bar but now we update it.
                            thisContentChannel.mostRecentWindow.gURLBar.value = 
                                thisContentChannel.URI.spec;
                        
                        aListener.onDataAvailable(thisContentChannel, aContext, 
                            pipe.inputStream, 0, content.length);
				
                        thisContentChannel.done = true;
                        aListener.onStopRequest(thisContentChannel, aContext, 
                            thisContentChannel.status);
					}
				}, 0);
            }
        };
		
        this.requestContent(contentListener);
    } catch (ex) {
        dump("ContentChannel.asyncOpen exception: " + ex + "\n");
    }
};

