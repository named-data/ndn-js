var port = null;

// Add listener to wait for msg from app scripts
window.addEventListener("message", function(event) {
    // We only accept messages from ourselves
    if (event.source != window)
	return;
	
    if (event.data.type && (event.data.type == "FromMicroForwarderTransport")) {
	if (port == null) {
	    port = chrome.runtime.connect();
	    // Add a listener to wait for msg from background script
	    port.onMessage.addListener(function(msg) {
		window.postMessage({
		    type: "FromMicroForwarderStub",
		    object: msg
		}, "*");
	    });
	    console.log("Forwarder stub connected to background script.");
	}
	port.postMessage(event.data.object);
    }
}, false);

console.log("NDN Micro Forwarder stub is loaded.");
