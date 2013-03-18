/*
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * This is called from the NDN toolbar and the doorhanger popup on Firefox for Android.
 */

Components.utils.import("chrome://modules/content/ndn-js.jsm");
Components.utils.import("chrome://modules/content/NdnProtocolInfo.jsm");

function ndnToolbarGetVersion(selector) {
  NdnProtocolInfo.getVersion(selector, window, alert);
}

/*
 * This is called when the connected NDN hub changes.
 */
function onNdnHubChanged(host, port) {
  document.getElementById("ndnHubLabel").setAttribute("value", "Hub: " + host + ":" + port);
}

if (window) 
  window.addEventListener("load", function() { NdnProtocolInfo.addNdnHubChangedListener(onNdnHubChanged); }, 
                          false);

function ndnToolbarSetHub() {
    var host = prompt("Enter hub host:", NdnProtocolInfo.ndn.host);
    if (!host)
        return;
    
    host = host.trim();
    if (host == "")
        return;
    if (host == NdnProtocolInfo.ndn.host)
        // No change.
        return;
    
    var port = 9695;
    NdnProtocolInfo.ndn.createRoute(host, port);
    document.getElementById("ndnHubLabel").setAttribute("value", "Hub: trying " + host + ":" + port);
    
    if (window._content.document.location.protocol == "ndn:")
        // Reload with the new hub.
        window._content.document.location = window._content.document.location.href;
}
