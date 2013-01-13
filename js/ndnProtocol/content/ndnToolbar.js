Components.utils.import("chrome://modules/content/ndn-js.jsm");
Components.utils.import("chrome://modules/content/NdnProtocolInfo.jsm");

function ndnToolbarGetLatest(event) {
  if (window._content.document.location.protocol != "ndn:") {
    alert("The address must start with ndn:");
    return;
  }

  // Parse the same as in ndnProtocolService newChannel.
  var uriParts = splitUri(window._content.document.location.href);
  var name = new Name(uriParts.name);
  var indexOfVersion = getIndexOfVersion(name);
  if (indexOfVersion < 0) {
    alert("The ndn address does not have a version");
    return;
  }

  var nameWithoutVersion = new Name(name.components.slice(0, indexOfVersion));
  var searchWithChildSelector = 
      (uriParts.search == "" ? "?" : uriParts.search + "&") + "ndn.ChildSelector=1";
    
  var uri = "ndn:" + nameWithoutVersion.to_uri() + searchWithChildSelector + uriParts.hash;
  window._content.document.location = uri;
} 

/*
 * Return the index of the last component that starts with 0xfd, or -1 if not found.
 */
function getIndexOfVersion(name) {
  for (var i = name.components.length - 1; i >= 0; --i) {
    if (name.components[i].length >= 1 && name.components[i][0] == 0xfd)
      return i;
  }

  return -1;
}

/*
 * This is called when the connected NDN hub changes.
 */
function onNdnHubChanged(host, port) {
   document.getElementById("ndnHubLabel").setAttribute("value", "Hub: " + host + ":" + port);
}

window.addEventListener("load", function() { addNdnHubChangedListener(onNdnHubChanged); }, false);
