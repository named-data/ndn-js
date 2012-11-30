Components.utils.import("chrome://modules/content/ndn-js.jsm");

function CcnxToolbarGetLatest(event){
  if (window._content.document.location.protocol != "ccnx:") {
    alert("The address must start with ccnx");
    return;
  }

  // Parse the same as in ccnxprotocolService newChannel.
  var spec = window._content.document.location.href.trim();
  var preHash = spec.split('#', 1)[0];
  var hash = spec.substr(preHash.length).trim();
  var preSearch = preHash.split('?', 1)[0];
  var search = preHash.substr(preSearch.length).trim();
  // Set nameString to the preSearch without the protocol.
  var nameString = preSearch.trim();
  if (nameString.indexOf(':') >= 0)
    nameString = nameString.substr(nameString.indexOf(':') + 1).trim();

  var name = new Name(nameString);
  var indexOfVersion = getIndexOfVersion(name);
  if (indexOfVersion < 0) {
    alert("The ccnx address does not have a version");
    return;
  }

  var nameWithoutVersion = new Name(name.components.slice(0, indexOfVersion));
  var searchWithChildSelector = (search == "" ? "?" : search + "&") + "ccnx.ChildSelector=1";
    
  var uri = "ccnx:" + nameWithoutVersion.to_uri() + searchWithChildSelector + hash;
  window._content.document.location = uri;
} 

// Return the index of the last component that starts with 0xfd, or -1 if not found.
function getIndexOfVersion(name) {
  for (var i = name.components.length - 1; i >= 0; --i) {
    if (name.components[i].length >= 1 && name.components[i][0] == 0xfd)
      return i;
  }

  return -1;
}
