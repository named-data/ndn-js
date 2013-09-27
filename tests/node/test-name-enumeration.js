var Name = require("../..").Name;
var NameEnumeration = require('../..').NameEnumeration;
var NDN = require('../..').NDN;

var ndn1 = new NDN({host: "localhost"});    
    
function onComponents(components)
{
  if (components == null)
    console.log("[unrecognized prefix]");
  else if (components.length == 0)
    console.log("");
  else {
    for (var i in components)
      console.log(new Name([components[i]]).to_uri());
  }

  ndn1.close();
}

var prefix = "/";    
console.log("Components:");
NameEnumeration.getComponents(ndn1, new Name(prefix), onComponents);
