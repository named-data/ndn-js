var Name = require("../..").Name;
var NameEnumeration = require('../..').NameEnumeration;
var Face = require('../..').Face;

var face = new Face({host: "localhost"});    
    
function onComponents(components)
{
  if (components == null)
    console.log("[unrecognized prefix]");
  else if (components.length == 0)
    console.log("");
  else {
    for (var i in components)
      console.log(new Name([components[i]]).toUri());
  }

  face.close();
}

var prefix = "/";    
console.log("Components:");
NameEnumeration.getComponents(face, new Name(prefix), onComponents);
