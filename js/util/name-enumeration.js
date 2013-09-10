/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

// Create a namespace.
var NameEnumeration = new Object();

/**
 * Use the name enumeration protocol to get the child components of the name prefix.
 * @param {NDN} ndn The NDN object for using expressInterest.
 * @param {Name} name The name prefix for finding the child components.
 * @param {function} onComponents On getting the response, this calls onComponents(components) where
 * components is an array of Uint8Array name components.  If there is no response, this calls onComponents(null). 
 */
NameEnumeration.getComponents = function(ndn, prefix, onComponents)
{
  var command = new Name(prefix);
  // Add %C1.E.be
  command.add([0xc1, 0x2e, 0x45, 0x2e, 0x62, 0x65])
  
  ndn.expressInterest(command, new NameEnumeration.Closure(onComponents));
};

/**
 * Create a closure for getting the response from the name enumeration command.
 * @param {function} onComponents The onComponents callback given to getComponents.
 */
NameEnumeration.Closure = function NameEnumerationClosure(onComponents) 
{
  // Inherit from Closure.
  Closure.call(this);
  
  this.onComponents = onComponents;
  this.components = [];
};

/**
 * Parse the response from the name enumeration command and call this.onComponents.
 * @param {type} kind
 * @param {type} upcallInfo
 * @returns {Closure.RESULT_OK}
 */
NameEnumeration.Closure.prototype.upcall = function(kind, upcallInfo) 
{
  try {
    if (kind == Closure.UPCALL_CONTENT || kind == Closure.UPCALL_CONTENT_UNVERIFIED) {
      var data = upcallInfo.contentObject;
    
      NameEnumeration.addComponents(data.content, this.components);
    }
    else
      // Treat anything else as a timeout.
      this.components = null;
  
    this.onComponents(this.components);
  } catch (ex) {
    console.log("NameEnumeration: ignoring exception: " + ex);
  }

  return Closure.RESULT_OK;
};

/**
 * Parse the content as a name enumeration response and add to components.  This makes a copy of the component.
 * @param {Uint8Array} content The content to parse.
 * @param {Array<Uint8Array>} components 
 * @returns {undefined}
 */
NameEnumeration.addComponents = function(content, components)
{
  var decoder = new BinaryXMLDecoder(content);
  
  decoder.readStartElement(NDNProtocolDTags.Collection);
 
  while (decoder.peekStartElement(NDNProtocolDTags.Link)) {
    decoder.readStartElement(NDNProtocolDTags.Link);    
    decoder.readStartElement(NDNProtocolDTags.Name);
    
    components.push(new Uint8Array(decoder.readBinaryElement(NDNProtocolDTags.Component)));
    
    decoder.readEndElement();  
    decoder.readEndElement();  
  }

  decoder.readEndElement();  
};