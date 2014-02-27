/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

var WireFormat = require('./wire-format.js').WireFormat;
var Tlv0_1a2WireFormat = require('./tlv-0_1a2-wire-format.js').Tlv0_1a2WireFormat;

/**
 * A TlvWireFormat extends Tlv0_1a2WireFormat to override its methods to 
 * implement encoding and decoding using the preferred implementation of NDN-TLV.
 * @constructor
 */
var TlvWireFormat = function TlvWireFormat() 
{
  // Inherit from Tlv0_1a2WireFormat.
  Tlv0_1a2WireFormat.call(this);
};

TlvWireFormat.prototype = new Tlv0_1a2WireFormat();
TlvWireFormat.prototype.name = "TlvWireFormat";

exports.TlvWireFormat = TlvWireFormat;

// Default object.
TlvWireFormat.instance = null;

/**
 * Get a singleton instance of a TlvWireFormat.  Assuming that the default 
 * wire format was set with WireFormat.setDefaultWireFormat(TlvWireFormat.get()), 
 * you can check if this is the default wire encoding with
 * if WireFormat.getDefaultWireFormat() == TlvWireFormat.get().
 * @returns {TlvWireFormat} The singleton instance.
 */
TlvWireFormat.get = function()
{
  if (TlvWireFormat.instance === null)
    TlvWireFormat.instance = new TlvWireFormat();
  return TlvWireFormat.instance;
};

// On loading this module, make this the default wire format.
// This module will be loaded because WireFormat loads it.
WireFormat.setDefaultWireFormat(TlvWireFormat.get());
