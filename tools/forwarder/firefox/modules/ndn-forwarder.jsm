/*
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

var EXPORTED_SYMBOLS = ["NdnForwarder"];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("chrome://modules/content/ndn-js.jsm");

dump("Debug: ndn-forwarder.jsm is loaded\n");

var NdnForwarder = function NdnForwarder()
{
};
