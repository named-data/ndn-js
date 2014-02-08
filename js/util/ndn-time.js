/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents NDNTime Objects
 */

var LOG = require('../log.js').Log.LOG;

/**
 * @constructor
 */
var NDNTime = function NDNTime(input) 
{
  this.NANOS_MAX = 999877929;
  
  if (typeof input =='number')
    this.msec = input;
  else {
    if (LOG > 1) console.log('UNRECOGNIZED TYPE FOR TIME');
  }
};

exports.NDNTime = NDNTime;

NDNTime.prototype.getJavascriptDate = function() 
{
  var d = new Date();
  d.setTime(this.msec);
  return d
};  
