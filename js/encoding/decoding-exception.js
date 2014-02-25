/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

/**
 * Create a new DecodingException wrapping the given error object.
 * Call with: throw new DecodingException(new Error("message")).
 * @constructor
 * @param {string} error The exception created with new Error.
 */
function DecodingException(error) 
{
  this.message = error.message;
  // Copy lineNumber, etc. from where new Error was called.
  for (var prop in error)
      this[prop] = error[prop];
}
DecodingException.prototype = new Error();
DecodingException.prototype.name = "DecodingException";

exports.DecodingException = DecodingException;
