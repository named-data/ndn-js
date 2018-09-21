var _savedGlobals = {};
Object.keys(ndn).forEach(function(k){
  _savedGlobals[k] = globals[k];
  globals[k] = ndn[k];
});

/**
 * Stop exposing ndn-js class names in the global namespace.
 *
 * By default, ndn-js exposes all class names into the global namespace for convenience.
 * This function removes ndn-js class names from the global namespace to avoid conflicts.
 * After that, the application must explicitly reference `ndn.` before a class name.
 */
ndn.noConflict = function() {
  Object.keys(_savedGlobals).forEach(function(k){
    if (globals[k] === ndn[k]) {
      if (typeof _savedGlobals[k] == 'undefined') {
        delete globals[k];
      }
      else {
        globals[k] = _savedGlobals[k];
      }
    }
  });
  return ndn;
};

globals.ndn = ndn;
})(this);
