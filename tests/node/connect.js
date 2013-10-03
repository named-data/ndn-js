var NDN = require('../..').NDN;

var ndn = new NDN();

ndn.onopen = function () {
    console.log('NDN connection established.');
    // Set this here because normally NDN sets it upon expressInterest or registerPrefix.
    ndn.readyStatus = NDN.OPENED;
    ndn.close();
};

ndn.transport.connect(ndn, ndn.onopen);