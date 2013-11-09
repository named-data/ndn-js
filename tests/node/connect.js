var Face = require('../..').Face;

var face = new Face();

face.onopen = function () {
    console.log('NDN connection established.');
    // Set this here because normally Face sets it upon expressInterest or registerPrefix.
    face.readyStatus = Face.OPENED;
    face.close();
};

face.transport.connect(face, face.onopen);