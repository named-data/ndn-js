//This module checks for the availability of various crypto.subtle api's at runtime,
//exporting a function that returns the known availability of necessary NDN crypto apis

function DetectSubtleCrypto(){
  var supportedApis = {};
  var baselineSupport = (
                            (crypto && crypto.subtle)
                            && (
                                (location.protocol === "https:" || "chrome-extension:" || "chrome:")
                                || (location.hostname === "localhost" || location.hostname === "127.0.0.1")
                               )
                        ) ? true : false ;
  if (!baselineSupport) {
    supportedApis = {}
  } else {
    try {
      crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash:{name:"SHA-256"}, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) },
        true, //exportable;
        ["sign", "verify"]).then(function(result){
          if (result.publicKey && result.privateKey) {

            supportedApis.generateRSA_SHA_256 = true;
            var key = result;
            var algo = {name:"RSASSA-PKCS1-v1_5",hash:{name:"SHA-256"}};
            crypto.subtle.sign(algo, key.privateKey, new Uint8Array([1,2,3,4,5])).then(function(signature){
              console.log("signed returned", signature);
              supportedApis.signRSA_SHA_256 = true;
              crypto.subtle.verify(algo, key.publicKey, signature, new Uint8Array([1,2,3,4,5])).then(function(verified){
                console.log("verified returned", verified)
                supportedApis.verifyRSA_SHA_256 = verified;
                if (verified && supportedApis.importSPKI){
                  supportedApis.ndn_rsa = true;
                }
              });
            });

            try{
             crypto.subtle.exportKey("pkcs8",key.privateKey).then(function(result){
                supportedApis.exportPrivatePKCS8 = true;
             });
            } catch (e) {
             console.log("error exporting private key as pkcs8")
             supportedApis.exportPrivatePKCS8 = false;
            }
            try {
             crypto.subtle.exportKey("spki",key.publicKey).then(function(result){
                supportedApis.exportSPKI = true;
                crypto.subtle.importKey("spki",result,algo, true, ["verify"]).then(function(key){
                  supportedApis.importSPKI = true;
                  if (supportedApis.verifyRSA_SHA_256){
                    supportedApis.ndn_rsa = true;
                  }
                })
             });
            } catch (e) {
             console.log("error exporting raw key", e)
             supportedApis.exportPrivateRAW = false;
            }
            try {
             crypto.subtle.exportKey("jwk",key.privateKey).then(function(result){
                supportedApis.exportPrivateJWK = true;
             })
            } catch (e) {
            console.log("error exporting private key as jwk", e)
             supportedApis.exportPrivateJWK = false;
            }
          } else {
            console.log("genKey failover, but no error... weird.")
            supportedApis.generateRSASSAKey = false
          }
      });
    } catch (e){
      console.log("unable to generate sign/verify key", e)
      supportedApis.sign = false;
      supportedApis.verify = false;
    }

    var testDigest = new Uint8Array(1000)
    try{
      crypto.subtle.digest({name:"SHA-256"}, testDigest.buffer).then(function(result){
        supportedApis.digestSHA256 = true;
      });
    } catch (e) {
      console.log("digestSHA256 error", e)
      supportedAPIs.digestSHA256 = false;
    }
  }

  return function (){
    //what I'm thinking here is that KeyChain could supply desired api's based on default/developer needs for encrypt/decrypt, key formats, storage formats, etc. please advise.
    //The most important thing about returning this closure is that it allows us to empirically test the crypto capabilities of the browser asyncronously at the beginning of runtime, and get only use the features we're sure are implimented.
    return supportedApis;
  }
}

UseSubtleCrypto = DetectSubtleCrypto();
 
module.exports = {UseSubtleCrypto: UseSubtleCrypto};
