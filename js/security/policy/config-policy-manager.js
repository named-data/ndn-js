/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN config_policy_manager.py by Adeola Bannis.
 * Originally from Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

/** @ignore */
var fs = require('fs'); /** @ignore */
var path = require('path'); /** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var Data = require('../../data.js').Data; /** @ignore */
var Interest = require('../../interest.js').Interest; /** @ignore */
var KeyLocator = require('../../key-locator.js').KeyLocator; /** @ignore */
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType; /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var IdentityCertificate = require('../certificate/identity-certificate.js').IdentityCertificate; /** @ignore */
var CertificateV2 = require('../v2/certificate-v2.js').CertificateV2; /** @ignore */
var CertificateCacheV2 = require('../v2/certificate-cache-v2.js').CertificateCacheV2; /** @ignore */
var BoostInfoParser = require('../../util/boost-info-parser.js').BoostInfoParser; /** @ignore */
var NdnRegexTopMatcher = require('../../util/regex/ndn-regex-top-matcher.js').NdnRegexTopMatcher; /** @ignore */
var CertificateCache = require('./certificate-cache.js').CertificateCache; /** @ignore */
var ValidationRequest = require('./validation-request.js').ValidationRequest; /** @ignore */
var SecurityException = require('../security-exception.js').SecurityException; /** @ignore */
var WireFormat = require('../../encoding/wire-format.js').WireFormat; /** @ignore */
var PolicyManager = require('./policy-manager.js').PolicyManager; /** @ignore */
var NdnCommon = require('../../util/ndn-common.js').NdnCommon;

/**
 * ConfigPolicyManager manages trust according to a configuration file in the
 * Validator Configuration File Format
 * (http://redmine.named-data.net/projects/ndn-cxx/wiki/CommandValidatorConf)
 *
 * Once a rule is matched, the ConfigPolicyManager looks in the
 * certificate cache for the certificate matching the name in the KeyLocator
 * and uses its public key to verify the data packet or signed interest. If the
 * certificate can't be found, it is downloaded, verified and installed. A chain
 * of certificates will be followed to a maximum depth.
 * If the new certificate is accepted, it is used to complete the verification.
 *
 * The KeyLocators of data packets and signed interests MUST contain a name for
 * verification to succeed.
 *
 * Create a new ConfigPolicyManager which will act on the rules specified in the
 * configuration and download unknown certificates when necessary. If
 * certificateCache is a CertificateCache (or omitted) this creates a security
 * v1 PolicyManager to verify certificates in format v1. To verify certificates
 * in format v2, use a CertificateCacheV2 for the certificateCache.
 *
 * @param {string} configFileName (optional) If not null or empty, the path to
 * the configuration file containing verification rules. (This only works in
 * Node.js since it reads files using the "fs" module.) Otherwise, you should
 * separately call load().
 * @param {CertificateCache|CertificateCacheV2} certificateCache (optional) A
 * CertificateCache to hold known certificates. If certificateCache is a
 * CertificateCache (or omitted or null) this creates a security v1
 * PolicyManager to verify certificates in format v1. If this is a
 * CertificateCacheV2, verify certificates in format v1. If omitted or null,
 * create an internal v1 CertificateCache.
 * @param {number} searchDepth (optional) The maximum number of links to follow
 * when verifying a certificate chain. If omitted, use a default.
 * @param {number} graceInterval (optional) The window of time difference
 * (in milliseconds) allowed between the timestamp of the first interest signed with
 * a new public key and the validation time. If omitted, use a default value.
 * @param {number} keyTimestampTtl (optional) How long a public key's last-used
 * timestamp is kept in the store (milliseconds). If omitted, use a default value.
 * @param {number} maxTrackedKeys The maximum number of public key use
 * timestamps to track. If omitted, use a default.
 * @constructor
 */
var ConfigPolicyManager = function ConfigPolicyManager
  (configFileName, certificateCache, searchDepth, graceInterval,
   keyTimestampTtl, maxTrackedKeys)
{
  // Call the base constructor.
  PolicyManager.call(this);

  if (certificateCache == undefined)
    certificateCache = null;
  if (searchDepth == undefined)
    searchDepth = 5;
  if (graceInterval == undefined)
    graceInterval = 3000;
  if (keyTimestampTtl == undefined)
    keyTimestampTtl = 3600000;
  if (maxTrackedKeys == undefined)
    maxTrackedKeys = 1000;

  if (certificateCache == null)
    certificateCache = new CertificateCache();
  if (certificateCache instanceof CertificateCache) {
    this.isSecurityV1_ = true;
    this.certificateCache_ = certificateCache;
    this.certificateCacheV2_ = null;
  }
  else {
    this.isSecurityV1_ = false;
    this.certificateCache_ = null;
    this.certificateCacheV2_ = certificateCache;
  }

  this.maxDepth = searchDepth;
  this.keyGraceInterval = graceInterval;
  this.keyTimestampTtl = keyTimestampTtl;
  this.maxTrackedKeys = maxTrackedKeys;

  this.reset();

  if (configFileName != null && configFileName != "")
    this.load(configFileName);
};

ConfigPolicyManager.prototype = new PolicyManager();
ConfigPolicyManager.prototype.name = "ConfigPolicyManager";

exports.ConfigPolicyManager = ConfigPolicyManager;

/**
 * Reset the certificate cache and other fields to the constructor state.
 */
ConfigPolicyManager.prototype.reset = function()
{
  if (this.isSecurityV1_)
    this.certificateCache_.reset();
  else
    this.certificateCacheV2_.clear();

  // Stores the fixed-signer certificate name associated with validation rules
  // so we don't keep loading from files.
  this.fixedCertificateCache = {};

  // Stores the timestamps for each public key used in command interests to
  // avoid replay attacks.
  // Key is public key name, value is last timestamp.
  this.keyTimestamps = {};

  this.requiresVerification = true;

  this.config = new BoostInfoParser();
  this.refreshManager = new ConfigPolicyManager.TrustAnchorRefreshManager
    (this.isSecurityV1_);
};

/**
 * Call reset() and load the configuration rules from the file name or the input
 * string. There are two forms:
 * load(configFileName) reads configFileName from the file system. (This only
 * works in Node.js since it reads files using the "fs" module.)
 * load(input, inputName) reads from the input, in which case inputName is used
 * only for log messages, etc.
 * @param {string} configFileName The path to the file containing configuration
 * rules.
 * @param {string} input The contents of the configuration rules, with lines
 * separated by "\n" or "\r\n".
 * @param {string} inputName Use with input for log messages, etc.
 */
ConfigPolicyManager.prototype.load = function(configFileNameOrInput, inputName)
{
  this.reset();
  this.config.read(configFileNameOrInput, inputName);
  this.loadTrustAnchorCertificates();
}

/**
 * Check if this PolicyManager has a verification rule for the received data.
 * If the configuration file contains the trust anchor 'any', nothing is
 * verified.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @return {boolean} true if the data must be verified, otherwise false.
 */
ConfigPolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  return this.requiresVerification;
};

/**
 * Override to always indicate that the signing certificate name and data name
 * satisfy the signing policy.
 *
 * @param {Name} dataName The name of data to be signed.
 * @param {Name} certificateName The name of signing certificate.
 * @return {boolean} True to indicate that the signing certificate can be used
 * to sign the data.
 */
ConfigPolicyManager.prototype.checkSigningPolicy = function
  (dataName, certificateName)
{
  return true;
};

/**
 * Check if the received signed interest can escape from verification and be
 * trusted as valid. If the configuration file contains the trust anchor
 * 'any', nothing is verified.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @return {boolean} true if the data or interest does not need to be verified
 * to be trusted as valid, otherwise false.
 */
ConfigPolicyManager.prototype.skipVerifyAndTrust = function(dataOrInterest)
{
  return !this.requiresVerification;
};

/**
 * Check whether the received data packet or interest complies with the
 * verification policy, and get the indication of the next verification step.
 *
 * @param {Data|Interest} dataOrInterest The Data object or interest with the
 * signature to check.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(dataOrInterest).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onValidationFailed If the signature check fails, this calls
 * onValidationFailed(dataOrInterest, reason).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {WireFormat} wireFormat
 * @return {ValidationRequest} The indication of next verification step, or
 * null if there is no further step.
 */
ConfigPolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onValidationFailed, wireFormat)
{
  var objectName = dataOrInterest.getName();
  var matchType = "data";

  // For command interests, we need to ignore the last 4 components when
  // matching the name.
  if (dataOrInterest instanceof Interest) {
    objectName = objectName.getPrefix(-4);
    matchType = "interest";
  }

  var signature = ConfigPolicyManager.extractSignature(dataOrInterest, wireFormat);
  // No signature -> fail.
  if (signature == null) {
    try {
      onValidationFailed
        (dataOrInterest, "Cannot extract the signature from " +
         dataOrInterest.getName().toUri());
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return null;
  }

  var failureReason = ["unknown"];
  var certificateInterest = this.getCertificateInterest_
    (stepCount, matchType, objectName, signature, failureReason);
  if (certificateInterest == null) {
    try {
      onValidationFailed(dataOrInterest, failureReason[0]);
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return null;
  }

  if (certificateInterest.getName().size() > 0) {
    var thisManager = this;

    var onCertificateDownloadComplete = function(data) {
      var certificate;
      if (thisManager.isSecurityV1_) {
        try {
          certificate = new IdentityCertificate(data);
        } catch (ex) {
          try {
            onValidationFailed
              (dataOrInterest, "Cannot decode certificate " + data.getName().toUri());
          } catch (ex) {
            console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
          }
          return null;
        }
        thisManager.certificateCache_.insertCertificate(certificate);
      }
      else {
        try {
          certificate = new CertificateV2(data);
        } catch (ex) {
          try {
            onValidationFailed
              (dataOrInterest, "Cannot decode certificate " + data.getName().toUri());
          } catch (ex) {
            console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
          }
          return null;
        }
        thisManager.certificateCacheV2_.insert(certificate);
      }

      thisManager.checkVerificationPolicy
        (dataOrInterest, stepCount + 1, onVerified, onValidationFailed);
    };

    return new ValidationRequest
      (certificateInterest, onCertificateDownloadComplete, onValidationFailed,
       2, stepCount + 1);
  }

  // For interests, we must check that the timestamp is fresh enough.
  // We do this after (possibly) downloading the certificate to avoid
  // filling the cache with bad keys.
  if (dataOrInterest instanceof Interest) {
    var signatureName = KeyLocator.getFromSignature(signature).getKeyName();
    var keyName;
    if (this.isSecurityV1_)
      keyName = IdentityCertificate.certificateNameToPublicKeyName
        (signatureName);
    else
      keyName = signatureName;
    var timestamp = dataOrInterest.getName().get(-4).toNumber();

    if (!this.interestTimestampIsFresh(keyName, timestamp, failureReason)) {
      try {
        onValidationFailed(dataOrInterest, failureReason[0]);
      } catch (ex) {
        console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
      }
      return null;
    }
  }

  // Certificate is known, so verify the signature.
  // wireEncode returns the cached encoding if available.
  var thisManager = this;
  this.verify(signature, dataOrInterest.wireEncode(), function (verified, reason) {
    if (verified) {
      try {
        onVerified(dataOrInterest);
      } catch (ex) {
        console.log("Error in onVerified: " + NdnCommon.getErrorWithStackTrace(ex));
      }
      if (dataOrInterest instanceof Interest)
        thisManager.updateTimestampForKey(keyName, timestamp);
    }
    else {
      try {
        onValidationFailed(dataOrInterest, reason);
      } catch (ex) {
        console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }
  });
};

/**
 * This is a helper for checkVerificationPolicy to verify the rule and return a
 * certificate interest to fetch the next certificate in the hierarchy if needed.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {string} matchType Either "data" or "interest".
 * @param {Name} objectName The name of the data or interest packet.
 * @param {Signature} signature The Signature object for the data or interest
 * packet.
 * @param {Array<string>} failureReason If can't determine the interest, set
 * failureReason[0] to the failure reason.
 * @return {Interest} null if can't determine the interest, otherwise the
 * interest for the ValidationRequest to fetch the next certificate. However, if
 * the interest has an empty name, the validation succeeded and no need to fetch
 * a certificate.
 */
ConfigPolicyManager.prototype.getCertificateInterest_ = function
  (stepCount, matchType, objectName, signature, failureReason)
{
  if (stepCount > this.maxDepth) {
    failureReason[0] = "The verification stepCount " + stepCount +
      " exceeded the maxDepth " + this.maxDepth;
    return null;
  }

  // First see if we can find a rule to match this packet.
  var matchedRule;
  try {
    matchedRule = this.findMatchingRule(objectName, matchType);
  } catch (ex) {
    return null;
  }

  // No matching rule -> fail.
  if (matchedRule == null) {
    failureReason[0] = "No matching rule found for " + objectName.toUri();
    return null;
  }

  if (!KeyLocator.canGetFromSignature(signature)) {
    // We only support signature types with key locators.
    failureReason[0] = "The signature type does not support a KeyLocator";
    return null;
  }

  var keyLocator = keyLocator = KeyLocator.getFromSignature(signature);

  var signatureName = keyLocator.getKeyName();
  // No key name in KeyLocator -> fail.
  if (signatureName.size() == 0) {
    failureReason[0] = "The signature KeyLocator doesn't have a key name";
    return null;
  }

  var signatureMatches = this.checkSignatureMatch
    (signatureName, objectName, matchedRule, failureReason);
  if (!signatureMatches)
    return null;

  // Before we look up keys, refresh any certificate directories.
  this.refreshManager.refreshAnchors();

  // If we don't actually have the certificate yet, return a certificateInterest
  // for it.
  if (this.isSecurityV1_) {
    var foundCert = this.refreshManager.getCertificate(signatureName);
    if (foundCert == null)
      foundCert = this.certificateCache_.getCertificate(signatureName);
    if (foundCert == null)
      return new Interest(signatureName);
  }
  else {
    var foundCert = this.refreshManager.getCertificateV2(signatureName);
    if (foundCert == null)
      foundCert = this.certificateCacheV2_.find(signatureName);
    if (foundCert == null)
      return new Interest(signatureName);
  }

  return new Interest();
};

/**
 * The configuration file allows 'trust anchor' certificates to be preloaded.
 * The certificates may also be loaded from a directory, and if the 'refresh'
 * option is set to an interval, the certificates are reloaded at the specified
 * interval.
 */
ConfigPolicyManager.prototype.loadTrustAnchorCertificates = function()
{
  var anchors = this.config.getRoot().get("validator/trust-anchor");

  for (var i = 0; i < anchors.length; ++i) {
    var anchor = anchors[i];

    var typeName = anchor.get("type")[0].getValue();
    var isPath = false;
    var certID;
    if (typeName == 'file') {
      certID = anchor.get("file-name")[0].getValue();
      isPath = true;
    }
    else if (typeName == 'base64') {
      certID = anchor.get("base64-string")[0].getValue();
      isPath = false;
    }
    else if (typeName == "dir") {
      var dirName = anchor.get("dir")[0].getValue();

      var refreshPeriod = 0;
      var refreshTrees = anchor.get("refresh");
      if (refreshTrees.length >= 1) {
        var refreshPeriodStr = refreshTrees[0].getValue();

        var refreshMatch = refreshPeriodStr.match(/(\d+)([hms])/);
        if (refreshMatch == null)
          refreshPeriod = 0;
        else {
          refreshPeriod = parseInt(refreshMatch[1]);
          if (refreshMatch[2] != 's') {
            refreshPeriod *= 60;
            if (refreshMatch[2] != 'm')
              refreshPeriod *= 60;
          }
        }
      }

      // Convert refreshPeriod from seconds to milliseconds.
      this.refreshManager.addDirectory(dirName, refreshPeriod * 1000);
      continue;
    }
    else if (typeName == "any") {
      // This disables all security!
      this.requiresVerification = false;
      break;
    }

    if (this.isSecurityV1_)
      this.lookupCertificate(certID, isPath);
    else
      this.lookupCertificateV2(certID, isPath);
  }
};

/**
 * Once a rule is found to match data or a signed interest, the name in the
 * KeyLocator must satisfy the condition in the 'checker' section of the rule,
 * else the data or interest is rejected.
 * @param {Name} signatureName The certificate name from the KeyLocator.
 * @param {Name} objectName The name of the data packet or interest. In the case
 * of signed interests, this excludes the timestamp, nonce and signature
 * components.
 * @param {BoostInfoTree} rule The rule from the configuration file that matches
 * the data or interest.
 * @param {Array<string>} failureReason If matching fails, set failureReason[0]
 * to the failure reason.
 * @return {boolean} True if matches.
 */
ConfigPolicyManager.prototype.checkSignatureMatch = function
  (signatureName, objectName, rule, failureReason)
{
  var checker = rule.get("checker")[0];
  var checkerType = checker.get("type")[0].getValue();
  if (checkerType == "fixed-signer") {
    var signerInfo = checker.get("signer")[0];
    var signerType = signerInfo.get("type")[0].getValue();

    var cert;
    if (signerType == "file") {
      if (this.isSecurityV1_)
        cert = this.lookupCertificate
          (signerInfo.get("file-name")[0].getValue(), true);
      else
        cert = this.lookupCertificateV2
          (signerInfo.get("file-name")[0].getValue(), true);
      if (cert == null) {
        failureReason[0] = "Can't find fixed-signer certificate file: " +
          signerInfo.get("file-name")[0].getValue();
        return false;
      }
    }
    else if (signerType == "base64") {
      if (this.isSecurityV1_)
        cert = this.lookupCertificate
          (signerInfo.get("base64-string")[0].getValue(), false);
      else
        cert = this.lookupCertificateV2
          (signerInfo.get("base64-string")[0].getValue(), false);
      if (cert == null) {
        failureReason[0] = "Can't find fixed-signer certificate base64: " +
          signerInfo.get("base64-string")[0].getValue();
        return false;
      }
    }
    else {
      failureReason[0] = "Unrecognized fixed-signer signerType: " + signerType;
      return false;
    }

    if (cert.getName().equals(signatureName))
      return true;
    else {
      failureReason[0] = "fixed-signer cert name \"" + cert.getName().toUri() +
        "\" does not equal signatureName \"" + signatureName.toUri() + "\"";
      return false;
    }
  }
  else if (checkerType == "hierarchical") {
    // This just means the data/interest name has the signing identity as a prefix.
    // That means everything before "ksk-?" in the key name.
    var identityRegex = "^([^<KEY>]*)<KEY>(<>*)<ksk-.+><ID-CERT>";
    var identityMatch = new NdnRegexTopMatcher(identityRegex);
    if (identityMatch.match(signatureName)) {
      var identityPrefix = identityMatch.expand("\\1").append
        (identityMatch.expand("\\2"));
      if (ConfigPolicyManager.matchesRelation
          (objectName, identityPrefix, "is-prefix-of"))
        return true;
      else {
        failureReason[0] = "The hierarchical objectName \"" + objectName.toUri() +
          "\" is not a prefix of \"" + identityPrefix.toUri() + "\"";
        return false;
      }
    }

    if (!this.isSecurityV1_) {
      // Check for a security v2 key name.
      var identityRegex2 = "^(<>*)<KEY><>$";
      var identityMatch2 = new NdnRegexTopMatcher(identityRegex2);
      if (identityMatch2.match(signatureName)) {
        var identityPrefix = identityMatch2.expand("\\1");
        if (ConfigPolicyManager.matchesRelation
            (objectName, identityPrefix, "is-prefix-of"))
          return true;
        else {
          failureReason[0] = "The hierarchical objectName \"" + objectName.toUri() +
            "\" is not a prefix of \"" + identityPrefix.toUri() + "\"";
          return false;
        }
      }
    }

    failureReason[0] = "The hierarchical identityRegex \"" + identityRegex +
      "\" does not match signatureName \"" + signatureName.toUri() + "\"";
    return false;
  }
  else if (checkerType == "customized") {
    var keyLocatorInfo = checker.get("key-locator")[0];
    // Not checking type - only name is supported.

    // Is this a simple relation?
    var relationType = keyLocatorInfo.getFirstValue("relation");
    if (relationType != null) {
      var matchName = new Name(keyLocatorInfo.get("name")[0].getValue());
      if (ConfigPolicyManager.matchesRelation
          (signatureName, matchName, relationType))
        return true;
      else {
        failureReason[0] = "The custom signatureName \"" + signatureName.toUri() +
          "\" does not match matchName \"" + matchName.toUri() +
          "\" using relation " + relationType;
        return false;
      }
    }

    // Is this a simple regex?
    var keyRegex = keyLocatorInfo.getFirstValue("regex");
    if (keyRegex != null) {
      if (new NdnRegexTopMatcher(simpleKeyRegex).match(signatureName))
        return true;
      else {
        failureReason[0] = "The custom signatureName \"" + signatureName.toUri() +
          "\" does not regex match simpleKeyRegex \"" + keyRegex + "\"";
        return false;
      }
    }

    // Is this a hyper-relation?
    var hyperRelationList = keyLocatorInfo.get("hyper-relation");
    if (hyperRelationList.length >= 1) {
      var hyperRelation = hyperRelationList[0];

      var keyRegex = hyperRelation.getFirstValue("k-regex");
      var keyExpansion = hyperRelation.getFirstValue("k-expand");
      var nameRegex = hyperRelation.getFirstValue("p-regex");
      var nameExpansion = hyperRelation.getFirstValue("p-expand");
      var relationType = hyperRelation.getFirstValue("h-relation");
      if (keyRegex != null && keyExpansion != null && nameRegex != null &&
          nameExpansion != null && relationType != null) {
        var keyMatch = new NdnRegexTopMatcher(keyRegex);
        if (!keyMatch.match(signatureName)) {
          failureReason[0] = "The custom hyper-relation signatureName \"" +
            signatureName.toUri() + "\" does not match the keyRegex \"" +
            keyRegex + "\"";
          return false;
        }
        var keyMatchPrefix = keyMatch.expand(keyExpansion);

        var nameMatch = new NdnRegexTopMatcher(nameRegex);
        if (!nameMatch.match(objectName)) {
          failureReason[0] = "The custom hyper-relation objectName \"" +
            objectName.toUri() + "\" does not match the nameRegex \"" +
            nameRegex + "\"";
          return false;
        }
        var nameMatchExpansion = nameMatch.expand(nameExpansion);

        if (ConfigPolicyManager.matchesRelation
            (nameMatchExpansion, keyMatchPrefix, relationType))
          return true;
        else {
          failureReason[0] = "The custom hyper-relation nameMatch \"" +
            nameMatchExpansion.toUri() + "\" does not match the keyMatchPrefix \"" +
            keyMatchPrefix.toUri() + "\" using relation " + relationType;
          return false;
        }
      }
    }
  }

  failureReason[0] = "Unrecognized checkerType: " + checkerType;
  return false;
};

/**
 * This looks up certificates specified as base64-encoded data or file names.
 * These are cached by filename or encoding to avoid repeated reading of files
 * or decoding.
 * @param {string} certID
 * @param {boolean} isPath
 * @return {IdentityCertificate} The certificate object, or null if not found.
 */
ConfigPolicyManager.prototype.lookupCertificate = function(certID, isPath)
{
  if (!this.isSecurityV1_)
    throw new SecurityException(new Error
      ("lookupCertificate: For security v2, use lookupCertificateV2()"));

  var cert;

  var cachedCertUri = this.fixedCertificateCache[certID];
  if (cachedCertUri === undefined) {
    if (isPath)
      // load the certificate data (base64 encoded IdentityCertificate)
      cert = ConfigPolicyManager.TrustAnchorRefreshManager.loadIdentityCertificateFromFile
        (certID);
    else {
      var certData = new Buffer(certID, 'base64');
      cert = new IdentityCertificate();
      cert.wireDecode(certData);
    }

    var certUri = cert.getName().getPrefix(-1).toUri();
    this.fixedCertificateCache[certID] = certUri;
    this.certificateCache_.insertCertificate(cert);
  }
  else
    cert = this.certificateCache_.getCertificate(new Name(cachedCertUri));

  return cert;
};

/**
 * This looks up certificates specified as base64-encoded data or file names.
 * These are cached by filename or encoding to avoid repeated reading of files
 * or decoding.
 * @param {string} certID
 * @param {boolean} isPath
 * @return {CertificateV2} The certificate object, or null if not found.
 */
ConfigPolicyManager.prototype.lookupCertificateV2 = function(certID, isPath)
{
  if (this.isSecurityV1_)
    throw new SecurityException(new Error
      ("lookupCertificateV2: For security v1, use lookupCertificate()"));

  var cert;

  var cachedCertUri = this.fixedCertificateCache[certID];
  if (cachedCertUri === undefined) {
    if (isPath)
      // load the certificate data (base64 encoded IdentityCertificate)
      cert = ConfigPolicyManager.TrustAnchorRefreshManager.loadCertificateV2FromFile
        (certID);
    else {
      var certData = new Buffer(certID, 'base64');
      cert = new CertificateV2();
      cert.wireDecode(certData);
    }

    var certUri = cert.getName().getPrefix(-1).toUri();
    this.fixedCertificateCache[certID] = certUri;
    this.certificateCacheV2_.insert(cert);
  }
  else
    cert = this.certificateCacheV2_.find(new Name(cachedCertUri));

  return cert;
};

/**
 * Search the configuration file for the first rule that matches the data or
 * signed interest name. In the case of interests, the name to match should
 * exclude the timestamp, nonce, and signature components.
 * @param {Name} objName The name to be matched.
 * @param {string} matchType The rule type to match, "data" or "interest".
 * @return {BoostInfoTree} The matching rule, or null if not found.
 */
ConfigPolicyManager.prototype.findMatchingRule = function(objName, matchType)
{
  var rules = this.config.getRoot().get("validator/rule");
  for (var iRule = 0; iRule < rules.length; ++iRule) {
    var r = rules[iRule];

    if (r.get('for')[0].getValue() == matchType) {
      var passed = true;
      var filters = r.get('filter');
      if (filters.length == 0)
        // No filters means we pass!
        return r;
      else {
        for (var iFilter = 0; iFilter < filters.length; ++iFilter) {
          var f = filters[iFilter];

          // Don't check the type - it can only be name for now.
          // We need to see if this is a regex or a relation.
          var regexPattern = f.getFirstValue("regex");
          if (regexPattern === null) {
            var matchRelation = f.get('relation')[0].getValue();
            var matchUri = f.get('name')[0].getValue();
            var matchName = new Name(matchUri);
            passed = ConfigPolicyManager.matchesRelation(objName, matchName, matchRelation);
          }
          else
            passed = new NdnRegexTopMatcher(regexPattern).match(objName);

          if (!passed)
            break;
        }

        if (passed)
          return r;
      }
    }
  }

  return null;
};

/**
 * Determines if a name satisfies the relation to matchName.
 * @param {Name} name
 * @param {Name} matchName
 * @param {string} matchRelation Can be one of:
 *   'is-prefix-of' - passes if the name is equal to or has the other
 *      name as a prefix
 *   'is-strict-prefix-of' - passes if the name has the other name as a
 *      prefix, and is not equal
 *   'equal' - passes if the two names are equal
 * @return {boolean}
 */
ConfigPolicyManager.matchesRelation = function(name, matchName, matchRelation)
{
  var passed = false;
  if (matchRelation == 'is-strict-prefix-of') {
    if (matchName.size() == name.size())
      passed = false;
    else if (matchName.match(name))
      passed = true;
  }
  else if (matchRelation == 'is-prefix-of') {
    if (matchName.match(name))
      passed = true;
  }
  else if (matchRelation == 'equal') {
    if (matchName.equals(name))
      passed = true;
  }
  return passed;
};

/**
 * Extract the signature information from the interest name or from the data
 * packet or interest.
 * @param {Data|Interest} dataOrInterest The object whose signature is needed.
 * @param {WireFormat} wireFormat (optional) The wire format used to decode
 * signature information from the interest name.
 * @return {Signature} The object of a sublcass of Signature or null if can't
 * decode.
 */
ConfigPolicyManager.extractSignature = function(dataOrInterest, wireFormat)
{
  if (dataOrInterest instanceof Data)
    return dataOrInterest.getSignature();
  else if (dataOrInterest instanceof Interest) {
    wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
    try {
      var signature = wireFormat.decodeSignatureInfoAndValue
        (dataOrInterest.getName().get(-2).getValue().buf(),
         dataOrInterest.getName().get(-1).getValue().buf(), false);
    }
    catch (e) {
      return null;
    }

    return signature;
  }

  return null;
};

/**
 * Determine whether the timestamp from the interest is newer than the last use
 * of this key, or within the grace interval on first use.
 * @param {Name} keyName The name of the public key used to sign the interest.
 * @param {number} timestamp The timestamp extracted from the interest name.
 * @param {Array<string>} failureReason If matching fails, set failureReason[0]
 * to the failure reason.
 * @return {boolean} True if timestamp is fresh as described above.
 */
ConfigPolicyManager.prototype.interestTimestampIsFresh = function
  (keyName, timestamp, failureReason)
{
  var lastTimestamp = this.keyTimestamps[keyName.toUri()];
  if (lastTimestamp == undefined) {
    var now = new Date().getTime();
    var notBefore = now - this.keyGraceInterval;
    var notAfter = now + this.keyGraceInterval;
    if (!(timestamp > notBefore && timestamp < notAfter)) {
      failureReason[0] =
        "The command interest timestamp is not within the first use grace period of " +
        this.keyGraceInterval + " milliseconds.";
      return false;
    }
    else
      return true;
  }
  else {
    if (timestamp <= lastTimestamp) {
      failureReason[0] =
        "The command interest timestamp is not newer than the previous timestamp";
      return false;
    }
    else
      return true;
  }
};

/**
 * Trim the table size down if necessary, and insert/update the latest interest
 * signing timestamp for the key. Any key which has not been used within the TTL
 * period is purged. If the table is still too large, the oldest key is purged.
 * @param {Name} keyName The name of the public key used to sign the interest.
 * @param {number} timestamp The timestamp extracted from the interest name.
 */
ConfigPolicyManager.prototype.updateTimestampForKey = function
  (keyName, timestamp)
{
  this.keyTimestamps[keyName.toUri()] = timestamp;

  // JavaScript does have a direct way to get the number of entries, so first
  //   get the keysToErase while counting.
  var keyTimestampsSize = 0;
  var keysToErase = [];

  var now = new Date().getTime();
  var oldestTimestamp = now;
  var oldestKey = null;
  for (var keyUri in this.keyTimestamps) {
    ++keyTimestampsSize;
    var ts = this.keyTimestamps[keyUri];
    if (now - ts > this.keyTimestampTtl)
      keysToErase.push(keyUri);
    else if (ts < oldestTimestamp) {
      oldestTimestamp = ts;
      oldestKey = keyUri;
    }
  }

  if (keyTimestampsSize >= this.maxTrackedKeys) {
    // Now delete the expired keys.
    for (var i = 0; i < keysToErase.length; ++i) {
      delete this.keyTimestamps[keysToErase[i]];
      --keyTimestampsSize;
    }

    if (keyTimestampsSize > this.maxTrackedKeys)
      // We have not removed enough.
      delete this.keyTimestamps[oldestKey];
  }
};

/**
 * Check the type of signatureInfo to get the KeyLocator. Look in the
 * IdentityStorage for the public key with the name in the KeyLocator and use it
 * to verify the signedBlob. If the public key can't be found, return false.
 * (This is a generalized method which can verify both a data packet and an
 * interest.)
 * @param {Signature} signatureInfo An object of a subclass of Signature, e.g.
 * Sha256WithRsaSignature.
 * @param {SignedBlob} signedBlob The SignedBlob with the signed portion to
 * verify.
 * @param {function} onComplete This calls onComplete(true, undefined) if the
 * signature verifies, otherwise onComplete(false, reason).
 */
ConfigPolicyManager.prototype.verify = function
  (signatureInfo, signedBlob, onComplete)
{
  // We have already checked once that there is a key locator.
  var keyLocator = KeyLocator.getFromSignature(signatureInfo);

  if (keyLocator.getType() == KeyLocatorType.KEYNAME) {
    // Assume the key name is a certificate name.
    var signatureName = keyLocator.getKeyName();

    var publicKeyDer;
    if (this.isSecurityV1_) {
      var certificate = this.refreshManager.getCertificate(signatureName);
      if (certificate == null)
        certificate = this.certificateCache_.getCertificate(signatureName);
      if (certificate == null) {
        onComplete(false,  "Cannot find a certificate with name " +
          signatureName.toUri());
        return;
      }

      publicKeyDer = certificate.getPublicKeyInfo().getKeyDer();
      if (publicKeyDer.isNull()) {
        // Can't find the public key with the name.
        onComplete(false, "There is no public key in the certificate with name " +
          certificate.getName().toUri());
        return;
      }
    }
    else {
      var certificate = this.refreshManager.getCertificateV2(signatureName);
      if (certificate == null)
        certificate = this.certificateCacheV2_.find(signatureName);
      if (certificate == null) {
        onComplete(false,  "Cannot find a certificate with name " +
          signatureName.toUri());
        return;
      }

      try {
        publicKeyDer = certificate.getPublicKey();
      } catch (ex) {
        // We don't expect this to happen.
        onComplete(false, "There is no public key in the certificate with name " +
          certificate.getName().toUri());
        return;
      }
    }

    PolicyManager.verifySignature
      (signatureInfo, signedBlob, publicKeyDer, function(verified) {
        if (verified)
          onComplete(true);
        else
          onComplete
            (false,
             "The signature did not verify with the given public key");
      });
  }
  else
    onComplete(false, "The KeyLocator does not have a key name");
};

/**
 * Manages the trust-anchor certificates, including refresh.
 * @constructor
 */
ConfigPolicyManager.TrustAnchorRefreshManager =
  function ConfigPolicyManagerTrustAnchorRefreshManager(isSecurityV1)
{
  this.isSecurityV1_ = isSecurityV1;

  this.certificateCache_ = new CertificateCache();
  this.certificateCacheV2_ = new CertificateCacheV2();
  // Maps the directory name to certificate names so they can be deleted when
  // necessary. The key is the directory name string. The value is the object
  //  {certificateNames,  // array of string
  //   nextRefresh,       // number
  //   refreshPeriod      // number
  //  }.
  this.refreshDirectories = {};
};

/**
 * @param {string} fileName
 * @return {IdentityCertificate}
 */
ConfigPolicyManager.TrustAnchorRefreshManager.loadIdentityCertificateFromFile =
  function(fileName)
{
  var encodedData = fs.readFileSync(fileName).toString();
  var decodedData = new Buffer(encodedData, 'base64');
  var cert = new IdentityCertificate();
  cert.wireDecode(new Blob(decodedData, false));
  return cert;
};

/**
 * @param {string} fileName
 * @return {CertificateV2}
 */
ConfigPolicyManager.TrustAnchorRefreshManager.loadCertificateV2FromFile =
  function(fileName)
{
  var encodedData = fs.readFileSync(fileName).toString();
  var decodedData = new Buffer(encodedData, 'base64');
  var cert = new CertificateV2();
  cert.wireDecode(new Blob(decodedData, false));
  return cert;
};

/**
 * @param {Name} certificateName
 * @return {IdentityCertificate}
 */
ConfigPolicyManager.TrustAnchorRefreshManager.prototype.getCertificate = function
  (certificateName)
{
  if (!this.isSecurityV1_)
    throw new SecurityException(new Error
      ("getCertificate: For security v2, use getCertificateV2()"));

  // This assumes the timestamp is already removed.
  return this.certificateCache_.getCertificate(certificateName);
};

/**
 * @param {Name} certificateName
 * @return {CertificateV2}
 */
ConfigPolicyManager.TrustAnchorRefreshManager.prototype.getCertificateV2 = function
  (certificateName)
{
  if (this.isSecurityV1_)
    throw new SecurityException(new Error
      ("getCertificateV2: For security v1, use getCertificate()"));

  // This assumes the timestamp is already removed.
  return this.certificateCacheV2_.find(certificateName);
};

// refreshPeriod in milliseconds.
ConfigPolicyManager.TrustAnchorRefreshManager.prototype.addDirectory = function
  (directoryName, refreshPeriod)
{
  var allFiles;
  try {
    allFiles = fs.readdirSync(directoryName);
  }
  catch (e) {
    throw new SecurityException(new Error
      ("Cannot list files in directory " + directoryName));
  }

  var certificateNames = [];
  for (var i = 0; i < allFiles.length; ++i) {
    if (this.isSecurityV1_) {
      var cert;
      try {
        var fullPath = path.join(directoryName, allFiles[i]);
        cert = ConfigPolicyManager.TrustAnchorRefreshManager.loadIdentityCertificateFromFile
          (fullPath);
      }
      catch (e) {
        // Allow files that are not certificates.
        continue;
      }

      // Cut off the timestamp so it matches the KeyLocator Name format.
      var certUri = cert.getName().getPrefix(-1).toUri();
      this.certificateCache_.insertCertificate(cert);
      certificateNames.push(certUri);
    }
    else {
      var cert;
      try {
        var fullPath = path.join(directoryName, allFiles[i]);
        cert = ConfigPolicyManager.TrustAnchorRefreshManager.loadCertificateV2FromFile
          (fullPath);
      }
      catch (e) {
        // Allow files that are not certificates.
        continue;
      }

      // Get the key name since this is in the KeyLocator.
      var certUri = CertificateV2.extractKeyNameFromCertName
        (cert.getName()).toUri();
      this.certificateCacheV2_.insert(cert);
      certificateNames.push(certUri);
    }
  }

  this.refreshDirectories[directoryName] = {
    certificates: certificateNames,
    nextRefresh: new Date().getTime() + refreshPeriod,
    refreshPeriod: refreshPeriod };
};

ConfigPolicyManager.TrustAnchorRefreshManager.prototype.refreshAnchors = function()
{
  var refreshTime =  new Date().getTime();
  for (var directory in this.refreshDirectories) {
    var info = this.refreshDirectories[directory];
    var nextRefreshTime = info.nextRefresh;
    if (nextRefreshTime <= refreshTime) {
      var certificateList = info.certificates.slice(0);
      // Delete the certificates associated with this directory if possible
      //   then re-import.
      // IdentityStorage subclasses may not support deletion.
      for (var i = 0; i < certificateList.length; ++i) {
        try {
          if (this.isSecurityV1_)
            this.certificateCache_.deleteCertificate(new Name(certificateList[i]));
          else {
            // The name in the CertificateCacheV2 contains the but the name in
            // the certificateList does not, so find the certificate based on
            // the prefix first.
            var foundCertificate = this.certificateCacheV2_.find
              (new Name(certificateList[i]));
            if (foundCertificate != null)
              this.certificateCacheV2_.deleteCertificate
                (foundCertificate.getName());
          }
        } catch (ex) {
          // Was already removed or not supported?
        }
      }

      this.addDirectory(directory, info.refreshPeriod);
    }
  }
};
