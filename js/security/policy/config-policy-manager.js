/**
 * Copyright (C) 2014-2017 Regents of the University of California.
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
 * CertificateCache for the IdentityCertificate matching the name in the KeyLocator
 * and uses its public key to verify the data packet or signed interest. If the
 * certificate can't be found, it is downloaded, verified and installed. A chain
 * of certificates will be followed to a maximum depth.
 * If the new certificate is accepted, it is used to complete the verification.
 *
 * The KeyLocators of data packets and signed interests MUST contain a name for
 * verification to succeed.
 *
 * Create a new ConfigPolicyManager which will act on the rules specified in the
 * configuration and download unknown certificates when necessary.
 *
 * @param {string} configFileName (optional) If not null or empty, the path to
 * the configuration file containing verification rules. (This only works in
 * Node.js since it reads files using the "fs" module.) Otherwise, you should
 * separately call load().
 * @param {CertificateCache} certificateCache (optional) A CertificateCache to
 * hold known certificates. If this is null or omitted, then create an internal
 * CertificateCache.
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
    this.certificateCache = new CertificateCache();
  else
    this.certificateCache = certificateCache;
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
  this.certificateCache.reset();

  // Stores the fixed-signer certificate name associated with validation rules
  // so we don't keep loading from files.
  this.fixedCertificateCache = {};

  // Stores the timestamps for each public key used in command interests to
  // avoid replay attacks.
  // Key is public key name, value is last timestamp.
  this.keyTimestamps = {};

  this.requiresVerification = true;

  this.config = new BoostInfoParser();
  this.refreshManager = new ConfigPolicyManager.TrustAnchorRefreshManager();
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
  if (stepCount > this.maxDepth) {
    try {
      onValidationFailed
        (dataOrInterest, "The verification stepCount " + stepCount +
           " exceeded the maxDepth " + this.maxDepth);
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return null;
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

  if (!KeyLocator.canGetFromSignature(signature)) {
    // We only support signature types with key locators.
    try {
      onValidationFailed
        (dataOrInterest, "The signature type does not support a KeyLocator");
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return null;
  }

  var keyLocator = null;
  try {
    keyLocator = KeyLocator.getFromSignature(signature);
  }
  catch (ex) {
    // No key locator -> fail.
    try {
      onValidationFailed
        (dataOrInterest, "Error in KeyLocator.getFromSignature: " + ex);
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return null;
  }

  var signatureName = keyLocator.getKeyName();
  // No key name in KeyLocator -> fail.
  if (signatureName.size() == 0) {
    try {
      onValidationFailed
        (dataOrInterest, "The signature KeyLocator doesn't have a key name");
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return null;
  }

  var objectName = dataOrInterest.getName();
  var matchType = "data";

  // For command interests, we need to ignore the last 4 components when
  // matching the name.
  if (dataOrInterest instanceof Interest) {
    objectName = objectName.getPrefix(-4);
    matchType = "interest";
  }

  // First see if we can find a rule to match this packet.
  var matchedRule = this.findMatchingRule(objectName, matchType);

  // No matching rule -> fail.
  if (matchedRule == null) {
    try {
      onValidationFailed
        (dataOrInterest, "No matching rule found for " + objectName.toUri());
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return null;
  }

  var failureReason = ["unknown"];
  var signatureMatches = this.checkSignatureMatch
    (signatureName, objectName, matchedRule, failureReason);
  if (!signatureMatches) {
    try {
      onValidationFailed(dataOrInterest, failureReason[0]);
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return null;
  }

  // Before we look up keys, refresh any certificate directories.
  this.refreshManager.refreshAnchors();

  // Now finally check that the data or interest was signed correctly.
  // If we don't actually have the certificate yet, create a
  // ValidationRequest for it.
  var foundCert = this.refreshManager.getCertificate(signatureName);
  if (foundCert == null)
    foundCert = this.certificateCache.getCertificate(signatureName);
  var thisManager = this;
  if (foundCert == null) {
    var certificateInterest = new Interest(signatureName);
    var onCertificateDownloadComplete = function(data) {
      var certificate;
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
      thisManager.certificateCache.insertCertificate(certificate);
      thisManager.checkVerificationPolicy
        (dataOrInterest, stepCount + 1, onVerified, onValidationFailed);
    };

    var nextStep = new ValidationRequest
      (certificateInterest, onCertificateDownloadComplete, onValidationFailed,
       2, stepCount + 1);

    return nextStep;
  }

  // For interests, we must check that the timestamp is fresh enough.
  // We do this after (possibly) downloading the certificate to avoid
  // filling the cache with bad keys.
  if (dataOrInterest instanceof Interest) {
    var keyName = foundCert.getPublicKeyName();
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

    this.lookupCertificate(certID, isPath);
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
      cert = this.lookupCertificate
        (signerInfo.get("file-name")[0].getValue(), true);
      if (cert == null) {
        failureReason[0] = "Can't find fixed-signer certificate file: " +
          signerInfo.get("file-name")[0].getValue();
        return false;
      }
    }
    else if (signerType == "base64") {
      cert = this.lookupCertificate
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
    else {
      failureReason[0] = "The hierarchical identityRegex \"" + identityRegex +
        "\" does not match signatureName \"" + signatureName.toUri() + "\"";
      return false;
    }
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
    this.certificateCache.insertCertificate(cert);
  }
  else
    cert = this.certificateCache.getCertificate(new Name(cachedCertUri));

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
    var certificate = this.refreshManager.getCertificate(signatureName);
    if (certificate == null)
      certificate = this.certificateCache.getCertificate(signatureName);
    if (certificate == null) {
      onComplete(false,  "Cannot find a certificate with name " +
        signatureName.toUri());
      return;
    }

    var publicKeyDer = certificate.getPublicKeyInfo().getKeyDer();
    if (publicKeyDer.isNull()) {
      // Can't find the public key with the name.
      onComplete(false, "There is no public key in the certificate with name " +
        certificate.getName().toUri());
      return;
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

ConfigPolicyManager.TrustAnchorRefreshManager =
  function ConfigPolicyManagerTrustAnchorRefreshManager()
{
  this.certificateCache = new CertificateCache();
  // Maps the directory name to certificate names so they can be deleted when
  // necessary. The key is the directory name string. The value is the object
  //  {certificateNames,  // array of string
  //   nextRefresh,       // number
  //   refreshPeriod      // number
  //  }.
  this.refreshDirectories = {};
};

ConfigPolicyManager.TrustAnchorRefreshManager.loadIdentityCertificateFromFile =
  function(fileName)
{
  var encodedData = fs.readFileSync(fileName).toString();
  var decodedData = new Buffer(encodedData, 'base64');
  var cert = new IdentityCertificate();
  cert.wireDecode(new Blob(decodedData, false));
  return cert;
};

ConfigPolicyManager.TrustAnchorRefreshManager.prototype.getCertificate = function
  (certificateName)
{
  // This assumes the timestamp is already removed.
  return this.certificateCache.getCertificate(certificateName);
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
    this.certificateCache.insertCertificate(cert);
    certificateNames.push(certUri);
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
      for (var c in certificateList)
        this.certificateCache.deleteCertificate(new Name(c));

      this.addDirectory(directory, info.refreshPeriod);
    }
  }
};
