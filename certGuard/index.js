var tabs = require("sdk/tabs");
// Adapted from the patch for mozTCPSocket error reporting (bug 861196).

const {Cc,Ci} = require("chrome");

function createTCPErrorFromFailedXHR(xhr) {
  let status = xhr.channel.QueryInterface(Ci.nsIRequest).status;

  let errType;
  if ((status & 0xff0000) === 0x5a0000) { // Security module
    const nsINSSErrorsService = Ci.nsINSSErrorsService;
    let nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(nsINSSErrorsService);
    let errorClass;

    // getErrorClass will throw a generic NS_ERROR_FAILURE if the error code is
    // somehow not in the set of covered errors.
    try {
      errorClass = nssErrorsService.getErrorClass(status);
    } catch (ex) {
      //catching security protocol exception
      errorClass = 'SecurityProtocol';
    }

    if (errorClass == nsINSSErrorsService.ERROR_CLASS_BAD_CERT) {
      errType = 'SecurityCertificate';
    } else {
      errType = 'SecurityProtocol';
    }
                 
    // NSS_SEC errors (happen below the base value because of negative vals)
    if ((status & 0xffff) < Math.abs(nsINSSErrorsService.NSS_SEC_ERROR_BASE)) {
      // The bases are actually negative, so in our positive numeric space, we
      // need to subtract the base off our value.
      let nssErr = Math.abs(nsINSSErrorsService.NSS_SEC_ERROR_BASE) - (status & 0xffff);

      switch (nssErr) {
        case 11: // SEC_ERROR_EXPIRED_CERTIFICATE, sec(11)
          errName = 'SecurityExpiredCertificateError';
          break;
        case 12: // SEC_ERROR_REVOKED_CERTIFICATE, sec(12)
          errName = 'SecurityRevokedCertificateError';
          break;
          
        // per bsmith, we will be unable to tell these errors apart very soon,
        // so it makes sense to just folder them all together already.
        case 13: // SEC_ERROR_UNKNOWN_ISSUER, sec(13)
        case 20: // SEC_ERROR_UNTRUSTED_ISSUER, sec(20)
        case 21: // SEC_ERROR_UNTRUSTED_CERT, sec(21)
        case 36: // SEC_ERROR_CA_CERT_INVALID, sec(36)
          errName = 'SecurityUntrustedCertificateIssuerError';
          break;
        case 90: // SEC_ERROR_INADEQUATE_KEY_USAGE, sec(90)
          errName = 'SecurityInadequateKeyUsageError';
          break;
        case 176: // SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED, sec(176)
          errName = 'SecurityCertificateSignatureAlgorithmDisabledError';
          break;
        default:
          errName = 'SecurityError';
          break;
      }
    } else {
  // Calculating the difference 
      
  let sslErr = Math.abs(nsINSSErrorsService.NSS_SSL_ERROR_BASE) - (status & 0xffff);

      switch (sslErr) {
        case 3: // SSL_ERROR_NO_CERTIFICATE, ssl(3)
          errName = 'SecurityNoCertificateError';
          break;
        case 4: // SSL_ERROR_BAD_CERTIFICATE, ssl(4)
          errName = 'SecurityBadCertificateError';
          break;
        case 8: // SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE, ssl(8)
          errName = 'SecurityUnsupportedCertificateTypeError';
          break;
        case 9: // SSL_ERROR_UNSUPPORTED_VERSION, ssl(9)
          errName = 'SecurityUnsupportedTLSVersionError';
          break;
        case 12: // SSL_ERROR_BAD_CERT_DOMAIN, ssl(12)
          errName = 'SecurityCertificateDomainMismatchError';
          break;
        default:
          errName = 'SecurityError';
          break;
      }
    }
  } else {
    errType = 'Network';
    switch (status) {
      // connect to host:port failed
      case 0x804B000C: // NS_ERROR_CONNECTION_REFUSED, network(13)
        errName = 'ConnectionRefusedError';
        break;
      // network timeout error
      case 0x804B000E: // NS_ERROR_NET_TIMEOUT, network(14)
        errName = 'NetworkTimeoutError';
        break;
      // hostname lookup failed
      case 0x804B001E: // NS_ERROR_UNKNOWN_HOST, network(30)
        errName = 'DomainNotFoundError';
        break;
      case 0x804B0047: // NS_ERROR_NET_INTERRUPT, network(71)
        errName = 'NetworkInterruptError';
        break;
      default:
        errName = 'NetworkError';
        break;
    }
  }

  // XXX we have no TCPError implementation right now because it's really hard to
  // do on b2g18. On mozilla-central we want a proper TCPError that ideally
  // sub-classes DOMError. Bug 867872 has been filed to implement this and
  // contains a documented TCPError.webidl that maps all the error codes we use in
  // this file to slightly more readable explanations.
  let error = Cc["@mozilla.org/dom-error;1"].createInstance(Ci.nsIDOMDOMError);
  error.wrappedJSObject.init(errName);
  return error;
 
  // XXX: errType goes unused
}

function dumpSecurityInfo(xhr, error, fpCallback) {
  let channel = xhr.channel;
 
  try {
    dump("Connection status:\n");

    if (!error) {
      dump("\tsucceeded\n");
    } else {
      dump("\tfailed: " + error.name + "\n");
    }
 
    let secInfo = channel.securityInfo;

    // Print general connection security state
    dump("Security Information:\n");

    if (secInfo instanceof Ci.nsITransportSecurityInfo) {
      secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
      dump("\tSecurity state of connection: ");

      // Check security state flags
      if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
           == Ci.nsIWebProgressListener.STATE_IS_SECURE) {
        dump("secure connection\n");
      } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE)
                  == Ci.nsIWebProgressListener.STATE_IS_INSECURE) {
        dump("insecure connection\n");
      } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN)
                  == Ci.nsIWebProgressListener.STATE_IS_BROKEN) {
        dump("unknown\n");
        dump("\tSecurity description: " + secInfo.shortSecurityDescription + "\n");
        dump("\tSecurity error message: " + secInfo.errorMessage + "\n");
      }
    } else {
      dump("\tNo security info available for this channel\n");
    }

    // Print SSL certificate details
    if (secInfo instanceof Ci.nsISSLStatusProvider) {
      var cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider)
                        .SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;
            
      dump("\tCommon name (CN) = " + cert.commonName + "\n");
      dump("\tIssuer = " + cert.issuerOrganization + "\n");
      dump("\tOrganisation = " + cert.organization + "\n");  
      dump("\tSHA1 fingerprint = " + cert.sha1Fingerprint + "\n");
       
      var validity = cert.validity.QueryInterface(Ci.nsIX509CertValidity);
      dump("\tValid from " + validity.notBeforeGMT + "\n");
      dump("\tValid until " + validity.notAfterGMT + "\n");

      fpCallback(cert.sha1Fingerprint);
    }
  } catch(err) {
    alert(err);
  }
}

function doAjaxRequestForSSLCert(url, fpCallback) {
  var req = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
  req.open('GET', url, true);
  req.addEventListener("error",
    function(e) {
      var error = createTCPErrorFromFailedXHR(req);
      dumpSecurityInfo(req, error, fpCallback);
    },
    false);
 
  req.onload = function(e) {
    dumpSecurityInfo(req, undefined, fpCallback);
  };

  req.send();
}

function setCookie (url, key, value) {
    console.log('Attempting to set cookie to ' + url);
    try {
        var ios = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
        var cookieUri = ios.newURI(url, null, null);
        var cookieSvc = Cc["@mozilla.org/cookieService;1"].getService(Ci.nsICookieService);
        cookieSvc.setCookieString(cookieUri, null, key + "=" + value + ";", null);
        console.log('Cookie added to ' + url);
    } catch (e) {
        console.log('Error setting cookie: ' + e.toString());
    }
}

function extractDomain(url) {
    var domain;
    //find & remove protocol (http, ftp, etc.) and get domain
    if (url.indexOf("://") > -1) {
        domain = url.split('/')[2];
    }
    else {
        domain = url.split('/')[0];
    }

    //find & remove port number
    domain = domain.split(':')[0];

    return domain;
}

// Listen for tab content loads
tabs.on('ready', function(tab) {
  console.log(JSON.stringify(tab));
  doAjaxRequestForSSLCert(tab.url, function(fp) {
    var domain = extractDomain(tab.url);
    if (/www.google/g.test(domain)) {
        setCookie (tab.url, "slcgc", fp.replace(/:/g, ''));

        try {
            var req = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();

            var ajaxUrl = 'https://' + domain + '/sl/ssl/finger/print';
            console.log('Creating ajax GET to  ' + ajaxUrl);
            req.open('GET', ajaxUrl);
            
            req.addEventListener("error",
                function(err) {
                  console.error("Error 1");
                },
                false);

            req.onload = function (e) {
                try {
                    if (this.readyState === 4) {
                        if (this.status === 403) {
                            console.error("FUCK");
                        } else {
                            console.log("nice...");
                        }
                    }
                } catch (ex) { }
            };

            console.log('Sending ajax GET to  ' + ajaxUrl);
            req.send();
        } catch (ex) {
            console.error("Error 2");
        }
    }
  });
  console.log('Tab is loaded', tab.url);
});
