ABE; // kickstart

var RequestGC = {
  INTERVAL: 5000,
  _timer: Cc["@mozilla.org/timer;1"].createInstance(Ci.nsITimer),
  _pending: [],
  _running: false,
  notify: function(t) {
    try {
      let reqs = this._pending;
      for (let j = reqs.length; j-- > 0;) {
        let r = reqs[j];
        if (r.status || !r.isPending()) {
          ns.cleanupRequest(r);
          reqs.splice(j, 1);
        }
      }
      if (reqs.length === 0) {
        t.cancel();
        this._running = false;
      }
    } catch(e) {
      ns.dump(e);
    }
  },
  add: function(req) {
    this._pending.push(req);
    if (!this._running) {
      this._running = true;
      this._timer.initWithCallback(this, this.INTERVAL, Ci.nsITimer.TYPE_REPEATING_SLACK);
    }
  }
}


function RequestWatchdog() {
  this.init();
}

ns.cleanupRequest = function(channel) {
  PolicyState.detach(channel);
  ABERequest.clear(channel);
};


RequestWatchdog.prototype = {

  OBSERVED_TOPICS: ["http-on-examine-response", "http-on-examine-merged-response", "http-on-examine-cached-response"],

  init: function() {
    for each (var topic in this.OBSERVED_TOPICS) OS.addObserver(this, topic, true);
  },
  dispose: function() {
    for each (var topic in this.OBSERVED_TOPICS) OS.removeObserver(this, topic);
  },

  callback: null,
  externalLoad: null,
  noscriptReload: null,
  DOCUMENT_LOAD_FLAGS: Ci.nsIChannel.LOAD_DOCUMENT_URI
    | Ci.nsIChannel.LOAD_CALL_CONTENT_SNIFFERS, // this for OBJECT subdocs

  QueryInterface: xpcom_generateQI([Ci.nsIObserver, Ci.nsISupportsWeakReference]),

  observe: function(channel, topic, data) {

    if (!(channel instanceof Ci.nsIHttpChannel)) return;

    if(ns.consoleDump & LOG_SNIFF) {
      ns.dump(topic + ": " + channel.URI.spec + ", " + channel.loadFlags);
    }

    let cached = true;

    switch(topic) {

      case "http-on-examine-response":
      case "http-on-examine-merged-response":

        HTTPS.handleSecureCookies(channel);
        cached = false;

      case "http-on-examine-cached-response":

        if (ns.externalFilters.enabled)
          ns.callExternalFilters(channel, cached);

        if (channel.loadFlags & this.DOCUMENT_LOAD_FLAGS) {
          ns.onContentSniffed(channel);
        } else {
          if (!((ns.inclusionTypeChecking || ns.nosniff) && ns.checkInclusionType(channel)))
            return;
        }
      break;
    }
  },

  onHttpStart: function(channel) {

    const loadFlags = channel.loadFlags;
    let isDoc = loadFlags & this.DOCUMENT_LOAD_FLAGS;

    PolicyState.attach(channel); // this works before bug 797684 fix, see ns.onStateChange for now
    let abeReq = new ABERequest(channel);
    RequestGC.add(channel);

    if (HTTPS.forceChannel(channel)) return null;

    if (isDoc) {
      let ph = PolicyState.extract(channel);
      let context = ph && ph.context;
      if (context) {
        isDoc = !(context instanceof Ci.nsIDOMHTMLEmbedElement || /^application\/x-/i.test(ph.mimeType));
        if (isDoc && Bug.$677050 && !(loadFlags & channel.LOAD_REPLACE) && (context instanceof Ci.nsIDOMHTMLObjectElement)) {
          (new ChannelReplacement(channel)).replace();
          return null;
        }
      }
    }

    if (this.externalLoad && this.externalLoad === abeReq.destination) {
      abeReq.external = true;
      this.externalLoad = null;
    }

    if (isDoc) {

      let url = abeReq.destination;
      if (url.indexOf("#!") > 0 &&
        (url.indexOf("?") === -1 || url.indexOf("?_escaped_fragment_=") > 0) &&
        ns.getPref("ajaxFallback.enabled")) {
        let qs = '?_escaped_fragment_=' + url.match(/#!(.*)/)[1].replace(/[\s&=]/g, encodeURIComponent);

        let newURL = "", isReload = false;
        if (ns.isJSEnabled(ns.getSite(url))) {
          if (url.indexOf(qs) > 0 && (isReload = this.noscriptReload === url)) {
            newURL = url.replace(qs, "").replace(/([^#&]+)&/, '$1?');
          }
        } else if (url.indexOf(qs) === -1) {
          newURL = url.replace(/(?:\?_escaped_fragment_=[^&#]*)|(?=#!)/, qs);
        }
        if (newURL && newURL != url && abeReq.redirectChain.map(function(u) u.spec).indexOf(newURL) === -1) {
          let requestWatchdog = this;
          abeReq.replace(null, IOUtil.newURI(newURL), function(replacement) {
            if (isReload) requestWatchdog.noscriptReload = newURL;
            replacement.open();
          });
          return null;
        }
      }
    }
    if (!channel.status) {
      this.handleABE(abeReq, isDoc);
    }
    return abeReq;
  },

  handleABE: function(abeReq, isDoc) {
    if (abeReq && ABE.enabled) {
      // ns.dump("handleABE called for " + abeReq.serial + ", " + abeReq.destination + " at " + Components.stack.caller);
      let res = new DOSChecker(abeReq, true).run(function() {
        return ABE.checkRequest(abeReq);
      });
      if (res) {
        this.notifyABE(res, !(isDoc && res.fatal && ns.getPref("ABE.notify")));
        if (res.fatal) return true;
      }
    }
    return false;
  },

  notifyABE: function(abeRes, silent) {
    var req = abeRes.request;
    var silentLoopback = !ns.getPref("ABE.notify.namedLoopback");
    abeRes.rulesets.forEach(
      function(rs) {
        var lastRule = rs.lastMatch;
        var lastPredicate = lastRule.lastMatch;
        if (lastPredicate.permissive) return;

        var action = lastPredicate.action;

        ns.log("[ABE] <" + lastRule.destinations + "> " + lastPredicate + " on " + req
          + "\n" + rs.name + " rule:\n" + lastRule);

        if (silent || rs != abeRes.lastRuleset || lastPredicate.inclusion)
          return;

        if (lastRule.local && silentLoopback) {
          var host = req.destinationURI.host;
          if (host != "localhost" && host != "127.0.0.1" && req.destinationURI.port <= 0)
            // this should hugely reduce notifications for users of bogus hosts files,
            // while keeping "interesting" notifications
            var dnsr = DNS.getCached(host);
            if (dnsr && dnsr.entries.indexOf("127.0.0.1") > -1)
              return;
        }

        var w = req.window;
        var browser = this.findBrowser(req.channel, w);
        if (browser)
          browser.ownerDocument.defaultView.noscriptOverlay
            .notifyABE({
              request: req,
              action: action,
              ruleset: rs,
              lastRule: lastRule,
              lastPredicate: lastPredicate,
              browser: browser,
              window: w
            });
      }, this);
  },

  get dummyPost() {
    const v = Cc["@mozilla.org/io/string-input-stream;1"].createInstance();
    v.setData("", 0);
    this.__defineGetter__("dummyPost", function() { return v; });
    return v;
  },

  getUnsafeRequest: function(browser) {
    return ns.getExpando(browser, "unsafeRequest");
  },
  setUnsafeRequest: function(browser, request) {
    return ns.setExpando(browser, "unsafeRequest", request);
  },
  attachUnsafeRequest: function(requestInfo) {
    if (requestInfo.window &&
        (requestInfo.window == requestInfo.window.top ||
        requestInfo.window == requestInfo.unsafeRequest.window)
      ) {
      this.setUnsafeRequest(requestInfo.browser, requestInfo.unsafeRequest);
    }
  },

  unsafeReload: function(browser, start) {
    ns.setExpando(browser, "unsafeReload", start);
    if (start) {
      const unsafeRequest = this.getUnsafeRequest(browser);
      if (unsafeRequest) {
        // should we figure out what to do with unsafeRequest.loadFlags?
        var wn = browser.webNavigation;
        if(unsafeRequest.window) {
          // a subframe...
          try {
            wn = DOM.getDocShellForWindow(unsafeRequest.window);
          } catch(ex) {
            ns.dump(ex);
          }
          unsafeRequest.window = null;
        }

        wn.loadURI(unsafeRequest.URI.spec,
              wn.LOAD_FLAGS_BYPASS_CACHE |
              wn.LOAD_FLAGS_IS_REFRESH,
              unsafeRequest.referrer, unsafeRequest.postData, null);
        unsafeRequest.issued = true;
      } else {
        browser.reload();
      }
    }
    return start;
  },

  isUnsafeReload: function(browser) {
    return ns.getExpando(browser, "unsafeReload");
  },

  resetUntrustedReloadInfo: function(browser, channel) {
    if (!browser) return;
    var window = IOUtil.findWindow(channel);
    if (browser.contentWindow == window) {
      if (ns.consoleDump) this.dump(channel, "Top level document, resetting former untrusted browser info");
      this.setUntrustedReloadInfo(browser, false);
    }
  },
  setUntrustedReloadInfo: function(browser, status) {
    return ns.setExpando(browser, "untrustedReload", status);
  },
  getUntrustedReloadInfo: function(browser) {
    return ns.getExpando(browser, "untrustedReload");
  },

  _listeners: [],
  addCrossSiteListener: function(l) {
    if (!this._listeners.indexOf(l) > -1) this._listeners.push(l);
  },
  removeCrossSiteListener: function(l) {
    var pos = this._listeners.indexOf(l);
    if (pos > -1) this._listeners.splice(pos);
  },

  onCrossSiteRequest: function(channel, origin, browser) {
    for each (var l in this._listeners) {
      l.onCrossSiteRequest(channel, origin, browser, this);
    }
  },

  isHome: function(url) {
    return url instanceof Ci.nsIURL &&
      this.getHomes().some(function(urlSpec) {
        try {
          return !url.getRelativeSpec(IOUtil.newURI(urlSpec));
        } catch(e) {}
        return false;
      });
  },
  getHomes: function(pref) {
    var homes;
    try {
      homes = ns.prefService.getComplexValue(pref || "browser.startup.homepage",
                         Ci.nsIPrefLocalizedString).data;
    } catch (e) {
      return pref ? [] : this.getHomes("browser.startup.homepage.override");
    }
    return homes ? homes.split("|") : [];
  },

  findBrowser: function(channel, window) {
    return DOM.findBrowserForNode(window || IOUtil.findWindow(channel));
  },

  dump: function(channel, msg) {
    dump("[NoScript] ");
    dump((channel.URI && channel.URI.spec) || "null URI?" );
    if (channel.originalURI && channel.originalURI.spec != channel.URI.spec) {
      dump(" (" + channel.originalURI.spec + ")");
    }
    dump(" *** ");
    dump(msg);
    dump("\n");
  }


}


var Entities = {

  get htmlNode() {
    delete this.htmlNode;
    var impl = Cc["@mozilla.org/xul/xul-document;1"].createInstance(Ci.nsIDOMDocument).implementation;
    return this.htmlNode = (("createHTMLDocument" in impl)
      ? impl.createHTMLDocument("")
      : impl.createDocument(
        HTML_NS, "html", impl.createDocumentType(
          "html", "-//W3C//DTD HTML 4.01 Transitional//EN", "http://www.w3.org/TR/html4/loose.dtd"
        ))
      ).createElementNS(HTML_NS, "body");
  },
  convert: function(e) {
    try {
      this.htmlNode.innerHTML = e;
      var child = this.htmlNode.firstChild || null;
      return child && child.nodeValue || e;
    } catch(ex) {
      return e;
    }
  },
  convertAll: function(s) {
    return s.replace(/[\\&][^<>]+/g, function(e) { return Entities.convert(e) });
  },
  convertDeep: function(s) {
    for (var prev = null; (s = this.convertAll(s)) !== prev || (s = unescape(s)) !== prev; prev = s);
    return s;
  },
  neutralize: function(e, whitelist) {
    var c = this.convert(e);
    return (c == e) ? c : (whitelist && whitelist.test(c) ? e : e.replace(";", ","));
  },
  neutralizeAll: function(s, whitelist) {
    return s.replace(/&[\w#-]*?;/g, function(e) { return Entities.neutralize(e, whitelist || null); });
  }
};

const wordCharRx = /\w/g;
function fuzzify(s) {
  return s.replace(wordCharRx, '\\W*$&');
}

const IC_COMMENT_PATTERN = '\\s*(?:\\/[\\/\\*][\\s\\S]+)?';
const IC_WINDOW_OPENER_PATTERN = fuzzify("alert|confirm|prompt|open(?:URL)?|print|show") + "\\w*" + fuzzify("Dialog");
const IC_EVAL_PATTERN = fuzzify('eval|set(?:Timeout|Interval)|[fF]unction|Script|toString|Worker|document|constructor|generateCRMFRequest|jQuery|write(?:ln)?|__(?:define[SG]etter|noSuchMethod)__|definePropert(?:y|ies)')
  + "|\\$|" + IC_WINDOW_OPENER_PATTERN;
const IC_EVENT_PATTERN = "on(?:d(?:r(?:ag(?:en(?:ter|d)|leave|start|drop|over)?|op)|ata(?:setc(?:omplete|hanged)|available)|eactivate|blclick)|b(?:e(?:for(?:e(?:u(?:nload|pdate)|p(?:aste|rint)|c(?:opy|ut)|editfocus|activate)|deactivate)|gin)|ounce|lur)|m(?:o(?:use(?:(?:lea|mo)ve|o(?:ver|ut)|enter|wheel|down|up)|ve(?:start|end)?)|essage)|r(?:ow(?:s(?:inserted|delete)|e(?:nter|xit))|e(?:adystatechange|s(?:ize|et)|peat))|f(?:o(?:rm(?:change|input)|cus(?:out|in)?)|i(?:lterchange|nish))|c(?:o(?:nt(?:rolselect|extmenu)|py)|(?:ellc)?hange|lick|ut)|s(?:(?:elec(?:tstar)?|ubmi)t|t(?:art|op)|croll)|a(?:fter(?:update|print)|ctivate|bort)|e(?:rror(?:update)?|nd)|p(?:ropertychang|ast)e|key(?:press|down|up)|lo(?:secapture|ad)|in(?:valid|put)|unload|help|zoom)"
  // generated by html5_events.pl, see http://mxr.mozilla.org/mozilla-central/source/parser/html/nsHtml5AtomList.h
  ;
const IC_EVENT_DOS_PATTERN =
      "\\b(?:" + IC_EVENT_PATTERN + ")[\\s\\S]*=[\\s\\S]*\\b(?:" + IC_WINDOW_OPENER_PATTERN + ")\\b"
      + "|\\b(?:" + IC_WINDOW_OPENER_PATTERN + ")\\b[\\s\\S]+\\b(?:" + IC_EVENT_PATTERN + ")[\\s\\S]*=";

function PostChecker(url, uploadStream, skip) {
  this.url = url;
  this.uploadStream = uploadStream;
  this.skip = skip || false;
}

PostChecker.prototype = {
  boundary: null,
  isFile: false,
  postData: '',
  check: function(callback) {
    var m, chunks, data, size, available, ret;
    const BUF_SIZE = 3 * 1024 * 1024; // 3MB
    const MAX_FIELD_SIZE = BUF_SIZE;
    try {
      var us = this.uploadStream;
      us.seek(0, 0);
      const sis = Cc['@mozilla.org/binaryinputstream;1'].createInstance(Ci.nsIBinaryInputStream);
      sis.setInputStream(us);

      // reset status
      delete this.boundary;
      delete this.isFile;
      delete this.postData;

      if ((available = sis.available())) do {
        size = this.postData.length;
        if (size >= MAX_FIELD_SIZE) return size + " bytes or more in one non-file field, assuming memory DOS attempt!";

        data = sis.readBytes(Math.min(available, BUF_SIZE));

        if (size !== 0) {
          this.postData += data;
        } else {
           if (data.length === 0) return false;
           this.postData = data;
        }
        available = sis.available();
        chunks = this.parse(!available);

        for (var j = 0, len = chunks.length; j < len; j++) {
          ret = callback(chunks[j]);
          if (ret) return ret;
        }
      } while(available)
    } catch(ex) {
      dump(ex + "\n" + ex.stack + "\n");
      return ex;
    } finally {
        try {
          us.seek(0, 0); // rewind
        } catch(e) {}
    }
    return false;
  },

  parse: function(eof) {
    var postData = this.postData;
    var m;

    if (typeof(this.boundary) != "string") {
      m = postData.match(/^Content-type: multipart\/form-data;\s*boundary=(\S*)/i);
      this.boundary = m && m[1] || '';
      if (this.boundary) this.boundary = "--" + this.boundary;
      postData = postData.substring(postData.indexOf("\r\n\r\n") + 2);
    }

    this.postData = '';

    var boundary = this.boundary;

    var chunks = [];
    var j, len, name;

    var skip = this.skip;

    if (boundary) { // multipart/form-data, see http://www.faqs.org/ftp/rfc/rfc2388.txt
      if(postData.indexOf(boundary) < 0) {
        // skip big file chunks
        return chunks;
      }
      var parts = postData.split(boundary);

      var part, last;
      for(j = 0, len = parts.length; j < len;) {
        part = parts[j];
        last = ++j == len;
        if (j == 1 && part.length && this.isFile) {
          // skip file internal terminal chunk
          this.isFile = false;
          continue;
        }
        m = part.match(/^\s*Content-Disposition: form-data; name="(.*?)"(?:;\s*filename="(.*)"|[^;])\r?\n(Content-Type: \w)?.*\r?\n/i);

        if (m) {
          // name and filename are backslash-quoted according to RFC822
          name = m[1];
          if (name) {
            chunks.push(name.replace(/\\\\/g, "\\")); // name and file name
          }
          if (m[2]) {
            chunks.push(m[2].replace(/\\\\/g, "\\")); // filename
            if (m[3]) {
              // Content-type: skip, it's a file
              this.isFile = true;

              if (last && !eof)
                this.postData = part.substring(part.length - boundary.length);

              continue;
            }
          }
          if (eof || !last) {
            if (!(skip && skip.indexOf(name) !== -1))
              chunks.push(part.substring(m[0].length)); // parameter body
          } else {
            this.postData = part;
          }
          this.isFile = false;
        } else {
          // malformed part, check it all or push it back
          if (eof || !last) {
            chunks.push(part)
          } else {
            this.postData = this.isFile ? part.substring(part.length - boundary.length) : part;
          }
        }
      }
    } else {
      this.isFile = false;

      parts = postData.replace(/^\s+/, '').split("&");
      if (!eof) this.postData = parts.pop();

      for (j = 0, len = parts.length; j < len; j++) {
        m = parts[j].split("=");
        name = m[0];
        if (skip && skip.indexOf(name) > -1) continue;
        chunks.push(name, m[1] || '');
      }
    }
    return chunks;
  }
}

// we need this because of https://bugzilla.mozilla.org/show_bug.cgi?id=439276

const Base64 = {

  purify: function(input) {
    return input.replace(/[^A-Za-z0-9\+\/=]+/g, '');
  },

  alt: function(s) {
    // URL base64 variant, see http://en.wikipedia.org/wiki/Base64#URL_applications
    return s.replace(/-/g, '+').replace(/_/g, '/')
  },

  decode: function (input, strict) {
    var output = '';
    var chr1, chr2, chr3;
    var enc1, enc2, enc3, enc4;
    var i = 0;

    // if (/[^A-Za-z0-9\+\/\=]/.test(input)) return ""; // we don't need this, caller checks for us

    const k = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    while (i < input.length) {

        enc1 = k.indexOf(input.charAt(i++));
        enc2 = k.indexOf(input.charAt(i++));
        enc3 = k.indexOf(input.charAt(i++));
        enc4 = k.indexOf(input.charAt(i++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        output += String.fromCharCode(chr1);

        if (enc3 != 64) {
          output += String.fromCharCode(chr2);
        }
        if (enc4 != 64) {
          output += String.fromCharCode(chr3);
        }

    }
    return output;

  }
};


function RequestInfo(channel, url, origin, window) {
  this.channel = channel;
  if (!url) url = channel.URI;
  this.sanitizedURI = url;
  this.window = window || IOUtil.findWindow(channel);
  if (!origin) {
    let originURI = ABERequest.getOrigin(channel);
    origin = originURI && originURI.spec || "???";
  }
  this.unsafeRequest = {
    URI: url.clone(),
    postData: null,
    referrer: channel.referrer && channel.referrer.clone(),
    origin: origin,
    loadFlags: channel.loadFlags,
    issued: false,
    window: null
  }
}


function DOSChecker(request, canSpin) {
  this.request = request;
  this.canSpin = canSpin;
  Thread.asap(this.check, this);
}

DOSChecker.abort = function(req, info) {
  if (req) IOUtil.abort(("channel" in req) ? req.channel : req, true);
  ns.log("[NoScript DOS] Aborted potential DOS attempt: " +
         ( ("name" in req) ? req.name : req ) +
         "\n" + (info || new Error().stack));
};

DOSChecker.prototype = {
  done: false,
  lastClosure: null,
  run: function(closure, self) {
    this.done = false;
    this.lastClosure = closure;
    try {
      return  self ? closure.apply(self) : closure();
    } finally {
      this.done = true;
    }
  },
  check: function() {
    MaxRunTime.restore();

    if (!(this.done || this.canSpin && Thread.activeLoops))
      DOSChecker.abort(this.request, (this.lastClosure && this.lastClosure.toSource()));
  }
}

var MaxRunTime = {
  branch: Cc["@mozilla.org/preferences-service;1"]
        .getService(Ci.nsIPrefService).getBranch("dom."),
  prefs: ["max_script_run_time", "max_chrome_script_run_time"],
  stored: [],
  increase: function(v) {
    let prefs = this.prefs, stored = this.stored;
    for (let j = prefs.length; j-- > 0;) {
      let cur, pref = prefs[j];
      try {
        cur = this.branch.getIntPref(pref);
      } catch(e) {
        cur = -1;
      }
      if (cur <= 0 || cur >= v) return;
      if (typeof stored[j] === "undefined") try {
        stored[j] = cur;
      } catch(e) {}
      this.branch.setIntPref(pref, v);
    }
  },
  restore: function() {
    let prefs = this.prefs, stored = this.stored;
    for (let j = stored.length; j-- > 0;) {
      this.branch.setIntPref(prefs[j], stored[j]);
    }
    stored.length = 0;
  }
};


var ASPIdiocy = {
  _replaceRx: /%u([0-9a-fA-F]{4})/g,
  _affectsRx: /%u[0-9a-fA-F]{4}/,
  _badPercentRx: /%(?!u[0-9a-fA-F]{4}|[0-9a-fA-F]{2})|%(?:00|u0000)[^&=]*/g,

  hasBadPercents: function(s) this._badPercentRx.test(s),
  removeBadPercents: function(s) s.replace(this._badPercentRx, ''),
  affects: function(s) this._affectsRx.test(s),
  process: function(s) {
    s = this.filter(s);
    return /[\uff5f-\uffff]/.test(s) ? s + '&' + s.replace(/[\uff5f-\uffff]/g, '?') : s;
  },
  filter: function(s) this.removeBadPercents(s).replace(this._replaceRx, this._replace),

  coalesceQuery: function(s) { // HPP protection, see https://www.owasp.org/images/b/ba/AppsecEU09_CarettoniDiPaola_v0.8.pdf
    let qm = s.indexOf("?");
    if (qm < 0) return s;
    let p = s.substring(0, qm);
    let q = s.substring(qm + 1);
    if (!q) return s;

    let unchanged = true;
    let emptyParams = false;

    let pairs = (function rearrange(joinNames) {
      let pairs = q.split("&");
      let accumulator = { __proto__: null };
      for (let j = 0, len = pairs.length; j < len; j++) {
        let nv = pairs[j];
        let eq = nv.indexOf("=");
        if (eq === -1) {
          emptyParams = true;
          if (joinNames && j < len - 1) {
            pairs[j + 1] = nv + "&" + pairs[j + 1];
            delete pairs[j];
          }
          continue;
        }
        let key = "#" + unescape(nv.substring(0, eq)).toLowerCase();
        if (key in accumulator) {
          delete pairs[j];
          pairs[accumulator[key]] += ", " + nv.substring(eq + 1);
          unchanged = false;
        } else {
          accumulator[key] = j;
        }
      }
      return (emptyParams && !(unchanged || joinNames))
        ? pairs.concat(rearrange(true).filter(function(p) pairs.indexOf(p) === -1))
        : pairs;
    })();

    if (unchanged) return s;
    for (let j = pairs.length; j-- > 0;) if (!pairs[j]) pairs.splice(j, 1);
    return p + pairs.join("&");
  },

  _replace: function(match, hex) {
     // lazy init
     INCLUDE("ASPIdiocy");
     return ASPIdiocy._replace(match, hex);
  }
}

var FlashIdiocy = {
  _affectsRx: /%(?:[8-9a-f]|[0-7]?[^0-9a-f])/i, // high (non-ASCII) percent encoding or invalid second digit
  affects: function(s) this._affectsRx.test(s),

  purgeBadEncodings: function(s) {
    INCLUDE("FlashIdiocy");
    return this.purgeBadEncodings(s);
  }
}
