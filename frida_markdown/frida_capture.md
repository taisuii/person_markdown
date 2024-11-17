frida处理抓包问题

> **justtrustme.js**

```js
var ByPassTracerPid = function () {
    var fgetsPtr = Module.findExportByName("libc.so", "fgets");
    var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        var retval = fgets(buffer, size, fp);
        var bufstr = Memory.readUtf8String(buffer);
        if (bufstr.indexOf("TracerPid:") > -1) {
            Memory.writeUtf8String(buffer, "TracerPid:\t0");
            console.log("tracerpid replaced: " + Memory.readUtf8String(buffer));
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']));
};

setImmediate(ByPassTracerPid);

function antiAntiFrida() {
    var strstr = Module.findExportByName(null, "strstr");
    if (null !== strstr) {
        Interceptor.attach(strstr, {
            onEnter: function (args) {
                this.frida = Boolean(0);

                this.haystack = args[0];
                this.needle = args[1];

                if (this.haystack.readCString() !== null && this.needle.readCString() !== null) {
                    if (this.haystack.readCString().indexOf("frida") !== -1 ||
                        this.needle.readCString().indexOf("frida") !== -1 ||
                        this.haystack.readCString().indexOf("gum-js-loop") !== -1 ||
                        this.needle.readCString().indexOf("gum-js-loop") !== -1 ||
                        this.haystack.readCString().indexOf("gmain") !== -1 ||
                        this.needle.readCString().indexOf("gmain") !== -1 ||
                        this.haystack.readCString().indexOf("linjector") !== -1 ||
                        this.needle.readCString().indexOf("linjector") !== -1) {
                        this.frida = Boolean(1);
                    }
                }
            },
            onLeave: function (retval) {
                if (this.frida) {
                    retval.replace(ptr("0x0"));
                }

            }
        })
        // console.log("anti anti-frida");
    }
}

function main() {
    Java.perform(function () {

        /*
        hook list:
        1.SSLcontext
        2.okhttp
        3.webview
        4.XUtils
        5.httpclientandroidlib
        6.JSSE
        7.network\_security\_config (android 7.0+)
        8.Apache Http client (support partly)
        9.OpenSSLSocketImpl
        10.TrustKit
        11.Cronet
        */

        // Attempts to bypass SSL pinning implementations in a number of
        // ways. These include implementing a new TrustManager that will
        // accept any SSL certificate, overriding OkHTTP v3 check()
        // method etc.
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var quiet_output = false;

        // Helper method to honor the quiet flag.

        function quiet_send(data) {

            if (quiet_output) {

                return;
            }

            send(data)
        }


        // Implement a new TrustManager
        // ref: https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8
        // Java.registerClass() is only supported on ART for now(201803). 所以android 4.4以下不兼容,4.4要切换成ART使用.
        /*
    06-07 16:15:38.541 27021-27073/mi.sslpinningdemo W/System.err: java.lang.IllegalArgumentException: Required method checkServerTrusted(X509Certificate[], String, String, String) missing
    06-07 16:15:38.542 27021-27073/mi.sslpinningdemo W/System.err:     at android.net.http.X509TrustManagerExtensions.<init>(X509TrustManagerExtensions.java:73)
            at mi.ssl.MiPinningTrustManger.<init>(MiPinningTrustManger.java:61)
    06-07 16:15:38.543 27021-27073/mi.sslpinningdemo W/System.err:     at mi.sslpinningdemo.OkHttpUtil.getSecPinningClient(OkHttpUtil.java:112)
            at mi.sslpinningdemo.OkHttpUtil.get(OkHttpUtil.java:62)
            at mi.sslpinningdemo.MainActivity$1$1.run(MainActivity.java:36)
    */
        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        var TrustManager;
        try {
            TrustManager = Java.registerClass({
                name: 'org.wooyun.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {
                    },
                    checkServerTrusted: function (chain, authType) {
                    },
                    getAcceptedIssuers: function () {
                        // var certs = [X509Certificate.$new()];
                        // return certs;
                        return [];
                    }
                }
            });
        } catch (e) {
            quiet_send("registerClass from X509TrustManager >>>>>>>> " + e.message);
        }


        // Prepare the TrustManagers array to pass to SSLContext.init()
        var TrustManagers = [TrustManager.$new()];

        try {
            // Prepare a Empty SSLFactory
            var TLS_SSLContext = SSLContext.getInstance("TLS");
            TLS_SSLContext.init(null, TrustManagers, null);
            var EmptySSLFactory = TLS_SSLContext.getSocketFactory();
        } catch (e) {
            quiet_send(e.message);
        }

        send('Custom, Empty TrustManager ready');

        // Get a handle on the init() on the SSLContext class
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

        // Override the init method, specifying our new TrustManager
        SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {

            quiet_send('Overriding SSLContext.init() with the custom TrustManager');

            SSLContext_init.call(this, null, TrustManagers, null);
        };

        /*** okhttp3.x unpinning ***/


        // Wrap the logic in a try/catch as not all applications will have
        // okhttp as part of the app.
        try {

            var CertificatePinner = Java.use('okhttp3.CertificatePinner');

            quiet_send('OkHTTP 3.x Found');

            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {

                quiet_send('OkHTTP 3.x check() called. Not throwing an exception.');
            }

        } catch (err) {

            // If we dont have a ClassNotFoundException exception, raise the
            // problem encountered.
            if (err.message.indexOf('ClassNotFoundException') === 0) {

                throw new Error(err);
            }
        }

        // Appcelerator Titanium PinningTrustManager

        // Wrap the logic in a try/catch as not all applications will have
        // appcelerator as part of the app.
        try {

            var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');

            send('Appcelerator Titanium Found');

            PinningTrustManager.checkServerTrusted.implementation = function () {

                quiet_send('Appcelerator checkServerTrusted() called. Not throwing an exception.');
            }

        } catch (err) {

            // If we dont have a ClassNotFoundException exception, raise the
            // problem encountered.
            if (err.message.indexOf('ClassNotFoundException') === 0) {

                throw new Error(err);
            }
        }

        /*** okhttp unpinning ***/


        try {
            var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
            OkHttpClient.setCertificatePinner.implementation = function (certificatePinner) {
                // do nothing
                quiet_send("OkHttpClient.setCertificatePinner Called!");
                return this;
            };

            // Invalidate the certificate pinnet checks (if "setCertificatePinner" was called before the previous invalidation)
            var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (p0, p1) {
                // do nothing
                quiet_send("okhttp Called! [Certificate]");
                return;
            };
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (p0, p1) {
                // do nothing
                quiet_send("okhttp Called! [List]");
                return;
            };
        } catch (e) {
            quiet_send("com.squareup.okhttp not found");
        }

        /*** WebView Hooks ***/

        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
        var WebViewClient = Java.use("android.webkit.WebViewClient");

        WebViewClient.onReceivedSslError.implementation = function (webView, sslErrorHandler, sslError) {
            quiet_send("WebViewClient onReceivedSslError invoke");
            //执行proceed方法
            sslErrorHandler.proceed();
            return;
        };

        WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function (a, b, c, d) {
            quiet_send("WebViewClient onReceivedError invoked");
            return;
        };

        WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function () {
            quiet_send("WebViewClient onReceivedError invoked");
            return;
        };

        /*** JSSE Hooks ***/

        /* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
        /* public final TrustManager[] getTrustManager() */
        /* TrustManagerFactory.getTrustManagers maybe cause X509TrustManagerExtensions error  */
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        TrustManagerFactory.getTrustManagers.implementation = function () {
            quiet_send("TrustManagerFactory getTrustManagers invoked");
            return TrustManagers;
        }

        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setDefaultHostnameVerifier(HostnameVerifier) */
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
            quiet_send("HttpsURLConnection.setDefaultHostnameVerifier invoked");
            return null;
        };
        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setSSLSocketFactory(SSLSocketFactory) */
        HttpsURLConnection.setSSLSocketFactory.implementation = function (SSLSocketFactory) {
            quiet_send("HttpsURLConnection.setSSLSocketFactory invoked");
            return null;
        };
        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setHostnameVerifier(HostnameVerifier) */
        HttpsURLConnection.setHostnameVerifier.implementation = function (hostnameVerifier) {
            quiet_send("HttpsURLConnection.setHostnameVerifier invoked");
            return null;
        };

        /*** Xutils3.x hooks ***/
            //Implement a new HostnameVerifier
        var TrustHostnameVerifier;
        try {
            TrustHostnameVerifier = Java.registerClass({
                name: 'org.wooyun.TrustHostnameVerifier',
                implements: [HostnameVerifier],
                method: {
                    verify: function (hostname, session) {
                        return true;
                    }
                }
            });

        } catch (e) {
            //java.lang.ClassNotFoundException: Didn't find class "org.wooyun.TrustHostnameVerifier"
            quiet_send("registerClass from hostnameVerifier >>>>>>>> " + e.message);
        }

        try {
            var RequestParams = Java.use('org.xutils.http.RequestParams');
            RequestParams.setSslSocketFactory.implementation = function (sslSocketFactory) {
                sslSocketFactory = EmptySSLFactory;
                return null;
            }

            RequestParams.setHostnameVerifier.implementation = function (hostnameVerifier) {
                hostnameVerifier = TrustHostnameVerifier.$new();
                return null;
            }

        } catch (e) {
            quiet_send("Xutils hooks not Found");
        }

        /*** httpclientandroidlib Hooks ***/
        try {
            var AbstractVerifier = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
            AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String', '[Ljava.lang.String', 'boolean').implementation = function () {
                quiet_send("httpclientandroidlib Hooks");
                return null;
            }
        } catch (e) {
            quiet_send("httpclientandroidlib Hooks not found");
        }

        /***
         android 7.0+ network_security_config TrustManagerImpl hook
         apache httpclient partly
         ***/
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        // try {
        //     var Arrays = Java.use("java.util.Arrays");
        //     //apache http client pinning maybe baypass
        //     //https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#471
        //     TrustManagerImpl.checkTrusted.implementation = function (chain, authType, session, parameters, authType) {
        //         quiet_send("TrustManagerImpl checkTrusted called");
        //         //Generics currently result in java.lang.Object
        //         return Arrays.asList(chain);
        //     }

        // } catch (e) {
        //     quiet_send("TrustManagerImpl checkTrusted nout found");
        // }

        try {
            // Android 7+ TrustManagerImpl
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                quiet_send("TrustManagerImpl verifyChain called");
                // Skip all the logic and just return the chain again :P
                //https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/november/bypassing-androids-network-security-configuration/
                // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
                return untrustedChain;
            }
        } catch (e) {
            quiet_send("TrustManagerImpl verifyChain nout found below 7.0");
        }
        // OpenSSLSocketImpl
        try {
            var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, authMethod) {
                quiet_send('OpenSSLSocketImpl.verifyCertificateChain');
            }

            quiet_send('OpenSSLSocketImpl pinning')
        } catch (err) {
            quiet_send('OpenSSLSocketImpl pinner not found');
        }
        // Trustkit
        try {
            var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
            Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
                quiet_send('Trustkit.verify1: ' + str);
                return true;
            };
            Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
                quiet_send('Trustkit.verify2: ' + str);
                return true;
            };

            quiet_send('Trustkit pinning')
        } catch (err) {
            quiet_send('Trustkit pinner not found')
        }

        try {
            //cronet pinner hook
            //weibo don't invoke

            var netBuilder = Java.use("org.chromium.net.CronetEngine$Builder");

            //https://developer.android.com/guide/topics/connectivity/cronet/reference/org/chromium/net/CronetEngine.Builder.html#enablePublicKeyPinningBypassForLocalTrustAnchors(boolean)
            netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function (arg) {

                //weibo not invoke
                console.log("Enables or disables public key pinning bypass for local trust anchors = " + arg);

                //true to enable the bypass, false to disable.
                var ret = netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                return ret;
            };

            netBuilder.addPublicKeyPins.implementation = function (hostName, pinsSha256, includeSubdomains, expirationDate) {
                console.log("cronet addPublicKeyPins hostName = " + hostName);

                //var ret = netBuilder.addPublicKeyPins.call(this,hostName, pinsSha256,includeSubdomains, expirationDate);
                //this 是调用 addPublicKeyPins 前的对象吗? Yes,CronetEngine.Builder
                return this;
            };

        } catch (err) {
            console.log('[-] Cronet pinner not found')
        }
    });
}


setImmediate(antiAntiFrida)
setImmediate(main);


var N_ENCRYPT_MODE = 1
var N_DECRYPT_MODE = 2
console.log(" jsHOOK脚本加载成功2");

function showStacks() {
    var Exception = Java.use("java.lang.Exception");
    var ins = Exception.$new("Exception");
    var straces = ins.getStackTrace();

    if (undefined == straces || null == straces) {
        return;
    }

    console.log("============================= Stack strat=======================");
    console.log("");

    for (var i = 0; i < straces.length; i++) {
        var str = "   " + straces[i].toString();
        console.log(str);
    }

    console.log("");
    console.log("============================= Stack end=======================\r\n");
    Exception.$dispose();
}

//工具相关函数
var base64EncodeChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    base64DecodeChars = new Array((-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), 62, (-1), (-1), (-1), 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, (-1), (-1), (-1), (-1), (-1), (-1), (-1), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, (-1), (-1), (-1), (-1), (-1), (-1), 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, (-1), (-1), (-1), (-1), (-1));

function stringToBase64(e) {
    var r, a, c, h, o, t;
    for (c = e.length, a = 0, r = ''; a < c;) {
        if (h = 255 & e.charCodeAt(a++), a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4),
                r += '==';
            break
        }
        if (o = e.charCodeAt(a++), a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
                r += base64EncodeChars.charAt((15 & o) << 2),
                r += '=';
            break
        }
        t = e.charCodeAt(a++),
            r += base64EncodeChars.charAt(h >> 2),
            r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
            r += base64EncodeChars.charAt((15 & o) << 2 | (192 & t) >> 6),
            r += base64EncodeChars.charAt(63 & t)
    }
    return r
}

function base64ToString(e) {
    var r, a, c, h, o, t, d;
    for (t = e.length, o = 0, d = ''; o < t;) {
        do
            r = base64DecodeChars[255 & e.charCodeAt(o++)];
        while (o < t && r == -1);
        if (r == -1)
            break;
        do
            a = base64DecodeChars[255 & e.charCodeAt(o++)];
        while (o < t && a == -1);
        if (a == -1)
            break;
        d += String.fromCharCode(r << 2 | (48 & a) >> 4);
        do {
            if (c = 255 & e.charCodeAt(o++), 61 == c)
                return d;
            c = base64DecodeChars[c]
        } while (o < t && c == -1);
        if (c == -1)
            break;
        d += String.fromCharCode((15 & a) << 4 | (60 & c) >> 2);
        do {
            if (h = 255 & e.charCodeAt(o++), 61 == h)
                return d;
            h = base64DecodeChars[h]
        } while (o < t && h == -1);
        if (h == -1)
            break;
        d += String.fromCharCode((3 & c) << 6 | h)
    }
    return d
}

function hexToBase64(str) {
    return base64Encode(String.fromCharCode.apply(null, str.replace(/\r|\n/g, "").replace(/([\da-fA-F]{2}) ?/g, "0x$1 ").replace(/ +$/, "").split(" ")));
}

function base64ToHex(str) {
    for (var i = 0, bin = base64Decode(str.replace(/[ \r\n]+$/, "")), hex = []; i < bin.length; ++i) {
        var tmp = bin.charCodeAt(i).toString(16);
        if (tmp.length === 1)
            tmp = "0" + tmp;
        hex[hex.length] = tmp;
    }
    return hex.join("");
}

function hexToBytes(str) {
    var pos = 0;
    var len = str.length;
    if (len % 2 != 0) {
        return null;
    }
    len /= 2;
    var hexA = new Array();
    for (var i = 0; i < len; i++) {
        var s = str.substr(pos, 2);
        var v = parseInt(s, 16);
        hexA.push(v);
        pos += 2;
    }
    return hexA;
}

function bytesToHex(arr) {
    var str = '';
    var k, j;
    for (var i = 0; i < arr.length; i++) {
        k = arr[i];
        j = k;
        if (k < 0) {
            j = k + 256;
        }
        if (j < 16) {
            str += "0";
        }
        str += j.toString(16);
    }
    return str;
}

function stringToHex(str) {
    var val = "";
    for (var i = 0; i < str.length; i++) {
        if (val == "")
            val = str.charCodeAt(i).toString(16);
        else
            val += str.charCodeAt(i).toString(16);
    }
    return val
}

function stringToBytes(str) {
    var ch, st, re = [];
    for (var i = 0; i < str.length; i++) {
        ch = str.charCodeAt(i);
        st = [];
        do {
            st.push(ch & 0xFF);
            ch = ch >> 8;
        }
        while (ch);
        re = re.concat(st.reverse());
    }
    return re;
}

//将byte[]转成String的方法
function bytesToString(arr) {
    var str = '';
    arr = new Uint8Array(arr);
    for (var i in arr) {
        str += String.fromCharCode(arr[i]);
    }
    return str;
}

function bytesToBase64(e) {
    var r, a, c, h, o, t;
    for (c = e.length, a = 0, r = ''; a < c;) {
        if (h = 255 & e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4),
                r += '==';
            break
        }
        if (o = e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
                r += base64EncodeChars.charAt((15 & o) << 2),
                r += '=';
            break
        }
        t = e[a++],
            r += base64EncodeChars.charAt(h >> 2),
            r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
            r += base64EncodeChars.charAt((15 & o) << 2 | (192 & t) >> 6),
            r += base64EncodeChars.charAt(63 & t)
    }
    return r
}

function base64ToBytes(e) {
    var r, a, c, h, o, t, d;
    for (t = e.length, o = 0, d = []; o < t;) {
        do
            r = base64DecodeChars[255 & e.charCodeAt(o++)];
        while (o < t && r == -1);
        if (r == -1)
            break;
        do
            a = base64DecodeChars[255 & e.charCodeAt(o++)];
        while (o < t && a == -1);
        if (a == -1)
            break;
        d.push(r << 2 | (48 & a) >> 4);
        do {
            if (c = 255 & e.charCodeAt(o++), 61 == c)
                return d;
            c = base64DecodeChars[c]
        } while (o < t && c == -1);
        if (c == -1)
            break;
        d.push((15 & a) << 4 | (60 & c) >> 2);
        do {
            if (h = 255 & e.charCodeAt(o++), 61 == h)
                return d;
            h = base64DecodeChars[h]
        } while (o < t && h == -1);
        if (h == -1)
            break;
        d.push((3 & c) << 6 | h)
    }
    return d
}

//stringToBase64 stringToHex stringToBytes
//base64ToString base64ToHex base64ToBytes
//               hexToBase64  hexToBytes
// bytesToBase64 bytesToHex bytesToString
//
//
// Java.perform(function () {
//
//     var secretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
//     secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (a, b) {
//         showStacks();
//         var result = this.$init(a, b);
//         console.log("======================================");
//         console.log("算法名：" + b + "|str密钥:" + bytesToString(a));
//         console.log("算法名：" + b + "|Hex密钥:" + bytesToHex(a));
//         return result;
//     }
//
//     var DESKeySpec = Java.use('javax.crypto.spec.DESKeySpec');
//     DESKeySpec.$init.overload('[B').implementation = function (a) {
//         showStacks();
//         var result = this.$init(a);
//         console.log("======================================");
//         var bytes_key_des = this.getKey();
//         console.log("des密钥  |str " + bytesToString(bytes_key_des));
//         console.log("des密钥  |hex " + bytesToHex(bytes_key_des));
//         return result;
//     }
//
//     DESKeySpec.$init.overload('[B', 'int').implementation = function (a, b) {
//         showStacks();
//         var result = this.$init(a, b);
//         console.log("======================================");
//         var bytes_key_des = this.getKey();
//         console.log("des密钥  |str " + bytesToString(bytes_key_des));
//         console.log("des密钥  |hex " + bytesToHex(bytes_key_des));
//         return result;
//     }
//
//     var mac = Java.use('javax.crypto.Mac');
//     mac.getInstance.overload('java.lang.String').implementation = function (a) {
//         showStacks();
//         var result = this.getInstance(a);
//         console.log("======================================");
//         console.log("算法名：" + a);
//
//         return result;
//     }
//     mac.update.overload('[B').implementation = function (a) {
//         //showStacks();
//         this.update(a);
//         console.log("======================================");
//         console.log("参数:" + bytesToString(a))
//     }
//     mac.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {
//         //showStacks();
//         this.update(a, b, c)
//         console.log("======================================");
//         console.log("参数:" + bytesToString(a) + "|" + b + "|" + c);
//     }
//     mac.doFinal.overload().implementation = function () {
//         //showStacks();
//         var result = this.doFinal();
//         console.log("======================================");
//         console.log("加密结果: |str  :" + bytesToString(result));
//         console.log("加密结果: |hex  :" + bytesToHex(result));
//         console.log("加密结果: |base64  :" + bytesToBase64(result));
//         return result;
//     }
//     mac.doFinal.overload('[B').implementation = function (a) {
//         //showStacks();
//         var result = this.doFinal(a);
//         console.log("======================================");
//         console.log("加密结果参数: |str  :" + bytesToString(a));
//         console.log("加密结果: |str  :" + bytesToString(result));
//         console.log("加密结果: |hex  :" + bytesToHex(result));
//         console.log("加密结果: |base64  :" + bytesToBase64(result));
//         return result;
//     }
//
//     var md = Java.use('java.security.MessageDigest');
//     md.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
//         //showStacks();
//         console.log("======================================");
//         console.log("算法名：" + a);
//         return this.getInstance(a, b);
//     }
//     md.getInstance.overload('java.lang.String').implementation = function (a) {
//         //showStacks();
//         console.log("======================================");
//         console.log("算法名：" + a);
//         return this.getInstance(a);
//     }
//     md.update.overload('[B').implementation = function (a) {
//         //showStacks();
//         console.log("======================================");
//         console.log("update:" + bytesToString(a))
//         return this.update(a);
//     }
//     md.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {
//         //showStacks();
//         console.log("======================================");
//         console.log("update:" + bytesToString(a) + "|" + b + "|" + c);
//         return this.update(a, b, c);
//     }
//     md.digest.overload().implementation = function () {
//         //showStacks();
//         console.log("======================================");
//         var result = this.digest();
//         console.log("返回值:" + bytesToHex(result));
//         console.log("返回值:" + bytesToBase64(result));
//         return result;
//     }
//     md.digest.overload('[B').implementation = function (a) {
//         //showStacks();
//         console.log("======================================");
//         console.log("digest参数:" + bytesToString(a));
//         var result = this.digest(a);
//         console.log("digest结果:" + bytesToHex(result));
//         console.log("digest结果:" + bytesToBase64(result));
//         return result;
//     }
//
//     var ivParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
//     ivParameterSpec.$init.overload('[B').implementation = function (a) {
//         //showStacks();
//         var result = this.$init(a);
//         console.log("======================================");
//         console.log("iv向量: |str:" + bytesToString(a));
//         console.log("iv向量: |hex:" + bytesToHex(a));
//         return result;
//     }
//
//     var cipher = Java.use('javax.crypto.Cipher');
//     cipher.getInstance.overload('java.lang.String').implementation = function (a) {
//         //showStacks();
//         var result = this.getInstance(a);
//         console.log("======================================");
//         console.log("模式填充:" + a);
//         return result;
//     }
//     cipher.init.overload('int', 'java.security.Key').implementation = function (a, b) {
//         //showStacks();
//         var result = this.init(a, b);
//         console.log("======================================");
//         if (N_ENCRYPT_MODE == a) {
//             console.log("init  | 加密模式");
//         } else if (N_DECRYPT_MODE == a) {
//             console.log("init  | 解密模式");
//         }
//
//         var bytes_key = b.getEncoded();
//         console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
//         console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
//         return result;
//     }
//     cipher.init.overload('int', 'java.security.cert.Certificate').implementation = function (a, b) {
//         //showStacks();
//         var result = this.init(a, b);
//         console.log("======================================");
//
//         if (N_ENCRYPT_MODE == a) {
//             console.log("init  | 加密模式");
//         } else if (N_DECRYPT_MODE == a) {
//             console.log("init  | 解密模式");
//         }
//
//         return result;
//     }
//     cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (a, b, c) {
//         //showStacks();
//         var result = this.init(a, b, c);
//         console.log("======================================");
//
//         if (N_ENCRYPT_MODE == a) {
//             console.log("init  | 加密模式");
//         } else if (N_DECRYPT_MODE == a) {
//             console.log("init  | 解密模式");
//         }
//
//         var bytes_key = b.getEncoded();
//         console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
//         console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
//
//         return result;
//     }
//     cipher.init.overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom').implementation = function (a, b, c) {
//         //showStacks();
//         var result = this.init(a, b, c);
//         if (N_ENCRYPT_MODE == a) {
//             console.log("init  | 加密模式");
//         } else if (N_DECRYPT_MODE == a) {
//             console.log("init  | 解密模式");
//         }
//         return result;
//     }
//     cipher.init.overload('int', 'java.security.Key', 'java.security.SecureRandom').implementation = function (a, b, c) {
//         //showStacks();
//         var result = this.init(a, b, c);
//         if (N_ENCRYPT_MODE == a) {
//             console.log("init  | 加密模式");
//         } else if (N_DECRYPT_MODE == a) {
//             console.log("init  | 解密模式");
//         }
//
//         var bytes_key = b.getEncoded();
//         console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
//         console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
//         return result;
//     }
//     cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters').implementation = function (a, b, c) {
//         //showStacks();
//         var result = this.init(a, b, c);
//         if (N_ENCRYPT_MODE == a) {
//             console.log("init  | 加密模式");
//         } else if (N_DECRYPT_MODE == a) {
//             console.log("init  | 解密模式");
//         }
//
//         var bytes_key = b.getEncoded();
//         console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
//         console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
//         return result;
//     }
//     cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom').implementation = function (a, b, c, d) {
//         //showStacks();
//         var result = this.init(a, b, c, d);
//         if (N_ENCRYPT_MODE == a) {
//             console.log("init  | 加密模式");
//         } else if (N_DECRYPT_MODE == a) {
//             console.log("init  | 解密模式");
//         }
//
//         var bytes_key = b.getEncoded();
//         console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
//         console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
//         return result;
//     }
//     cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom').implementation = function (a, b, c, d) {
//         //showStacks();
//         var result = this.update(a, b, c, d);
//         if (N_ENCRYPT_MODE == a) {
//             console.log("init  | 加密模式");
//         } else if (N_DECRYPT_MODE == a) {
//             console.log("init  | 解密模式");
//         }
//
//         var bytes_key = b.getEncoded();
//         console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
//         console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
//         return result;
//     }
//
//     cipher.update.overload('[B').implementation = function (a) {
//         //showStacks();
//         var result = this.update(a);
//         console.log("======================================");
//         console.log("update:" + bytesToString(a));
//         return result;
//     }
//     cipher.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {
//         //showStacks();
//         var result = this.update(a, b, c);
//         console.log("======================================");
//         console.log("update:" + bytesToString(a) + "|" + b + "|" + c);
//         return result;
//     }
//     cipher.doFinal.overload().implementation = function () {
//         //showStacks();
//         var result = this.doFinal();
//         console.log("======================================");
//         console.log("doFinal结果: |str  :" + bytesToString(result));
//         console.log("doFinal结果: |hex  :" + bytesToHex(result));
//         console.log("doFinal结果: |base64  :" + bytesToBase64(result));
//         return result;
//     }
//     cipher.doFinal.overload('[B').implementation = function (a) {
//         //showStacks();
//         var result = this.doFinal(a);
//         console.log("======================================");
//         console.log("加密结果参数: |str  :" + bytesToString(a));
//         console.log("加密结果结果: |str  :" + bytesToString(result));
//         console.log("加密结果结果: |hex  :" + bytesToHex(result));
//         console.log("加密结果结果: |base64  :" + bytesToBase64(result));
//         return result;
//     }
//
//     var x509EncodedKeySpec = Java.use('java.security.spec.X509EncodedKeySpec');
//     x509EncodedKeySpec.$init.overload('[B').implementation = function (a) {
//         //showStacks();
//         var result = this.$init(a);
//         console.log("======================================");
//         console.log("RSA密钥:" + bytesToBase64(a));
//         return result;
//     }
//
//     var rSAPublicKeySpec = Java.use('java.security.spec.RSAPublicKeySpec');
//     rSAPublicKeySpec.$init.overload('java.math.BigInteger', 'java.math.BigInteger').implementation = function (a, b) {
//         //showStacks();
//         var result = this.$init(a, b);
//         console.log("======================================");
//         //console.log("RSA密钥:" + bytesToBase64(a));
//         console.log("RSA密钥N:" + a.toString(16));
//         console.log("RSA密钥E:" + b.toString(16));
//         return result;
//     }
//
//     var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');
//     KeyPairGenerator.generateKeyPair.implementation = function () {
//         //showStacks();
//         var result = this.generateKeyPair();
//         console.log("======================================");
//
//         var str_private = result.getPrivate().getEncoded();
//         var str_public = result.getPublic().getEncoded();
//         console.log("公钥  |hex" + bytesToHex(str_public));
//         console.log("私钥  |hex" + bytesToHex(str_private));
//
//         return result;
//     }
//
//     KeyPairGenerator.genKeyPair.implementation = function () {
//         //showStacks();
//         var result = this.genKeyPair();
//         console.log("======================================");
//
//         var str_private = result.getPrivate().getEncoded();
//         var str_public = result.getPublic().getEncoded();
//         console.log("公钥  |hex" + bytesToHex(str_public));
//         console.log("私钥  |hex" + bytesToHex(str_private));
//         return result;
//     }
//
// });
//
```
