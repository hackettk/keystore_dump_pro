//在https双向认证的情况下，dump客户端证书为p12. 证书密码: hooker
var password = "hooker";



function dateFormat(fmt, date) {
    let ret;
    const opt = {
        "Y+": date.getFullYear().toString(),
        // 年
        "m+": (date.getMonth() + 1).toString(),
        // 月
        "d+": date.getDate().toString(),
        // 日
        "H+": date.getHours().toString(),
        // 时
        "M+": date.getMinutes().toString(),
        // 分
        "S+": date.getSeconds().toString() // 秒
    };
    for (let k in opt) {
        ret = new RegExp("(" + k + ")").exec(fmt);
        if (ret) {
            fmt = fmt.replace(ret[1], (ret[1].length == 1) ? (opt[k]) : (opt[k].padStart(ret[1].length, "0")))
        };
    };
    return fmt;
}

function random(min, max) {
    return Math.floor(Math.random() * (max - min)) + min;
}

function getNowTime() {
    return dateFormat("YYYY_mm_dd_HH_MM_SS", new Date()) + "_" + random(1, 100);
}

function getPackageName() {
    var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
    var context = currentApplication.getApplicationContext();
    return context.getPackageName();
};

function newMethodBeat(text, executor) {
    var threadClz = Java.use("java.lang.Thread");
    var androidLogClz = Java.use("android.util.Log");
    var exceptionClz = Java.use("java.lang.Exception");
    var processClz = Java.use("android.os.Process");
    var currentThread = threadClz.currentThread();
    var beat = new Object();
    beat.invokeId = Math.random().toString(36).slice( - 8);
    beat.executor = executor;
    beat.myPid = processClz.myPid();
    beat.threadId = currentThread.getId();
    beat.threadName = currentThread.getName();
    beat.text = text;
    beat.startTime = new Date().getTime();
    beat.stackInfo = androidLogClz.getStackTraceString(exceptionClz.$new()).substring(20);
    return beat;
};

function printBeat(beat) {
    var str = ("------------pid:" + beat.myPid + ",startFlag:" + beat.invokeId + ",objectHash:"+beat.executor+",thread(id:" + beat.threadId +",name:" + beat.threadName + "),timestamp:" + beat.startTime+"---------------\n");
    str += beat.text + "\n";
    str += beat.stackInfo;
    str += ("------------endFlag:" + beat.invokeId + ",usedtime:" + (new Date().getTime() - beat.startTime) +"---------------\n");
	console.log(str);
};

function dump2sdcard(pri, p7, filePath) {
    console.log("dump:" + filePath);
    var X509CertificateClass = Java.use("java.security.cert.X509Certificate");
    var myX509 = Java.cast(p7, X509CertificateClass);
    var chain = Java.array("java.security.cert.X509Certificate", [myX509]);
    var ks = Java.use("java.security.KeyStore").getInstance("PKCS12", "BC");
    ks.load(null, null);
    ks.setKeyEntry("client", pri, Java.use('java.lang.String').$new(password).toCharArray(), chain);
    try {
        var out = Java.use("java.io.FileOutputStream").$new(filePath);
        ks.store(out, Java.use('java.lang.String').$new(password).toCharArray());
    } catch(error) {
        console.log(error);
    }
}

// 新增代码
function dumpKeyStoreEntry(entry) {
	// java.security.KeyStore$PrivateKeyEntry, java.security.KeyStore$SecretKeyEntry, java.security.KeyStore$TrustedCertificateEntry, android.security.WrappedKeyEntry
	if (entry != null) {
		var entryCls = entry.$className;
		var castedEntry = Java.cast(entry, Java.use(entryCls));
		if (entryCls.localeCompare("java.security.KeyStore$PrivateKeyEntry") == 0) {
            // 通过把entry类型转换后进行返回，实现keystore_dump
            console.log("" + entryCls + " [implement key dumping if needed] ");
			var getPrivateKeyEntryMethod = Java.use('java.security.KeyStore$PrivateKeyEntry')['getPrivateKey'];
			var key = getPrivateKeyEntryMethod.call(castedEntry);
			return "" + entryCls + " [implement key dumping if needed] " + key.$className;
		}
		else if (entryCls.localeCompare("java.security.KeyStore$SecretKeyEntry") == 0) {
			var getSecretKeyMethod = Java.use('java.security.KeyStore$SecretKeyEntry')['getSecretKey'];
			var key = getSecretKeyMethod.call(castedEntry);
			var keyGetFormatMethod = Java.use(key.$className)['getFormat'];
			var keyGetEncodedMethod = Java.use(key.$className)['getEncoded'];
			//console.log(""+key.$className);
			if (key.$className.localeCompare("android.security.keystore.AndroidKeyStoreSecretKey") == 0)
				return "keyClass: android.security.keystore.AndroidKeyStoreSecretKey can't dump";
			return "keyFormat: " + keyGetFormatMethod.call(key) + ", encodedKey: '" + keyGetEncodedMethod.call(key) + "', key: " + key;
		}
		else if (entryCls.localeCompare("java.security.KeyStore$TrustedCertificateEntry") == 0) {
			return "" + entryCls + " [implement key dumping if needed]";
		}
		else if (entryCls.localeCompare("android.security.WrappedKeyEntry") == 0) {
			return "" + entryCls + " [implement key dumping if needed]";
		}
		else
			return "Unknown key entry type: " + entryCls;
	}
	else
		return "null";
}

function dumpProtectionParameter(protection) {
	if (protection != null) {
		// android.security.keystore.KeyProtection, java.security.KeyStore.CallbackHandlerProtection, java.security.KeyStore.PasswordProtection, android.security.KeyStoreParameter
		var protectionCls = protection.$className;
		if (protectionCls.localeCompare("android.security.keystore.KeyProtection") == 0) {
			return "" + protectionCls + " [implement dumping if needed]";
		}
		else if (protectionCls.localeCompare("java.security.KeyStore.CallbackHandlerProtection") == 0) {
			return "" + protectionCls + " [implement dumping if needed]";
		}
		else if (protectionCls.localeCompare("java.security.KeyStore.PasswordProtection") == 0) {
			getPasswordMethod = Java.use('java.security.KeyStore.PasswordProtection')['getPassword'];
			password = getPasswordMethod.call(protection);
			return "password: " + charArrayToString(password);
		}
		else if (protectionCls.localeCompare("android.security.KeyStoreParameter") == 0) {
			isEncryptionRequiredMethod = Java.use('android.security.KeyStoreParameter')['isEncryptionRequired'];
			result = isEncryptionRequiredMethod.call(protection);
			return "isEncryptionRequired: " + result;
		}
		else
			return "Unknown protection parameter type: " + protectionCls;
	}
	else
		return "null";

}

function hookKeystoreGetEntry() {
	var keyStoreGetEntry = Java.use('java.security.KeyStore')['getEntry'].overload("java.lang.String", "java.security.KeyStore$ProtectionParameter");
	keyStoreGetEntry.implementation = function (alias, protection) {
		//console.log("[Call] Keystore.getEntry(java.lang.String, java.security.KeyStore$ProtectionParameter )")
		console.log("[Keystore.getEntry()]: alias: " + alias + ", protection: '" + dumpProtectionParameter(protection) + "'");
		var entry = this.getEntry(alias, protection);
		console.log("[getEntry()]: Entry: " + dumpKeyStoreEntry(entry));
		return entry;
	}
}


// 主程序
Java.perform(function() {
    var packageName = getPackageName();
    hookKeystoreGetEntry()
    console.log("在https双向认证的情况下，dump客户端证书为p12. 存储位置:/data/user/0/"+packageName+"/client_keystore_{nowtime}.p12 证书密码: hooker");
    Java.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function() {
        console.log("java.security.KeyStore$PrivateKeyEntr.getPrivateKey hooking");
    	 var executor = this.hashCode();
        var beatText = 'public java.security.cert.Certificate java.security.KeyStore$PrivateKeyEntry.getPrivateKey()';
        var beat = newMethodBeat(beatText, executor);
        var result = this.getPrivateKey();
        let filePath = '/data/user/0/' + packageName + "/client_keystore_" + "_" + getNowTime() + '.p12';
        dump2sdcard(this.getPrivateKey(), this.getCertificate(), filePath);
        printBeat(beat);
        return result;
    }
    Java.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function() {
        console.log("java.security.KeyStore$PrivateKeyEntr.getCertificateChain hooking");
        var executor = this.hashCode();
        var beatText = 'public java.security.cert.Certificate java.security.KeyStore$PrivateKeyEntry.getCertificate()';
        var beat = newMethodBeat(beatText, executor);
        var result = this.getCertificateChain();
        let filePath = '/data/user/0/' + packageName + "/client_keystore_" + getNowTime() + '.p12';
        dump2sdcard(this.getPrivateKey(), this.getCertificate(), filePath);
        return result;
    }
})
