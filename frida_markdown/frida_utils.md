frida的杂七杂八用法

hook dlopen

```js
function hookdlopen() {
    var dlopen = Module.findExportByName(null, "dlopen");
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            var path_ptr = args[0];
            var path = ptr(path_ptr).readCString();
            console.log("[dlopen:]", path);
        },
        onLeave: function (retval) {
        }
    });
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function (args) {
            var path_ptr = args[0];
            var path = ptr(path_ptr).readCString();
            console.log("[dlopen_ext:]", path);
        },
        onLeave: function (retval) {
        }
    });
}
```

dump so

```js
function dump_so(so_name) {
    Java.perform(function () {
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
        var dir = currentApplication.getApplicationContext().getFilesDir().getPath();
        var libso = Process.getModuleByName(so_name);
        console.log("[name]:", libso.name);
        console.log("[base]:", libso.base);
        console.log("[size]:", ptr(libso.size));
        console.log("[path]:", libso.path);
        var file_path = dir + "/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + ".so";
        var file_handle = new File(file_path, "wb");
        if (file_handle && file_handle != null) {
            Memory.protect(ptr(libso.base), libso.size, 'rwx');
            var libso_buffer = ptr(libso.base).readByteArray(libso.size);
            file_handle.write(libso_buffer);
            file_handle.flush();
            file_handle.close();
            console.log("[dump]:", file_path);

        }
    });
}
```

hook RegisterNatives

```js
function ILhook() {
    var addrRegisterNatives = null;

    var symbols = Module.enumerateSymbolsSync("libart.so");
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >= 0 &&
            symbol.name.indexOf("RegisterNatives") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0) {

            addrRegisterNatives = symbol.address;
            console.log("RegisterNatives is at ", symbol.address, symbol.name);
            break
        }
    }
    if (addrRegisterNatives) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function (args) {
                var env = args[0];        // jni对象
                var java_class = args[1]; // 类
                var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                var taget_class = "lte.NCall";   //111 某个类中动态注册的so
                if (class_name === taget_class) {
                    //只找我们自己想要类中的动态注册关系
                    console.log("\n[RegisterNatives] method_count:", args[3]);
                    var methods_ptr = ptr(args[2]);
                    var method_count = parseInt(args[3]);
                    for (var i = 0; i < method_count; i++) {
                        // Java中函数名字的
                        var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                        // 参数和返回值类型
                        var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
                        // C中的函数内存地址
                        var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));
                        var name = Memory.readCString(name_ptr);
                        var sig = Memory.readCString(sig_ptr);
                        var find_module = Process.findModuleByAddress(fnPtr_ptr);
                        // 地址、偏移量、基地址
                        var offset = ptr(fnPtr_ptr).sub(find_module.base);
                        console.log("name:", name, "sig:", sig, 'module_name:', find_module.name, "offset:", offset);

                    }
                }
            }
        });
    }
}
```

值得注意的是如果上面的方法找不到的话，就直接搜索导出函数表

```js
var modules = Process.enumerateModules();
modules.forEach(function (module) {
    var exports = Module.enumerateExports(module.name);
    exports.forEach(function (exp) {
        if (exp.name.indexOf("getHNASignature") >= 0) {
            console.log("Found in module: " + module.name);
            console.log("Address: " + exp.address);
        }
    });
});
```

打印调用栈，其实这个一行代码就可以搞定

```js
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
```

hook Okhttp3

```js
console.log("success load")
// Hooking into the network calls


Java.perform(function () {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.newCall.overload('okhttp3.Request').implementation = function (request) {

        var Method = request.method();
        var url = request.url().toString();
        console.log(Method + ' URL: ' + url);
        return this.newCall(request);

    };
})
```

frida rpc写法

```js
function de(data) {
    let ret = "1"
    Java.perform(function () {
        Java.choose("com.baidu.face.tools.faceTools", {
            onMatch: function (instance) {
                ret = instance.de(data)
            }, onComplete: function () {
            }
        })
    })
    return ret
}

console.log(de('1658310750118336{"key":"1658310750","wan":"0"}qs'))

rpc.exports = {
    getde: de
}
```

```js
import frida

rdev = frida.get_remote_device()
session = rdev.attach("得物")

scr = """
rpc.exports = {   
    encrypt:function(){
        var result;
        Java.perform(function (){
        let SzSdk = Java.use("com.shizhuang.stone.main.SzSdk");
        var str = ''
        var str2 = 'aa22c2593bb0909e' // uuid
        var j = Date.now()
        result = SzSdk["ltk"](str, str2, j)
        })
        return result;
    }
}
"""
script = session.create_script(scr)
script# 如果连接不了,先运行下面的端口转发
# import subprocess
# subprocess.getoutput('adb forward tcp:27042 tcp:27042')
# subprocess.getoutput('adb forward tcp:27043 tcp:27043').load()
ltk = script.exports.encrypt()
print('ltk==>',ltk)
```

线程替换

```js
function replace_thread() {
    var pthread_create_addr = Module.findExportByName(null, "pthread_create");
    var pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
    Interceptor.replace(pthread_create_addr, new NativeCallback((parg0, parg1, parg2, parg3) => {
        var so_name = Process.findModuleByAddress(parg2).name;
        var so_base = Module.getBaseAddress(so_name);
        var offset = (parg2 - so_base);
        var PC = 0;
        console.log("normal find thread func offset", so_name, parg2,offset, offset.toString(16));
        // i加密
        if(
        (so_name.indexOf("libexec.so")>-1 && offset===197069)||
        (so_name.indexOf("libexec.so")>-1 && offset===196137)
        ){

        }else if((so_name.indexOf("libDexHelper.so")>-1 && offset===684452)||
        (so_name.indexOf("libDexHelper.so")>-1 && offset===724380)){

        }
        else if(so_name.indexOf("libshell-super.com.showstartfans.activity.so")>-1&& offset==360656){

        }
        else{
            PC = pthread_create(parg0, parg1, parg2, parg3);
        }
        return PC;
    }, "int", ["pointer", "pointer", "pointer", "pointer"]));
}
```
