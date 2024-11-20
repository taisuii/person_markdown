frida 处理检测问题

Hook fgets线程创建函数

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
```

字符串替换，Hook  strst中的字符串比较函数

```js
function replace_str() {
    var pt_strstr = Module.findExportByName("libc.so", 'strstr');
    var pt_strcmp = Module.findExportByName("libc.so", 'strcmp');

    Interceptor.attach(pt_strstr, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            if (
                str2.indexOf("REJECT") !== -1 ||
                str2.indexOf("tmp") !== -1 ||
                str2.indexOf("frida") !== -1 ||
                str2.indexOf("gum-js-loop") !== -1 ||
                str2.indexOf("gmain") !== -1 ||
                str2.indexOf("linjector") !== -1
            ) {
                console.log("strstr-->", str1, str2);
                this.hook = true;
            }
        }, onLeave: function (retval) {
            if (this.hook) {
                retval.replace(0);
            }
        }
    });

    Interceptor.attach(pt_strcmp, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            if (
                str2.indexOf("REJECT") !== -1 ||
                str2.indexOf("tmp") !== -1 ||
                str2.indexOf("frida") !== -1 ||
                str2.indexOf("gum-js-loop") !== -1 ||
                str2.indexOf("gmain") !== -1 ||
                str2.indexOf("linjector") !== -1
            ) {
                //console.log("strcmp-->", str1, str2);
                this.hook = true;
            }
        }, onLeave: function (retval) {
            if (this.hook) {
                retval.replace(0);
            }
        }
    })

}
```

> 过掉libmsaoaidsec.so检测，libmsaoaidsec.so 会在初始化的时候创建 3 条检测 Frida 的线程，我们只需要让这 3 条线程不运行即可绕过检测，理论上支持所有使用 libmsaoaidsec.so 来反 Frida 调试的app

```js
function locate_init() {
    let secmodule = null
    Interceptor.attach(Module.findExportByName(null, "__system_property_get"),
        {
            // _system_property_get("ro.build.version.sdk", v1);
            onEnter: function (args) {
                secmodule = Process.findModuleByName("libmsaoaidsec.so")
                var name = args[0];
                if (name !== undefined && name != null) {
                    name = ptr(name).readCString();
                    if (name.indexOf("ro.build.version.sdk") >= 0) {
                        // 这是.init_proc刚开始执行的地方，是一个比较早的时机点
                        // do something
                        hook_pthread_create()
                    }
                }
            }
        }
    );
}let i = 0;
function hook_pthread_create() {
    //只有三条检测线程被干掉之后才开始hook
    if (i >= 3) {
        hook()
    }

    let baseAddress = Process.findModuleByName("libmsaoaidsec.so").base;
    console.log("libmsaoaidsec.so --- " + baseAddress);

    Interceptor.replace(Module.findExportByName("libc.so", "pthread_create"), new NativeCallback(function (attr, start_routine, arg1, arg2) {
        // console.log("The thread function address is ", arg1)
        let func_addr = arg1.sub(baseAddress); // 计算相对地址

        // 判断 func_addr 的值是否为指定的偏移
        if (func_addr.equals(ptr(0x1B8D4)) || func_addr.equals(ptr(0x26E5C)) || func_addr.equals(ptr(0x1c544))) {
            i++
            console.log(func_addr, i)

            //假装成功创建线程
            return 0
        }


        // 获取系统库中的 pthread_create 函数并调用
        let pthread_create = new NativeFunction(Module.findExportByName("libc.so", "pthread_create"), 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
        return pthread_create(attr, start_routine, arg1, arg2);
    }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
}

setImmediate(hook_dlopen, "libmsaoaidsec.so")
```
