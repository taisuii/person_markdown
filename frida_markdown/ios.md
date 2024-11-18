> **CFNetworkCopySystemProxySettings**检测代理

```js
var _imports = Process.findModuleByName("XXX").enumerateImports(); 
//获取可执行文件所有的导入函数
var _CFNetworkCopySystemProxySettings = null;
//遍历导入函数，当包含CFNetworkCopySystemProxySettings时，获取其地址
for (var i = 0; i < _imports.length; i++) {   
    //查找CFNetworkCopySystemProxySettings系统代理函数
    if (_imports[i].name.indexOf("CFNetworkCopySystemProxySettings") !== -1) {
        console.log(_imports[i].name, _imports[i].address);
        _CFNetworkCopySystemProxySettings = _imports[i].address;
    }
}
 
 
//修改CFNetworkCopySystemProxySettings函数的返回值
if (_CFNetworkCopySystemProxySettings) {
    Interceptor.attach(_CFNetworkCopySystemProxySettings, {
        onEnter: function (agrgs) {
 
        }, onLeave: function (retval) {
            console.log("retval: ", ObjC.Object(retval));
            //将返回值全部nop
            retval.replace(0);
        }
    })
}
 
```

> 越狱检测
> 
> 利用stat检查一些越狱后才有的敏感路径，如：*/Applications/Cydia.app* 和 */usr/sbin/sshd*，以此来判断是否越狱。stat判断文件是否存在, 返回0则为获取成功，-1为获取失败。可通过hook stat，过掉检测

```js
function hook_stat(is_pass){
  var stat = Module.findExportByName('libSystem.B.dylib', 'stat');
  Interceptor.attach(stat, {
    onEnter: function(args) {
      // 这里是方法被调用时的处理逻辑
      // args[0] 是 stat 方法的第一个参数，通常是文件路径
      // args[1] 是 stat 方法的第二个参数，这里可以添加其他参数的处理
      console.log('stat is hooked: ');
    },
    onLeave: function(retval){
      if (is_pass){
        retval.replace(-1);
        console.log(`stat retval: ${Number(retval.toString())} -> -1`);
      }
    }
  });
}
```

> ### 检查dylib是否合法
> 
> 越狱后会产生一些特殊的链接库，ipa可以通过*_dyld_get_image_name*来获取所有的链接库，再遍历匹配，判断是否为越狱设备。  
> 可以通过分析找到ipa检测的dylib，再hook *_dyld_get_image_name*，将返回替换为合法dylib，过掉检测。

```js
function hook_dyld_get_image_name(is_pass){
  let cheek_paths = [
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
  ]
 
  let NSString = ObjC.classes.NSString;
  let true_path = NSString.stringWithString_( "/System/Library/Frameworks/Intents.framework/Intents");
 
 
 
  let _dyld_get_image_name = Module.findExportByName(null, "_dyld_get_image_name");
  Interceptor.attach(_dyld_get_image_name, {
    onEnter: function(args){
 
      console.log("_dyld_get_image_name is hooked.")
      this.idx = eval(args[0]).toString(10);
 
    },
    onLeave: function(retval){
      let rtnStr = retval.readCString();
 
      if(is_pass){
        for (let i=0;i<cheek_paths.length;i++){
 
          if (cheek_paths[i] === rtnStr.toString()){
            retval.replace(true_path);
            console.log(`replace: (${this.idx}) ${rtnStr} => ${true_path}`)
          }
        }
 
      }
 
    }
  })
 
}
```

> ### 检测能否启动越狱app
> 
> 越狱后会在手机上安装越狱设备，如cydia。可以通过 *-[UIApplication canOpenURL:]* 来检测是否能启动app。
> 
> 可hook *-[UIApplication canOpenURL:]* 替换返回过掉检测。但canOpenURL方法 返回是个 *BOOL*，即YES/NO，也就是1和0的宏。但在Interceptor.attach里用 *retval.replace()*总是会导致app崩溃（不知道原理，望大佬指点）。  
> 所以使用 Interceptor.replace() + NaviteCallback, 替换掉方法，使其固定返回 0,也就是 NO。但这个解法，也不能算是好方法。。。

```js
function hook_canopenurl(is_pass){
 
  let api = new ApiResolver("objc");
  api.enumerateMatches("-[UIApplication canOpenURL:]").forEach((matche) => {
 
    console.log("canOpenURL is hooked.");
 
    if (is_pass){
      Interceptor.replace(matche.address, new NativeCallback((url_obj) => {return 0;}, "int", ["pointer"]))
    }
  })
 
 
}
```

> ### 检测越狱文件和目录
> 
> 越狱后会产生特殊的文件和目录，可以通过 *fileExistsAtPath* 来检测，直接hook过掉

```js
function hook_fileExistsAtPath(is_pass){
 
 
  let api = new ApiResolver("objc");
  let matches = api.enumerateMatches("-[NSFileManager fileExistsAtPath:isDirectory:]")
  matches.forEach((matche) => {
 
    console.log("fileExistsAtPath is hooked.");
 
    if(is_pass){
      Interceptor.replace(matche.address, new NativeCallback((path, is_dir) => {
        console.log(ObjC.Object(path).toString(), is_dir)
        return 0;
      }, "int", ["pointer", "bool"]))
    }
 
  })
 
}
```

> ### 检测是否可写私有路径权限
> 
> 越狱后为root权限，可以在私有路径如 */private/* 下创建文件。如果创建文件无异常则越狱，反之。
> 
> 可通过 *ObjC.classes.NSError.alloc()* 构建一个异常写入ipa检测的异常指针中

```js
function hook_writeToFile(is_pass){
 
  let api = new ApiResolver("objc");
  api.enumerateMatches("-[NSString writeToFile:atomically:encoding:error:]").forEach((matche) => {
 
    Interceptor.attach(matche.address, {
 
      onEnter: function(args){
        this.error = args[5];
        this.path = ObjC.Object(args[2]).toString();
        console.log("writeToFile is hooked");
      },
      onLeave: function(retval){
        if(is_pass){
          let err = ObjC.classes.NSError.alloc();
          Memory.writePointer(this.error, err);
        }
      }
 
    })
 
  })
 
}
```

> ### 检测文件路径和是否是路径链接
> 
> 越狱后有些文件会被移动，但这个文件路径又必须存在，所以可能会创一个文件链接。ipa可以检测一些敏感路径是否是链接来判断是否越狱。
> 
> 这里仅过掉路径检测（符号链接不会过T.T）

```objectivec
// oc 检测函数
+ (Boolean)isLstatAtLnk{
    // 检测文件路径是否存在，是否是路径链接
    Boolean result = FALSE;
 
    NSArray* jbPaths = @[
        @"/Applications",
        @"/var/stash/Library/Ringtones",
        @"/var/stash/Library/Wallpaper",
        @"/var/stash/usr/include",
        @"/var/stash/usr/libexec",
        @"/var/stash/usr/share",
        @"/var/stash/usr/arm-apple-darwin9",
    ];
 
    struct stat stat_info;
 
    for(NSString* jbPath in jbPaths){
        char jbPathChar[jbPath.length];
        memcpy(jbPathChar, [jbPath cStringUsingEncoding:NSUTF8StringEncoding], jbPath.length);
 
        if (lstat(jbPathChar, &stat_info)){
            NSLog(@"stat_info.st_mode: %hu, S_IFLNK: %d, %d", stat_info.st_mode, S_IFLNK, stat_info.st_mode & S_IFLNK);
            if(stat_info.st_mode & S_IFLNK){
                result = TRUE;
                NSLog(@"是路径链接>> %@", jbPath);
            }
        }else{
            NSLog(@"路径不存在>> %@", jbPath);
            result = TRUE;
        }
    }
 
    return result;
 
}
```

```js
// 过lstat
function hook_lstat(is_pass){
  var stat = Module.findExportByName('libSystem.B.dylib', 'lstat');
  Interceptor.attach(stat, {
    onEnter: function(args) {
 
      console.log('lstat is hooked: ');
    },
    onLeave: function(retval){
      if (is_pass){
        retval.replace(1);
        console.log(`lstat retval: ${Number(retval.toString())} -> 1`);
      }
    }
  });
}
```

> ### 检测fork
> 
> 未越狱的设备是无法fork子进程

```js
function hook_fork(is_pass){
 
  let fork = Module.findExportByName(null, "fork");
  if (fork){
    console.log("fork is hooked.");
    Interceptor.attach(fork, {
      onLeave: function(retval){
        console.log(`fork -> pid:${retval}`);
        if(is_pass){
          retval.replace(-1)
        }
      }
    })
  }
 
}
```

> ### 检测越狱常用的类
> 
> 查看是否有注入异常的类,比如HBPreferences 是越狱常用的类，再用 *NSClassFromString* 判断类是否存在
> 
> 通过分析找出检测的类名，再去hook *NSClassFromString*

```js
function hook_NSClassFromString(is_pass){
 
  let clses = ["HBPreferences"];
 
  var foundationModule = Process.getModuleByName('Foundation');
  var nsClassFromStringPtr = Module.findExportByName(foundationModule.name, 'NSClassFromString');
 
  if (nsClassFromStringPtr){
    Interceptor.attach(nsClassFromStringPtr, {
      onEnter: function(args){
        this.cls = ObjC.Object(args[0])
        console.log("NSClassFromString is hooked");
      },
      onLeave: function(retval){
 
        if (is_pass){
          clses.forEach((ck_cls) => {
 
            if (this.cls.toString().indexOf(ck_cls) !== -1){
              console.log(`nsClassFromStringPtr -> ${this.cls} - ${ck_cls}`)
              retval.replace(ptr(0x00))
            }
          })
 
        }
 
 
      }
    })
 
  }
 
 
}
```

> ### 检测是否有环境变量
> 
> 通过getenv函数，查看环境变量DYLD_INSERT_LIBRARIES来检测是否越狱
> 
> hook getenv

```js
function hook_getenv(is_pass){
 
  let getenv = Module.findExportByName(null, "getenv");
 
  Interceptor.attach(getenv, {
    onEnter: function(args){
      console.log("getenv is hook");
      this.env = ObjC.Object(args[0]).toString();
    },
    onLeave: function(retval){
      if (is_pass && this.env == "DYLD_INSERT_LIBRARIES"){
        console.log(`env: ${this.env} - ${retval.readCString()}`)
 
        retval.replace(ptr(0x0))
 
      }
 
    }
  })
 
}
```
