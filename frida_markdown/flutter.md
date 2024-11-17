flutter

```js
function hook_ssl_verify_result(address)
{
  Interceptor.attach(address, {
    onEnter: function(args) {
      console.log("Disabling SSL validation")
    },
    onLeave: function(retval)
    {
      console.log("Retval: " + retval)
      retval.replace(0x1);

    }
  });
}
function disablePinning(){
    // Change the offset on the line below with the binwalk result
    // If you are on 32 bit, add 1 to the offset to indicate it is a THUMB function: .add(0x1)
    // Otherwise, you will get  'Error: unable to intercept function at ......; please file a bug'
    var address = Module.findBaseAddress('libflutter.so').add(0x37F780)
    hook_ssl_verify_result(address);
}
```

hook

```js
function main() {
    Java.perform(function () {
        var str_name_so = "libapp.so";
        var n_addr_so = Module.findExportByName(str_name_so, "_kDartIsolateSnapshotInstructions")

        Interceptor.attach(n_addr_so.add(0x00000000001e7b4c), {
            onEnter: function (args) {
                // console.log('输出调用栈:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
                console.log("============================= input ===============================", "\n")
                var i = 0
                console.log(hexdump(args[i], {length: 0x200}), "\r\n");
            },
        });


        Interceptor.attach(n_addr_so.add(0x00000000001e7b4c), {
            onEnter: function (args) {
                // console.log('输出调用栈:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
                console.log("============================= input ===============================", "\n")
                var i = 0
                console.log(hexdump(args[i], {length: 0x200}), "\r\n");
            },
        });

        Interceptor.attach(n_addr_so.add(0x00000000001f3ec0), {
            onEnter: function (args) {
                // console.log('输出调用栈:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
                console.log("============================= input ===============================", "\n")
                var i = 0
                console.log(hexdump(args[i], {length: 0x200}), "\r\n");
            },
        });

    });
}

setTimeout(main, 20);
```
