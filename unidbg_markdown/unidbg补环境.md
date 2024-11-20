> 补环境开始

如果有以下代码，请注释掉

`ProxyDvmClass` 是一个代理类，可以拦截和定制 `DvmClass` 的行为

而ProxyClassFactory 实现了ProxyDvmClass接口，等于是自定义 `DvmClass`类，因此无法补环境

```java
// 如果有以下代码请注释，不然会
// vm.setDvmClassFactory(new ProxyClassFactory());
```

> 关于空指针问题，这个是unidbg 常见报错

情况1 可能是调用系统so的时候找不到地址，解决方法，实例化的时候添加系统库

```java
        new JniGraphics(emulator, vm).register(memory);
        new AndroidModule(emulator, vm).register(memory);
```

情况2 使用签名调用so函数时异常，解决方法，使用地址调用

```java
    public String funbyaddr(List<Object> list) {
        Number number = module.callFunction(emulator, 0x12740, list.toArray());
        DvmObject<?> i = vm.getObject(number.intValue());
        return (String) i.getValue();
    }

    public String funbysig(List<Object> list) {
        StringObject result = clazz.callStaticJniMethodObject(emulator,
                "getHNASignature(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", list.toArray()); // 执行Jni方法
        return result.getValue();
    }

    public static void main(String[] args) {
        hainanhangkong test = new hainanhangkong();
        VM vm = test.vm;

        List<Object> list = new ArrayList<>(7);
        list.add(vm.getJNIEnv());
        list.add(0);
        list.add(vm.addLocalObject(new StringObject(vm, "{}")));
        list.add(vm.addLocalObject(new StringObject(vm, "{}")));
        list.add(vm.addLocalObject(new StringObject(vm, "{\"akey\":\"184C5F04D8BE43DCBD2EE3ABC928F616\",\"aname\":\"com.rytong.hnair\",\"atarget\":\"standard\",\"aver\":\"9.9.0\",\"did\":\"18b21e4e9858695a\",\"dname\":\"Google_Pixel 6 Pro\",\"gtcid\":\"ba5a775c68993a5f9640b6dace00e28a\",\"mchannel\":\"huawei\",\"schannel\":\"AD\",\"slang\":\"zh-CN\",\"sname\":\"google\\/raven\\/raven:13\\/TP1A.220624.021\\/8877034:user\\/release-keys\",\"stime\":\"1731943291640\",\"sver\":\"13\",\"system\":\"AD\",\"szone\":\"+0800\",\"abuild\":\"64764\",\"riskToken\":\"673b5b7cqfRzYfuIZI1zZC1GYKrl6RPQVJr2AnT3\",\"hver\":\"9.8.5.37904.85a5acc18.standard\",\"cms\":[{\"name\":\"cdnConfig\"}],\"h5Version\":\"9.8.5.37904.85a5acc18.standard\"}")));
        list.add(vm.addLocalObject(new StringObject(vm, "21047C596EAD45209346AE29F0350491")));
        list.add(vm.addLocalObject(new StringObject(vm, "F6B15ABD66F91951036C955CB25B069F")));

        String result;
        try {
            result = test.funbysig(list);
        } catch (Exception e) {
            System.out.println("使用地址调用");
            result = test.funbyaddr(list);
        }

        System.out.println("result:" + result);
        test.destroy();
    }
```
