> 补环境开始

如果有以下代码，请注释掉

`ProxyDvmClass` 是一个代理类，可以拦截和定制 `DvmClass` 的行为

而ProxyClassFactory 实现了ProxyDvmClass接口，等于是自定义 `DvmClass`类，因此无法补环境

```java
// 如果有以下代码请注释，不然会
// vm.setDvmClassFactory(new ProxyClassFactory());
```




