> 传入Context，app上下文传入一般还有调用包名，app版本，app签名的环境需要补，null意为传入空对象

```java
vm.resolveClass("android.content.Context").newObject(null)
```
