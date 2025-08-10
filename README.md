# sdbox-plus_sign
[sdbox-plus签名解决方案](https://www.52pojie.cn/thread-2016480-1-1.html)
致谢[zunmx](https://www.52pojie.cn/home.php?mod=space&uid=2250589)

本帖最后由 zunmx 于 2025-3-19 17:41 编辑


如有违规，麻烦版主删帖，谢谢。
目的
因为一些签名被禁用，导致无法使用高级功能，这里使用了内存修改方式规避检测，附上C++代码提供一种绕过黑名单签名的方法。
泄露的赞助凭证自行查找，本文不予提供。

思考过程
通过grep -rl 发现禁用的签名存在于SbieSvc.exe中，因为它被签名，所以需要其他方式进行修改
内存注入方式，始终注入不进去，功力不够，(lll￢ω￢)
通过openark或cheat engine修改SbieSvc.exe关键字符串，成功实现规避。
因为一旦提示过 【您尝试使用的许可证已被封禁，这意味着它已因故失效。任何使用该许可证的企图都构成对其使用条款的违反！】，逻辑将会先走注册表中的计算机\HKEY_LOCAL_MACHINE\SECURITY\SBIE\里面的CertBlockList，所以需要删掉它（需提权）


代码C++

代码部分借鉴了AI。

[1](https://attach.52pojie.cn/forum/202503/19/144049kz6c0ww27x13cwwx.png)
[2](https://attach.52pojie.cn/forum/202503/19/144101uja0fwmgk0bbiaxa.png)

其中有一些疑问，就是我用飘云阁的注入工具没有注入成功不知道为什么，应该怎么注入？
通过winapi删除注册表报错87，但是reg命令是可以删除的？

这种方式是启动器的逻辑，如果通过映像劫持会不会更好呢？

编译一定要和应用位数一致 如x64

最后需要psexec进行提权，我把psexec放到了沙箱的安装目录。
在 D:\software\Sandboxie-Plus\ 中运行
PsExec.exe -s -i 1 D:\software\Sandboxie-Plus\sandboxie_launcher.exe

最终可以简化成
D:\software\Sandboxie-Plus\PsExec.exe -s -i 1 D:\software\Sandboxie-Plus\sandboxie_launcher.exe
start D:\software\Sandboxie-Plus\SandMan.exe
