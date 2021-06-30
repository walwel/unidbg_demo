## Unidbg


### 1. 使用Unidbg的工作流程

* Frida 主动调用获取一份正确结果
* Unidbg写代码尝试运行→Unidbg给出报错→补环境
* 循环往复，最后得到和Frida主动调用一致的结果


### 2. Unidbg 补环境

Unidbg中的补环境，大体上可以分成两类，**运行环境缺失**和**上下文缺失**

#### 2.1 运行环境缺失
目标函数中通过JNI调用到了某个自己的JAVA方法，Unidbg会及时报错，给出堆栈以及这个JAVA方法的签名，需要我们补上对应的JAVA方法。
当然，JAVA环境并不是工作的全部。运行环境包含以下几类

* JAVA环境
* 文件读写——对linux虚拟文件的读写，对ASSETS资源文件的读写、对app目录下文件的读取，对Sharedpreference的读取等等
* 系统调用具体实现——比如popen函数所涉及的系统调用等
* 系统库SO，Unidbg并没有，实际上也不可能模拟完整的Android系统SO环境，有的SO所依赖的SO比较多，很难调起来，所以Unidbg设计了VirtualModule（虚拟SO模块）

**补不了，打patch**

#### 2.2 上下文缺失

上下文缺失则是由于样本在运行目标函数前对SO或目标函数做了一些初始化工作，如果我们在Unidbg中只对目标函数单独运行，自然就导致了上下文缺失     
上下文缺失相较于运行环境缺失，是一种更加隐蔽的环境缺失。它常常难倒Unidbg的使用者