## 新浪国际

### 特征说明
* 分析目标：com.sina.weibo.security.WeiboSecurityUtils.calculateS方法
    ```java
    public native String calculateS(Context context, String str, String str2);
    ```
    
* ida 打开目标so文件，搜素关键词，可发现是静态注册，舒服

* 参数一是Context上下文，参数二是传入的明文，参数三是固定的值，疑似Key或者盐

* 返回值是8位的Sign，且输入不变的情况下，输出也固定不变

*  样本百度网盘：https://pan.baidu.com/s/18_WCIb_KaKCAgxLj_1bLMA 提取码：k1f3 

### Unidbg模拟执行

IDA 7.5中，JNIEnv不需要导入jni.h，设置一下type(第一个参数类型，替换成JNIEnv *env)就可以识别JNI函数    

```c++
int __fastcall Java_com_sina_weibo_security_WeiboSecurityUtils_calculateS(JNIEnv *a1, int a2, int a3, int a4, int a5)
{
  const char *v6; // r5
  size_t v7; // r6
  size_t v8; // r6
  void *v9; // r7
  _BYTE *v10; // r6
  char *v11; // r5
  char v12; // r3
  jsize v13; // r0
  jsize v14; // r0
  jstring v15; // r0
  jobject v16; // r6
  char *v18; // [sp+Ch] [bp-2Ch]
  jbyteArray v19; // [sp+10h] [bp-28h]
  jclass v21; // [sp+18h] [bp-20h]
  struct _jmethodID *v22; // [sp+1Ch] [bp-1Ch]

  if ( sub_1C60(a1, a3) )
  {
    if ( (*a1)->PushLocalFrame(a1, 16) >= 0 )
    {
      v6 = (*a1)->GetStringUTFChars(a1, a5, 0);
      v18 = (char *)(*a1)->GetStringUTFChars(a1, a4, 0);
      v7 = j_strlen(v18);
      v8 = v7 + j_strlen(v6) + 1;
      v9 = j_malloc(v8);
      j_memset(v9, 0, v8);
      j_strcpy((char *)v9, v18);
      j_strcat((char *)v9, v6);
      v10 = (_BYTE *)MDStringOld(v9);
      v11 = (char *)j_malloc(9u);
      *v11 = v10[1];
      v11[1] = v10[5];
      v11[2] = v10[2];
      v11[3] = v10[10];
      v11[4] = v10[17];
      v11[5] = v10[9];
      v11[6] = v10[25];
      v12 = v10[27];
      v11[8] = 0;
      v11[7] = v12;
      v21 = (*a1)->FindClass(a1, "java/lang/String");
      v22 = (*a1)->GetMethodID(a1, v21, "<init>", "([BLjava/lang/String;)V");
      v13 = j_strlen(v11);
      v19 = (*a1)->NewByteArray(a1, v13);
      v14 = j_strlen(v11);
      (*a1)->SetByteArrayRegion(a1, v19, 0, v14, v11);
      v15 = (*a1)->NewStringUTF(a1, "utf-8");
      v16 = (*a1)->NewObject(a1, v21, v22, v19, v15);
      j_free(v11);
      j_free(v9);
      (*a1)->ReleaseStringUTFChars(a1, (jstring)a4, v18);
      a4 = (int)(*a1)->PopLocalFrame(a1, v16);
    }
    else
    {
      a4 = 0;
    }
  }
  return a4;
}
```
如果sub_1C60函数False，函数直接返回0，显然这是一条错误的逻辑，而传入的参数又是context，这很容易让人想到是一个**签名校验函数**
先搭一下基础的架子，这个样本连JNI OnLoad都没有, ida中搜不到
```java
package com.lession2;

// 导入通用且标准的类库
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.lession1.oasis;

import java.io.File;

public class sina extends AbstractJni{
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    sina() {
        // 创建模拟器实例,进程名建议依照实际进程名填写，可以规避针对进程名的校验
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.sina.International").build();
        // 获取模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
        // 创建Android虚拟机,传入APK，Unidbg可以替我们做部分签名校验的工作
        vm = emulator.createDalvikVM(new File("unidbg-android\\src\\test\\java\\com\\lession2\\sinaInternational.apk"));
        //
//        vm = emulator.createDalvikVM(null);

        // 加载目标SO
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android\\src\\test\\java\\com\\lession2\\libutility.so"), true); // 加载so到虚拟内存
        //获取本SO模块的句柄,后续需要用它
        module = dm.getModule();
        vm.setJni(this); // 设置JNI
        vm.setVerbose(true); // 打印日志
        // 样本连JNI OnLoad都没有
        // dm.callJNI_OnLoad(emulator); // 调用JNI OnLoad
    };

    public static void main(String[] args) {
        sina test = new sina();
    }
}

```
接下来添加一个calculateS函数(偏移量：00001E7C), ARM32有Thumb和ARM两种指令模式，此处是thumb模式，所以地址要在start基础上+1
入参有一些新情况：
 * context如何构造
 * 字符串类型如何构造

 **如何判断是Thumb还是Arm模式 ：**

*  试错法，比如此处不加1，指令肯定就跑偏，会报错非法指令 【Invalid instruction(UC_ERR_INSN_INVALID)】
*  ARM模式指令总是4字节长度，Thumb指令长度多数为2字节，少部分指令是4字节 
*  找准一行汇编，Alt+G快捷键 ,  Thumb模式是1，ARM模式是0 
*  除此之外，如果偶尔IDA反汇编出了问题，可以考虑它识别错了模式，需要Alt+G手动修改，调整模式 

**除了基本类型，比如int，long等，其他的对象类型一律要手动 addLocalObject**

```java
	public String calculateS(){
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        list.add(0); // 第二个参数，实例方法是jobject，静态方法是jclazz，直接填0，一般用不到。
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);// context
        list.add(vm.addLocalObject(context));
        list.add(vm.addLocalObject(new StringObject(vm, "12345")));
        list.add(vm.addLocalObject(new StringObject(vm, "r0ysue")));
		// 因为代码是thumb模式，别忘了+1
        Number number = module.callFunction(emulator, 0x1E7C + 1, list.toArray())[0];
        String result = vm.getObject(number.intValue()).getValue().toString();
        return result;
    };

    public static void main(String[] args) {
        sina test = new sina();
        System.out.println(test.calculateS());
    }

```

运行 报错了，而且没有较为明确的提示 , 看一下Warn一行显示的报错所处地址 `0x2c8d`

```log 
[16:07:20 562]  WARN [com.github.unidbg.linux.ARM32SyscallHandler] (ARM32SyscallHandler:457) - handleInterrupt intno=2, NR=0, svcNumber=0x113, PC=unidbg@0xfffe01c4, LR=RX@0x40002c8d[libutility.so]0x2c8d, syscall=null

```

IDA G健跟进`0x2c8d`,  来到`sub_2C3C`函数，看架势a1是JNIEnv指针 ,  把a1转成JNIEnv ，还原下

 按X查看一下交叉引用，有两个结果，其中一个是上面提到的sub_1C60函数 

 从先前的分析可以看出，这个函数会返回一个值，如果为真，就继续执行，为假，就返回0。再结合此地里面找的这些类，诸如PackageManager之流，很难不让人联想到签名校验函数 

**可以直接patch掉对这个函数的调用，说人话就是把这儿的函数跳转改成不跳转了呗** 

 **根据ARM调用约定，入参前四个分别通过R0-R3调用，返回值通过R0返回，所以这儿可以通过“mov r0,1”实现我们的目标——不执行这个函数，并给出正确的返回值** 

**此处的机器码是FF F7 EB FE, 查看一下“mov r0,1”的机器码，这里我们使用[ARMConvert](https://armconverter.com/?code=mov r0,1)看一下** 

 即把 FF F7 EB FE 替换成 4FF00100 即可 

#### Unidbg提供了两种方法打Patch

##### 1. 修改虚拟内存

 简单的需求可以调用Unicorn对虚拟内存进行修改，如下 ：

```java
public void patchVerify(){
    int patchCode = 0x4FF00100; // 
    emulator.getMemory().pointer(module.base + 0x1E86).setInt(0,patchCode);
}

```
上图中0x1E86是这么来的：
在函数calculateS的汇编流程图中，找到sub_1C60指定对应的位置，并单击，然后切换到Hex View-1 选项卡，效果如下：

![](imgs\001.png)

0x1E80 + 6 = 0x1E86

##### 2.  使用Unidbg封装的Patch方法 

有些情况下，我们可能要动态打Patch，或者我们并不想上什么网站，看MOV R0,1的机器码是什么，这时候可以使用Unidbg给我们封装的Patch方法 

```java
public void patchVerify1(){
    Pointer pointer = UnidbgPointer.pointer(emulator, module.base + 0x1E86);
    assert pointer != null;
    byte[] code = pointer.getByteArray(0, 4);
    if (!Arrays.equals(code, new byte[]{ (byte)0xFF, (byte) 0xF7, (byte) 0xEB, (byte) 0xFE })) { // BL sub_1C60
        throw new IllegalStateException(Inspector.inspectString(code, "patch32 code=" + Arrays.toString(code)));
    }
    try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb)) {
        KeystoneEncoded encoded = keystone.assemble("mov r0,1");
        byte[] patch = encoded.getMachineCode();
        if (patch.length != code.length) {
            throw new IllegalStateException(Inspector.inspectString(patch, "patch32 length=" + patch.length));
        }
        pointer.write(0, patch, 0, patch.length);
    }
};

```

 逻辑也非常清晰，先确认有没有找对地方，地址上是不是 FF F7 EB FE，再用Unicorn的好兄弟Keystone 把patch代码“mov r0,1"转成机器码，填进去，校验一下长度是否相等，收工 

***

### 算法分析

![](imgs\002.PNG)

 代码逻辑非常简单，将text和key拼接起来，然后放到MDStringOld函数中，出来的结果，从中分别抽出第1位（从0开始），第5位，等8位，即为结果了【**C语言字符串末尾需要终止符"\0"**】

 我们的关注点就是MDStringOld函数，首要的就是获取它的参数和返回值 :

- 它的参数可以验证我们对MDStringOld函数前面的分析有没有出错
- 它的返回值可以验证我们对MDStringOld函数后面和结果的分析有没有出错

 这个函数(其实还是个导出函数)的地址是0x1BD0+1 。  纯粹用Unidbg如何做算法分析 ？



 Unidbg内嵌了多种Hook工具，目前主要是四种 ：

- **Dobby**
- **HookZz**
- xHook： 爱奇艺开源的基于PLT HOOK的Hook框架，它无法Hook不在符号表里的函数，也不支持inline hook 
- Whale： 在Unidbg的测试用例中只有对符号表函数的Hook，没看到Inline Hook 或者 非导出函数的Hook 

 **HookZz是Dobby的前身，两者都可以Hook 非导出表中的函数，即IDA中显示为sub_xxx的函数，也都可以进行inline hook，所以二选一就行了** 

```java
public void HookMDStringold(){
        // 加载HookZz
        IHookZz hookZz = HookZz.getInstance(emulator);

        hookZz.wrap(module.base + 0x1BD0 + 1, new WrapCallback<HookZzArm32RegisterContext>() { // inline wrap导出函数
            @Override
            // 类似于 frida onEnter
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                // 类似于Frida args[0]
                Pointer input = ctx.getPointerArg(0);
                System.out.println("input:" + input.getString(0));
            };

            @Override
            // 类似于 frida onLeave
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer result = ctx.getPointerArg(0);
                System.out.println("input:" + result.getString(0));
            }
        });
    }

    public static void main(String[] args) {
        sina test = new sina();
//        test.patchVerify();
        test.patchVerify1();
        test.HookMDStringold();
        System.out.println(test.calculateS());
    }

```





![](imgs\003.png)



***

### TODO 

* 1.熟悉unidbg
* 2.frida hook测试

