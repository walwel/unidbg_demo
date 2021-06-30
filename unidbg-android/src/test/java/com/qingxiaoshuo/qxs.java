package com.qingxiaoshuo;


import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class qxs extends AbstractJni{
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    qxs() throws FileNotFoundException {
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.qxs").build(); // 创建模拟器实例，要模拟32位或者64位，在这里区分
        final Memory memory = emulator.getMemory(); // 模拟器的内存操作接口
        memory.setLibraryResolver(new AndroidResolver(23)); // 设置系统类库解析

        vm = emulator.createDalvikVM(new File("unidbg-android\\src\\test\\java\\com\\qingxiaoshuo\\qingxiaoshuo.apk")); // 创建Android虚拟机
        vm.setVerbose(true); // 设置是否打印Jni调用细节
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android\\src\\test\\java\\com\\qingxiaoshuo\\libsfdata.so"), false); // 加载libttEncrypt.so到unicorn虚拟内存，加载成功以后会默认调用init_array等函数
        module = dm.getModule(); //

        // 先把JNI Onload跑起来，里面做了大量的初始化工作
        vm.setJni(this);
        dm.callJNI_OnLoad(emulator);

    }

    public String getSFsecurity(){

        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(0);
        DvmObject<?>context = vm.resolveClass("android/content/Context").newObject(null);
        list.add(vm.addLocalObject(context));
        list.add(vm.addLocalObject(new StringObject(vm, "r0ysue")));
        Number number = module.callFunction(emulator,0xA944+1, list.toArray())[0];
        String result = vm.getObject(number.intValue()).getValue().toString();
        return result;
    };

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature){
            case "java/util/UUID->randomUUID()Ljava/util/UUID;": {
                return dvmClass.newObject(UUID.randomUUID());
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    };

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature){
            case "java/util/UUID->toString()Ljava/lang/String;": {
                String uuid = dvmObject.getValue().toString();
                return new StringObject(vm, uuid);
            }
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    };

    public static void main(String[] args) throws Exception {
        qxs test = new qxs();
        System.out.println(test.getSFsecurity());
    }

}

