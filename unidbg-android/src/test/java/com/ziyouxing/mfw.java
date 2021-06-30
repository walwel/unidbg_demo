package com.ziyouxing;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.hookzz.*;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import net.fornwall.jelf.MemoizedObject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class mfw extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    mfw(){
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.mfw.roadbook").build();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("unidbg-android\\src\\test\\java\\com\\ziyouxing\\mafengwo_ziyouxing.apk"));
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android\\src\\test\\java\\com\\ziyouxing\\libmfw.so"), true);
        module = dm.getModule();

        vm.setJni(this);
        vm.setVerbose(true);
        dm.callJNI_OnLoad(emulator);

    }

    public String xPreAuthencode(){
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());   // 第一个入参env;
        list.add(0);                // 第二个参数，直接填0，一般用不到；
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        list.add(vm.addLocalObject(context));
        list.add(vm.addLocalObject(new StringObject(vm, "r0ysue")));
        list.add(vm.addLocalObject(new StringObject(vm, "com.mfw.roadbook")));

        Number number = module.callFunction(emulator, 0x2e301, list.toArray())[0];
        String result = vm.getObject(number.intValue()).getValue().toString();
        return result;
    }

    public void hook_312E0(){
        // 获取HookZz对象
        IHookZz hookZz = HookZz.getInstance(emulator); // 加载HookZz，支持inline hook，文档看https://github.com/jmpews/HookZz
        // enable hook
        hookZz.enable_arm_arm64_b_branch(); // 测试enable_arm_arm64_b_branch，可有可无
        // hook hook_312E0
        hookZz.wrap(module.base + 0x312E0 + 1, new WrapCallback<HookZzArm32RegisterContext>() { // inline wrap导出函数
            @Override
            // 方法执行前
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer input = ctx.getPointerArg(0);
//                System.out.println("input:" + input.getString(0));
                byte[] inputhex = input.getByteArray(0, ctx.getR2Int());
                Inspector.inspect(inputhex, "input");
//
                Pointer out = ctx.getPointerArg(1);
                ctx.push(out);
            };

            @Override
            // 方法执行后
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer output = ctx.pop();
//                Pointer result = ctx.getPointerArg(0);
//                System.out.println("output:" + result.getString(0));
                byte[] outputhex = output.getByteArray(0, 20);
                Inspector.inspect(outputhex, "output");
            }
        });
        hookZz.disable_arm_arm64_b_branch();
    };

    public static void main(String[] args) {
        mfw test = new mfw();
        test.hook_312E0();
        System.out.println(test.xPreAuthencode());
        // 57c043fe945355a64cb9c3d75db4bd767d1bbccb  // 长度40，疑似SHA1算法
    }
}
