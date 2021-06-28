function call_65540(base_addr){
    // 函数在内存中的地址
    var real_addr = base_addr.add(0x65541)
    var md5_function = new NativeFunction(real_addr, "int", ["pointer", "int", "pointer"])
    // 参数1 明文字符串的指针
    var input = "r0ysue";
    var arg1 = Memory.allocUtf8String(input);
    // 参数2 明文长度
    var arg2 = input.length;
    // 参数3，存放结果的buffer
    var arg3 = Memory.alloc(16);
    md5_function(arg1, arg2, arg3);
    console.log(hexdump(arg3,{length:0x10}));
}

function callMd5(){
    // 确定SO 的基地址
    var base_addr = Module.findBaseAddress("libnet_crypto.so");
    call_65540(base_addr);
}

// frida -UF -l path\hookright.js

