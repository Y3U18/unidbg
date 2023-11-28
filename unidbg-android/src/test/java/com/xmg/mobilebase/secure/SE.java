package com.xmg.mobilebase.secure;

import capstone.Capstone;
import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class SE extends AbstractJni {
    private AndroidEmulator emulator;
    private VM vm;
    private DalvikModule dm;
    Module module;
    DvmClass cSecure;
    public SE(){
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.example.antiollvm")
                .build();
        Memory memory = emulator.getMemory();
        //设置andorid系统库版本
        memory.setLibraryResolver(new AndroidResolver(26));
        //创建虚拟机
        vm = emulator.createDalvikVM();
        vm.setJni(this);
        vm.setVerbose(true);
        //加载动态库
        //加载动态库
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/libc.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/libm.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/liblog.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/libz.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/libdl.so"),false);
        dm = vm.loadLibrary(new File("/home/t/Desktop/deollvm/libUserEnv.so"), false);
        module = dm.getModule();

    }
    public void logIns(){
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user)  {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] instructions = capstone.disasm(bytes, 0);
                // System.out.printf("%x:%s %s\n",address-module.base ,instructions[0].getMnemonic(), instructions[0].getOpStr());
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, module.base, module.base+module.size, null);
    }
    private void callJniOnload() {
        dm.callJNI_OnLoad(emulator);
    }
    private String ue() {
        cSecure = vm.resolveClass("com/xmg/mobilebase/secure/SE");
        String methodSign = "ue(J)Ljava/lang/String;";

        StringObject obj = cSecure.callStaticJniMethodObject(emulator, methodSign, 10000);
        return obj.getValue();
    }
    public static void main(String[] args) {
        SE ao = new SE();
        ao.callJniOnload();
        ao.ue();
    }


}

