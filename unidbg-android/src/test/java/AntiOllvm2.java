import capstone.Capstone;
import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import unicorn.Arm64Const;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

public class AntiOllvm2 {
    interface ICallback {
        public void xx();
    }
    private AndroidEmulator emulator;
    private VM vm;
    private DalvikModule dm;
    Module module;

    // 指令栈
    private  Stack<InsAndCtx> instructions;

    //所有需要patch的指令
    private List<PatchIns> patchs;



    public AntiOllvm2(){
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
        vm.setVerbose(true);
        //加载动态库
        //加载动态库
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/libc.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/libm.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/libstdc++.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/ld-android.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/deollvm/lib64/libdl.so"),false);
        dm = vm.loadLibrary(new File("/home/t/Desktop/deollvm/libtprt.so"), false);
        module = dm.getModule();
        instructions = new Stack<InsAndCtx>();
    }
    public void callJniOnLoad(){
        dm.callJNI_OnLoad(emulator);
    }

    public void logIns(){
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user)  {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] instructions = capstone.disasm(bytes, 0);
                System.out.printf("%x:%s %s\n",address-module.base ,instructions[0].getMnemonic(),instructions[0].getOpStr());
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, module.base, module.base+module.size, null);
    }

    static class InsAndCtx {
        long addr;
        Instruction ins;
        List<Number> regs;
        public long getAddr() {
            return addr;
        }

        public void setAddr(long addr) {
            this.addr = addr;
        }

        public void setIns(Instruction ins) {
            this.ins = ins;
        }

        public Instruction getIns() {
            return ins;
        }

        public void setRegs(List<Number> regs) {
            this.regs = regs;
        }

        public List<Number> getRegs() {
            return regs;
        }
    }

    static class PatchIns{
        long addr;//patch 地址
        String ins;//patch的指令

        public long getAddr() {
            return addr;
        }

        public void setAddr(long addr) {
            this.addr = addr;
        }

        public String getIns() {
            return ins;
        }

        public void setIns(String ins) {
            this.ins = ins;
        }
    }

    private List<Number> saveRegs(Backend backend) {
        List<Number> nb = new ArrayList<>();
        for(int i=0;i<29;i++) {
            nb.add(backend.reg_read(i + Arm64Const.UC_ARM64_REG_X0));
        }
        nb.add(backend.reg_read(Arm64Const.UC_ARM64_REG_FP));
        nb.add(backend.reg_read(Arm64Const.UC_ARM64_REG_LR));
        return nb;
    }

    private void processIBR(){
        Instruction ins = instructions.peek().getIns();
        if (instructions.size() < 5) {
            return;
        }
        if(!ins.toString().equals("br x9")){
            return;
        }


        for(int i=4; i >0; i-- ){
            InsAndCtx insAndCtx  = instructions.pop();
            System.out.println(insAndCtx.getIns());
        }
        System.out.println("---------------------\n");




    }


    private void processIns(long  start, long end) {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] inses = capstone.disasm(bytes, 0);

                InsAndCtx iac = new InsAndCtx();
                iac.setIns(inses[0]);
                iac.setRegs(saveRegs(backend));
                iac.setAddr(address);

                instructions.push(iac);
                processIBR();
            }

            @Override
            public void onAttach(UnHook unHook) {
                System.out.println("attach");
            }

            @Override
            public void detach() {
                System.out.println("detach");
            }
        },module.base + start, module.base +end, null);
    }

    public static void main(String[] args) {
        final AntiOllvm2 antiOllvm2 = new AntiOllvm2();
        antiOllvm2.processIns(0x61F14, 0x6232c);
        antiOllvm2.callJniOnLoad();
    }


}
