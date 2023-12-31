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
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;

import java.io.*;
import java.math.BigInteger;
import java.util.*;

public class AntiOllvm {
    private final  String obfLibPath;
    private final AndroidEmulator emulator;
    private final DalvikModule dm;
    private final Module module;
    private final Stack<InsAndCtx> instructions;
    private final List<PatchIns> patchs;
    private static final long dispatcher = 0x5E46C;
    private static final long toend = 0x5E6BC;
    //记录真实块
    private List<TrueBlock>tbs;
    //记录条件块
    private List<selectBr> sbs ;
    //记录索引顺序
    private List<Long> indexOrder;
    BufferedWriter writer;

    public AntiOllvm(String inName) throws IOException {
        this.obfLibPath = inName;
        instructions = new Stack<>();
        patchs = new ArrayList<>();
        tbs = new ArrayList<>();
        sbs = new ArrayList<>();
        indexOrder = new ArrayList<>();
        //创建模拟器
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.example.antiollvm")
                .build();
        Memory memory = emulator.getMemory();
        //设置andorid系统库版本
        memory.setLibraryResolver(new AndroidResolver(33));
        //创建虚拟机
        VM vm = emulator.createDalvikVM();
        vm.setVerbose(true);
        //加载动态库
        vm.loadLibrary(new File("/home/t/Desktop/unidbg/unidbg_libs/lib64/libc.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/unidbg/unidbg_libs/lib64/libm.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/unidbg/unidbg_libs/lib64/libstdc++.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/unidbg/unidbg_libs/lib64/ld-android.so"),false);
        vm.loadLibrary(new File("/home/t/Desktop/unidbg/unidbg_libs/lib64/libdl.so"),false);

        dm = vm.loadLibrary(new File(inName), false);
        module = dm.getModule();
        writer = new BufferedWriter(new FileWriter("ins.log"));
        //processFlt(0x61F14, 0x6232C);
    }

    public void logIns(long start, long end) {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user)  {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] disasm = capstone.disasm(bytes, 0);
                System.out.printf("%x:%s %s\n",address-module.base ,disasm[0].getMnemonic(),disasm[0].getOpStr());
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, module.base+start, module.base+end, null);
    }


    public void callJniOnload() {
        dm.callJNI_OnLoad(emulator);
    }



    //保存指令和寄存器环境类：
    class InsAndCtx
    {
        public InsAndCtx(long addr, Instruction ins, List<Number> regs){
            this.addr = addr;
            this.ins = ins;
            this.regs = regs;
        }
        long addr;
        Instruction ins;
        List<Number> regs;

        public long getAddr() {
            return addr;
        }


        public Instruction getIns() {
            return ins;
        }

        public List<Number> getRegs() {
            return regs;
        }

    }

    //patch类
    class PatchIns{
        long addr;//patch 地址
        String ins;//patch的指令

        public long getAddr() {
            return addr;
        }

        PatchIns(long addr, String ins){
            this.addr = addr;
            this.ins  = ins;
        }
        public String getIns() {
            return ins;
        }


    }

    public List<Number> saveRegs(Backend bk)
    {
        List<Number> nb = new ArrayList<>();
        for(int i=0;i<29;i++)
        {
            nb.add(bk.reg_read(i+ Arm64Const.UC_ARM64_REG_X0));
        }
        nb.add(bk.reg_read(Arm64Const.UC_ARM64_REG_FP));
        nb.add(bk.reg_read(Arm64Const.UC_ARM64_REG_LR));
        return nb;
    }
    public Number getRegValue(String reg, List<Number> regsaved)
    {
        if(reg.equals("xzr"))
        {
            return 0;
        }
        return regsaved.get(Integer.parseInt(reg.substring(1)));
    }

    public long readInt64(Backend bk,long addr)
    {
        byte[] bytes = bk.mem_read(addr, 8);
        long res = 0;
        for (int i=0;i<bytes.length;i++)
        {
            res =((bytes[i]&0xffL) << (8*i)) + res;
        }
        return res;
    }

    public long StringToLong(String bt)
    {
        return Long.parseLong(bt,16);
    }

    public void patch(String outName) {
        System.out.println("size:" + patchs.size());
        try {
            File f = new File(obfLibPath);
            FileInputStream fis = new FileInputStream(f);
            byte[] data = new byte[(int) f.length()];
            fis.read(data);
            fis.close();
            for(PatchIns pi:patchs)
            {
                System.out.println("procrss addr:"+Integer.toHexString((int) pi.addr)+",code:"+pi.getIns());
                Keystone ks = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);
                KeystoneEncoded assemble = ks.assemble(pi.getIns());
                for(int i=0;i<assemble.getMachineCode().length;i++)
                {
                    data[(int) pi.addr+i] = assemble.getMachineCode()[i];
                }
            }
            File fo = new File(outName);
            FileOutputStream fos = new FileOutputStream(fo);
            fos.write(data);
            fos.flush();
            fos.close();
            System.out.println("finish");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    class selectBr
    {
        long insaddr;
        long trueindex;
        long falseindex;
        String cond;
        public String getCond() {
            return cond;
        }
        public void setCond(String cond) {
            this.cond = cond;
        }
        public long getInsaddr() {
            return insaddr;
        }
        public void setInsaddr(long insaddr) {
            this.insaddr = insaddr;
        }
        public long getTrueindex() {
            return trueindex;
        }
        public void setTrueindex(long trueindex) {
            this.trueindex = trueindex;
        }
        public long getFalseindex() {
            return falseindex;
        }
        public void setFalseindex(long falseindex) {
            this.falseindex = falseindex;
        }
    }

    class TrueBlock{

        long index;
        long startAddr;

        public TrueBlock(){}
        public TrueBlock(long l,long s)
        {
            index = l;
            startAddr = s;
        }

        public long getIndex() {
            return index;
        }

        public void setIndex(long index) {
            this.index = index;
        }

        public long getStartAddr() {
            return startAddr;
        }

        public void setStartAddr(long startAddr) {
            this.startAddr = startAddr;
        }
    }

    public long strToLong(String hexString)
    {
        BigInteger bi = new BigInteger(hexString,16);
        return bi.longValue();
    }

    public long getLongFromOpConst(String op)
    {
        if(op.startsWith("#0x"))
        {
            return strToLong(op.substring(3));
        }
        else if(op.startsWith("#"))
        {
            return strToLong(op.substring(1));
        }
        else
        {
            return 0;
        }
    }
    public void processFlt(long start, long end)
    {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] disasm = capstone.disasm(bytes, 0);

                instructions.add(new InsAndCtx(address, disasm[0], saveRegs(backend)));
                do_processflt();
            }

            @Override
            public void onAttach(UnHook unHook) {
                System.out.println("attach");
            }

            @Override
            public void detach() {
                System.out.println("detach");
            }
        },module.base+start, module.base+end, null);
    }
    public void do_processflt()
    {
        if(instructions.empty())
        {
            return;
        }
        Instruction ins = instructions.peek().getIns();
        if(instructions.peek().getAddr() - module.base == dispatcher)
        {
            indexOrder.add(getRegValue("x8",instructions.peek().getRegs()).longValue());
        }
        if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("b.eq")) {
            InsAndCtx beq = instructions.peek();
            //等于跳转，检查是否为cmp x8,
            while (true)
            {
                if(instructions.empty())
                {
                    break;
                }
                instructions.pop();
                ins = instructions.peek().getIns();
                if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("cmp"))
                {
                    String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");
                    if(sp[0].equals("w8"))
                    {
                        //找到一个真实块
                        TrueBlock tb = new TrueBlock();
                        long regValue = getRegValue(sp[1].trim(), instructions.peek().getRegs()).longValue();
                        long targetAddr = 0;
                        String offset = beq.getIns().getOpStr().toLowerCase(Locale.ROOT);
                        long offsetvalue = getLongFromOpConst(offset);
                        targetAddr = beq.getAddr() + offsetvalue - module.base;
                        tb.setIndex(regValue);
                        tb.setStartAddr(targetAddr);
                        tbs.add(tb);
                        break;
                    }
                }
            }
        }
        //处理分支块
        if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("b"))
        {
            long offset = getLongFromOpConst(ins.getOpStr());
            if(offset != 0)
            {
                long target = offset + instructions.peek().getAddr() - module.base;
                //直接跳向主发生器
                if(target == dispatcher)
                {
                    instructions.pop();
                    ins = instructions.peek().getIns();
                    if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("csel"))
                    {
                        String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");
                        if(sp[0].trim().equals("w8"))
                        {
                            String cond = sp[3].trim();
                            String reg1 = sp[1].trim();
                            String reg2 = sp[2].trim();
                            selectBr sb = new selectBr();
                            sb.setInsaddr(instructions.peek().getAddr() - module.base);
                            sb.setCond(cond);
                            sb.setTrueindex(getRegValue(reg1,instructions.peek().getRegs()).longValue());
                            sb.setFalseindex(getRegValue(reg2,instructions.peek().getRegs()).longValue());
                            sbs.add(sb);
                        }
                    }
                }
            }
        }
    }
    private long getIndexAddr(long index)
    {
        for(TrueBlock tb:tbs)
        {
            if(tb.getIndex() == index)
            {
                return tb.getStartAddr();
            }
        }
        System.out.printf("not found addr for index:%x,result may be wrong!\n",index);
        return -1;
    }

    private void reorderblock()
    {
        tbs.add(new TrueBlock(0x6e142ec8L,0x5E6B0));
        tbs.add(new TrueBlock(0xf07b1447L,0x5E608));
        tbs.add(new TrueBlock(0x5d7b4e5aL,0x5E5E8));
        tbs.add(new TrueBlock(0x5ad22f2fL,0x5E628));

        for(TrueBlock tb:tbs)
        {
            System.out.printf("true block index %x,addr %x\n",tb.getIndex(),tb.getStartAddr());
        }
        for(selectBr sb:sbs)
        {
            System.out.printf("select block inds addr: %x,cond: %s . true for %x,false for %x\n",sb.getInsaddr(),sb.getCond(),sb.getTrueindex(),sb.getFalseindex());
        }
        for(long l:indexOrder)
        {
            System.out.printf("index order:%x\n",l);
        }

        for(selectBr sb:sbs)
        {
            String ins1 = "b" + sb.getCond() + " 0x"+Integer.toHexString((int) (getIndexAddr(sb.getTrueindex()) -  sb.getInsaddr()));
            String ins2 = "b 0x"+ Integer.toHexString((int) (getIndexAddr(sb.getFalseindex())-sb.getInsaddr()-4));
            patchs.add(new PatchIns(sb.getInsaddr(), ins1));
            patchs.add(new PatchIns(sb.getInsaddr() + 4, ins2));
        }

//        PatchIns pi = new PatchIns();
//        pi.setAddr(dispatcher);
//        pi.setIns("b 0x"+Integer.toHexString((int) (getIndexAddr(0x22f0693f)-dispatcher)));
//        patchs.add(pi);
//        PatchIns pie = new PatchIns();
//        pie.setAddr(toend);
//        pie.setIns("b 0x"+Integer.toHexString((int) (getIndexAddr(0x83a9af56L)- toend)));
//        patchs.add(pie);
//        PatchIns pie1 = new PatchIns();
//        pie1.setAddr(0x5E674L);
//        pie1.setIns("b 0x"+Integer.toHexString((int) (getIndexAddr(0x83a9af56L) - 0x5E674L)));
//        patchs.add(pie1);
    }

    public void do_processbr() {
        InsAndCtx insAndCtx =  instructions.peek();
        Instruction ins = insAndCtx.getIns();


        if(!ins.toString().equals("br x9")) {
            return ;
        }

        long br_ins_addr = instructions.peek().getAddr() - module.base;
        boolean finish = false;
        long base = -1;
        long list_offset = -1;
        long condT = -1;
        long condF = -1;
        String cond = "";
        long add_inst_addr = -1;

        long csel_inst_addr = -1;
        long ldr_inst_addr = -1;

        while (!finish && !instructions.empty()) {
            instructions.pop();
            ins = instructions.peek().getIns();
            String mnemonic = ins.getMnemonic().toLowerCase(Locale.ROOT);

            //定位add 指令
            if (ins.toString().equals("add x9, x9, x24")) {
                base = getRegValue("x24", instructions.peek().getRegs()).longValue();
                add_inst_addr = instructions.peek().getAddr() - module.base;
            }

            if (ins.toString().equals("ldr x9, [x19, x9]")) {
                list_offset = getRegValue("x19", instructions.peek().getRegs()).longValue() - module.base;
                ldr_inst_addr = instructions.peek().getAddr() - module.base;
            }


            //csel x9, x28, x23, lt
            if (mnemonic.equals("csel")) {
                String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");
                if (sp.length == 4) {
                    cond = sp[3].trim();
                    if (sp[0].trim().equals("x9")) {
                        String reg1 = sp[1].trim();
                        String reg2 = sp[2].trim();
                        condT = getRegValue(reg1, instructions.peek().getRegs()).longValue();
                        condF = getRegValue(reg2, instructions.peek().getRegs()).longValue();
                        csel_inst_addr = instructions.peek().getAddr() - module.base;
                    }
                }
            }


            if (ins.getMnemonic().trim().toLowerCase(Locale.ROOT).equals("cmp")) {
                if (base == -1 || list_offset == -1 || condT == -1 || condF == -1 || cond.equals("") || add_inst_addr == -1 || ldr_inst_addr == -1 || csel_inst_addr == -1) {
                    return;
                }

                long offsetT = base + readInt64(emulator.getBackend(), module.base + list_offset + condT) - module.base;
                long offsetF = base + readInt64(emulator.getBackend(), module.base + list_offset + condF) - module.base;
                if (br_ins_addr - add_inst_addr != 4) {
                    System.out.println("add ins and br ins gap more than 4 size,may make mistake");
                }
                String condBr = "b" + cond.toLowerCase(Locale.ROOT) + " 0x" + Integer.toHexString((int) (offsetT - add_inst_addr));
                String br = "b 0x" + Integer.toHexString((int) (offsetF - br_ins_addr));
                patchs.add(new PatchIns(add_inst_addr, condBr));
                patchs.add(new PatchIns(br_ins_addr, br));
                patchs.add(new PatchIns(csel_inst_addr, "nop"));
                patchs.add(new PatchIns(ldr_inst_addr, "nop"));
                finish = true;

            }
        }


    }

    public void processBr(long start, long end) {

        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                try{

                    Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                    byte[] bytes = emulator.getBackend().mem_read(address, 4);
                    Instruction[] disasm = capstone.disasm(bytes, 0);


                    String ins = String.format("0x%x: %s \r\n", (address - module.base), disasm[0].toString());
                    writer.write(ins);
                    writer.flush();

                    System.out.print(ins);
                    if(address - module.base == 0x62144) {
                        System.out.println("0x62144: W8  = " + backend.reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());
                        System.out.println("0x62144: W12 = " + backend.reg_read(Arm64Const.UC_ARM64_REG_W12).intValue());
                        //System.out.println("0x62138: W8 = " + getRegValue("W8", instructions.peek().getRegs()).intValue());
                        backend.reg_write(Arm64Const.UC_ARM64_REG_W8, 0);
                    }
                    if(address-module.base == 0x62190){

                    }


                    instructions.add(new InsAndCtx(address, disasm[0], saveRegs(backend)));
                    do_processbr();
                }catch (Throwable t){
                    t.printStackTrace();
                }

            }

            @Override
            public void onAttach(UnHook unHook) {
                System.out.println("attach");
            }

            @Override
            public void detach() {
                System.out.println("detach");
            }
        },module.base+start, module.base + end,null);
    }

    public static void main(String[] args) throws IOException {
        String inName = "/home/t/Desktop/unidbg/unidbg_libs/libtprt1.so";
        AntiOllvm ao = new AntiOllvm(inName);
        // ao.logIns();
        ao.processBr(0x61F14, 0x62170);
        //ao.processBr(0x61F14, 0x62150);
        ao.callJniOnload();
        ao.patch("/home/t/Desktop/unidbg/unidbg_libs/libtprt2.so");

        //ao.reorderblock();
        //ao.patch();
    }
}
