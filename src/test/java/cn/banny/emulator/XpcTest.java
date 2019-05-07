package cn.banny.emulator;

import cn.banny.emulator.ios.DarwinARMEmulator;
import cn.banny.emulator.ios.DarwinResolver;
import cn.banny.emulator.memory.MemoryBlock;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;

import java.io.File;

public class XpcTest extends EmulatorTest {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver("7.1");
    }

    @Override
    protected Emulator createARMEmulator() {
        return new DarwinARMEmulator();
    }

    public void testXpc() throws Exception {
//        emulator.attach().addBreakPoint(null, 0x403b7dfc);
//        emulator.traceCode();
        emulator.getMemory().setCallInitFunction();
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/xpc"));

        Symbol malloc_default_zone = module.findSymbolByName("_malloc_default_zone");
        Pointer zone = UnicornPointer.pointer(emulator, malloc_default_zone.call(emulator)[0].intValue());
        assertNotNull(zone);
        System.err.println("_malloc_default_zone zone=" + zone);

        long start = System.currentTimeMillis();
//        emulator.traceCode();
        int ret = module.callEntry(emulator);
        System.err.println("xpc ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        MemoryBlock[] blocks = new MemoryBlock[0x40];
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = emulator.getMemory().malloc(1, false);
            System.out.println("Test block=" + blocks[i].getPointer());
        }
//        emulator.traceCode();
        emulator.attach().addBreakPoint(null, 0x40415dd2);
        for (MemoryBlock block : blocks) {
            block.free(false);
        }
    }

    public static void main(String[] args) throws Exception {
        XpcTest test = new XpcTest();
        test.setUp();
        test.testXpc();
        test.tearDown();
    }

}