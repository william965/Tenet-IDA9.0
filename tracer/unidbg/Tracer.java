package test.test.util;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.*;
import org.apache.commons.codec.binary.Hex;
import unicorn.Arm64Const;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;
public class Tracer {
    Emulator emulator;
    String out_path;
    FileOutputStream log_stream;
    long base;
    long end;
    long init_sp;
    static int memIndex = 0;
    boolean isLog = false;
    Module module;
    boolean isStart = false;
    String pre_instr;
    String mem_record;
    long pos = 0;
    StringBuilder record = new StringBuilder();
    private Map<Integer, String> REGS = new HashMap<Integer, String>() {{
        put(Arm64Const.UC_ARM64_REG_X0, "X0");
        put(Arm64Const.UC_ARM64_REG_X1, "X1");
        put(Arm64Const.UC_ARM64_REG_X2, "X2");
        put(Arm64Const.UC_ARM64_REG_X3, "X3");
        put(Arm64Const.UC_ARM64_REG_X4, "X4");
        put(Arm64Const.UC_ARM64_REG_X5, "X5");
        put(Arm64Const.UC_ARM64_REG_X6, "X6");
        put(Arm64Const.UC_ARM64_REG_X7, "X7");
        put(Arm64Const.UC_ARM64_REG_X8, "X8");
        put(Arm64Const.UC_ARM64_REG_X9, "X9");
        put(Arm64Const.UC_ARM64_REG_X10, "X10");
        put(Arm64Const.UC_ARM64_REG_X11, "X11");
        put(Arm64Const.UC_ARM64_REG_X12, "X12");
        put(Arm64Const.UC_ARM64_REG_X13, "X13");
        put(Arm64Const.UC_ARM64_REG_X14, "X14");
        put(Arm64Const.UC_ARM64_REG_X15, "X15");
        put(Arm64Const.UC_ARM64_REG_X16, "X16");
        put(Arm64Const.UC_ARM64_REG_X17, "X17");
        put(Arm64Const.UC_ARM64_REG_X18, "X18");
        put(Arm64Const.UC_ARM64_REG_X19, "X19");
        put(Arm64Const.UC_ARM64_REG_X20, "X20");
        put(Arm64Const.UC_ARM64_REG_X21, "X21");
        put(Arm64Const.UC_ARM64_REG_X22, "X22");
        put(Arm64Const.UC_ARM64_REG_X23, "X23");
        put(Arm64Const.UC_ARM64_REG_X24, "X24");
        put(Arm64Const.UC_ARM64_REG_X25, "X25");
        put(Arm64Const.UC_ARM64_REG_X26, "X26");
        put(Arm64Const.UC_ARM64_REG_X27, "X27");
        put(Arm64Const.UC_ARM64_REG_X28, "X28");
        put(Arm64Const.UC_ARM64_REG_LR, "X29");
        put(Arm64Const.UC_ARM64_REG_FP, "X30");
        put(Arm64Const.UC_ARM64_REG_PC, "PC");
        put(Arm64Const.UC_ARM64_REG_NZCV, "NZCV");
    }};
  
          
    public Tracer(Emulator emulator, Module module, String out_path, boolean isLog) {
        this.emulator = emulator;
        this.out_path = out_path;
        this.isLog = isLog;
        this.module = module;
        try {
            this.log_stream =  new FileOutputStream(this.out_path);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        init_sp = emulator.getContext().getStackPointer().peer;
  
        if (module == null) {
            base = 0;
            end = -1;
            return;
        }
        base = module.base;
        end = base + module.size;

        String one = String.format("# SO: %s @ 0x%x", "libwb-native-lib.so", module.base);
        writeTrace(one);
    }
  
    public String getSymbolByAddr(long addr) {
  
        try {
            Symbol symbol = emulator.getMemory().findModuleByAddress(addr).findClosestSymbolByAddress(addr, false);
            long offset = addr - symbol.getAddress();
            if (offset >= 0x1000) return null;
            return String.format("%s+%x", symbol, offset);
        } catch (Exception e) {
            //ignore
            return null;
        }
    }
  
    public String getRegs(Backend backend) {
        StringBuilder ret = new StringBuilder();
  
        REGS.forEach((id, s) -> {
            long v = backend.reg_read(id).longValue();
//            String symbol = getSymbolByAddr(v);
//            if (symbol == null) {
//                ret.append(String.format("%s=%x,",s, v));
//            } else {
//                ret.append(String.format("%s=%x:%s,", s,v, symbol));
//            }
//            if(v>module.base && v < module.base + module.size && id !=Arm64Const.UC_ARM64_REG_PC ){
//                v = v - module.base;
//            }
            ret.append(String.format("%s=0x%x,",s, v));
        });
        return ret.toString();
    }
  
    private void writeTrace(String data){
        try {
            if (this.isLog){
                System.out.println(data);
            }
            this.log_stream.write(data.getBytes());
            this.log_stream.write('\n');
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public void trace() {
  
        // here is pre hook
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                String instrValue = Hex.encodeHexString(backend.mem_read(address, 4));
                //                Instruction instr = emulator.disassemble(address, 4, 1)[0];
//                if (!isStart) {
//                    //pre_instr = String.format("%s instr=%x:%s,", instr.toString(), address, instrValue);
//                    String symbolByAddr = getSymbolByAddr(address);
//                    if (symbolByAddr != null) {
//                        pre_instr = String.format("inst=%x:%s:%s,",  address, instrValue, symbolByAddr);
//                    }else {
//                        pre_instr = String.format("inst=%x:%s,",  address, instrValue);
//                    }
//                    isStart = true;
//                    return;
//                }
                String now_reg = getRegs(backend);
  
                record.append(now_reg)
                      .append(mem_record);
  
                writeTrace(record.toString());
                record = new StringBuilder();
                pos += 1;
                mem_record = "";
                //pre_instr = String.format("inst=%x:%s,",  address, instrValue);
            }
  
            @Override
            public void onAttach(UnHook unHook) {
            }
            @Override
            public void detach() {
  
            }
        }, module.base, module.size, null);
  
        emulator.getBackend().hook_add_new(new ReadHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                Class c;
                byte[] bytes = backend.mem_read(address, size);
                String v;
                switch (size) {
                    case 1:
                        c = Byte.class;
                        v = String.valueOf(bytes[0] & 0xFF);
                        break;
                    case 2:
                        c = Short.class;
                        Number number = bytesToNumber(bytes, c, ByteOrder.LITTLE_ENDIAN);
                        v = String.valueOf(Short.toUnsignedInt(number.shortValue()));
                        break;
                    case 4:
                        c = Integer.class;
                        int i = bytesToNumber(bytes, c, ByteOrder.LITTLE_ENDIAN).intValue();
                        v = Integer.toUnsignedString(i);
  
                        break;
                    case 8:
                        c = Long.class;
                        long L = bytesToNumber(bytes, c, ByteOrder.LITTLE_ENDIAN).longValue();
                        v = Long.toUnsignedString(L);
  
                        break;
                    default:
                        throw new IllegalStateException("convert mem bytes, size=" + size);
                }
                //mem_record += String.format("mr=%x:%s:%d,", address, v, size);
                mem_record += String.format("mr=%x:%s,", address, v);
            }
            @Override
            public void onAttach(UnHook unHook) {}
            @Override
            public void detach() {}
        }, 0, -1, null);
  
        emulator.getBackend().hook_add_new(new WriteHook() {
            @Override
            public void hook(Backend backend, long address, int size, long value, Object user) {
                //mem_record += String.format("mw=%x:%s:%d,", address, Long.toUnsignedString(value), size);
                mem_record += String.format("mw=%x:%s,", address, Long.toUnsignedString(value));
            }
  
            @Override
            public void onAttach(UnHook unHook) {}
            @Override
            public void detach() {}
        }, 0, -1, null);
    }
    public static short bytesToShort(byte[] bytes, int start, ByteOrder byteOrder) {
        return ByteOrder.LITTLE_ENDIAN == byteOrder ? (short)(bytes[start] & 255 | (bytes[start + 1] & 255) << 8) : (short)(bytes[start + 1] & 255 | (bytes[start] & 255) << 8);
    }
    public static int bytesToInt(byte[] bytes, int start, ByteOrder byteOrder) {
        return ByteOrder.LITTLE_ENDIAN == byteOrder ? bytes[start] & 255 | (bytes[1 + start] & 255) << 8 | (bytes[2 + start] & 255) << 16 | (bytes[3 + start] & 255) << 24 : bytes[3 + start] & 255 | (bytes[2 + start] & 255) << 8 | (bytes[1 + start] & 255) << 16 | (bytes[start] & 255) << 24;
    }
    public static long bytesToLong(byte[] bytes, int start, ByteOrder byteOrder) {
        long values = 0L;
        int i;
        if (ByteOrder.LITTLE_ENDIAN == byteOrder) {
            for(i = 7; i >= 0; --i) {
                values <<= 8;
                values |= (long)(bytes[i + start] & 255);
            }
        } else {
            for(i = 0; i < 8; ++i) {
                values <<= 8;
                values |= (long)(bytes[i + start] & 255);
            }
        }
        return values;
    }
    public static <T extends Number> T bytesToNumber(byte[] bytes, Class<T> targetClass, ByteOrder byteOrder) throws IllegalArgumentException {
        Object number = null;
        if (Byte.class == targetClass) {
            number = bytes[0];
        } else if (Short.class == targetClass) {
            number = bytesToShort(bytes,0, byteOrder);
        } else if (Integer.class == targetClass) {
            number = bytesToInt(bytes, 0,byteOrder);
        } else if (Long.class == targetClass) {
            number = bytesToLong(bytes, 0,byteOrder);
        } else {
            if (Number.class != targetClass) {
                throw new IllegalArgumentException("Unsupported Number type: " + targetClass.getName());
            }
        }
        return (T) number;
    }
}