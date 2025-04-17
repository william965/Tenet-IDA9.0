# Unidbg Tracer 工具

感谢 Logan 大佬提供的 unidbg tracer 工具。

## 功能

生成符合Tenet格式的Trace文件

## 使用方法

### 1. 集成 Tracer.java

*   将 `Tracer.java` 文件复制到你的 unidbg 项目的源代码目录中。
*   **注意:** `Tracer.java` 文件顶部的包声明是 `package test.test.util;`。你需要根据你的项目结构修改这个包声明，例如修改为 `package com.yourcompany.unidbg.utils;`。
*   确保你的项目包含了 `unidbg` 核心库的依赖。`Tracer.java` 还导入了 `org.apache.commons.codec.binary.Hex`，虽然当前主要用于指令值的十六进制表示（已注释掉），但最好也确保相关依赖存在（通常 unidbg 会间接依赖）。

### 2. 在你的 Unidbg 代码中使用 Tracer

在你初始化 `Emulator` 和加载了目标 `Module` 之后，但在开始执行你想要跟踪的代码 *之前*，实例化并启动 `Tracer`。

```java
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
// 导入你修改包名后的 Tracer 类
// import com.yourcompany.unidbg.utils.Tracer;
import test.test.util.Tracer; // 假设你没有修改包名

import java.io.File;
import java.io.IOException;

public class YourUnidbgApp {

    public static void main(String[] args) throws IOException {
        // 1. 初始化 Unidbg 模拟器
        Emulator<?> emulator = AndroidEmulatorBuilder.for64Bit().build(); // 以 ARM64 为例
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23)); // 设置 API Level

        // 2. 创建 DVM 和 VM
        VM vm = emulator.createDalvikVM(new File("path/to/your/apk")); // 如果需要 APK 环境
        // vm.setVerbose(true); // 开启 Unidbg 自身的日志（可选）

        // 3. 加载目标 SO 库
        File soFile = new File("path/to/your/libexample.so");
        DalvikModule dm = vm.loadLibrary(soFile, true); // 加载库
        Module module = dm.getModule(); // 获取 Module 对象

        // 4. 实例化 Tracer
        // 参数: emulator, module (要跟踪的模块), 输出日志路径, 是否在控制台打印日志
        String logFilePath = "tracer_output.log"; // 指定日志输出文件
        boolean logToConsole = false; // true 会同时打印到控制台
        Tracer tracer = new Tracer(emulator, module, logFilePath, logToConsole);

        // 5. 启动跟踪 (!!! 必须在调用目标函数之前 !!!)
        tracer.trace();

        // 6. 调用你想要跟踪的 SO 库中的函数
        System.out.println("Calling JNI function...");
        // 例如: module.callEntry(emulator);
        // 或者: dm.callJniMethod(emulator, "Java_com_example_NativeClass_targetFunction(I)V", 123);

        // 7. 清理资源
        System.out.println("Execution finished. Tracer log saved to: " + logFilePath);
        emulator.close();
    }
}
```

### 构造函数参数详解

*   `Emulator emulator`: 当前的 `unidbg` 模拟器实例。
*   `Module module`: 你想要跟踪的目标 `Module` 对象。可以通过 `emulator.getMemory().findModule("libname.so")` 或 `DalvikModule.getModule()` 获取。如果传入 `null`，Tracer 会尝试跟踪所有地址范围的代码（通常不推荐，会导致日志量巨大且难以分析）。
*   `String out_path`: 指定跟踪日志输出文件的完整路径。文件会被创建（如果不存在）或覆盖（如果已存在）。
*   `boolean isLog`: 设置为 `true` 时，除了写入文件，跟踪信息也会实时打印到 Java 控制台。

### 启动跟踪

调用 `tracer.trace()` 方法会注册必要的钩子（Hooks）到 `unidbg` 的后端（Backend）。之后，模拟器执行的每一条在指定 `module` 地址范围内的指令，以及所有的内存读写操作，都会被记录下来。

## 日志格式说明

输出的日志文件 (`out_path`) 包含以下格式的信息：

1.  **文件头 (如果提供了 `module`):**
    ```
    # SO: <模块名> @ <模块基地址>
    ```
    例如: `# SO: libexample.so @ 0x40000000`

2.  **每行跟踪记录:**
    每一行代表目标模块中一条指令 *执行前* 的状态快照。格式如下：
    ```
    Reg1=0xValue1,Reg2=0xValue2,...,RegN=0xValueN,mr=Addr1:Value1,mw=Addr2:Value2,mr=Addr3:Value3,...
    ```
    *   `RegX=0xValueX`: 表示各个 ARM64 寄存器（X0-X30, PC, NZCV）及其十六进制值。
    *   `mr=Addr:Value`: 表示在 *上一条* 指令执行期间发生的 **内存读取** 操作。`Addr` 是读取的内存地址（十六进制），`Value` 是读取到的值（十进制无符号数）。
    *   `mw=Addr:Value`: 表示在 *上一条* 指令执行期间发生的 **内存写入** 操作。`Addr` 是写入的内存地址（十六进制），`Value` 是写入的值（十进制无符号数）。
    *   一行中可能包含多个 `mr` 和 `mw` 条目，表示上一条指令执行期间有多次内存访问。

## 注意事项

*   **包名:** 请务必根据你的项目结构修改 `Tracer.java` 文件头部的 `package` 声明。
*   **性能:** 启用跟踪会显著增加模拟执行的开销，导致程序运行速度变慢。
*   **日志大小:** 对于复杂或长时间运行的任务，生成的日志文件可能会非常大。请确保有足够的磁盘空间。
*   **环境:** 确保你的 `unidbg` 环境已正确配置并可以正常运行。
*   **ARM64:** 当前版本的 `Tracer.java` 主要针对 ARM64 架构设计（使用了 `Arm64Const`）。如果用于其他架构（如 ARM32），可能需要进行适配。
*   **符号查找:** `getSymbolByAddr` 方法在当前代码中被注释掉了。如果需要显示地址对应的符号信息，可以取消注释相关代码，但这可能会进一步影响性能。
