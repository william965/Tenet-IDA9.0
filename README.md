# Tenet Trace Explorer (修改版)

本项目是对 [Tenet Trace Explorer](https://github.com/gaasedelen/tenet) 的修改版本，进行了一些改进和适配。

## 效果图

### 对抗虚假控制流、各种未知的混淆

使用单步执行可以有效对抗这些混淆。

![image-20250413124003343](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554975.png)

### 分析算法

分析算法时可便捷查看内存变化信息。

![image-20250413124106913](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554993.png)

### 时间回溯调试

支持向上单步、向下单步以及时间回溯。

![CleanShot_2025_04_13_at_12_42_13](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554004.png)

*   红色为已经走过的路径。
*   蓝色为未来要走的路径。

例如，我们可以明确知道 `BLR X8` 跳转到了 `B.CS`，并且知道 `B.CS` 进行了向左的分支跳转。

### 寄存器跟踪

![CleanShot_2025_04_13_at_15_50_56](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554015.png)

有两个左右的小按钮，可以找涉及到这个寄存器的上一条汇编的位置

### 时间旅行

![CleanShot_2025_04_13_at_15_52_14](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554026.png)

## 主要改动

1.  支持了 AArch64 架构的 Trace 格式导入。
2.  解决了 ASLR 地址随机化后的基地址识别问题。
3.  增加了单步调试等多个快捷键。
4.  修复了原版存在的一些 Bug。
5.  支持 IDA Pro 8.x 及 9.0。
6.  美化了部分 UI 显示。

## 如何使用

1.  **安装插件**
    *   在 IDA Python 窗口输入以下命令获取插件目录路径：
        ```python
        import idaapi, os; print(os.path.join(idaapi.get_user_idadir(), "plugins"))
        ```
    *   将 `tenet` 文件夹和 `tenet_plugin.py` 文件一起复制到上一步获取的 `plugins` 文件夹中。
    *   重启 IDA Pro。

2.  **加载 Trace 文件**
    *   打开 `demo` 文件夹，将 `libRequestEncoder.so` 文件拖入 IDA Pro 进行分析。
    *   在 IDA 窗口左上角选择 `File -> Load File -> Tenet Trace File`。
    *   选择 `demo` 文件夹中的 `log.txt` 文件打开。

3.  **开始追踪**
    *   在 IDA 右下角的 `Position` 输入框中输入 `1`，跳转到 Trace 的起始位置。
    *   或者使用快捷键（见下文）开始单步调试。

## 快捷键

![Shortcuts Configuration](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554037.png)

![Shortcuts List](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554046.png)

*   `prev_insn`: 回到上一个执行位置。
*   `step_into`: 步入（F7）。
*   `step_out`: 步出函数（有 Bug）。
*   `step_over`: 步过（F8）。
*   `next_execution`: 跳转到当前选中地址的下一次执行位置。
    *   例如，在以下循环中：
        ```c
        for(int i=0; i<10; i++){
            printf("%d\n", i); // 假设当前选中此行
        }
        ```
    *   如果当前 `i` 的值是 `0`，在 `printf` 行使用 `next_execution` 快捷键，则会直接跳转到下一次执行 `printf` 时（即 `i` 为 `1` 时）的状态。

## 更多实用技巧（原版作者）

请参考原版作者的博客文章：
[Tenet: A Trace Explorer for Reverse Engineers](https://blog.ret2.io/2021/04/20/tenet-trace-explorer/)

## Trace 格式

Trace 文件的格式规范可以参考原版仓库中的 `tracers` 目录：
[https://github.com/gaasedelen/tenet/tree/master/tracers](https://github.com/gaasedelen/tenet/tree/master/tracers)

**注意：** 本项目使用的 Trace 格式针对 ASLR 进行了定制修改。请参考 `demo` 文件夹中 `log.txt` 的第一行输出格式。其他部分与原版作者的格式保持一致。