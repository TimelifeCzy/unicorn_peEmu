### Unicorn ：

&emsp;&emsp;学习笔记，基于Unicorn封装一套PE分析环境，Unicorn提供了Cpu仿真能力。

### 代码思路：

&emsp;&emsp;仿真和传统概念os有诸多不同，代码访问os所需要资源数据，都要虚拟内存中构造，包括Peb/Teb/Ldr/线程管理/堆管理/句柄管理/文件管理/多线程/异步同步/Api模拟等等，经过几周的踩坑和Heisenberg师傅的耐心知道，写了个轮子demo，基础环境执行需要如下几个模块：

1. 进程空间栈/堆空间/GDT/代码映射。
2. 初始化PEB/TEB/PEB_LDR__DATA/Register。
3. 加载导入SystemDLL - 修复IAT重定位(虚拟地址)
4. 样本自身的Iat/重定位。
5. 设置函数回调，处理Api执行。
6. 异常处理

###### 代码不完善，还不能运行到oep，近期补齐。

### 参考源码：

unicorn: https://github.com/unicorn-engine/unicorn

unicorn_pe: https://github.com/hzqst/unicorn_pe

