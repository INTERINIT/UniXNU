小米平板6S Pro（sheng）/ iPadOS 27.0.1（24A446）实验候选包

首次安装
1. 手动进入平板的 FASTBOOT 界面，保持 USB 连接，双击 Flash.cmd。
   这会用27替换现有 userdata（包括平板上的17及其设置）；电脑上的17参考资料保留。
2. 进入 UniXNU 菜单后，选择 First install - initialize iPadOS Data，
   再确认 Erase iPadOS Data and boot。新 Data 只初始化这一次。

以后启动
先手动进入 FASTBOOT 并连接 USB，再双击 Boot.cmd，
然后选择 iPadOS 27.0.1 - GPU and persistent Data。
这只从 RAM 启动，不重刷根卷、不清除 Data；不要反复选择 First install。
请保留包内的 install-state.json，它记录本次安装。

菜单默认停在 Tools，需手动选择系统项。
GPU／Metal 和持久化 Data 已启用，实际启动、图形和外设可用性仍需实机测试。
当前内核仍有未映射引用，可能在启动中停止；构建成功不代表已在平板上启动成功。

Check.cmd 可单独检查电脑上的包文件，不连接或操作平板。
出现错误时，保留脚本显示的日志和最后画面，不要反复运行 Flash.cmd。

电脑需有 Python 3.11 或更新版本。脚本会使用已有 py/python 或包内 tools\python\python.exe。
fastboot 优先使用 D:\platform-tools\fastboot.exe。刷写入口仅处理 userdata，不修改其他启动分区。
