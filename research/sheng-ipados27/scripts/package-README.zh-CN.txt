sheng / iPadOS 27.0.1（24A446）实验候选包

仅当同目录 manifest.json 的 status 为 assembled 且 Check.cmd 通过时，才是完整的本地候选包。
host_verified 表示主机校验通过，仍需实机验证启动、GPU、触摸和持久化 Data。

Check.cmd
  只核对本地文件、哈希、容器、认证策略和稀疏镜像，不连接或操作平板。

Flash.cmd
  首次安装入口。请先把平板手动置于 bootloader FASTBOOT 并连接电脑。
  脚本核对指定设备、解锁状态、userdata 精确容量和下载缓冲区。
  仅刷写 userdata，再从 RAM 启动 boot 镜像。
  此操作会替换平板上原有的 17 根卷及 Data；电脑上的 17 参考资料不受影响。
  不修改 GPT、boot、vendor_boot、vbmeta、ABL、XBL 或槽位。

Boot.cmd
  已安装后的启动入口。只从 RAM 启动匹配的 boot，不重刷根卷或清除 Data。
  系统正常运行时会向持久化 Data 写入设置和文件。
  需要同目录中与本次安装匹配的 install-state.json。

首次进入 UniXNU 菜单
  菜单默认停在 Tools，不会自动进入内核。
  新建 Data 只初始化一次：选择 First install - initialize iPadOS Data，确认 Erase iPadOS Data and boot。
  之后每次启动均选择 iPadOS 27.0.1 - GPU and persistent Data。
  正常 Boot 不带 sheng-data-reset，不能反复选择 First install。

本候选启用 GPU／Metal 和持久化 Data。显示比例、联网和其他外设以实机结果为准。
出现停滞、错误或黑屏时保留最后画面和日志；不要用 Flash.cmd 反复重写 userdata。
刷写中断会保留失败/未完成的安装记录，防止误清 Data；先排查记录，再决定如何恢复。

使用电脑已有的 fastboot，优先 D:\platform-tools\fastboot.exe，或通过 --fastboot 指定。
Python 需要 3.11 或更新版本；可使用同目录 tools\python\python.exe，也可使用已安装的 py/python。
以上脚本不会自动执行，准备完成后等待用户回来测试。
