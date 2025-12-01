# yhsearch
简单的银狐病毒检测工具，用于排查电脑是否中了银狐木马。

其原理就是使用网上历史银狐木马执行后释放的病毒文件和恶意IP来判断电脑是否中了银狐木马，**没有查杀功能，只有检查功能**。

**情报来源：https://www.kdocs.cn/l/coHIXmgRe2u4**

工具原理：
1、根据网上大佬们提供的情报，查找对应目录下是否存在情报中的恶意文件，以及对比文件hash。
<img width="1920" height="879" alt="image" src="https://github.com/user-attachments/assets/deab4821-6004-49c8-bd61-4281cd567063" />

2、获取系统外联IP（类似netstat获取），获取的IP与威胁情报中的恶意IP进行对比，查看是否存在外联的恶意IP，如果存在，则尝试获取外联进程、程序位置、程序执行的命令、父进程、父进程位置等信息。
<img width="1920" height="879" alt="image" src="https://github.com/user-attachments/assets/993d6116-a3ab-4902-a714-a6356b4a83b9" />

运行结果展示（懒得找银狐病毒来测试，有bug，反馈。）
<img width="454" height="544" alt="image" src="https://github.com/user-attachments/assets/4a1f5649-56f7-4168-b756-d76e64641582" />
