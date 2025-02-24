#!/usr/bin/env python
# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import messagebox
import time
import logging
import threading
import os
import telnetlib
from ftplib import FTP

"""
核心说明
1.UI 部分：
    和原先第一个脚本类似，提供两个按钮来选择“删除已设置参数”或“保留已设置参数”，并最终点击“开始升级”。
    这样做可以满足在升级 JSON 文件时，是否要删除设备上的旧配置文件（/mnt/cfg/*.json）的需求。
2.上传 .gz 文件并升级：
    在 upload_gz_files() 函数里，和第二个脚本类似，会去 localpath（比如 up_files）下搜索所有 .gz 文件，上传到设备后解压到同名文件夹，并调用 update.sh。
3.上传 JSON 文件：
    在 upload_feature_json() 函数中，遍历当前 up_files 目录下所有 .json 结尾的文件，如果存在，就将它们上传至目标设备指定目录（/mnt/data/upgrade/），然后执行替换 /opt/cvcam/feature.json 的命令。
    如果勾选了“删除已设置参数”，就会额外执行 rm -f /mnt/cfg/*.json。
4.线程与重启：
    为了可以并行升级多个设备，每个 IP 启动一个线程，执行完后设置线程事件（reboot_event），表示升级结束。
    所有线程升级完成后，再统一依次登陆设备执行 reboot。
    这样避免了在每个设备刚刚升级完就立刻重启，从而影响到其他设备升级进行中的并发操作。
5.文件位置：
    脚本默认读取与脚本同级的 ips.txt（存放设备 IP），也默认在与脚本同级的 up_files 目录下扫描 .json 与 .gz 文件。
"""

DEBUG = True  # 可以根据需要，决定是否打开调试日志

logging.basicConfig(
    level=logging.INFO,  # 设置为 INFO 级别，才能看到 logging.info 的输出
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# 全局变量用于记录第一次和第二次尝试升级失败的 IP
failed_ips_first_attempt = []
failed_ips_second_attempt = []
lock_failed_ips = threading.Lock()  # 锁用于保护 failed_ips 列表


def worker(host_ip, command, remotepath, localpath, reboot_event, delete_or_not, attempt):
    """
    每个线程里执行对单个设备的升级逻辑：
    1) 登录 telnet
    2) 先升级 .gz（如果有）
    3) 再升级 JSON（如果有）
    4) 设置事件标记 -> 表示升级完成
    5) 如果登录或升级失败，记录失败的 IP
    """
    telnet_client = TelnetClient('root', 'cvcam')
    success = telnet_client.process_all(
        host_ip=host_ip,
        command=command,
        remotepath=remotepath,
        localpath=localpath,
        reboot_event=reboot_event,
        delete_params=delete_or_not
    )
    if not success:
        # 登录或升级失败，记录失败的 IP
        with lock_failed_ips:
            if attempt == 1:
                failed_ips_first_attempt.append(host_ip)
                logging.info(f"[{host_ip}] 已记录为第一次尝试失败")
            elif attempt == 2:
                failed_ips_second_attempt.append(host_ip)
                logging.info(f"[{host_ip}] 已记录为第二次尝试失败")

#日志模块
def download_logs(ip, username, password):
    try:
        ftp = FTP(ip)
        ftp.login(user=username, passwd=password)
        ftp.cwd('/var/log')
        filenames = ftp.nlst()
        
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        for filename in filenames:
            local_filename = os.path.join('logs', f"{ip}_{filename}")
            with open(local_filename, 'wb') as f:
                ftp.retrbinary('RETR ' + filename, f.write)
        
        ftp.quit()
        print(f"Logs from {ip} downloaded successfully.")
    except Exception as e:
        print(f"Failed to download logs from {ip}: {e}")


class TelnetClient():
    lock = threading.Lock()  # 类级别共享锁

    def __init__(self, username, password):
        self.tn = telnetlib.Telnet()
        self.username = username
        self.password = password

    def login_host(self, host_ip):
        """
        Telnet 登录
        """
        try:
            self.tn.open(host_ip, port=23, timeout=10)
        except Exception as e:
            logging.warning(f'{host_ip} 网络连接失败: {e}')
            return False

        try:
            self.tn.read_until(b'login: ', timeout=10)
            self.tn.write(self.username.encode('ascii') + b'\n')
            self.tn.read_until(b'Password: ', timeout=10)
            self.tn.write(self.password.encode('ascii') + b'\n')

            time.sleep(3)
            command_result = self.tn.read_very_eager().decode('ascii')
            if 'Login incorrect' not in command_result:
                logging.info(f'{host_ip} 登录成功')
                return True
            else:
                logging.warning(f'{host_ip} 登录失败，用户名或密码错误')
                return False
        except Exception as e:
            logging.warning(f'{host_ip} 登录过程中出现异常: {e}')
            return False

    def execute_some_command(self, command, timeout=60):
        """
        统一执行命令的函数，带一个特殊的“cmd done flag”方便截断输出。
        """
        if DEBUG:
            logging.info(f"执行命令: {command}")
        self.tn.write(f"{command}\n".encode('ascii'))
        self.tn.write(b"echo 'cmd done flag 168168' | tr '[:lower:]' '[:upper:]'\n")
        try:
            command_result = self.tn.read_until(b"CMD DONE FLAG 168168", timeout=timeout).decode('ascii')
        except EOFError:
            logging.warning("连接被关闭，命令执行超时或异常")
            raise TimeoutError(f"命令执行超时或连接被关闭: {command}")

        if "CMD DONE FLAG 168168" not in command_result:
            logging.warning("命令执行超时")
            raise TimeoutError(f"命令执行超时: {command}")

        if DEBUG:
            logging.info(f'命令执行结果：\n{command_result}')
        return command_result

    def ftpConnect(self, ftpserver, port):
        """
        连接 FTP
        """
        ftp = FTP()
        try:
            ftp.connect(ftpserver, port, timeout=10)
            ftp.login(self.username, self.password)
        except Exception as e:
            raise IOError(f'{ftpserver} FTP连接失败: {e}')
        else:
            logging.info(f'{ftpserver} FTP连接成功')
            return ftp

    def remove_dirs(self, folder_path):
        """
        删除指定目录（含所有文件）
        """
        folder_path = folder_path + "*"
        command = f"rm -rf {folder_path}"
        try:
            res = self.execute_some_command(command)
            if DEBUG:
                logging.warning(res)
        except TimeoutError:
            logging.warning(f"删除 {folder_path} 时超时或异常")

    def verify_upload(self, ftp, remote_file, local_file, host_ip):
        """
        上传后校验本地、远程文件大小是否一致
        """
        local_size = os.path.getsize(local_file)
        remote_size = ftp.size(remote_file)

        if local_size != remote_size:
            raise IOError(f'{remote_file} [{host_ip}] 上传失败，文件大小不一致！')
        else:
            logging.info(f"{remote_file} [{host_ip}] 上传成功，文件大小一致。")

    def upload_feature_json(self, ftp, remotepath, localpath, host_ip, delete_params):
        """
        如果 localpath 目录下有 .json 文件，则进行上传并更新 /opt/cvcam/feature.json
        """
        found_json = False  # 是否找到 .json 文件的标记

        # 这里使用 os.walk 可以递归子目录
        for root, dirs, files in os.walk(localpath):
            for file in files:
                if file.endswith('.json'):
                    found_json = True
                    local_file = os.path.join(root, file)  # 本地完整路径
                    remote_file = os.path.join(remotepath, file)  # 远程完整路径（拼接）

                    # 上传
                    with open(local_file, 'rb') as fp:
                        ftp.storbinary(f'STOR {remote_file}', fp)

                    # 上传后验证
                    self.verify_upload(ftp, remote_file, local_file, host_ip)

                    # 根据是否要删除本地已设置的参数来组织命令
                    if delete_params:
                        # 删除参数升级
                        cmd_update_feature = (
                            f"mount -o remount,rw / && rm -f /opt/cvcam/feature.json && cp {remote_file} /opt/cvcam/feature.json;"
                            "rm -f /mnt/cfg/*.json;"
                        )
                    else:
                        # 保留参数升级
                        cmd_update_feature = (
                            f"mount -o remount,rw / && rm -f /opt/cvcam/feature.json && cp {remote_file} /opt/cvcam/feature.json;"
                        )

                    self.execute_some_command(cmd_update_feature)
        # 打印日志
        if found_json:
            logging.info(f"[{host_ip}] JSON 文件升级完成")
        else:
            logging.info(f"[{host_ip}] 未检测到 .json 文件，跳过 JSON 升级")

    def upload_gz_files(self, ftp, remotepath, localpath, host_ip):
        """
        如果 localpath 目录下有 .gz 文件，上传、解压并调用 `update.sh`
        """
        # 建立 /mnt/data/upgrade/
        self.execute_some_command(f"mkdir -p {remotepath}")
        # 搜索本地的所有 .gz 文件
        found_gz = False
        for root, dirs, files in os.walk(localpath):
            for file in files:
                if file.endswith(".gz"):
                    found_gz = True
                    local_file = os.path.join(root, file)
                    remote_file = remotepath + file

                    # 上传 gz 文件
                    with open(local_file, 'rb') as fp:
                        ftp.storbinary(f'STOR {remote_file}', fp)
                        ftp.set_debuglevel(0)

                    # 校验文件大小
                    self.verify_upload(ftp, remote_file, local_file, host_ip)

                    # 解压到同名文件夹
                    file_base = file.rstrip(".gz")
                    cmd_ungzip = (
                        f"mkdir -p {remotepath}{file_base} && "
                        f"tar -zxvf {remotepath}{file} -C {remotepath}{file_base}"
                    )

                    try:
                        res = self.execute_some_command(cmd_ungzip, timeout=120)
                        if "tar: Error" in res:
                            logging.warning(f"[{host_ip}] 解压文件 {file} 失败，错误信息：{res}")
                        else:
                            logging.info(f"[{host_ip}] 解压文件 {file} 成功")
                    except TimeoutError:
                        logging.warning(f"[{host_ip}] 解压文件 {file} 超时或异常")

                    # 调用 update.sh
                    update_sh = f"cd {remotepath}{file_base}/ && sh update.sh"
                    try:
                        res2 = self.execute_some_command(update_sh, timeout=120)
                        # 直接在 res2 里搜索关键字来判断
                        if "Update failed" in res2:
                            logging.error(f"[{host_ip}] {file_base} 升级失败，请检查相关日志")
                        else:
                            logging.info(f"[{host_ip}] {file_base} 升级成功")
                    except TimeoutError:
                        logging.warning(f"[{host_ip}] 执行 update.sh 超时或异常")

        if found_gz:
            logging.info(f"[{host_ip}] .gz 文件升级流程完成")
        else:
            logging.info(f"[{host_ip}] 未检测到 .gz 文件，跳过 .gz 升级")

    @staticmethod
    def get_ip():
        """
        从 ips.txt 文件中读取 IP 列表
        """
        lis = []
        try:
            with open("ips.txt", "r") as ips_file:
                for ip in ips_file.readlines():
                    ip = ip.strip()
                    if ip:
                        lis.append(ip)
            logging.info(f"读取到的 IP 列表: {lis}")
        except FileNotFoundError:
            logging.error("文件 'ips.txt' 未找到，请确保文件存在并包含设备 IP。")
        return lis

    def process_all(self, host_ip, command, remotepath, localpath, reboot_event, delete_params):
        """
        核心处理流程：
        1. 登录
        2. 执行开 FTP 等初始命令
        3. 删除旧文件
        4. 上传 JSON（如有）、更新 /opt/cvcam/feature.json
        5. 上传 .gz（如有），解压并执行 update.sh
        6. 升级完成后设事件，等待所有升级完成再统一重启
        返回值表示是否登录成功并成功升级
        """
        if self.login_host(host_ip):
            TelnetClient.lock.acquire()
            logging.info(f"[{host_ip}] 开始执行升级流程...")

            try:
                # 执行开 FTP 等操作
                self.execute_some_command(command)

                # 删除远端旧文件
                self.remove_dirs(remotepath)

                # 连接 FTP
                ftp = self.ftpConnect(host_ip, 21)

                # 1) 升级 .gz
                self.upload_gz_files(ftp, remotepath, localpath, host_ip)

                # 2) 升级 JSON
                self.upload_feature_json(ftp, remotepath, localpath, host_ip, delete_params)

                logging.info(f"===== [{host_ip}] ===== 升级流程完成")
                return True  # 登录并升级成功

            except Exception as e:
                logging.error(f"[{host_ip}] 升级出现异常：{e} !!!")
                return False  # 升级过程中出现异常

            finally:
                # 每个设备升级完成都 set 一下事件
                reboot_event.set()
                TelnetClient.lock.release()
        else:
            # 登录失败，设置事件
            reboot_event.set()
            return False  # 登录失败

    def reboot_all_devices(self, reboot_events, ips_list):
        """
        等待所有设备升级完成后，再统一给所有设备执行 reboot
        """
        logging.info("等待所有设备完成升级...")
        for event in reboot_events:
            event.wait()
        logging.info("所有设备升级完成，开始依次重启...")

        for ip in ips_list:
            if self.login_host(ip):
                try:
                    self.execute_some_command("mount -o remount,rw /")
                except Exception as e:
                    logging.warning(f"[{ip}] 执行 mount 命令时出现异常: {e}")
                try:
                    self.execute_some_command("reboot")
                    logging.info(f"[{ip}] 已发送重启命令")
                except Exception as e:
                    logging.warning(f"[{ip}] 执行重启命令时出现异常: {e}")
            else:
                logging.warning(f"无法登录 {ip}，跳过重启")


def main():
    root = tk.Tk()
    root.title("固件升级工具(GZ & JSON)_V3.3")
    root.geometry("500x400")  # 可以调整界面大小

    # 使用 BooleanVar 来保存当前是否“删除参数”；
    # False = 保留已设置参数（默认）
    # True  = 删除已设置参数
    delete_params = tk.BooleanVar(value=False)  # 默认选中“保留已设置参数”

    # 这几个列表在 main() 范围定义，子函数里无需 nonlocal，只要“操作同一个列表”即可
    threads = []
    reboot_events = []
    ips_list = []

    # 定义 init_command, remotepath, localpath 为 main() 的局部变量，供子函数使用
    init_command = (
        "mount -o remount,rw / && "
        "mount -o remount,rw /mnt/data/ && "
        "mkdir -p /mnt/data/upgrade/ && "
        "(pgrep -x tcpsvd > /dev/null || tcpsvd -vE 0.0.0.0 21 ftpd -w / &) && "
        "sync"
    )
    remotepath = "/mnt/data/upgrade/"
    localpath = r'up_files'  # 升级固件文件的目录

    # 定义第二次尝试失败的 IP 列表
    global failed_ips_second_attempt
    failed_ips_second_attempt = []

    def check_all_threads(attempt=1):
        """使用 root.after 轮询线程是否结束，从而不阻塞主线程"""
        all_done = all(not t.is_alive() for t in threads)
        if all_done and threads:
            # 所有线程都结束，进行统一重启操作
            telnet_client_for_reboot = TelnetClient('root', 'cvcam')
            telnet_client_for_reboot.reboot_all_devices(reboot_events, ips_list)
            logging.info("所有设备升级流程已完成")

            # 如果有第一次尝试失败的 IP，进行第二次尝试
            with lock_failed_ips:
                if attempt == 1 and failed_ips_first_attempt:
                    logging.info("开始对第一次登录失败的设备进行第二次尝试升级...")
                    # 记录第二次尝试失败的 IP
                    failed_ips_second_attempt.clear()

                    # 启动第二批线程
                    for host_ip in failed_ips_first_attempt:
                        logging.info(f"[{host_ip}] 开始第二次升级尝试...")
                        reboot_event = threading.Event()
                        reboot_events.append(reboot_event)
                        t = threading.Thread(
                            target=worker,
                            args=(host_ip, init_command, remotepath, localpath, reboot_event, delete_params.get(), 2)
                        )
                        t.daemon = True  # 守护线程
                        threads.append(t)
                        t.start()

                    # 清空第一次失败的列表
                    failed_ips_first_attempt.clear()

                    # 重新开始轮询，进行第二次尝试
                    root.after(200, lambda: check_all_threads(attempt=2))
                    return  # 退出当前函数，等待第二批线程完成

            # 如果是第二次尝试完成后，检查是否还有失败的设备
            with lock_failed_ips:
                if attempt == 2:
                    if failed_ips_second_attempt:
                        failed_str = ", ".join(failed_ips_second_attempt)
                        messagebox.showwarning("升级失败", f"以下设备升级失败：{failed_str}")
                        logging.error(f"升级失败的设备: {failed_str}")
                    else:
                        messagebox.showinfo("完成", "所有设备升级流程已完成！")

        else:
            # 还没结束，0.2 秒后继续检查
            root.after(200, lambda: check_all_threads(attempt=attempt))

    def start_upgrade():
        """点击“开始升级”后，启动线程但不阻塞"""
        # 清空旧数据（而不是重新赋值）
        threads.clear()
        reboot_events.clear()
        ips_list.clear()

        # 清空失败列表
        with lock_failed_ips:
            failed_ips_first_attempt.clear()
            failed_ips_second_attempt.clear()

        telnet_client = TelnetClient('root', 'cvcam')
        # 读取 IP
        new_ips = telnet_client.get_ip()
        ips_list.extend(new_ips)

        if not ips_list:
            messagebox.showerror("错误", "没有读取到任何设备 IP，请检查 ips.txt 文件。")
            return

        for host_ip in ips_list:
            logging.info(f"[{host_ip}] 开始升级...")
            reboot_event = threading.Event()
            reboot_events.append(reboot_event)
            t = threading.Thread(
                target=worker,
                args=(host_ip, init_command, remotepath, localpath, reboot_event, delete_params.get(), 1)
            )
            t.daemon = True  # 守护线程，主程序退出时不必等待它
            threads.append(t)
            t.start()

        # 异步轮询，而不是在这里阻塞
        check_all_threads(attempt=1)

    frame = tk.Frame(root)
    frame.pack(padx=20, pady=20)

    # 用 Radiobutton 来做互斥选择：删除 or 保留
    # value=True  对应“删除”，value=False 对应“保留”
    rdb_delete = tk.Radiobutton(
        frame,
        text="删除已设置参数",
        variable=delete_params,
        value=True
    )
    rdb_delete.grid(row=0, column=0, pady=5, padx=20)

    rdb_keep = tk.Radiobutton(
        frame,
        text="保留已设置参数",
        variable=delete_params,
        value=False
    )
    rdb_keep.grid(row=0, column=1, pady=5, padx=20)

    # “开始升级”按钮
    start_btn = tk.Button(frame, text="开始升级", command=start_upgrade, width=30)
    start_btn.grid(row=1, column=0, columnspan=2, pady=20)

    # 添加说明备注，两个标签各占一行，左对齐
    lbl_delete_desc = tk.Label(
        frame,
        text="删除已设置参数：多用于出厂升级时，以默认参数进行升级",
        wraplength=400,  # 根据窗口宽度调整换行长度
        justify="left",
        fg="blue"
    )
    lbl_delete_desc.grid(row=2, column=0, columnspan=2, pady=(0, 10), padx=20, sticky='w')

    lbl_keep_desc = tk.Label(
        frame,
        text="保留已设置参数：多用于现场升级，使用者对相机内部已有例如旋转、分辨率、帧率、osd叠加...已设置好的参数",
        wraplength=400,
        justify="left",
        fg="red"
    )
    lbl_keep_desc.grid(row=3, column=0, columnspan=2, pady=(0, 10), padx=20, sticky='w')

    root.mainloop()


if __name__ == '__main__':
    main()
