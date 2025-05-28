import cmd
import datetime
import ipaddress
import shlex
from tkinter import messagebox
import matplotlib.pyplot as plt
import os
import pandas
import random
import re
import requests
import subprocess
import time
import threading
import webbrowser
import tkinter as tk
import tempfile
import shutil
import psutil
import numpy as np
from urllib.parse import urlparse


import mysql.connector

from bs4 import BeautifulSoup as bp
from functools import partial
from fpdf import FPDF
from pylab import title, figure, xlabel, ylabel, xticks, bar, legend, axis, savefig
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinter import ttk, filedialog
from selenium import webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from webdriver_manager.firefox import GeckoDriverManager



mydb = mysql.connector.connect(
    host="localhost",
    user="nikto",
    passwd="projectuse",
    database="project",
    charset='utf8mb4',
    collation='utf8mb4_general_ci'
)

mydb = mysql.connector.connect(
    host="localhost",
    user="nikto",
    passwd="projectuse",
    database="project",
    charset='utf8mb4',
    collation='utf8mb4_general_ci'
)

# Nikto RE
instrest_list_n = ["Php", "CVE", "Backdoor",]
instrest_list_re = [r"phpinfo()", r"OSVDB-", r"backdoor",]

instrest_list_content = []
instrest_list_count = []

item_list_count = []
res_list = []
cve_list = {} # {"3555":234, "4559":213}
cve_content = []
url_path = []

def run_nikto():
    result_text.delete('1.0', tk.END)
    t = threading.Thread(target = rnikto)    
    t.start()

def reset():
    en_target.delete(0, tk.END)
    #port_80.set(0)
    #port_443.set(0)
    #port_8080.set(0)
    en_dir.delete(0, tk.END)
    # clear_evasion()
    clear_tuning()
    # clear_chart()
    cb_output.set("")
    clear()
    
def clear():
    clear_value()
    clear_instrest()
    clear_result()
    clear_result_text()
    # clear_evasion()
    clear_tuning()  
    clear_chart()
    clear_sec()
    clear_table()

def clear_value():
    res_list.clear()
    item_list_count.clear()
    unlock_entry()
    for i in range(len(instrest_list_content)):
        instrest_list_content[i].clear()
        instrest_list_count[i] = 0
    cve_list.clear()
    cve_content.clear()
    # for item in cve_content:
    #     item.clear()

def clear_instrest():
    for i in range(len(instrest_list_value_n)):
        instrest_list_value_n[i].delete(0, tk.END)

def clear_result():
    for i in range(len(result_list_value_n)):
        result_list_value_n[i].delete(0, tk.END)

def clear_result_text():
    result_text.delete('1.0', tk.END)

def clear_sec():
    en_sec.delete(0, tk.END)
    en_sec.config(fg = "black", background = "white")

def clear_table():
    x = st.get_children()
    for item in x:
        st.delete(item)
# def clear_evasion():
#     for i in range(len(evasion_list_value_n)):
#         evasion_list_value_n[i].set(0)

def clear_tuning():
    for i in range(len(tuning_list_value_n)):
        tuning_list_value_n[i].set(0)


def valid_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
           if re.match(r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$',target):
            return True
    return False

def get_target():
    raw_target = en_target.get().strip()
    parsed_url = urlparse(raw_target)
    if not parsed_url.scheme:
        parsed_url = urlparse(f"http://{raw_target}")
    
    host = parsed_url.hostname
    if not host:
        return raw_target, False
    
    port = parsed_url.port
    path = parsed_url.path

    
    target_cmd = f" -h {host}"
    if port:
        target_cmd += f" -port {port}"
    if path:
        target_cmd += f" -root {path}"

        if valid_target(host):
            return target_cmd, True
        else:
            return raw_target, False

# def get_evasion():
#     optlen = 0
#     cmd_e = " -e "
#     for i in range(len(evasion_list_value_n)):
#         if (evasion_list_value_n[i].get() == 1):
#             if (optlen != 0):
#                 cmd_e += ","
#             if (i == 10):
#                 cmd_t += "0"
#             elif (i == 11):
#                 cmd_e += "a"
#             else:
#                 cmd_e += str(i+1)
#             optlen += 1
#     if (optlen == 0):
#         return ""
#     return cmd_e

def get_tuning():
    optlent = 0
    cmd_t = " -Tuning "
    for i in range(len(tuning_list_value_n)):
        if (tuning_list_value_n[i].get() == 1):
            if i == 0:
                cmd_t += "4"
            else:
                cmd_t += "c"
            optlent += 1
    if (optlent == 0):
        return ""
    return cmd_t

# def get_port():
#     porta = port_80.get()
#     portb = port_443.get()
#     portc = port_8080.get()
#     port_count = 0
#     port_cmd = " -p "
#     if porta == 1:
#         port_cmd += "80"
#         port_count = 1
#     if portb == 1:
#         if port_count == 1:
#             port_cmd += ','
#         port_cmd += "443"
#         port_count = 1
#     if portc == 1:
#         if port_count == 1:
#             port_cmd += ','
#         port_cmd += "8080"
#         port_count = 1
#     # Default using 80
#     if port_count == 0:
#         port_cmd += "80"
#     return port_cmd

def get_save():
    save_dir = en_dir.get()
    if (save_dir != ""):
        save_format = cb_output.get()
        name = str(datetime.datetime.today()).replace(" ", "_")
        return " -o " + save_dir + name + "." +save_format
    else:
        return ""

def lock_entry():
    for item in result_list_value_n:
        item.config(state="readonly")

def unlock_entry():
    for item in result_list_value_n:
        item.config(state="normal")

def rnikto():
    target_cmd, check = get_target()
    if check == False:
        result_text.insert(tk.END, f"Error: Invalid IP: {target_cmd}\n")
        return
    #port = get_port()
        # cmd_e = ""
        # cmd_e = get_evasion()
    cmd_t = get_tuning()
        # cmd_t = ""
    cmd_s = get_save()
    cmd = f"nikto {target_cmd} {cmd_t}{cmd_s} -ask no"
    result_text.insert(tk.END, "Nikto process Scanning...\n")
    result_text.insert(tk.END, "Using option " + cmd + "\n")

    nik = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True, stdin=subprocess.PIPE)
        # nik.stdin.write(b"y\n")
        # nik.stdin.write(b"y\n")
    (output, error) = nik.communicate()# Table
    if output:
            msg1 = output.decode('utf-8', errors='replace')
            test = msg1.split('\n')
            root.after(0, lambda: display_result(test, cmd))
            db_content = '||NEWLINE||'.join(test)
    for i in range(len(test)):
            db_content += test[i]
            db_content += ","     
    mycursor = mydb.cursor()
    sql = "INSERT INTO nikto (date, content, cmd) values (%s, %s, %s)"
    val = (datetime.date.today().strftime("%y-%m-%d"), db_content, cmd)
    mycursor.execute(sql, val)
    mydb.commit()
    mycursor.close()

#ZAP Function
class ZAPController:
    def __init__(self):
        self.zap_process = None
        self.firefox_driver = None
        self.api_key = "c1o192l9bl4gt0jpeapjapkqaq"
        self.zap_port = 8080
        self.zap_dir = tempfile.mkdtemp(prefix="ZAP_")
        self._kill_existing_zap()
    
    def _kill_existing_zap(self):
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                if 'zaproxy' in proc.name().lower() or any('zaproxy' in cmd for cmd in proc.cmdline()):
                   proc.kill()
                   proc.wait(timeout=5)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                continue

        lock_files = ['session.lck', 'db.lck']
        for lf in lock_files:
            lock_path = os.path.expanduser(f"~/.ZAP/{lf}")
            if os.path.exists(lock_path):
                try:
                   os.remove(lock_path)
                except Exception as e:
                   print(f"Failed to remove lock file {lock_path}: {str(e)}")

    def start_zap(self):
        try:
            self._kill_existing_zap()
            os.makedirs(self.zap_dir, exist_ok=True)

            self.zap_process = subprocess.Popen(
                ['zaproxy', '-daemon',
                '-port', str(self.zap_port),
                '-dir', self.zap_dir,
                '-config', f'api.key={self.api_key}',
                '-config', 'hud.enabledForDaemon=true'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )
        
            for _ in range(15):
                time.sleep(3)
                if self.zap_process.poll() is not None:
                   error = self.zap_process.stderr.read()
                   print(f"ZAP Died: {error}")
                   return False
                try:
                    requests.get(f'http://localhost:{self.zap_port}', timeout=2)
                    return True
                except (requests.ConnectionError, requests.ReadTimeout):
                    continue

            print("ZAP Startup Timeout!")
            return False
        except Exception as e:
            print(f"ZAP Strating Up Exceprion: {str(e)}")
            return False
        
    
    def cleanup(self):

        if self.zap_process:
            try:
               self.zap_process.terminate()
               self.zap_process.wait(timeout=20)
            except subprocess.TimeoutExpired:
               self.zap_process.kill()
        self.zap_process = None

        if not self.keep_open and self.firefox_driver:
            self.firefox_driver.quit()

        try:
            shutil.rmtree(self.zap_dir, ignore_errors=True)
        except Exception as e:
            print(f"Cleanup Error: {str(e)}")

    def __del__(self):
       self.cleanup()

    def launch_attack(self, target_url):
        try:
            if not self.start_zap():
                print("ZAP StartUp Failed")
                return False
            
            options = Options()
            options.set_preference("acceptInsecureCerts", True)
            options.set_preference("security.enterprise_roots.enabled", True)
            options.set_preference("network.proxy.type", 1)
            options.set_preference("network.proxy.http", "localhost")
            options.set_preference("network.proxy.http_port", self.zap_port)
            options.set_preference("network.proxy.ssl", "localhost")
            options.set_preference("network.proxy.ssl_port", self.zap_port)
            options.set_preference("network.proxy.no_proxies_on", "")
            options.set_preference("extensions.checkCompatibility.nightly", False)
            options.set_preference("extensions.zap.hud.enabled", True)
            options.set_preference("network.proxy.share_proxy_settings", True)
            options.headless = False

            requests.packages.urllib3.disable_warnings()

            gecko_path = "/usr/local/bin/geckodriver"
            service = Service(executable_path=gecko_path)

            self.firefox_driver = webdriver.Firefox(service=service, options=options)


            try:
                test_response = requests.get(
                   f'http://localhost:{self.zap_port}/JSON/core/view/version',
                   params={'apikey': self.api_key},
                   timeout=5
                )
                if test_response.status_code != 200:
                    raise ConnectionError("ZAP API not responding")
            except Exception as e:
                print(f"ZAP Proxy Verification Failed: {str(e)}")
                return False
            
            self.firefox_driver.get(target_url)
            return True
        
        except Exception as e:
            print(f"Attack Failed: {str(e)}")
            if hasattr(self, 'firefox_driver') and self.firefox_driver:
               self.firefox_driver.quit()
            return False
        


def start_zap_attack():
    target = en_target.get().strip()
    if not target:
        result_text.insert(tk.END, "Error: Please Enter a target URL First\n")
        return
        
    result_text.insert(tk.END, "Starting HUD Mode.... \n")
    result_text.update_idletasks()

    try:
        zap = ZAPController()
        parsed_url = urlparse(target)
        if not parsed_url.scheme:
            target = f"http://{target}"

        if zap.launch_attack(target):
            result_text.insert(tk.END, f"HUD Active For: {target}\n")
            result_text.insert(tk.END, "Open Firefox to Interact With The HUD MODE\n")
        else:
            result_text.insert(tk.END, "Enable Failed - Check Terminal\n")
        
    except Exception as e:
        result_text.insert(tk.END, f"Error: {str(e)}\n")
    

#ZAP Function





def open_prev():
    try:
        if n_prev.state() == "normal" : n_prev.focus()
    except:
        n_prev = tk.Toplevel()
        n_prev.geometry("600x300+500+200")
        lb_prev = tk.Listbox(n_prev, width=400)
        mycursor = mydb.cursor()
        mycursor.execute("select id, date, cmd from nikto")
        db_prev = mycursor.fetchall()
        for i in range(len(db_prev)):
            lb_prev.insert(tk.END, str(db_prev[i][0]) + " " + str(db_prev[i][1]) + " >" + db_prev[i][2])
        mycursor.close()
        btn_prev = tk.Button(n_prev, text="Open", command=partial(select_prev, lb_prev, n_prev))
        lb_prev.pack()
        btn_prev.pack()


def select_prev(lb_prev, n_prev):
    db_id = lb_prev.get(tk.ACTIVE).split(" ")[0]
    mycursor = mydb.cursor()
    sql = "select * from nikto where id = " + db_id
    mycursor.execute(sql)
    db_result = mycursor.fetchall()
    db_content = db_result[0][2].split('||NEWLINE||')
    display_result(db_content, db_result[0][3])
    mycursor.close()
    n_prev.destroy()
                        
def add_zap_button(self):
    btn_zap = tk.Button(n_button,
                text="HUD MODE",
                command=self.start_zap_attack)
    btn_zap.grid(row=6, column=0, pady=5, sticky="nsew")

def compare_to():
    try:
        if n_prev.state() == "normal" : n_prev.focus()
    except:
        if len(res_list) != 0:
            n_prev = tk.Toplevel()
            n_prev.geometry("600x300+500+200")
            lb_prev = tk.Listbox(n_prev, width=400)
            mycursor = mydb.cursor()
            mycursor.execute("select id, date, cmd from nikto")
            db_prev = mycursor.fetchall()
            for i in range(len(db_prev)):
                lb_prev.insert(tk.END, str(db_prev[i][0]) + " " + str(db_prev[i][1]) + " >" + db_prev[i][2])
            mycursor.close()
            btn_prev = tk.Button(n_prev, text="Open", command=partial(open_compare_to, lb_prev, n_prev))
            lb_prev.pack()
            btn_prev.pack()
        else:
            result_text.insert(tk.END, "There are no current report, please scan or open a previous file.\n")


def open_compare_to(lb_prev, n_prev):
    try:
        if n_compare.state() == "normal" : n_prev.focus()
    except:
        n_compare = tk.Toplevel()
        n_compare.geometry("1550x550+500+200")
        lb_current_tag = tk.Label(n_compare, text = "Current file info:")
        lb_current_tag.grid(row = 0, column = 0, pady = 5, sticky = "nsw")
        lb_current = tk.Listbox(n_compare, width = 38, height = 9)
        lb_current.grid(row = 1, column = 0, pady = 5, sticky = "nsew")
        lb_target_tag = tk.Label(n_compare, text = "Target file info:")
        lb_target_tag.grid(row = 2, column = 0, pady = 5, sticky = "nsw")
        lb_target = tk.Listbox(n_compare, width = 38, height = 9)
        lb_target.grid(row = 3, column = 0, pady = 5, sticky = "nsew")
        canvas1 = tk.Canvas(n_compare, width = 60, height = 30)
        canvas1.grid(row = 0, column = 1, rowspan = 4)
        canvas2 = tk.Canvas(n_compare, width = 60, height = 30)
        canvas2.grid(row = 0, column = 2, rowspan = 4)

        db_id = lb_prev.get(tk.ACTIVE).split(" ")[0]
        mycursor = mydb.cursor()
        sql = "select * from nikto where id = " + db_id
        mycursor.execute(sql)
        db_result = mycursor.fetchall()
        test = db_result[0][2].split("||NEWLINE||")

        count_list_name = instrest_list_content
        count_list = [0,0,0]
        count_list2 = [0,0,0]

        count_total = item_list_count
        count_total2 = []

        info1 = ["","","","","","","",""]
        info2 = ["","","","","","","",""]

        for i in range(len(res_list)):
            for j in range(len(instrest_list_re)):
                if re.search(instrest_list_re[j], res_list[i]):
                    count_list[j] += 1
            if re.search(r"Target IP or URL:", res_list[i]):
                msg = res_list[i].replace(" ", '')
                msg = msg.split(":")[1]
                info1[0] = msg
            # elif re.search(r"Target Port:", res_list[i]):
            #     msg = res_list[i].replace(" ", '')
            #     msg = msg.split(":")[1]
            #     info1[1] = msg
            elif re.search(r"Target Hostname:", res_list[i]):
                msg = res_list[i].replace(" ", '')
                msg = msg.split(":")[1]
                info1[2] = msg
            elif re.search(r"Server:", res_list[i]):
                msg = res_list[i].replace(" ", '')
                msg = msg.split(":")[1]
                info1[3] = msg
            elif re.search(r"Start Time:", res_list[i]):
                match = re.search(r'(\d+-\d+-\d+ +\d+:\d+:\d+)', res_list[i])
                match.group(1)
                info1[4] = match.group(1)
            elif re.search(r"End Time:", res_list[i]):
                match = re.search(r'(\d+-\d+-\d+ +\d+:\d+:\d+)', res_list[i])
                match.group(1)
                info1[5] = match.group(1)
            elif re.search(r"requests:", res_list[i]):
                match = re.search(r'\d+ +requests:', res_list[i])
                msg = re.search(r'\d+', match.group())
                info1[6] = msg.group()

                match_item = re.search(r'\d+ +item', res_list[i])
                msg_item = re.search(r'\d+', match_item.group())
                info1[7] = msg_item.group()

        for i in range(len(test)):
            for j in range(len(instrest_list_re)):
                if re.search(instrest_list_re[j], test[i]):
                    count_list2[j] += 1
            if re.search(r"Target IP or URL:", test[i]):
                msg = test[i].replace(" ", '')
                msg = msg.split(":")[1]
                info2[0] = msg
            # elif re.search(r"Target Port:", test[i]):
            #     msg = test[i].replace(" ", '')
            #     msg = msg.split(":")[1]
            #     info2[1] = msg
            elif re.search(r"Target Hostname:", test[i]):
                msg = test[i].replace(" ", '')
                msg = msg.split(":")[1]
                info2[2] = msg
            elif re.search(r"Server:", test[i]):
                msg = test[i].replace(" ", '')
                msg = msg.split(":")[1]
                info2[3] = msg
            elif re.search(r"Start Time:", test[i]):
                match = re.search(r'(\d+-\d+-\d+ +\d+:\d+:\d+)', test[i])
                match.group(1)
                info2[4] = match.group(1)
            elif re.search(r"End Time:", test[i]):
                match = re.search(r'(\d+-\d+-\d+ +\d+:\d+:\d+)', test[i])
                match.group(1)
                info2[5] = match.group(1)
            elif re.search(r"requests:", test[i]):
                match = re.search(r'\d+ +requests:', test[i])
                msg = re.search(r'\d+', match.group())
                info2[6] = msg.group()

                match_item = re.search(r'\d+ +item', test[i])
                msg_item = re.search(r'\d+', match_item.group())
                info2[7] = msg_item.group()
                count_total2.append(msg_item.group())

        for key, val in zip(result_list_n, info1):
            lb_current.insert(tk.END, key + val)

        for key, val in zip(result_list_n, info2):
            lb_target.insert(tk.END, key + val)
        if not count_total:
            count_total = [0]
        if not count_total2:
            count_total2 = [0]

        max_length = max(len(count_total), len(count_total2))
        count_total += [0] * (max_length - len(count_total))
        count_total2 += [0] * (max_length - len(count_total2))

        df = pandas.DataFrame({
            "Current": count_total,
            "Target": count_total2,
            "Item": [f"Item [i+1]"]
        })


        n_prev.destroy()
        df = pandas.DataFrame({"Current":count_total, "Target":count_total2, "Item":["Item"]})
        df.set_index("Item", inplace = True)
        df.Current = pandas.to_numeric(df.Current)
        df.Target = pandas.to_numeric(df.Target)

        df2 = pandas.DataFrame({"Current":count_list, "Target":count_list2, "Type":instrest_list_n})
        df2.set_index("Type", inplace = True)
        df2.Current = pandas.to_numeric(df2.Current)
        df2.Target = pandas.to_numeric(df2.Target)

        figure1 = plt.Figure(figsize=(6, 5), dpi=100)
        ax1 = figure1.add_subplot(111)
        ax1.set_xlabel("Level")
        ax1.set_ylabel("Amount")
        ax1.set_title('Item amount compare')
        bar1 = FigureCanvasTkAgg(figure1, canvas1)
        bar1.get_tk_widget().pack()
        try:
            df.plot(kind='bar', legend=True, ax=ax1)
        except:
            pass

        figure2 = plt.Figure(figsize=(6,5), dpi=100)
        ax2 = figure2.add_subplot(111)
        ax2.set_xlabel("Type")
        ax2.set_ylabel("Amount")
        ax2.set_title('Discoved Instresting info type')
        ax2.figure.autofmt_xdate(rotation=45)
        ax2.tick_params(axis="x", labelsize=6)
        bar2 = FigureCanvasTkAgg(figure2, canvas2)
        bar2.get_tk_widget().pack()
        try:
            df2.plot(kind='bar', legend=True, ax=ax2)
        except:
            pass




def display_result(test, cmd):
    target_line = cmd.split(" ")
    target = target_line[2]
    clear_value()
    clear_sec()
    clear_result()
    clear_instrest()
    clear_result_text()
    clear_table()
    unlock_entry()
    cveCount = 0
    for i in range(len(test)):
        res_list.append(test[i])
        for j in range(len(instrest_list_re)):
            if re.search(instrest_list_re[j], test[i]):
                instrest_list_content[j].append(test[i])
                instrest_list_count[j] += 1
                if instrest_list_n[j] == "CVE":
                    cve_content.append([])
                    first = test[i].split("OSVDB-")
                    cve_no = first[1].split(":")[0]
                    if cve_no not in cve_list:
                        cve_list[cve_no] = 1
                    else:
                        cve_list[cve_no] += 1
                    cve_process_line = test[i].split(": ")
                    cve_content[cveCount].append(cve_process_line[2])
                    cve_content[cveCount].append("http://" + target + cve_process_line[1])
                    cve_content[cveCount].append(cve_process_line[0])
                    cveCount += 1
        if re.search(r"Target IP:", test[i]):
            msg = test[i].replace(" ", '')
            msg = msg.split(":")[1]
            result_list_value_n[0].insert(0, msg)
        # elif re.search(r"Target Port:", test[i]):
        #     msg = test[i].replace(" ", '')
        #     msg = msg.split(":")[1]
        #     result_list_value_n[1].insert(0, msg)
        elif re.search(r"Target Hostname:", test[i]):
            msg = test[i].replace(" ", '')
            msg = msg.split(":")[1]
            result_list_value_n[1].insert(0, msg)
        elif re.search(r"Server:", test[i]):
            msg = test[i].replace(" ", '')
            msg = msg.split(":")[1]
            result_list_value_n[2].insert(0, msg)
        elif re.search(r"Start Time:", test[i]):
            match = re.search(r'(\d+-\d+-\d+ +\d+:\d+:\d+)', test[i])
            match.group(1)
            result_list_value_n[3].insert(0, match.group(1))
        elif re.search(r"End Time:", test[i]):
            match = re.search(r'(\d+-\d+-\d+ +\d+:\d+:\d+)', test[i])
            match.group(1)
            result_list_value_n[4].insert(0, match.group(1))
        elif re.search(r"requests:", test[i]):
            match = re.search(r'\d+ +requests:', test[i])
            msg = re.search(r'\d+', match.group())
            result_list_value_n[5].insert(0, msg.group())

            match_item = re.search(r'\d+ +item', test[i])
            msg_item = re.search(r'\d+', match_item.group())
            result_list_value_n[6].insert(0, msg_item.group())
            item_list_count.append(msg_item.group())
    df1 = pandas.DataFrame(instrest_list_count, index = instrest_list_n)
    display_general(cmd, df1)
    for item in cve_content:
        st.insert("", "end", values=item)
        st.bind('<ButtonRelease-1>', select_item)
    # ax1.set_title('Country Vs. GDP Per Capita')

    # bar1.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH)
    # df1.plot(kind='bar', legend=False, ax=ax1)
    # pie_data = instrest_list_count
    # subplot.pie(pie_data, autopct='%1.1f%%', shadow=True, startangle=90)
    # subplot.legend(instrest_list_n)
    # subplot.axis('equal')
    # pie.draw_event()
    # pie.get_tk_widget().pack()

def display_general(cmd, df1):
    # result_text.insert(tk.END, "-------Process done, here is the general result-------\n")
    # for i in range(len(result_list_n)):
    #     result_text.insert(tk.END, result_list_n[i] + " " + result_list_value_n[i].get() + "\n")
    # result_text.insert(tk.END, "Using option: " + cmd + "\n")
    # result_text.insert(tk.END, "\n-------Instresting item-------\n")
    for i in range(len(instrest_list_count)):
        result_text.insert(tk.END, instrest_list_n[i] + " count: " + str(instrest_list_count[i]) + "\n")
        if instrest_list_n[i] == "CVE":
            for key, val in cve_list.items():
                result_text.insert(tk.END, " > OSVDB-" + key + " count: " + str(val) + "\n")
            if int(instrest_list_count[i]) >= 10:
                en_sec.insert(0, "High")
                en_sec.config(fg = "white", background = "red")
            elif int(instrest_list_count[i]) >=4:
                en_sec.insert(0, "Medium")
                en_sec.config(fg = "white", background = "orange")
            else:
                en_sec.insert(0, "Low")
                en_sec.config(fg = "white", background = "green")
    if cve_list:
        df2 = pandas.DataFrame(
            list(cve_list.values()), 
            index=list(cve_list.keys())
        )
        root.after(0, lambda: updateChart(df1, df2))
    else:
        figure2.clf()
        bar2.draw_idle()
    lock_entry()

                

def instrest_result():
    clear_result_text()
    target = cb_instrest.get()
    tar_v = len(instrest_list_n)
    for i in range(len(instrest_list_n)):
        if target == instrest_list_n[i]:
            tar_v = i
    if tar_v < len(instrest_list_n):
        if len(instrest_list_content[tar_v]) == 0:
            result_text.insert(tk.END, "There are no any result related to " + instrest_list_n[tar_v] + '\n')
        else:
            for j in range(len(instrest_list_content[tar_v])):
                result_text.insert(tk.END, instrest_list_content[tar_v][j] + '\n')
    else:
        if len(res_list) == 0:
            result_text.insert(tk.END, "There are no any related result" + '\n')
        for j in range(len(res_list)):
            result_text.insert(tk.END, res_list[j] + '\n')

def export_result():
    # Pre Process data
    if (False):
        print("true")
    else:
        scan_info = {"IP":"", "Port":"", "Hostname":"", "Server":"", "Start":"", "End":"", "Request":"", "Item":""}
    for i in range(len(res_list)):
        if re.search(r"Target IP:", res_list[i]):
            msg = res_list[i].replace(" ", '')
            msg = msg.split(":")[1]
            # print(msg)
            scan_info["IP"] = msg
        # elif re.search(r"Target Port:", res_list[i]):
        #     msg = res_list[i].replace(" ", '')
        #     # print(msg)
        #     msg = msg.split(":")[1]
            # scan_info["Port"] = msg
        elif re.search(r"Target Hostname:", res_list[i]):
            msg = res_list[i].replace(" ", '')
            msg = msg.split(":")[1]
            scan_info["Hostname"] = msg
        elif re.search(r"Server:", res_list[i]):
            msg = res_list[i].replace(" ", '')
            msg = msg.split(":")[1]
            scan_info["Server"] = msg
        elif re.search(r"Start Time:", res_list[i]):
            match = re.search(r'(\d+-\d+-\d+ +\d+:\d+:\d+)', res_list[i])
            match.group(1)
            scan_info["Start"] = match.group(1)
        elif re.search(r"End Time:", res_list[i]):
            match = re.search(r'(\d+-\d+-\d+ +\d+:\d+:\d+)', res_list[i])
            match.group(1)
            scan_info["End"] = match.group(1)
        elif re.search(r"requests:", res_list[i]):
            match = re.search(r'\d+ +requests:', res_list[i])
            msg = re.search(r'\d+', match.group())
            scan_info["Request"] = match.group().split(" ")[0]


            match_item = re.search(r'\d+ +item', res_list[i])
            msg_item = re.search(r'\d+', match_item.group())
            scan_info["Item"] = msg_item.group()

        result_info = []
        for i in range(len(instrest_list_count)):
            result_info.append(instrest_list_n[i] + " count: " + str(instrest_list_count[i]) + "\n")
            if instrest_list_n[i] == "CVE":
                for key, val in cve_list.items():
                    result_info.append(" > OSVDB-" + key + " count: " + str(val) + "\n")
                if int(instrest_list_count[i]) >= 10:
                    sec_info = "High"
                elif int(instrest_list_count[i]) >=4:
                    sec_info = "Medium"
                else:
                    sec_info = "Low"

    # PreProcess figure  
    df1 = pandas.DataFrame(instrest_list_count, index = instrest_list_n)
    df2 = pandas.DataFrame(list(cve_list.values()), index=list(cve_list.keys()))
    root.after(0, lambda: updateChart(df1, df2))
    figure1x = plt.Figure(figsize=(8,4), dpi=100)
    ax1 = figure1x.add_subplot(111)
    ax1.set_title("Insteresting type count", fontsize=9)
    plt.ylim(bottom=0)
    try:
        df1.plot(kind="bar", legend=False, ax=ax1)
    except:
        pass
    ax1.figure.autofmt_xdate(rotation=0)
    for i in range(len(instrest_list_n)):
        ax1.get_children()[i].set_color("#" + "%06x" % random.randint(0xAAAAAA, 0xFFFFFF))
    
    figure2x = plt.Figure(figsize=(8,4), dpi=100)
    ax2 = figure2x.add_subplot(111)
    ax2.set_title("OSVDB type", fontsize=9)
    try:
        df2.plot(kind="bar", legend=False, ax=ax2)
    except:
        pass
    ax2.figure.autofmt_xdate(rotation=0)
    for i in range(len(cve_list)):
        ax2.get_children()[i].set_color("#" + "%06x" % random.randint(0xAAAAAA, 0xFFFFFF))
    
    figure1x.savefig("figure1x.png")
    figure2x.savefig("figure2x.png")

    # Create PDF
    pdf = FPDF(format="A4")
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_xy(0, 0)
    pdf.cell(60)
    pdf.cell(75, 10, "Nikto Scanning report", 0, 2, 'C')
    pdf.cell(90, 10, " ", 0, 2, 'C')
    pdf.cell(-50)
    pdf.cell(50, 10, 'Security Level: ' + sec_info, 0, 1, 'C')
    # pdf.cell(0,40, " ")
    for key, val in scan_info.items():
        pdf.cell(50, 10, key + ": " + val, 0, 2)
    pdf.ln(10)
    pdf.cell(100, 10 , "Discovered item:", 0, 2)
    for item in result_info:
        pdf.cell(100, 5, item, 0 ,2)
        pdf.ln(5)
    pdf.cell(-5)
    pdf.image('figure1x.png', x = None, y = None, w = 0, h = 0, type = '', link = '')
    pdf.ln(70)
    pdf.image('figure2x.png', x = None, y = None, w = 0, h = 0, type = '', link = '')
    pdf.ln(70)
    epw = pdf.w - 2 * pdf.l_margin
    w1 = epw / 6
    w2 = w1 * 5
    pdf.set_font_size(9)
    th = pdf.font_size
    x = pdf.get_x()
    pdf.cell(-x)
    y = pdf.get_y()
    pdf.ln(th)
    pdf.cell(w1, th*2, "OSVDB", 1, 0, 'C')
    pdf.cell(w2, th*2, "Description", 1, 0, 'C')
    pdf.ln(th*2)
    for item in cve_content:
        if len(item) >= 3:
           pdf.cell(w1, th*2, item[0], 1, 0, 'C')
           pdf.cell(w2, th*2, item[2], 1, 0, 'C')
           pdf.ln(th*2)

    path = os.getcwd() + '/' + scan_info["Start"].replace(" ","_")
    pdf.output(path, 'F')
    webbrowser.open(path)


    # print(df1)
    # print(df2)  
    # print(scan_info)
    # print(sec_info)
    # print(result_info)
    # export_result(df1, df2, scan_info, sec_info, result_info)

def select_item(self):
    selected = st.selection()
    if selected:
       item = st.item(st.selection())
       if len(item["values"]) > 1:
          webbrowser.open_new_tab(item["values"][1])
       else:
           print("No valid link found")
    else:
        print("No item selected")


# General setting
btn_width = 30

# Basic setting
root = tk.Tk()
root.title("Project")
root_nb = ttk.Notebook(root)

# Nikto layout
nikto = ttk.Frame(root_nb)
n_input = ttk.Frame(nikto)
n_button = ttk.Frame(nikto)
n_evasion  = ttk.Frame(nikto)
n_tuning = ttk.Frame(nikto)
n_result = ttk.Frame(nikto)
n_instrest = ttk.Frame(nikto)
n_chart = ttk.Frame(nikto)
n_result_text = ttk.Frame(nikto)
n_table = ttk.Frame(nikto)

n_input.grid(row = 0, column = 1, sticky="nsew")
n_tuning.grid(row = 1, column = 1, sticky="nsew")
n_evasion.grid(row = 2, column = 1, sticky="nsew")
n_result.grid(row = 3, column = 1, sticky="nsew")
n_instrest.grid(row = 4, column = 1, sticky="nsew")
n_chart.grid(row = 0, column = 3, rowspan = 3, sticky="nsew")
n_button.grid(row = 0, column = 2, sticky="nsew")
n_result_text.grid(row = 3, column = 3, sticky="nsew")
n_table.grid(row = 5, column = 0, columnspan = 4, sticky="nsew")



# Skipfish layout
skipfish = ttk.Frame(root_nb)
s_button = ttk.Frame(skipfish)
s_input = ttk.Frame(skipfish)
s_scope = ttk.Frame(skipfish)
s_report = ttk.Frame(skipfish)
s_dir = ttk.Frame(skipfish)
s_per = ttk.Frame(skipfish)
s_result_text = ttk.Frame(skipfish)
s_chart = ttk.Frame(skipfish)

s_input.grid(row = 0, column = 0, sticky="nsew")
s_scope.grid(row = 1, column = 0, sticky="nsew")

s_per.grid(row = 2, column = 0, sticky="nsew")
s_report.grid(row = 3, column = 0, sticky="nsew")
s_button.grid(row = 0, column = 1, rowspan = 2,  sticky="nsew")

# s_dir.grid(row = 2, column = 1, columnspan = 2, sticky="nsew")
s_chart.grid(row = 0, column = 5, rowspan = 2, sticky="nsew")
s_result_text.grid(row = 2, column = 5, rowspan = 3, sticky="nsew")

# Root layout
root_nb.add(nikto, text="Nikto")
root_nb.add(skipfish, text="Skipfish")
root_nb.pack()


# Basic Input
def select_dir():
    filename = filedialog.askdirectory()
    en_dir.delete(0, tk.END)
    en_dir.insert(tk.END, filename)

lb_info_bi = tk.Label(n_input, text="Basic Input")
lb_info_bi.grid(row = 0, column = 0, pady = 5, sticky="w")

lb_target = tk.Label(n_input, text="Target (IP or URL):")
lb_target.grid(row = 1, column = 0, pady = 5, sticky="nsew")
en_target = tk.Entry(n_input)
en_target.grid(row = 1, column = 1, pady = 5, sticky="nsew")

# lb_port = tk.Label(n_input, text="Port:")
# lb_port.grid(row = 2, column = 0, sticky="nsew")
# port_80 = tk.IntVar()
# port_443 = tk.IntVar()
# port_8080 = tk.IntVar()
# port_customer = tk.IntVar()
# tk.Checkbutton(n_input, text="80", variable = port_80).grid(row = 2, column = 1, sticky="nsew")
# tk.Checkbutton(n_input, text="443", variabl = port_443).grid(row = 3, column = 1, sticky="nsew")
# tk.Checkbutton(n_input, text="8080", variable = port_8080).grid(row = 4, column = 1, sticky="nsew")

btn_dir = tk.Button(n_input, text="Directory", command = select_dir)
btn_dir.grid(row = 5, column = 0, sticky="nsew")
en_dir = ttk.Entry(n_input)
en_dir.grid(row = 5, column = 1, sticky="nsew")

lb_output = tk.Label(n_input, text="Output Format:")
lb_output.grid(row = 6, column = 0, sticky="nsew")
cb_output = ttk.Combobox(n_input, values=["", "csv", "htm", "nbe", "sql", "txt", "xml"])
cb_output.grid(row = 6, column = 1, sticky="nsew")

# Result
lb_info_btn = tk.Label(n_result, text="Basic Info:")
lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")

result_list_n = ["Ip address:", "Host name:", "Server type:",
                "Start Time:", "End Time:", "Reqeuest count:", "Item count:"]
result_list_value_n = []

for i in range(len(result_list_n)):
    tk.Label(n_result, text=result_list_n[i]).grid(row = i + 1, column = 0, pady = 5, sticky="nsew")
    result_list_value_n.append(tk.Entry(n_result))
    result_list_value_n[i].grid(row = i + 1, column = 1, pady = 5, sticky = "nsew")    


# Result text
result_text = tk.Text(n_result_text, width = 125, height = 14)
result_text.grid(row = 1, column = 0, columnspan = 3,  sticky="nsew")

# Instrest
lb_info_btn = tk.Label(n_result_text, text="Insteresting Info:")
lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")


instrest_list_value_n = []
instrest_selection = instrest_list_n.copy()
instrest_selection.append("All")
cb_instrest = ttk.Combobox(n_result_text, values=instrest_selection)
cb_instrest.grid(row = 0, column = 1, pady = 5, sticky="nsew")
btn_instrest = tk.Button(n_result_text, text = ("Details"), command=instrest_result).grid(row = 0, column = 2, pady = 5, sticky="nsew")

for i in range(len(instrest_list_n)):
    instrest_list_count.append(0)
    instrest_list_content.append([])

# Chart
canvas = tk.Canvas(n_chart, width = 100, height = 100)
canvas2 = tk.Canvas(n_chart, width = 100, height = 100)

canvas.grid(row = 0, column = 0, pady = 5, sticky = "nsew")
canvas2.grid(row = 0, column = 1, pady = 5, sticky = "nsew")
figure1 = plt.Figure(figsize=(5,4), dpi=100)
bar1 = FigureCanvasTkAgg(figure1, canvas)
bar1.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH)
figure2 = plt.Figure(figsize=(5,4), dpi=100)
bar2 = FigureCanvasTkAgg(figure2, canvas2)
bar2.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH)


def clear_chart():
    figure1.clear()
    bar1.draw_idle()
    figure2.clear()
    bar2.draw_idle()

def updateChart(df1, df2):
    figure1.clf()
    figure2.clf()

    ax1 = figure1.add_subplot(111)
    ax1.set_title("Interesting type count")
    if not df1.empty:
       df1.plot(kind='bar', ax=ax1, legend=False)
       for i in range(len(instrest_list_n)):
           ax1.get_children()[i].set_color("#%06x" % random.randint(0xAAAAAA, 0xFFFFFF))
       ax1.set_xticklabels(instrest_list_n, rotation=45, fontsize=8)
    else:
        ax1.text(0.5,0.5, 'No Data', ha='center', va='center')
    
    
    ax2 = figure2.add_subplot(111)
    ax2.set_title("OSVDB type")
    if not df2.empty and df2[0].dtype.kind in 'iuf':
       df2.plot(kind='bar', ax=ax2, legend=False)
       for i in range(len(df2)):
           ax2.get_children()[i].set_color("#%06x" % random.randint(0xAAAAAA, 0xFFFFFF))
       ax2.set_xticklabels(df2.index, rotation=45, fontsize=8)
    else:
        ax2.text(0.5,0.5, 'No OSVDB Data', ha='center', va='center')

    bar1.draw_idle()
    bar2.draw_idle()

# fig = Figure(figsize=(4,3), dpi=100)
# pie = FigureCanvasTkAgg(fig, canvas)
# subplot = fig.add_subplot(111)


# Evasion
lb_sec_lb = tk.Label(n_evasion, text="Security level")
lb_sec_lb.grid(row = 0, column = 0, pady = 5, sticky="w")
en_sec = tk.Entry(n_evasion)
en_sec.grid(row = 0, column = 1, pady = 5, sticky = "w")
# lb_info_btn = tk.Label(n_evasion, text="Evasion options")
# lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")

# evasion_list_n = ["Random URI encoding (non-UTF8)", "Directory self-reference (/./)", "Premature URL ending",
# "Prepend long random string", "Fake parameter", "TAB as request spacer", "Change the case of the URL", "Use Windows directory separator (\)",
# "Use a carriage return (0x0d) as a request spacer", "Use binary value 0x0b as a request spacer"]
# evasion_list_value_n = []
# for i in range(len(evasion_list_n)):
#     evasion_list_value_n.append(tk.IntVar())
#     tk.Checkbutton(n_evasion, text=evasion_list_n[i], variable=evasion_list_value_n[i]).grid(row = i + 3, column = 0, pady = 5, sticky="w")

# Tuning
lb_info_btn = tk.Label(n_tuning, text="Tuning options")
lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")

tuning_list_n = ["Injection", "Remote Source Inclusion"]
tuning_list_value_n = []
for i in range(len(tuning_list_n)):
    tuning_list_value_n.append(tk.IntVar())
    tk.Checkbutton(n_tuning, text=tuning_list_n[i], variable=tuning_list_value_n[i]).grid(row = i + 3, column = 0, pady = 5, sticky="w")

# Table
scroll_x = tk.Scrollbar(n_table, orient=tk.HORIZONTAL)
scroll_y = tk.Scrollbar(n_table, orient=tk.VERTICAL)

st = ttk.Treeview(n_table, columns=("OSVDB", "Link", "Description"), xscrollcommand=scroll_x.set, yscrollcommand=scroll_y.set)
scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
scroll_x.config(command=st.xview)
scroll_y.config(command=st.yview)
st.heading("OSVDB", text="OSVDB No.")
st.heading("Link", text="Link")
st.heading("Description", text="Description")
st['show'] = "headings"
st.column("OSVDB", width = 150)
st.column("Link", width = 600)
st.column("Description", width = 600)
st.pack()

# Button
lb_info_btn = tk.Label(n_button, text="Control")
lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")

btn_start = tk.Button(n_button, text="Start", command = run_nikto)
btn_start.grid(row = 1, column = 0, pady = 5, sticky="nsew")

btn_reset = tk.Button(n_button, text="Reset", command = reset)
btn_reset.grid(row = 2, column = 0, pady = 5, sticky="nsew")

btn_open = tk.Button(n_button, text="Open previous", command = open_prev)
btn_open.grid(row = 3, column = 0, pady = 5, sticky="nsew")


btn_compare = tk.Button(n_button, text="Compare to", command = compare_to)
btn_compare.grid(row = 4, column = 0, pady = 5, sticky="nsew")

btn_export = tk.Button(n_button, text="Export", command = export_result)
btn_export.grid(row = 5, column = 0, pady = 5, sticky="nsew")

btn_zap = tk.Button(n_button, text="HUD MODE", command = start_zap_attack)
btn_zap.grid(row = 6, column = 0, pady = 5, sticky="nsew")






# Nikto 

# skipfish -o 

def select_dir_s():
    filename = filedialog.askdirectory()
    en_op_s.delete(0, tk.END)
    en_op_s.insert(tk.END, filename)

def run_skipfish():
    result_text.delete('1.0', tk.END)
    t2 = threading.Thread(target = rskipfish)    
    t2.start()


def reset_skip():
    url_path.clear()
    en_ip_s.delete(0, tk.END)
    en_dir_s.delete(0, tk.END)
    en_op_s.delete(0, tk.END)
    reset_chart()

    # for i in range(len(bi_list_value_s)):
    #     bi_list_value_s[i].set(0)
    #     bi_list_text_s[i].delete(0, tk.END)

    for i in range(len(per_list_value_s)):
        per_list_value_s[i].set(0)
    
    for i in range(len(per_list_text_s)):
        per_list_text_s[i].delete(0, tk.END)

    for i in range(len(rp_list_value_s)):
        rp_list_value_s[i].set(0)
    
    for i in range(len(rp_list_text_s)):
        rp_list_text_s[i].delete(0, tk.END)
    reset_skip_info()
    reset_skip_result()

def reset_skip_result():
    result_text_s.delete('1.0', tk.END)

def reset_skip_info():
    unlock_skipfish()
    for i in range(len(s_result_list_value_n)):
        s_result_list_value_n[i].delete(0, tk.END)
        s_result_list_value_n[i].config(fg = "black", background = "white")

def lock_skipfish():
    for i in range(1, len(s_result_list_value_n)):
        s_result_list_value_n[i].config(state="disable")

def unlock_skipfish():
    for i in range(1, len(s_result_list_value_n)):
            s_result_list_value_n[i].config(state="normal")

#def get_skip_ip():
 #   ip = en_ip_s.get()
  #  if valid_ip(ip):
   #     return ip, True
    #else:
     #   return ip, False

def get_skip_ip_dir():
    return en_dir_s.get()

# def get_skip_auth():
#     skip_auth = ""
#     for i in range(len(bi_list_s)):
#         if bi_list_value_s[i].get() == 1:
#             if i == 0:
#                 skip_auth += " -F host="
#             elif i == 1:
#                 skip_auth += " -C name="
#             else:
#                 skip_auth += " -H name="
#             skip_auth += bi_list_text_s[i].get()
#     return skip_auth

def get_skip_report():
    report_opts = []
    if rp_list_value_s [0].get() == 1:
        report_opts.append("-Q")
    if rp_list_value_s[1].get() == 1:
        report_opts.append("-u")
    return " ".join(report_opts)

def get_skip_per():
    options = []
    for i, value in enumerate(per_list_value_s):
        if value.get() == 1:
            entry = per_list_text_s[i].get().strip()
            if entry:

                if i == 0:
                    options.extend(["-g", 20])
                elif i == 1:
                    options.extend(["-m", 10])
                elif i == 2:
                    options.extend(["-t", 15])
                elif i == 3:
                    options.extend(["-i", entry])
                elif i == 4:
                    options.extend(["-s", 100000])
    return options

def get_skip_dir():
    dirt = en_op_s.get()
    if dirt[(len(dirt)-1)] == '/':
        return dirt
    else:
        return dirt + '/'
    
status_var = tk.StringVar()
progress_bar = ttk.Progressbar(s_button, mode='indeterminate')

    
def update_result(text):
    tag = "STDERR" if "ERROR" in text else "INFO"
    result_text_s.insert(tk.END, text)
    result_text_s.see(tk.END)

    result_text_s.tag_config("STDERR", foreground="red")
    result_text_s.tag_config("INFO", foreground="black")

def handle_scan_error(error_msg):
    result_text_s.insert(tk.END, f"Fatel Error: {error_msg}\n")
    unlock_skipfish()
    progress_bar.stop()



def rskipfish():
    target = en_ip_s.get().strip()
    parsed_url = urlparse(target)
    if not parsed_url.scheme:
        parsed_url = urlparse(f"http://{target}")
  
    host = parsed_url.hostname
    if not host:
        result_text_s.insert(tk.END, "Error: Invalid target. Missing host. \n")
        return
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.match(r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$',host):
            result_text_s.insert(tk.END, f"Error: Invalid host: {host}\n")
            return
    
    target_url= parsed_url.geturl()
        
    try:
        response = requests.head(target_url, timeout=10)
        if response.status_code >=400:
            raise requests.exceptions.RequestException
    except requests.exceptions.RequestException:
        result_text_s.insert(tk.END, f"Error: Target{target_url} is unreachable\n")
        return
    if en_op_s.get():
        path = get_skip_dir() + datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")

    else:
        path = os.path.join(os.getcwd(), datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S"))

        cmd = (f"skipfish -S /usr/share/skipfish/dictionaries/complete.wl "
            f"{' '.join(get_skip_per())} {get_skip_report()}"
            f"-o {shlex.quote(path)} {shlex.quote(target_url)}")

    try:
        root.after(0, update_result, f"Command: {cmd}\n")
        skip = subprocess.Popen(
            cmd,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

        stdout, stderr = skip.communicate()
        if skip.returncode != 0:
            root.after(0, update_result, f"Error: {stderr}\n")
            return
        root.after(0, update_result, f"Scan Completed.\n")
        
        result_text_s.insert(tk.END, f"Scan completed successfully ({datetime.datetime.now()})\n")
        url = f"file://{os.path.abspath(path)}/index.html"
        url_path.append(url)
        display_skipfish(url, cmd)
        
        mycursor = mydb.cursor()
        sql = "INSERT INTO skipfish(date, cmd, path) VALUES(%s,%s,%s)"
        val = (datetime.date.today(), cmd, url)
        mycursor.execute(sql, val)
        mydb.commit()
        mycursor.close() 
        
    except Exception as e:
        result_text_s.insert(tk.END, f"Fatal error: {str(e)}\n:")
                               

def open_prev_s():
    try:
        if n_prev.state() == "normal" : n_prev.focus()
    except:
        reset_skip()
        n_prev = tk.Toplevel()
        n_prev.geometry("800x300+500+200")
        lb_prev = tk.Listbox(n_prev, width=400)
        mycursor = mydb.cursor()
        mycursor.execute("select id, date, cmd from skipfish")
        db_prev = mycursor.fetchall()
        for i in range(len(db_prev)):
            lb_prev.insert(tk.END, str(db_prev[i][0]) + " " + str(db_prev[i][1]) + " >" + db_prev[i][2])
        mycursor.close()
        btn_prev = tk.Button(n_prev, text="Open", command=partial(select_prev_s, lb_prev, n_prev))
        lb_prev.pack()
        btn_prev.pack()

def compare_to_s():
    try:
        if n_prev.state() == "normal" : n_prev.focus()
    except:
        if len(url_path) != 0:
            n_prev = tk.Toplevel()
            n_prev.geometry("800x300+500+200")
            lb_prev = tk.Listbox(n_prev, width=400)
            mycursor = mydb.cursor()
            mycursor.execute("select id, date, cmd from skipfish")
            db_prev = mycursor.fetchall()
            for i in range(len(db_prev)):
                lb_prev.insert(tk.END, str(db_prev[i][0]) + " " + str(db_prev[i][1]) + " >" + db_prev[i][2])
            mycursor.close()
            btn_prev = tk.Button(n_prev, text="Open", command=partial(open_compare_to_s, lb_prev, n_prev))
            lb_prev.pack()
            btn_prev.pack()
        else:
            result_text_s.insert(tk.END, "There are no current report, please scan or open a previous file.\n")


def open_compare_to_s(lb_prev, n_prev):
    try:
        if n_compare.state() == "normal" : n_prev.focus()
    except:
        n_compare = tk.Toplevel()
        n_compare.geometry("1550x550+500+200")
        lb_current_tag = tk.Label(n_compare, text = "Current file info:")
        lb_current_tag.grid(row = 0, column = 0, pady = 5, sticky = "nsw")
        lb_current = tk.Listbox(n_compare, width = 38, height = 4)
        lb_current.grid(row = 1, column = 0, pady = 5, sticky = "nsew")
        lb_target_tag = tk.Label(n_compare, text = "Target file info:")
        lb_target_tag.grid(row = 2, column = 0, pady = 5, sticky = "nsw")
        lb_target = tk.Listbox(n_compare, width = 38, height = 4)
        lb_target.grid(row = 3, column = 0, pady = 5, sticky = "nsew")
        canvas1 = tk.Canvas(n_compare, width = 60, height = 30)
        canvas1.grid(row = 0, column = 1, rowspan = 4)
        canvas2 = tk.Canvas(n_compare, width = 60, height = 30)
        canvas2.grid(row = 0, column = 2, rowspan = 4)
        # Current
        soup = get_scan_soup(url_path[0])
        scan_info = get_scan_info(soup, "test")
        scan_count_number = get_scan_count_number(soup)
        scan_level_count = get_scan_level(soup)
        file_len = scan_count_number - len(scan_level_count)
        scan_cout_file, scan_count = get_scan_count(soup, file_len)
        scan_item_file, scan_item = get_scan_item(soup, file_len)
        # Target
        db_id = lb_prev.get(tk.ACTIVE).split(" ")[0]
        mycursor = mydb.cursor()
        sql = "select date, cmd, path from skipfish where id = " + db_id
        mycursor.execute(sql)
        db_result = mycursor.fetchall()
        db_cmd = db_result[0][1]
        db_path = db_result[0][2]
        mycursor.close()
        n_prev.destroy()
        url_path.append(db_path)
        soup2 = get_scan_soup(db_path)
        scan_info2 = get_scan_info(soup2, db_cmd)
        scan_count_number2 = get_scan_count_number(soup2)
        scan_level_count2 = get_scan_level(soup2)
        file_len2 = scan_count_number - len(scan_level_count2)
        scan_cout_file2, scan_count2 = get_scan_count(soup, file_len2)
        scan_item_file2, scan_item2 = get_scan_item(soup, file_len2)
        # Analysis data
        security_level_set = [[],[]]
        for i in range(0,5):
            security_level_set[0].append(0)
            security_level_set[1].append(0)
        for key, val in zip(scan_level_count, scan_count):
            security_level_set[0][int(key) - 1] +=  int(val)
        for key, val in zip(scan_level_count2, scan_count2):
            security_level_set[1][int(key) - 1] +=  int(val)
        tag = ["One", "Two", "Three", "Four", "Five"]
        df = pandas.DataFrame({"Level":tag, "Current":security_level_set[0], "Target":security_level_set[1]})
        df.set_index("Level", inplace=True, drop=True)

        file1 = pandas.DataFrame({"Type":scan_item_file, "Amount":scan_cout_file})
        file2 = pandas.DataFrame({"Type":scan_item_file2, "Amount":scan_cout_file2})
        df2 = pandas.merge(file1, file2, on="Type", how="outer")
        df2.fillna(0, inplace = True)
        df2.columns = ["Type", "Current", "Target"]
        df2.set_index("Type", inplace = True, drop = True)
        df2.Current = pandas.to_numeric(df2.Current)
        df2.Target = pandas.to_numeric(df2.Target)
        
        # Data
        figure1 = plt.Figure(figsize=(6, 5), dpi=100)
        ax1 = figure1.add_subplot(111)
        ax1.set_xlabel("Level")
        ax1.set_ylabel("Amount")
        ax1.set_title('Security level compare')
        bar1 = FigureCanvasTkAgg(figure1, canvas1)
        bar1.get_tk_widget().pack()
        try:
            df.plot(kind='bar', legend=True, ax=ax1)
        except:
            pass

        figure2 = plt.Figure(figsize=(6,5), dpi=100)
        ax2 = figure2.add_subplot(111)
        ax2.set_xlabel("Type")
        ax2.set_ylabel("Amount")
        ax2.set_title('Discoved File type compare')
        ax2.figure.autofmt_xdate(rotation=45)
        ax2.tick_params(axis="x", labelsize=6)
        bar2 = FigureCanvasTkAgg(figure2, canvas2)
        bar2.get_tk_widget().pack()
        try:
            df2.plot(kind='bar', legend=True, ax=ax2)
        except:
            pass
        # insert data

        for key, val in scan_info.items():
            if key == "Scan option: ":
                continue
            lb_current.insert(tk.END, "{:>20} {:<}".format(key, val))
        for key, val in scan_info2.items():
            if key == "Scan option: ":
                continue
            lb_target.insert(tk.END, "{:>20} {:<}".format(key, val))

def select_prev_s(lb_prev, n_prev):
    db_id = lb_prev.get(tk.ACTIVE).split(" ")[0]
    mycursor = mydb.cursor()
    sql = "select date, cmd, path from skipfish where id = " + db_id
    mycursor.execute(sql)
    db_result = mycursor.fetchall()
    db_cmd = db_result[0][1]
    db_path = db_result[0][2]
    mycursor.close()
    n_prev.destroy()
    url_path.append(db_path)
    soup = get_scan_soup(db_path)
    scan_info = get_scan_info(soup, db_cmd)
    scan_count_number = get_scan_count_number(soup)
    scan_level_count = get_scan_level(soup)
    file_len = scan_count_number - len(scan_level_count)
    scan_cout_file, scan_count = get_scan_count(soup, file_len)
    scan_item_file, scan_item = get_scan_item(soup, file_len)
    display_skipfish_data(scan_info, scan_cout_file, scan_item_file, scan_count, scan_item, scan_level_count)

def get_scan_soup(url):
    opt = Options()
    opt.add_argument("--headless")
    browser = Firefox(options=opt)
    browser.get(url)
    soup = bp(browser.page_source, 'lxml')
    browser.quit()
    return soup

def get_scan_info(soup, cmd_opt):
    scan_name = {}
    scan_name["Scan option: "] = cmd_opt
    scan_name["Scanner version: "] = soup.find("td", id="sf_version").text
    scan_name["Scan date: "] = soup.find("td", id="scan_date").text
    scan_name["Random seed: "] = soup.find("td", id="scan_seed").text
    scan_name["Scan time: "] = soup.find("td", id="scan_time").text
    return scan_name

def get_scan_count_number(soup):
    scan_count_number = 0
    for item in soup.find_all("span", class_="sum_name"):
        scan_count_number += 1
    return scan_count_number

def get_scan_level(soup):
    scan_level = []
    for x in soup.find_all("div", id="issue_types"):
        for y in x.find_all("img"):
            if y['src'] == "i_note.png":
                scan_level.append("1")
            elif y['src'] == "i_warn.png":
                scan_level.append("2")
            elif y['src'] == "i_low.png":
                scan_level.append("3")
            elif y['src'] == "i_medium.png":
                scan_level.append("4")
            else:
                scan_level.append("5")
    return scan_level

def get_scan_count(soup, file_len):
    scan_count_file = []
    scan_count = []
    for count in soup.find_all("span", class_="s_cnt"):
        temp = count.text[1:-1].split(" ")
        if len(temp) == 1:
            if len(scan_count_file) < file_len:
                scan_count_file.append(temp[0])
            else:
                scan_count.append(temp[0])
    return scan_count_file, scan_count
        
def get_scan_item(soup, file_len):
    scan_item_file = []
    scan_item = []
    for item in soup.find_all("span", class_="sum_name"):
        if len(scan_item_file) < file_len:
            scan_item_file.append(item.text)
        else:
            scan_item.append(item.text)
    return scan_item_file, scan_item

def display_skipfish_data(scan_name, scan_count_file, scan_item_file, scan_count, scan_item, scan_level_count):
    reset_skip_info()
    reset_skip_result()
    reset_chart()
    count = 1
    lv = scan_level_count[0]
    # Level
    if lv == "5":
        s_result_list_value_n[0].insert(0, "Five")
        s_result_list_value_n[0].config(fg = "white", background="black")
    elif lv == "4":
        s_result_list_value_n[0].insert(0, "Four")
        s_result_list_value_n[0].config(fg = "white", background="red")
    elif lv == "3":
        s_result_list_value_n[0].insert(0, "Three")
        s_result_list_value_n[0].config(fg = "white", background="orange")
    elif lv == "2":
        s_result_list_value_n[0].insert(0, "Two")
        s_result_list_value_n[0].config(fg = "white", background="blue")
    else:
        s_result_list_value_n[0].insert(0, "One")
        s_result_list_value_n[0].config(fg = "white", background="green")


    for key, val in scan_name.items():
        s_result_list_value_n[count].insert(0, val)
        count = count + 1
        # result_text_s.insert(tk.END, "{:>20} {:<}\n".format(key, val))

    result_text_s.insert(tk.END, "=======Discovered file type=======\n")
    for x, y in zip(scan_count_file, scan_item_file):
        result_text_s.insert(tk.END, "{:>3} : {:<45}\n".format(x, y))

    result_text_s.insert(tk.END, "=======Discovered security issues=======\n")
    for x, y, z in zip(scan_count, scan_item, scan_level_count):
        result_text_s.insert(tk.END, "Count: {:>3} > {:<45} Security Level: {}\n".format(x, y, z))

    security_level_set = [0,0,0,0,0]
    for key, val in zip(scan_level_count, scan_count):
        security_level_set[int(key) - 1] += int(val)

    tag = ["One", "Two", "Three", "Four", "Five"]
    df1 = pandas.DataFrame({"Level":tag, "Amount":security_level_set})
    df1.set_index("Level", inplace = True, drop = True)
    df2 = pandas.DataFrame({"Type":scan_item_file, "Amount":scan_count_file})
    df2.set_index("Type", inplace = True, drop = True)
    df2.Amount = pandas.to_numeric(df2.Amount)
    updateChart_s(df1, df2, len(scan_item_file))

    lock_skipfish()

def display_skipfish(url, cmd_opt):
    reset_skip_result()
    opt = Options()
    opt.add_argument("--headless")
    browser = Firefox(options=opt)
    browser.get(url)
    soup = bp(browser.page_source, 'lxml')
    browser.quit()
    scan_info = get_scan_info(soup, cmd_opt)
    scan_count_number = get_scan_count_number(soup)
    scan_level_count = get_scan_level(soup)
    file_len = scan_count_number - len(scan_level_count)
    scan_cout_file, scan_count = get_scan_count(soup, file_len)
    scan_item_file, scan_item = get_scan_item(soup, file_len)
    display_skipfish_data(scan_info, scan_cout_file, scan_item_file, scan_count, scan_item, scan_level_count)
    
    # scan_name = {}
    # scan_name["Scan option: "] = cmd_opt
    # scan_name["Scanner version: "] = soup.find("td", id="sf_version").text
    # scan_name["Scan date: "] = soup.find("td", id="scan_date").text
    # scan_name["Random seed: "] = soup.find("td", id="scan_seed").text
    # scan_name["Scan time: "] = soup.find("td", id="scan_time").text

    # scan_count_number = 0

    # for item in soup.findAll("span", class_="sum_name"):
    #     scan_count_number += 1


    # scan_count_file = []
    # scan_item_file = []
    # scan_count = []
    # scan_item = []
    # scan_level = []

    # for x in soup.findAll("div", id="issue_types"):
    #     for y in x.findAll("img"):
    #         if y['src'] == "i_note.png":
    #             scan_level.append("1")
    #         elif y['src'] == "i_warn.png":
    #             scan_level.append("2")
    #         elif y['src'] == "i_low.png":
    #             scan_level.append("3")
    #         elif y['src'] == "i_medium.png":
    #             scan_level.append("4")
    #         else:
    #             scan_level.append("5")

    # file_len = scan_count_number - len(scan_level)

    # for count in soup.findAll("span", class_="s_cnt"):
    #     temp = count.text[1:-1].split(" ")
    #     if len(temp) == 1:
    #         if len(scan_count_file) < file_len:
    #             scan_count_file.append(temp[0])
    #         else:
    #             scan_count.append(temp[0])

    # for item in soup.findAll("span", class_="sum_name"):
    #     if len(scan_item_file) < file_len:
    #         scan_item_file.append(item.text)
    #     else:
    #         scan_item.append(item.text)

    # result_text_s.insert(tk.END, "=======Discovered file type=======\n")
    # for x, y in zip(scan_count_file, scan_item_file):
    #     result_text_s.insert(tk.END, "{:>3} : {:<45}\n".format(x, y))

    # result_text_s.insert(tk.END, "=======Discovered security issues=======\n")
    # for x, y, z in zip(scan_count, scan_item, scan_level):
    #     result_text_s.insert(tk.END, "Count: {:>3} > {:<45} Security Level: {}\n".format(x, y, z))

def open_detail():
    result_text_s.insert(tk.END, "Report data is aleady displayed in the GUI.\n")
    if len(url_path) != 0:
        webbrowser.open(url_path[0])
    else:
        result_text_s.insert(tk.END, "There are no current report, please scan or open a previous file.\n")

# Input
lb_info_bi_s = tk.Label(s_input, text="Basic Input")
lb_info_bi_s.grid(row = 0, column = 0, pady = 5, sticky="w")

lb_ip_s = tk.Label(s_input, text="Ip address:")
lb_ip_s.grid(row = 1, column = 0, pady = 5, sticky="nsew")
en_ip_s = tk.Entry(s_input)
en_ip_s.grid(row = 1, column = 1, pady = 5, sticky="nsew")

lb_ip_s = tk.Label(s_input, text="Directory:")
lb_ip_s.grid(row = 2, column = 0, pady = 5, sticky="nsew")
en_dir_s = tk.Entry(s_input)
en_dir_s.grid(row = 2, column = 1, pady = 5, sticky="nsew")

btn_op_s = tk.Button(s_input, text="Output Dir:", command = select_dir_s)
btn_op_s.grid(row = 3, column = 0, pady = 5, sticky="nsew")
en_op_s = tk.Entry(s_input)
en_op_s.grid(row = 3, column = 1, pady = 5, sticky="nsew")


# bi_list_s = ["Http auth", "Custom cookie", "Custom Http header"]
# bi_list_value_s = []
# bi_list_text_s = []
# for i in range(len(bi_list_s)):
#     bi_list_value_s.append(tk.IntVar())
#     tk.Checkbutton(s_input, text=bi_list_s[i], variable=bi_list_value_s[i]).grid(row = i + 4, column = 0, pady = 5, sticky="nsew")
#     bi_list_text_s.append(tk.Entry(s_input))
#     bi_list_text_s[i].grid(row = i + 4, column = 1, pady = 5, sticky="nsew")

# # Scope
lb_info_btn = tk.Label(s_scope, text="Sacn information:")
lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="nsew")

s_result_list_n = ["Security level:" ,"Scan option:", "Scanner version:", "Scan date:", "Random seed:",
                "Scan Time:"]
s_result_list_value_n = []

for i in range(len(s_result_list_n)):
    tk.Label(s_scope, text=s_result_list_n[i]).grid(row = i + 1, column = 0, pady = 5, sticky="nsew")
    s_result_list_value_n.append(tk.Entry(s_scope))
    s_result_list_value_n[i].grid(row = i + 1, column = 1, pady = 5, sticky = "nsew")    



# lb_info_btn = tk.Label(s_scope, text="Crawl scope options")
# lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")

# s_list_s = ["Maximum crawl tree depth", "maximum children to index per node", "maximum descendants to index per branch", 
# "max total number of requests to send", "node and link crawl probability", "repeat probabilistic scan with given seed",
# "only follow URLs matching 'string'", "exclude URLs matching 'string'", "do not fuzz parameters named 'string'", "crawl cross-site links to another domain",
# "trust, but do not crawl, another domain", "do not descend into 5xx locations", "do not submit any forms", "do  not parse HTML, etc, to find new links"]
# s_list_value_s = []
# s_list_text_s = []
# for i in range(len(s_list_s)):
#     s_list_value_s.append(tk.IntVar())
#     tk.Checkbutton(s_scope, text=s_list_s[i], variable=s_list_value_s[i]).grid(row = i + 2, column = 0, pady = 5, sticky="w")
#     if i < len(s_list_s) - 3:
#         s_list_text_s.append(tk.Entry(s_scope))
#         s_list_text_s[i].grid(row = i + 2, column = 1, pady = 5, sticky="nsew")
    
# Report
lb_info_btn = tk.Label(s_report, text="Reporting options")
lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")

rp_list_s = ["completely suppress duplicate nodes in reports", "be quiet, disable realtime progress stats"]
rp_list_value_s = []
rp_list_text_s = []
for i in range(len(rp_list_s)):
    rp_list_value_s.append(tk.IntVar())
    tk.Checkbutton(s_report, text=rp_list_s[i], variable=rp_list_value_s[i]).grid(row = i + 2, column = 0, pady = 5, sticky="w")
    
# Dictionary
# lb_info_btn = tk.Label(s_dir, text="Dictionary management options")
# lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")

# dir_list_s = ["use a specified read-write wordlist (required)", "load a supplemental read-only wordlist", "purge words hit more than 'age' scans ago",
#  "add new form auto-fill rule", "maximum number of keyword guesses to keep (256)", "do not auto-learn new keywords for the site", "do not fuzz extensions in directory brute-force"]
# dir_list_value_s = []
# dir_list_text_s = []
# for i in range(len(dir_list_s)):
#     dir_list_value_s.append(tk.IntVar())
#     tk.Checkbutton(s_dir, text=dir_list_s[i], variable=dir_list_value_s[i]).grid(row = i + 2, column = 0, pady = 5, sticky="w")
#     if i < len(dir_list_s) - 1:
#         dir_list_text_s.append(tk.Entry(s_dir))
#         dir_list_text_s[i].grid(row = i + 2, column = 1, pady = 5, sticky="nsew")
    

# Performance setting
lb_info_btn = tk.Label(s_per, text="Performance setting")
lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")

per_list_s = ["max simultaneous TCP connections, global", "max simultaneous connections, per target IP",
"total request response timeout", "timeout on idle HTTP connections",
"response size limit"]
per_list_value_s = []
per_list_text_s = []
for i in range(len(per_list_s)):
    per_list_value_s.append(tk.IntVar())
    tk.Checkbutton(s_per, text=per_list_s[i], variable=per_list_value_s[i]).grid(row = i + 2, column = 0, pady = 5, sticky="w")
    

# Result text
result_text_s = tk.Text(s_result_text, width = 124, height = 18)
result_text_s.grid(row = 3, column = 0, rowspan = 3,  sticky="nsew")

# Chart
canvas3 = tk.Canvas(s_chart, width = 100, height = 100)
canvas4 = tk.Canvas(s_chart, width = 100, height = 100)

canvas3.grid(row = 0, column = 0, pady = 5, sticky = "nsew")
canvas4.grid(row = 0, column = 1, pady = 5, sticky = "nsew")
figure3 = plt.Figure(figsize=(5,4), dpi=100)
bar3 = FigureCanvasTkAgg(figure3, canvas3)
bar3.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH)
figure4 = plt.Figure(figsize=(5,4), dpi=100)
bar4 = FigureCanvasTkAgg(figure4, canvas4)
bar4.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH)


def reset_chart():
    figure3.clear()
    bar3.draw_idle()
    figure4.clear()
    bar4.draw_idle()

def updateChart_s(df1, df2, x):
    figure3.clear()
    figure4.clear()
    ax3 = figure3.add_subplot(111)
    ax3.set_title("Security Level Count")
    try:
        df1.plot(kind="bar", legend=False, ax=ax3)
    except:
        pass
    color = ["green", "blue", "orange", "red","black"]
    ax3.figure.autofmt_xdate(rotation=0)
    for i in range(len(color)):
        ax3.get_children()[i].set_color(color[i])
    
    bar3.draw_idle()
    ax4 = figure4.add_subplot(111)
    ax4.set_title("Discovered File type")
    try:
        df2.plot(kind="bar", legend=False, ax=ax4)
    except:
        pass
    for i in range(x):
        ax4.get_children()[i].set_color("#" + "%06x" % random.randint(0xAAAAAA, 0xFFFFFF))
    ax4.figure.autofmt_xdate(rotation=25)
    bar4.draw_idle()

# Button
lb_info_btn = tk.Label(s_button, text="Control")
lb_info_btn.grid(row = 0, column = 0, pady = 5, sticky="w")

btn_start_s = tk.Button(s_button, text="Start", command = run_skipfish)
btn_start_s.grid(row = 1, column = 0, pady = 5, sticky="nsew")

btn_reset_s = tk.Button(s_button, text="Reset", command = reset_skip)
btn_reset_s.grid(row = 2, column = 0, pady = 5, sticky="nsew")

btn_open_s = tk.Button(s_button, text="Open previous", command = open_prev_s)
btn_open_s.grid(row = 3, column = 0, pady = 5, sticky="nsew")

btn_detail_s = tk.Button(s_button, text="Open detail", command = open_detail)
btn_detail_s.grid(row = 4, column = 0, pady = 5, sticky="nsew")

btn_compare_s = tk.Button(s_button, text="Compare", command = compare_to_s)
btn_compare_s.grid(row = 5, column = 0, pady = 5, sticky="nsew")

#  Run
root.mainloop()
