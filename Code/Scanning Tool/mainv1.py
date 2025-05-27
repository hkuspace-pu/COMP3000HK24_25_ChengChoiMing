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