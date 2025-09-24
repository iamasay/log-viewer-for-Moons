import ttkbootstrap as tb
from tkinter import filedialog
from tkinter import ttk  # Для Combobox и Progressbar
import tkinter as tk
import re
import os
import time

window = tb.Window(themename="darkly")
window.title("Парсер логов by iamasay")
window.geometry("400x300")

buttons = []

# Добавляем контейнер для списка файлов с чекбоксами
files_frame = tb.Frame(window)
files_frame.pack(fill="both", expand=False, padx=10, pady=5)

# Словарь: ключ - путь к файлу, значение - tk.BooleanVar для чекбокса
file_vars = {}

def merge_selected_logs():
    # Собираем пути выбранных файлов (чекбокс отмечен)
    selected_files = [path for path, var in file_vars.items() if var.get()]
    if len(selected_files) < 2:
        tb.Messagebox.show_warning(title="Внимание", message="Выберите минимум два файла для объединения.")
        return

    all_lines = []       # Список кортежей (время, строка)
    all_round_ids = set()  # Множество уникальных round ID

    # Регулярное выражение для извлечения временной метки из начала строки
    datetime_pattern = re.compile(r'^$$(?P<datetime>[^]]+)$$')

    for file_path in selected_files:
        # Извлекаем round ID из файла
        round_id = extract_round_id_from_file(file_path)
        if round_id:
            all_round_ids.add(round_id)

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    # Пропускаем строку с round ID в начале файла
                    if line.startswith("Starting up round ID"):
                        continue

                    m = datetime_pattern.match(line)
                    if m:
                        dt_str = m.group("datetime")
                        # Преобразуем строку времени в объект time.struct_time для сортировки
                        try:
                            dt_obj = time.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                        except Exception:
                            # Если парсинг не удался, ставим минимальное время (чтобы такие строки были в начале)
                            dt_obj = time.gmtime(0)
                        all_lines.append((dt_obj, line))
                    else:
                        # Если нет временной метки, ставим минимальное время
                        all_lines.append((time.gmtime(0), line))
        except Exception as e:
            tb.Messagebox.show_error(title="Ошибка", message=f"Не удалось прочитать файл {file_path}:\n{e}")
            return

    # Сортируем все строки по времени (dt_obj)
    all_lines.sort(key=lambda x: x[0])

    # Извлекаем только текст строк
    merged_lines = [line for _, line in all_lines]

    # Создаем временный "файл" в памяти с объединённым логом
    # Для отображения используем существующую функцию new_window_with_log,
    # но передадим ей данные напрямую (cached_data)

    # Формируем заголовок с перечислением уникальных round ID через запятую
    round_ids_str = ", ".join(sorted(all_round_ids))

    # Создаем новое окно для объединённого лога
    new_window = tb.Toplevel(window)
    new_window.title(f"Объединённый лог — Round ID: {round_ids_str}")
    new_window.geometry("700x600")

    filter_frame = tb.Frame(new_window)
    filter_frame.pack(fill="x", padx=10, pady=5)

    filter_ckey_label = tb.Label(filter_frame, text="Фильтр по ckey: нет", bootstyle="info")
    filter_ckey_label.pack(side="left", padx=5)

    search_label = tb.Label(filter_frame, text="Поиск ckey:")
    search_label.pack(side="left", padx=(20, 5))

    search_var = tk.StringVar()
    search_entry = tb.Entry(filter_frame, textvariable=search_var, width=15)
    search_entry.pack(side="left", padx=5)

    hide_no_key_var = tk.BooleanVar(value=False)
    hide_no_key_check = tb.Checkbutton(filter_frame, text="Скрыть логи мобов", variable=hide_no_key_var)
    hide_no_key_check.pack(side="left", padx=10)

    filter_logtype_var = tk.StringVar(value="Все")
    logtypes_list = ["Все"] + sorted({lt for lt in LOGTYPE_COLORS.keys() if lt not in ("datetime", "ckey", "charname", "message", "location", "other")})
    filter_logtype_combo = ttk.Combobox(filter_frame, textvariable=filter_logtype_var, values=logtypes_list, state="readonly", width=10)
    filter_logtype_combo.pack(side="right", padx=5)
    filter_logtype_combo_label = tb.Label(filter_frame, text="Фильтр по типу лога:")
    filter_logtype_combo_label.pack(side="right")

    reset_filter_btn = tb.Button(new_window, text="Сбросить фильтр", bootstyle="warning-outline")
    reset_filter_btn.pack(pady=5)
    reset_filter_btn.pack_forget()

    close_button = tb.Button(new_window, text="Закрыть окно", command=new_window.destroy)
    close_button.pack(pady=5)

    canvas_frame = tb.Frame(new_window)
    canvas_frame.pack(fill="both", expand=True)

    v_scroll = tb.Scrollbar(canvas_frame, orient="vertical")
    v_scroll.pack(side="right", fill="y")

# Кнопка для объединения выбранных файлов
merge_button = tb.Button(window, text="Объединить выбранные файлы", bootstyle="success", command=merge_selected_logs)
merge_button.pack(pady=10)

PADDING_X = 6
PADDING_Y = 3
SPACING_X = 8
LINE_SPACING_Y = 30

LOGTYPE_COLORS = {
    "OOC": "#4caf50",
    "SAY": "#2196f3",
    "EMOTE": "#ff9800",
    "GAME": "#9c27b0",
    "ACCESS": "#f44336",
    "VOTE": "#00bcd4",
    "ADMIN": "#795548",
    "ATTACK": "#e67e22",
    "datetime": "#3b5998",
    "ckey": "#e91e63",
    "charname": "#535353",
    "message": "#9e9e9e",
    "location": "#607d8b",
    "other": "#888888",
}

# Кеш: ключ - путь к файлу,
# значение - dict с keys: "data" (список распарсенных строк), "timestamp" (время добавления)
loaded_logs = {}
MAX_CACHE_SIZE = 5  # Максимум 5 файлов в кеше

def extract_round_id_from_file(log_file_path):
    round_id = None
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for _ in range(20):  # читаем первые 20 строк
                line = f.readline()
                if not line:
                    break
                m = re.search(r'^Starting up round ID ([^.\s]+)', line)
                if m:
                    round_id = m.group(1)
                    break
    except Exception as e:
        print(f"Ошибка при чтении файла для round ID: {e}")
    return round_id

class LogCanvas(tk.Canvas):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.font = ("TkDefaultFont", 10)
        self.lines = []
        self.filtered_lines = []
        self.text_items = []
        self.tooltip = None
        self.bind_events()
        self.line_height = LINE_SPACING_Y
        self.visible_start = 0
        self.visible_end = 0

        self.bind("<Configure>", lambda e: self.redraw_visible_lines())
        self.bind("<Expose>", lambda e: self.redraw_visible_lines())
        self.bind("<Button-4>", self.on_mousewheel)  # Linux scroll up
        self.bind("<Button-5>", self.on_mousewheel)  # Linux scroll down

    def bind_events(self):
        # Вместо bind_all теперь bind к конкретному виджету
        self.bind("<MouseWheel>", self.on_mousewheel)  # Windows/Mac scroll
        self.bind("<Button-1>", self.on_click)
        self.bind("<Motion>", self.on_motion)
        self.bind("<Leave>", self.on_leave)

    def on_mousewheel(self, event):
        # Прокрутка и обновление отображения
        if event.num == 4:
            self.yview_scroll(-1, "units")
        elif event.num == 5:
            self.yview_scroll(1, "units")
        else:
            self.yview_scroll(int(-1*(event.delta/120)), "units")
        self.redraw_visible_lines()

    def clear(self):
        self.delete("all")
        self.text_items.clear()

    def add_line(self, parts):
        self.lines.append(parts)

    def set_filtered_lines(self, filtered):
        self.filtered_lines = filtered
        # Обновляем scrollregion
        height = len(self.filtered_lines) * self.line_height + 20
        self.configure(scrollregion=(0, 0, self.winfo_width(), height))
        self.yview_moveto(0)
        self.redraw_visible_lines()

    def redraw_visible_lines(self):
        # Рисуем только видимые строки
        self.delete("all")
        self.text_items.clear()

        if not self.filtered_lines:
            return

        # Получаем текущий видимый регион по вертикали
        y0 = self.canvasy(0)
        y1 = self.canvasy(self.winfo_height())

        # Определяем индексы видимых строк
        start_idx = max(0, int(y0 // self.line_height))
        end_idx = min(len(self.filtered_lines), int(y1 // self.line_height) + 1)

        y = start_idx * self.line_height + 10
        for line_idx in range(start_idx, end_idx):
            line = self.filtered_lines[line_idx]
            x = 10
            for part_idx, (text, color) in enumerate(line):
                text_id = self.draw_tag(x, y, text, color)
                if color == LOGTYPE_COLORS["ckey"]:
                    bbox = self.bbox(text_id)
                    if bbox:
                        self.text_items.append({
                            "id": text_id,
                            "text": text,
                            "line_idx": line_idx,
                            "part_idx": part_idx,
                            "bbox": bbox,
                        })
                bbox = self.bbox(text_id)
                if bbox:
                    x = bbox[2] + SPACING_X
            y += self.line_height

    def draw_tag(self, x, y, text, color):
        # Рисуем цветной прямоугольник с текстом
        # Сначала рисуем текст в невидимом месте для измерения
        text_id = self.create_text(
            x + PADDING_X,
            y + PADDING_Y,
            text=text,
            font=self.font,
            anchor="nw",
            fill="#ffffff"
        )
        self.update_idletasks()
        bbox = self.bbox(text_id)
        if not bbox:
            width = 0
            height = 0
        else:
            width = bbox[2] - bbox[0]
            height = bbox[3] - bbox[1]

        self.delete(text_id)

        rect_id = self.create_rectangle(
            x, y,
            x + width + 2*PADDING_X,
            y + height + 2*PADDING_Y,
            fill=color,
            outline="#222222",
            width=1,
        )
        text_id = self.create_text(
            x + PADDING_X,
            y + PADDING_Y,
            text=text,
            font=self.font,
            anchor="nw",
            fill="#ffffff"
        )
        return text_id

    def on_click(self, event):
        x, y = self.canvasx(event.x), self.canvasy(event.y)
        for item in self.text_items:
            bbox = item["bbox"]
            if bbox and bbox[0] <= x <= bbox[2] and bbox[1] <= y <= bbox[3]:
                if hasattr(self, "ckey_click_callback"):
                    ckey = item["text"].strip()
                    self.ckey_click_callback(ckey)
                break

    def on_motion(self, event):
        x, y = self.canvasx(event.x), self.canvasy(event.y)
        hovered_ckey = None
        for item in self.text_items:
            bbox = item["bbox"]
            if bbox and bbox[0] <= x <= bbox[2] and bbox[1] <= y <= bbox[3]:
                hovered_ckey = item["text"]
                break

        if hovered_ckey:
            self.config(cursor="hand2")
            self.show_tooltip(event.x_root, event.y_root, f"Фильтровать по ckey: {hovered_ckey}")
        else:
            self.config(cursor="")
            self.hide_tooltip()

    def on_leave(self, event):
        self.config(cursor="")
        self.hide_tooltip()

    def show_tooltip(self, x, y, text):
        if self.tooltip is None:
            self.tooltip = tk.Toplevel(self)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.attributes("-topmost", True)
            label = tk.Label(self.tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1,
                             font=("TkDefaultFont", 9))
            label.pack()
            self.tooltip_label = label
        else:
            self.tooltip_label.config(text=text)
        self.tooltip.wm_geometry(f"+{x+15}+{y+15}")
        self.tooltip.deiconify()

    def hide_tooltip(self):
        if self.tooltip:
            self.tooltip.withdraw()

def parse_log_line(line):
    # Вариант 1: has attacked/has fired с NEWHP и локацией
    pattern1 = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<attacker_ckey>\*no key\*|[^/]+)/\((?P<attacker_charname>[^)]+)\)\s+'
        r'has\s+(?P<action>\w+)'
        r'(?:\s+(?:at\s+)?(?P<target_ckey>\*no key\*|[^/]+)/\((?P<target_charname>[^)]+)\))?'
        r'(?:\s+with\s+(?P<weapon>.*?))?'
        r'\s*'
        r'(?P<extras>(?:\([A-Z]+:\s*[^)]+\)\s*)*)'
        r'\(NEWHP:\s*(?P<newhp>\d+)\)\s+'
        r'\((?P<location>.+)\)'
    )
    m = pattern1.match(line)
    if m:
        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("attacker_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('attacker_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" has ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("action"), LOGTYPE_COLORS["message"]))
        if m.group("target_ckey") and m.group("target_charname"):
            parts.append((" ", LOGTYPE_COLORS["other"]))
            parts.append((m.group("target_ckey"), LOGTYPE_COLORS["ckey"]))
            parts.append((f"/({m.group('target_charname')})", LOGTYPE_COLORS["charname"]))
        if m.group("weapon"):
            parts.append((" with ", LOGTYPE_COLORS["other"]))
            parts.append((m.group("weapon").strip(), LOGTYPE_COLORS["message"]))
        parts.append((f" (NEWHP: {m.group('newhp')})", LOGTYPE_COLORS["message"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts

    # Вариант 2: has transferred reagents (...) from ... to ... (NEWHP: ...) (location)
    pattern_transfer = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<ckey>[^/]+)/\((?P<charname>[^)]+)\)\s+'
        r'has transferred\s+'
        r'(?P<item>.+?)\s+from\s+(?P<source>.*?)\s+to\s+(?P<target>.+?)\s+'
        r'\(NEWHP:\s*(?P<newhp>\d+)\)\s+'
        r'\((?P<location>.+)\)$'
    )

    m = pattern_transfer.match(line)
    if m:
        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" has transferred ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("item"), LOGTYPE_COLORS["message"]))
        parts.append((" from ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("source"), LOGTYPE_COLORS["message"]))
        parts.append((" to ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("target"), LOGTYPE_COLORS["message"]))
        parts.append((f" (NEWHP: {m.group('newhp')})", LOGTYPE_COLORS["other"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts


    # Вариант 3: has thrown the <item> (location)
# Вариант 3: has thrown the <item> (location), "the" необязательно
    pattern_throw = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<attacker_ckey>\*no key\*|[^/]+)/\((?P<attacker_charname>[^)]+)\)\s+'
        r'has\s+(?P<action>\w+)\s+(?:the\s+)?(?P<item>.+?)\s+'
        r'\((?P<location>.+)\)'
    )
    m = pattern_throw.match(line)
    if m:
        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("attacker_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('attacker_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" has ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("action"), LOGTYPE_COLORS["message"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("item"), LOGTYPE_COLORS["message"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts


    # Вариант 4: has died (damage params) (location)
    pattern_died = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<attacker_ckey>\*no key\*|[^/]+)/\((?P<attacker_charname>[^)]+)\)\s+'
        r'has\s+(?P<action>\w+)'
        r'\s+\((?P<damage_params>[^)]+)\)\s+'
        r'\((?P<location>.+)\)'
    )
    m = pattern_died.match(line)
    if m:
        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("attacker_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('attacker_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" has ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("action"), LOGTYPE_COLORS["message"]))
        parts.append((" (", LOGTYPE_COLORS["other"]))
        parts.append((m.group("damage_params"), LOGTYPE_COLORS["message"]))
        parts.append((") ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts

    # Вариант 5: cast the spell ... с HTML-тегами
    pattern_spell = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<attacker_ckey>\*no key\*|[^/]+)/\((?P<attacker_charname>[^)]+)\)\s+'
        r'(?P<html><span[^>]*>.+?</span>)\s*'
        r'\((?P<location>.+)\)'
    )
    m = pattern_spell.match(line)
    if m:
        from html import unescape
        html_text = m.group("html")
        text = re.sub(r'<[^>]+>', '', html_text)
        text = unescape(text)

        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("attacker_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('attacker_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((text.strip(), LOGTYPE_COLORS["message"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts

    pattern_leashed = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<attacker_ckey>\*no key\*|[^/]+)/\((?P<attacker_charname>[^)]+)\)\s+'
        r'has\s+leashed\s+'
        r'(?P<target_ckey>\*no key\*|[^/]+)/\((?P<target_charname>[^)]+)\)\s+'
        r'(?P<extra>.+?)\s*'
        r'\(NEWHP:\s*(?P<newhp>\d+)\)\s+'
        r'\((?P<location>.+)\)\s*'
    )
    m = pattern_leashed.match(line)
    if m:
        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("attacker_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('attacker_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" has leashed ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("target_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('target_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("extra"), LOGTYPE_COLORS["message"]))
        parts.append((f" (NEWHP: {m.group('newhp')})", LOGTYPE_COLORS["message"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts

    pattern_started_typing = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<attacker_ckey>[^/]+)/\((?P<attacker_charname>[^)]+)\)\s+'
        r'started typing\s+'
        r'\((?P<location>.+)\)\s*'
    )
    m = pattern_started_typing.match(line)
    if m:
        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("attacker_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('attacker_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" started typing ", LOGTYPE_COLORS["other"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts

    pattern_grabbed = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<attacker_ckey>\*no key\*|[^/]+)/\((?P<attacker_charname>[^)]+)\)\s+'
        r'has\s+grabbed\s+'
        r'(?P<target_ckey>\*no key\*|[^/]+)/\((?P<target_charname>[^)]+)\)\s+'
        r'(?P<extra>.+?)\s*'
        r'\(NEWHP:\s*(?P<newhp>\d+)\)\s+'
        r'\((?P<location>.+)\)\s*'
    )
    m = pattern_grabbed.match(line)
    if m:
        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("attacker_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('attacker_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" has grabbed ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("target_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('target_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("extra"), LOGTYPE_COLORS["message"]))
        parts.append((f" (NEWHP: {m.group('newhp')})", LOGTYPE_COLORS["message"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts

    pattern_resisted_grab = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<attacker_ckey>\*no key\*|[^/]+)/\((?P<attacker_charname>[^)]+)\)\s+'
        r'has\s+resisted\s+grab\s+'
        r'(?P<target_ckey>\*no key\*|[^/]+)/\((?P<target_charname>[^)]+)\)\s+'
        r'\(NEWHP:\s*(?P<newhp>\d+)\)\s+'
        r'\((?P<location>.+)\)\s*'
    )
    m = pattern_resisted_grab.match(line)
    if m:
        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("attacker_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('attacker_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" has resisted grab ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("target_ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('target_charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((f" (NEWHP: {m.group('newhp')})", LOGTYPE_COLORS["message"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts

    pattern_lockpick = re.compile(
        r'^\[(?P<datetime>[^\]]+)\]\s+ATTACK:\s+'
        r'(?P<ckey>[^/]+)/\((?P<charname>[^)]+)\)\s+'
        r'(?P<action>(?:attempting to lockpick \w+|finished lockpicking \w+))\s+'
        r'"(?P<object>[^"]+)"\s+'
        r'\((?P<extra>[^)]+)\)\.?\s+'
        r'\((?P<location>.+)\)$'
    )

    m = pattern_lockpick.match(line)
    if m:
        parts = []
        parts.append((f"[{m.group('datetime')}]", LOGTYPE_COLORS["datetime"]))
        parts.append((" ATTACK: ", LOGTYPE_COLORS["ATTACK"]))
        parts.append((m.group("ckey"), LOGTYPE_COLORS["ckey"]))
        parts.append((f"/({m.group('charname')})", LOGTYPE_COLORS["charname"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((m.group("action"), LOGTYPE_COLORS["message"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append(('"', LOGTYPE_COLORS["other"]))
        parts.append((m.group("object"), LOGTYPE_COLORS["message"]))
        parts.append(('"', LOGTYPE_COLORS["other"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('extra')})", LOGTYPE_COLORS["message"]))
        parts.append((" ", LOGTYPE_COLORS["other"]))
        parts.append((f"({m.group('location')})", LOGTYPE_COLORS["location"]))
        return parts


    # Остальные логи — стандартный парсер
    m = re.match(r'^\[(?P<datetime>[^\]]+)\]\s+(?P<logtype>[A-Z]+):\s+(?P<rest>.*)', line)
    if not m:
        return [(line.strip(), LOGTYPE_COLORS["other"])]

    dt = m.group("datetime")
    lt = m.group("logtype")
    rest = m.group("rest")

    parts = [(f"[{dt}]", LOGTYPE_COLORS["datetime"]), (f"{lt}:", LOGTYPE_COLORS.get(lt, LOGTYPE_COLORS["other"]))]

    if lt in ("OOC", "SAY", "EMOTE"):
        m2 = re.match(
            r'^(?P<ckey>[^/]+)/(?:\((?P<charname>[^)]+)\))?\s+"(?P<message>[^"]*)"\s*(?P<location>\(.*\))?', rest)
        if m2:
            ckey = m2.group("ckey")
            charname = m2.group("charname")
            message = m2.group("message")
            location = m2.group("location")

            parts.append((ckey, LOGTYPE_COLORS["ckey"]))
            if charname:
                parts.append((f"/({charname})", LOGTYPE_COLORS["charname"]))
            parts.append((" \"" + message + "\"", LOGTYPE_COLORS["message"]))
            if location:
                parts.append((" " + location, LOGTYPE_COLORS["location"]))
        else:
            parts.append((rest, LOGTYPE_COLORS["message"]))

    elif lt in ("GAME", "ACCESS", "VOTE", "ADMIN"):
        parts.append((rest, LOGTYPE_COLORS["message"]))
    else:
        parts.append((rest, LOGTYPE_COLORS["message"]))

    return parts

    m = re.match(r'^\[(?P<datetime>[^\]]+)\]\s+(?P<logtype>[A-Z]+):\s+(?P<rest>.*)', line)
    if not m:
        return [(line.strip(), LOGTYPE_COLORS["other"])]

    dt = m.group("datetime")
    lt = m.group("logtype")
    rest = m.group("rest")

    parts = [(f"[{dt}]", LOGTYPE_COLORS["datetime"]), (f"{lt}:", LOGTYPE_COLORS.get(lt, LOGTYPE_COLORS["other"]))]

    if lt in ("OOC", "SAY", "EMOTE"):
        m2 = re.match(r'^(?P<ckey>[^/\s]+)/(?:\((?P<charname>[^)]+)\))?\s+"(?P<message>[^"]*)"\s*(?P<location>\(.*\))?', rest)
        if m2:
            ckey = m2.group("ckey")
            charname = m2.group("charname")
            message = m2.group("message")
            location = m2.group("location")

            parts.append((ckey, LOGTYPE_COLORS["ckey"]))
            if charname:
                parts.append((f"/({charname})", LOGTYPE_COLORS["charname"]))
            parts.append((" \"" + message + "\"", LOGTYPE_COLORS["message"]))
            if location:
                parts.append((" " + location, LOGTYPE_COLORS["location"]))
        else:
            parts.append((rest, LOGTYPE_COLORS["message"]))

    elif lt in ("GAME", "ACCESS", "VOTE", "ADMIN"):
        parts.append((rest, LOGTYPE_COLORS["message"]))
    else:
        parts.append((rest, LOGTYPE_COLORS["message"]))

    return parts

    # Ваш существующий парсер для остальных строк
    m = re.match(r'^\[(?P<datetime>[^\]]+)\]\s+(?P<logtype>[A-Z]+):\s+(?P<rest>.*)', line)
    if not m:
        return [(line.strip(), LOGTYPE_COLORS["other"])]

    dt = m.group("datetime")
    lt = m.group("logtype")
    rest = m.group("rest")

    parts = [(f"[{dt}]", LOGTYPE_COLORS["datetime"]), (f"{lt}:", LOGTYPE_COLORS.get(lt, LOGTYPE_COLORS["other"]))]

    if lt in ("OOC", "SAY", "EMOTE"):
        m2 = re.match(r'^(?P<ckey>[^/\s]+)/(?:\((?P<charname>[^)]+)\))?\s+"(?P<message>[^"]*)"\s*(?P<location>\(.*\))?', rest)
        if m2:
            ckey = m2.group("ckey")
            charname = m2.group("charname")
            message = m2.group("message")
            location = m2.group("location")

            parts.append((ckey, LOGTYPE_COLORS["ckey"]))
            if charname:
                parts.append((f"/({charname})", LOGTYPE_COLORS["charname"]))
            parts.append((" \"" + message + "\"", LOGTYPE_COLORS["message"]))
            if location:
                parts.append((" " + location, LOGTYPE_COLORS["location"]))
        else:
            parts.append((rest, LOGTYPE_COLORS["message"]))

    elif lt in ("GAME", "ACCESS", "VOTE", "ADMIN"):
        parts.append((rest, LOGTYPE_COLORS["message"]))
    else:
        parts.append((rest, LOGTYPE_COLORS["message"]))

    return parts

    # Парсим остальные логи
    m = re.match(r'^\[(?P<datetime>[^\]]+)\]\s+(?P<logtype>[A-Z]+):\s+(?P<rest>.*)', line)
    if not m:
        return [(line.strip(), LOGTYPE_COLORS["other"])]

    dt = m.group("datetime")
    lt = m.group("logtype")
    rest = m.group("rest")

    parts = [(f"[{dt}]", LOGTYPE_COLORS["datetime"]), (f"{lt}:", LOGTYPE_COLORS.get(lt, LOGTYPE_COLORS["other"]))]

    if lt in ("OOC", "SAY", "EMOTE"):
        m2 = re.match(r'^(?P<ckey>[^/\s]+)/(?:\((?P<charname>[^)]+)\))?\s+"(?P<message>[^"]*)"\s*(?P<location>\(.*\))?', rest)
        if m2:
            ckey = m2.group("ckey")
            charname = m2.group("charname")
            message = m2.group("message")
            location = m2.group("location")

            parts.append((ckey, LOGTYPE_COLORS["ckey"]))
            if charname:
                parts.append((f"/({charname})", LOGTYPE_COLORS["charname"]))
            parts.append((" \"" + message + "\"", LOGTYPE_COLORS["message"]))
            if location:
                parts.append((" " + location, LOGTYPE_COLORS["location"]))
        else:
            parts.append((rest, LOGTYPE_COLORS["message"]))

    elif lt in ("GAME", "ACCESS", "VOTE", "ADMIN"):
        parts.append((rest, LOGTYPE_COLORS["message"]))
    else:
        parts.append((rest, LOGTYPE_COLORS["message"]))

    return parts

def update_cache(log_file_path, data):
    now = time.time()
    loaded_logs[log_file_path] = {"data": data, "timestamp": now}
    # Ограничиваем размер кеша
    if len(loaded_logs) > MAX_CACHE_SIZE:
        oldest = min(loaded_logs.items(), key=lambda x: x[1]["timestamp"])
        del loaded_logs[oldest[0]]

def remove_from_cache(log_file_path):
    if log_file_path in loaded_logs:
        del loaded_logs[log_file_path]

def new_window_with_log(log_file_path, cached_data=None):
    new_window = tb.Toplevel(window)
    round_id = extract_round_id_from_file(log_file_path)
    if round_id:
        new_window.title(f"{os.path.basename(log_file_path)} — Round ID: {round_id}")
        new_window.geometry("700x600")
    else:
        new_window.title(os.path.basename(log_file_path))
        new_window.geometry("700x600")

    filter_frame = tb.Frame(new_window)
    filter_frame.pack(fill="x", padx=10, pady=5)

    filter_ckey_label = tb.Label(filter_frame, text="Фильтр по ckey: нет", bootstyle="info")
    filter_ckey_label.pack(side="left", padx=5)

    # Добавляем поле ввода для поиска ckey
    search_label = tb.Label(filter_frame, text="Поиск ckey:")
    search_label.pack(side="left", padx=(20, 5))

    search_var = tk.StringVar()
    search_entry = tb.Entry(filter_frame, textvariable=search_var, width=15)
    search_entry.pack(side="left", padx=5)

    # Чекбокс "Скрыть логи с ckey = *no key*"
    hide_no_key_var = tk.BooleanVar(value=False)
    hide_no_key_check = tb.Checkbutton(filter_frame, text="Скрыть логи мобов", variable=hide_no_key_var)
    hide_no_key_check.pack(side="left", padx=10)

    filter_logtype_var = tk.StringVar(value="Все")
    logtypes_list = ["Все"] + sorted({lt for lt in LOGTYPE_COLORS.keys() if lt not in ("datetime", "ckey", "charname", "message", "location", "other")})
    filter_logtype_combo = ttk.Combobox(filter_frame, textvariable=filter_logtype_var, values=logtypes_list, state="readonly", width=10)
    filter_logtype_combo.pack(side="right", padx=5)
    filter_logtype_combo_label = tb.Label(filter_frame, text="Фильтр по типу лога:")
    filter_logtype_combo_label.pack(side="right")

    reset_filter_btn = tb.Button(new_window, text="Сбросить фильтр", bootstyle="warning-outline")
    reset_filter_btn.pack(pady=5)
    reset_filter_btn.pack_forget()

    close_button = tb.Button(new_window, text="Закрыть окно", command=new_window.destroy)
    close_button.pack(pady=5)

    progress = ttk.Progressbar(new_window, orient="horizontal", mode="determinate")
    progress.pack(fill="x", padx=10, pady=5)

    canvas_frame = tb.Frame(new_window)
    canvas_frame.pack(fill="both", expand=True)

    v_scroll = tb.Scrollbar(canvas_frame, orient="vertical")
    v_scroll.pack(side="right", fill="y")

    log_canvas = LogCanvas(canvas_frame, bg="#222222", highlightthickness=0)
    log_canvas.pack(side="left", fill="both", expand=True)

    log_canvas.configure(yscrollcommand=v_scroll.set)
    v_scroll.config(command=log_canvas.yview)
    
    filter_ckey = None
    all_lines_parsed = []
    batch_size = 100

    def display_lines(filter_ckey_param=None, filter_logtype_param=None, hide_no_key=False):
        nonlocal filter_ckey
        filter_ckey = filter_ckey_param

        filter_ckey_lower = filter_ckey.lower() if filter_ckey else None
        filter_logtype_val = filter_logtype_param if filter_logtype_param and filter_logtype_param != "Все" else None

        filtered = []
        for parts in all_lines_parsed:
            ckeys = [text for (text, color) in parts if color == LOGTYPE_COLORS["ckey"]]
            logtype_str = parts[1][0].rstrip(":") if len(parts) > 1 else None

            if hide_no_key and any(ck == "*no key*" for ck in ckeys):
                continue

            ckey_match = True
            logtype_match = True

            if filter_ckey_lower:
                # Ищем подстроку, а не точное совпадение
                ckey_match = any(filter_ckey_lower in ck.lower() for ck in ckeys)
            if filter_logtype_val:
                logtype_match = (logtype_str == filter_logtype_val)

            if ckey_match and logtype_match:
                filtered.append(parts)

        log_canvas.set_filtered_lines(filtered)

        if filter_ckey:
            filter_ckey_label.config(text=f"Фильтр по ckey: {filter_ckey}")
        else:
            filter_ckey_label.config(text="Фильтр по ckey: нет")

        if filter_ckey or filter_logtype_val or hide_no_key:
            reset_filter_btn.pack(pady=5)
        else:
            reset_filter_btn.pack_forget()

    def on_ckey_click(ckey):
        display_lines(filter_ckey_param=ckey,
                      filter_logtype_param=filter_logtype_var.get(),
                      hide_no_key=hide_no_key_var.get())

    log_canvas.ckey_click_callback = on_ckey_click

    def on_logtype_change(event):
        display_lines(filter_ckey_param=filter_ckey,
                      filter_logtype_param=filter_logtype_var.get(),
                      hide_no_key=hide_no_key_var.get())

    filter_logtype_combo.bind("<<ComboboxSelected>>", on_logtype_change)

    def on_hide_no_key_toggle(*args):
        display_lines(filter_ckey_param=filter_ckey,
                      filter_logtype_param=filter_logtype_var.get(),
                      hide_no_key=hide_no_key_var.get())

    hide_no_key_var.trace_add("write", on_hide_no_key_toggle)

    def on_search_apply(event=None):
        ckey_text = search_var.get().strip()
        if ckey_text == "":
            ckey_text = None
        display_lines(filter_ckey_param=ckey_text,
                      filter_logtype_param=filter_logtype_var.get(),
                      hide_no_key=hide_no_key_var.get())

    search_entry.bind("<Return>", on_search_apply)
    search_button = tb.Button(filter_frame, text="Применить", command=on_search_apply)
    search_button.pack(side="left", padx=5)

    def reset_filters():
        filter_logtype_var.set("Все")
        hide_no_key_var.set(False)
        search_var.set("")
        display_lines(None, None, False)

    reset_filter_btn.configure(command=reset_filters)

    # Обработчик закрытия окна — удаляем из кеша
    def on_close():
        remove_from_cache(log_file_path)
        new_window.destroy()

    new_window.protocol("WM_DELETE_WINDOW", on_close)

    if cached_data is not None:
        all_lines_parsed = cached_data
        progress.pack_forget()
        display_lines(None, None, False)
    else:
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
        except Exception as e:
            tb.Messagebox.show_error(title="Ошибка", message=f"Не удалось открыть файл:\n{e}")
            new_window.destroy()
            return

        total_lines = len(all_lines)
        progress["maximum"] = total_lines
        current_index = 0
        all_lines_parsed = []

        def load_batch():
            nonlocal current_index, all_lines_parsed
            end_index = min(current_index + batch_size, total_lines)
            batch = all_lines[current_index:end_index]
            for line in batch:
                all_lines_parsed.append(parse_log_line(line))
            current_index = end_index

            progress["value"] = current_index
            new_window.update_idletasks()

            if current_index < total_lines:
                new_window.after(10, load_batch)
            else:
                progress.pack_forget()
                display_lines(None, None, False)
                update_cache(log_file_path, all_lines_parsed)

        load_batch()

def show_log(log_file_path):
    if log_file_path in loaded_logs:
        cached_data = loaded_logs[log_file_path]["data"]
        new_window_with_log(log_file_path, cached_data=cached_data)
    else:
        new_window_with_log(log_file_path)

def add_file_checkbox(log_file_path):
    filename = os.path.basename(log_file_path)
    if log_file_path in file_vars:
        return  # файл уже добавлен

    var = tk.BooleanVar(value=True)

    # Контейнер для строки с чекбоксом и кнопкой
    row_frame = tb.Frame(files_frame)
    row_frame.pack(anchor="w", fill="x", pady=2)

    cb = tb.Checkbutton(row_frame, text=filename, variable=var)
    cb.pack(side="left", fill="x", expand=True)

    def on_open():
        show_log(log_file_path)

    open_btn = tb.Button(row_frame, text="Открыть", width=8, bootstyle="info", command=on_open)
    open_btn.pack(side="right", padx=5)

    file_vars[log_file_path] = var


def add_new_logs():
    # Выбираем несколько файлов
    log_files = filedialog.askopenfilenames(title="Выберите log файлы", filetypes=[("Логи", "*.log")])
    for log_file_path in log_files:
        add_file_checkbox(log_file_path)

start_button = tb.Button(window, text="Выберите лог файл", command=add_new_logs)
start_button.pack(pady=10)

window.mainloop()