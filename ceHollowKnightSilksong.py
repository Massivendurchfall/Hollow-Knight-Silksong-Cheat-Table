import tkinter as tk
from tkinter import ttk
import ctypes, sys
from pymem import Pymem
from pymem import process as pm_process

game_title = "Hollow Knight Silksong"
module_name = "UnityPlayer.dll"
value_type = "int32"

targets = {
    "Shards": {
        "base_offset": "0x1EFD460",
        "offsets": [0, 0x10, 0x148, 0x18, 0, 0x30, 0x908],
    },
    "Health": {
        "base_offset": "0x1EFD460",
        "offsets": [0, 0x10, 0x148, 0x18, 0, 0x30, 0x21C],
    },
    "Other Shards": {
        "base_offset": "0x1F23788",
        "offsets": [0x90, 0xC8, 0x118, 0x20, 0x48, 0x50, 0x23C],
    },
}

user32 = ctypes.windll.user32
GetWindowTextW = user32.GetWindowTextW
GetWindowTextLengthW = user32.GetWindowTextLengthW
IsWindowVisible = user32.IsWindowVisible
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

def find_pids_by_title(part):
    results = []
    part_l = part.lower()
    def cb(hwnd, lparam):
        if not IsWindowVisible(hwnd):
            return True
        ln = GetWindowTextLengthW(hwnd)
        if ln == 0:
            return True
        buf = ctypes.create_unicode_buffer(ln + 1)
        GetWindowTextW(hwnd, buf, ln + 1)
        title = buf.value
        if part_l in title.lower():
            pid = ctypes.c_ulong()
            GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            results.append((hwnd, title, pid.value))
        return True
    EnumWindows(EnumWindowsProc(cb), 0)
    return results

def to_int(text):
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t)

def read_ptr(pm, addr):
    if pm_process.is_64_bit(pm.process_handle):
        return pm.read_ulonglong(addr)
    else:
        return pm.read_uint(addr)

def resolve_address(pm, module, base_off, offsets):
    mod = pm_process.module_from_name(pm.process_handle, module)
    base = mod.lpBaseOfDll
    addr = base + base_off
    ptr = read_ptr(pm, addr)
    if not offsets:
        return ptr
    for off in offsets[:-1]:
        ptr = read_ptr(pm, ptr + off)
    return ptr + offsets[-1]

def read_value(pm, addr, typ):
    if typ == "int32":
        return pm.read_int(addr)
    if typ == "uint32":
        return pm.read_uint(addr)
    if typ == "int64":
        return pm.read_longlong(addr)
    if typ == "uint64":
        return pm.read_ulonglong(addr)
    if typ == "float":
        return pm.read_float(addr)
    if typ == "double":
        return pm.read_double(addr)
    raise ValueError("Unknown type")

def write_value(pm, addr, typ, text):
    if typ in ("int32", "uint32", "int64", "uint64"):
        val = int(text, 16) if text.lower().startswith("0x") else int(text)
    elif typ in ("float", "double"):
        val = float(text)
    else:
        raise ValueError("Unknown type")
    if typ == "int32":
        pm.write_int(addr, val)
    elif typ == "uint32":
        pm.write_uint(addr, val)
    elif typ == "int64":
        pm.write_longlong(addr, val)
    elif typ == "uint64":
        pm.write_ulonglong(addr, val)
    elif typ == "float":
        pm.write_float(addr, val)
    elif typ == "double":
        pm.write_double(addr, val)

def current_target_cfg():
    key = combo_target.get()
    return targets[key]

def pretty_offsets(lst):
    return ",".join([f"0x{x:X}" if x >= 10 else str(x) for x in lst])

def update_target_labels(event=None):
    cfg = current_target_cfg()
    lbl_base_var.set(cfg["base_offset"])
    lbl_offsets_var.set(pretty_offsets(cfg["offsets"]))

def set_status(text):
    status_var.set(text)

def auto_connect():
    global pm_obj, current_pid, found_windows
    try:
        wins = find_pids_by_title(game_title)
        found_windows = wins
        listbox.delete(0, tk.END)
        for hwnd, title, pid in wins:
            listbox.insert(tk.END, f"[{pid}] {title}")
        if not wins:
            pm_obj = None
            current_pid = None
            set_status("Waiting for game ...")
            toggle_io(False)
            app.after(1500, auto_connect)
            return
        hwnd, title, pid = wins[0]
        pm = Pymem()
        pm.open_process_from_id(pid)
        pm_obj = pm
        current_pid = pid
        set_status(f"Connected PID {pid}: {title}")
        listbox.selection_clear(0, tk.END)
        listbox.selection_set(0)
        toggle_io(True)
        app.after(200, auto_refresh_tick)
    except Exception as e:
        pm_obj = None
        current_pid = None
        toggle_io(False)
        set_status(f"Error: {e}")
        app.after(1500, auto_connect)

def connect_from_list(event=None):
    global pm_obj, current_pid
    try:
        idxs = listbox.curselection()
        if not idxs:
            return
        hwnd, title, pid = found_windows[idxs[0]]
        pm = Pymem()
        pm.open_process_from_id(pid)
        pm_obj = pm
        current_pid = pid
        set_status(f"Connected PID {pid}: {title}")
        toggle_io(True)
    except Exception as e:
        pm_obj = None
        current_pid = None
        toggle_io(False)
        set_status(f"Error: {e}")

def disconnect():
    global pm_obj, current_pid
    try:
        if pm_obj:
            pm_obj.close_process()
    finally:
        pm_obj = None
        current_pid = None
        toggle_io(False)
        set_status("Disconnected")

def toggle_io(on):
    state = "normal" if on else "disabled"
    btn_read.configure(state=state)
    btn_write.configure(state=state)
    btn_load_current.configure(state=state)
    entry_value.configure(state=state)

def do_read():
    try:
        if not pm_obj:
            return
        cfg = current_target_cfg()
        base_off = to_int(cfg["base_offset"])
        offs = cfg["offsets"]
        addr = resolve_address(pm_obj, module_name, base_off, offs)
        val = read_value(pm_obj, addr, value_type)
        current_value_var.set(str(val))
        lbl_addr_var.set(f"Address: 0x{addr:016X}")
        set_status("Read OK")
    except Exception as e:
        set_status(f"Error: {e}")

def do_write():
    try:
        if not pm_obj:
            return
        cfg = current_target_cfg()
        base_off = to_int(cfg["base_offset"])
        offs = cfg["offsets"]
        addr = resolve_address(pm_obj, module_name, base_off, offs)
        write_value(pm_obj, addr, value_type, entry_value.get().strip())
        lbl_addr_var.set(f"Address: 0x{addr:016X}")
        set_status("Write OK")
    except Exception as e:
        set_status(f"Error: {e}")

def load_current_into_entry():
    entry_value.delete(0, tk.END)
    entry_value.insert(0, current_value_var.get())

def auto_refresh_tick():
    try:
        if pm_obj and var_auto.get():
            do_read()
    finally:
        app.after(500, auto_refresh_tick)

app = tk.Tk()
app.title("Silksong Pointer Tool")
app.geometry("820x500")

pm_obj = None
current_pid = None
found_windows = []

frame_top = ttk.Frame(app, padding=10)
frame_top.pack(fill="x")

ttk.Label(frame_top, text="Game:").grid(row=0, column=0, sticky="w")
ttk.Label(frame_top, text=game_title).grid(row=0, column=1, sticky="w", padx=6)
btn_rescan = ttk.Button(frame_top, text="Rescan", command=auto_connect)
btn_rescan.grid(row=0, column=2, padx=6)
btn_disc = ttk.Button(frame_top, text="Disconnect", command=disconnect)
btn_disc.grid(row=0, column=3)
frame_top.columnconfigure(1, weight=1)

list_frame = ttk.Frame(app, padding=(10, 0))
list_frame.pack(fill="x")
ttk.Label(list_frame, text="Found windows:").pack(anchor="w")
listbox = tk.Listbox(list_frame, height=3)
listbox.pack(fill="x")
listbox.bind("<<ListboxSelect>>", connect_from_list)

status_var = tk.StringVar(value="Not connected")
ttk.Label(app, textvariable=status_var, padding=(10, 6)).pack(fill="x")

frame_cfg = ttk.Frame(app, padding=10)
frame_cfg.pack(fill="x")

ttk.Label(frame_cfg, text="Target:").grid(row=0, column=0, sticky="w")
combo_target = ttk.Combobox(frame_cfg, values=list(targets.keys()), state="readonly")
combo_target.current(0)
combo_target.grid(row=0, column=1, sticky="w", padx=6)
combo_target.bind("<<ComboboxSelected>>", update_target_labels)

ttk.Label(frame_cfg, text="Module:").grid(row=1, column=0, sticky="w")
ttk.Label(frame_cfg, text=module_name).grid(row=1, column=1, sticky="w", padx=6)

ttk.Label(frame_cfg, text="Base offset:").grid(row=2, column=0, sticky="w")
lbl_base_var = tk.StringVar(value="")
ttk.Label(frame_cfg, textvariable=lbl_base_var).grid(row=2, column=1, sticky="w", padx=6)

ttk.Label(frame_cfg, text="Offsets (bottom→top):").grid(row=3, column=0, sticky="w")
lbl_offsets_var = tk.StringVar(value="")
ttk.Label(frame_cfg, textvariable=lbl_offsets_var).grid(row=3, column=1, sticky="w", padx=6)

ttk.Label(frame_cfg, text="Type:").grid(row=4, column=0, sticky="w")
ttk.Label(frame_cfg, text=value_type).grid(row=4, column=1, sticky="w", padx=6)
frame_cfg.columnconfigure(1, weight=1)

frame_io = ttk.Frame(app, padding=10)
frame_io.pack(fill="x")

ttk.Label(frame_io, text="Current:").grid(row=0, column=0, sticky="w")
current_value_var = tk.StringVar(value="")
ttk.Label(frame_io, textvariable=current_value_var).grid(row=0, column=1, sticky="w", padx=6)

ttk.Label(frame_io, text="New value:").grid(row=1, column=0, sticky="w")
entry_value = ttk.Entry(frame_io)
entry_value.grid(row=1, column=1, sticky="ew", padx=6)

btn_load_current = ttk.Button(frame_io, text="Load current", command=load_current_into_entry)
btn_load_current.grid(row=1, column=2, padx=6)

btn_read = ttk.Button(frame_io, text="Read", command=do_read)
btn_read.grid(row=2, column=2, padx=6, pady=(6, 0))

btn_write = ttk.Button(frame_io, text="Write", command=do_write)
btn_write.grid(row=2, column=3, pady=(6, 0))

frame_io.columnconfigure(1, weight=1)

frame_status2 = ttk.Frame(app, padding=(10, 0))
frame_status2.pack(fill="x")
lbl_addr_var = tk.StringVar(value="Address: -")
ttk.Label(frame_status2, textvariable=lbl_addr_var).pack(side="left")
var_auto = tk.BooleanVar(value=True)
ttk.Checkbutton(frame_status2, text="Auto refresh", variable=var_auto).pack(side="right")

update_target_labels()
toggle_io(False)

if sys.platform == "win32":
    app.after(200, auto_connect)
    app.after(300, auto_refresh_tick)
else:
    set_status("Windows only")

app.mainloop()
