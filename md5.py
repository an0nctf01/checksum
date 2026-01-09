import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib, os, zipfile

from tkinterdnd2 import TkinterDnD, DND_FILES

SUSPICIOUS_EXT = [".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".dll"]

window = TkinterDnD.Tk()
window.title("Zip/SFX Safety Checker Made By An0nCTF")
window.geometry("780x620")
window.configure(bg="#101010")

style = ttk.Style()
style.configure("TButton", font=("Segoe UI", 11), padding=6)

frame = tk.Frame(window, bg="#101010")
frame.pack(pady=10)

entry_file = tk.Entry(frame, width=60, font=("Consolas", 11))
entry_file.pack(side=tk.LEFT, padx=5)

output_box = tk.Text(window, font=("Consolas", 11), bg="#000000", fg="#00FF00")
output_box.pack(expand=True, fill="both", padx=10, pady=10)

output_box.tag_config("red", foreground="#FF4040")
output_box.tag_config("green", foreground="#40FF40")
output_box.tag_config("yellow", foreground="#FFFF40")
output_box.tag_config("blue", foreground="#40B0FF")



# DRAG & DROP HANDLER
def drop_file(event):
    filepath = event.data.strip("{}") # Handle spaces in file paths 
    if os.path.isfile(filepath):
        entry_file.delete(0, tk.END) 
        entry_file.insert(0, filepath)

# Register drag & drop
window.drop_target_register(DND_FILES)
window.dnd_bind("<<Drop>>", drop_file)


def read_file_header(filepath, length=4):
    try:
        with open(filepath, "rb") as f:
            return f.read(length).hex(" ").upper()
    except:
        return None


def detect_header_type(header_hex):
    if header_hex.startswith("50 4B"):
        return "SAFE ZIP (PK header)", "green"
    elif header_hex.startswith("4D 5A"):
        return "DANGEROUS / SFX EXE (MZ header)", "red"
    elif header_hex.startswith("37 7A BC AF"):
        return "SAFE 7z ARCHIVE", "green"
    elif header_hex.startswith("52 61 72 21"):
        return "SAFE RAR ARCHIVE", "green"
    elif header_hex.startswith("25 50 44 46"):
        return "SAFE PDF DOCUMENT", "green"
    elif header_hex.startswith("89 50 4E 47"):
        return "SAFE PNG IMAGE", "green"
    elif header_hex.startswith("FF D8 FF"):
        return "SAFE JPG IMAGE", "green"
    else:
        return f"Unknown header: {header_hex}", "yellow"


def compute_hash(filepath, algo):
    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_zip(filepath):
    try:
        with zipfile.ZipFile(filepath, "r") as z:
            return [(n, any(n.lower().endswith(e) for e in SUSPICIOUS_EXT)) for n in z.namelist()]
    except:
        return None


def open_file():
    filepath = filedialog.askopenfilename(title="Select File", filetypes=[("All Files", "*.*")])
    if filepath:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, filepath)


def run_analysis():
    file = entry_file.get()
    if not os.path.isfile(file):
        messagebox.showerror("Error", "Select a valid file.")
        return

    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, f"Checking file:\n{file}\n\n")

    header = read_file_header(file)
    if not header:
        output_box.insert(tk.END, "Failed to read file header.\n", "red")
        return

    status, color = detect_header_type(header)
    output_box.insert(tk.END, f"[HEADER] {status}\n", color)
    output_box.insert(tk.END, f"Raw header bytes: {header}\n\n")

    output_box.insert(tk.END, "[HASHES]\n", "blue")
    for algo in ["md5", "sha1", "sha256"]:
        output_box.insert(tk.END, f"{algo.upper()}: {compute_hash(file, algo)}\n")

    output_box.insert(tk.END, "\n[ZIP SCAN]\n", "blue")
    result = scan_zip(file)

    if not result:
        output_box.insert(tk.END, "Not a ZIP archive or unreadable.\n", "yellow")
    else:
        for name, suspicious in result:
            tag = "red" if suspicious else None
            prefix = "⚠ " if suspicious else "   "
            output_box.insert(tk.END, f"{prefix}{name}\n", tag)

    output_box.insert(tk.END, "\nDone.\n", "green")


btn_browse = ttk.Button(frame, text="Browse...", command=open_file)
btn_browse.pack(side=tk.LEFT, padx=5)

btn_run = ttk.Button(window, text="Run Safety Check", command=run_analysis)
btn_run.pack(pady=10)

window.mainloop()
