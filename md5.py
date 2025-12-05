import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib,os,zipfile

SUSPICIOUS_EXT = [".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".dll"]

window = tk.Tk()
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


def read_file_header(filepath, length=4):
    try:
        with open(filepath,     "rb") as f:
            data = f.read(length)
        return data.hex(" ").upper()
    except Exception:
        return None

def detect_header_type(header_hex):
    if header_hex.startswith("50 4B"):    # PK
        return "SAFE ZIP (PK header)", "green"
    elif header_hex.startswith("4D 5A"):  # MZ
        return "DANGEROUS / SFX EXE (MZ header)", "red"
    else:
        return f"Unknown header: {header_hex}", "yellow"

def compute_hash(filepath, algo):
    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_zip(filepath):
    result = []
    try:
        with zipfile.ZipFile(filepath, "r") as z:
            for name in z.namelist():
                lower = name.lower()
                is_suspicious = any(lower.endswith(ext) for ext in SUSPICIOUS_EXT)
                result.append((name, is_suspicious))
        return result
    except:
        return None

def open_file():
    filepath = filedialog.askopenfilename(
        title="Select ZIP or EXE",
        filetypes=[("All Files", "*.*")]
    )
    if filepath:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, filepath)

def run_analysis():
    file = entry_file.get()
    if not os.path.isfile(file):
        messagebox.showerror("Error", "Select a valid file.")
        return

    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, f"Checking file: {file}\n\n")

    
    header = read_file_header(file)
    if header is None:
        output_box.insert(tk.END, "Failed to read file header.\n", "red")
        return

    status, color = detect_header_type(header)
    output_box.insert(tk.END, f"[HEADER] {status}\n", color)
    output_box.insert(tk.END, f"Raw header bytes: {header}\n\n")

    
    output_box.insert(tk.END, "[HASHES]\n", "blue")
    for algo in ["md5", "sha1", "sha256"]:
        h = compute_hash(file, algo)
        output_box.insert(tk.END, f"  {algo.upper()}: {h}\n")

    output_box.insert(tk.END, "\n[ZIP SCAN]\n", "blue")

    
    zip_result = scan_zip(file)
    if zip_result is None:
        output_box.insert(tk.END, "Not a valid or readable ZIP archive.\n", "yellow")
    else:
        for name, suspicious in zip_result:
            if suspicious:
                output_box.insert(tk.END, f"⚠ Suspicious: {name}\n", "red")
            else:
                output_box.insert(tk.END, f"   {name}\n")

    output_box.insert(tk.END, "\nDone.\n", "green")



#MAIN LOOP - TKINTER

btn_browse = ttk.Button(frame, text="Browse...", command=open_file)
btn_browse.pack(side=tk.LEFT, padx=5)

btn_run = ttk.Button(window, text="Run Safety Check", command=run_analysis)
btn_run.pack(pady=10)

window.mainloop()
