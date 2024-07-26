import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
from scanner import MalwareScanner
import time

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Malware Scanner")
        self.root.geometry("1000x800")
        self.root.configure(bg="#2e2e2e")
        
        self.title_label = tk.Label(root, text="Malware Scanner", font=("Helvetica", 28, "bold"), bg="#2e2e2e", fg="#ffffff")
        self.title_label.pack(pady=20)

        self.hash_files_button = tk.Button(root, text="Select Hash Files", command=self.load_hash_files, bg="#404040", fg="#ffffff", font=("Helvetica", 12), relief="flat", borderwidth=1, padx=10, pady=5)
        self.hash_files_button.pack(pady=10, fill=tk.X, padx=20)
        self.hash_files_button.bind("<Enter>", self._on_hover)
        self.hash_files_button.bind("<Leave>", self._on_hover_leave)

        self.files_button = tk.Button(root, text="Select Files to Scan", command=self.load_files, bg="#404040", fg="#ffffff", font=("Helvetica", 12), relief="flat", borderwidth=1, padx=10, pady=5)
        self.files_button.pack(pady=10, fill=tk.X, padx=20)
        self.files_button.bind("<Enter>", self._on_hover)
        self.files_button.bind("<Leave>", self._on_hover_leave)

        self.scan_button = tk.Button(root, text="Scan", command=self.scan_files, bg="#4a90e2", fg="#ffffff", font=("Helvetica", 12, "bold"), relief="flat", borderwidth=1, padx=10, pady=5)
        self.scan_button.pack(pady=20, fill=tk.X, padx=20)
        self.scan_button.bind("<Enter>", self._on_hover)
        self.scan_button.bind("<Leave>", self._on_hover_leave)

        # Text area for results
        self.text_area = tk.Text(root, wrap=tk.WORD, height=30, width=100, bg="#333333", fg="#ffffff", font=("Helvetica", 10), borderwidth=2, relief="flat", padx=10, pady=10)
        self.text_area.pack(pady=10, padx=20)
        self.text_area.configure(bg="#333333")

        self.scrollbar = tk.Scrollbar(root, command=self.text_area.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area.config(yscrollcommand=self.scrollbar.set)

        self.hash_files = []
        self.files_to_scan = []

    def _on_hover(self, event):
        event.widget.config(bg="#5a5a5a")

    def _on_hover_leave(self, event):
        event.widget.config(bg="#404040" if event.widget != self.scan_button else "#4a90e2")

    def load_hash_files(self):
        files = filedialog.askopenfilenames(filetypes=[("Text files", "*.txt")])
        self.hash_files = list(files)
        if self.hash_files:
            self._animate_text_area(f"Loaded hash files: {', '.join(self.hash_files)}\n")

    def load_files(self):
        files = filedialog.askopenfilenames(filetypes=[("All files", "*.*")])
        self.files_to_scan = list(files)
        if self.files_to_scan:
            self._animate_text_area(f"Loaded files to scan: {', '.join(self.files_to_scan)}\n")

    def scan_files(self):
        if not self.hash_files or not self.files_to_scan:
            messagebox.showerror("Error", "Please select both hash files and files to scan.")
            return

        self._animate_text_area("Scanning files...\n")
        self.scan_button.config(state=tk.DISABLED)
        self.root.update_idletasks()

        scanner = MalwareScanner(self.hash_files)
        results = scanner.scan_files(self.files_to_scan)

        self.root.after(500, lambda: self.show_results(results))

    def show_results(self, results):
        results_window = tk.Toplevel(self.root)
        results_window.title("Scan Results")
        results_window.geometry("800x600")
        results_window.configure(bg="#2e2e2e")

        status_frame = tk.Frame(results_window, bg="#2e2e2e")
        status_frame.pack(pady=20, fill=tk.X)

        status_label = tk.Label(status_frame, text="Scan Status", font=("Helvetica", 20, "bold"), bg="#2e2e2e", fg="#ffffff")
        status_label.pack(pady=10)

        infected = any(result['infected'] for result in results)
        status_color = "#f44336" if infected else "#4caf50"
        status_message = "Malware Detected" if infected else "Clean"

        status_circle = tk.Canvas(status_frame, width=200, height=200, bg="#2e2e2e", highlightthickness=0)
        status_circle.create_oval(10, 10, 190, 190, fill=status_color)
        status_circle.pack()

        status_circle.create_text(100, 100, text=status_message, fill="white", font=("Helvetica", 12, "bold"))

        text_area = tk.Text(results_window, wrap=tk.WORD, bg="#333333", fg="#ffffff", font=("Helvetica", 10), borderwidth=2, relief="flat", padx=10, pady=10)
        text_area.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)

        scrollbar = tk.Scrollbar(results_window, command=text_area.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_area.config(yscrollcommand=scrollbar.set)

        for result in results:
            self._format_result(text_area, result)

        self.scan_button.config(state=tk.NORMAL)

    def _format_result(self, text_area, result):
        text_area.insert(tk.END, f"\n{'='*40}\n")
        text_area.insert(tk.END, f"File Path: {result['file_path']}\n")
        text_area.insert(tk.END, f"Hashes:\n")
        for k, v in result['hashes'].items():
            text_area.insert(tk.END, f"  {k.upper()}: {v}\n")
        text_area.insert(tk.END, f"CRC32: {result['crc32']}\n")
        text_area.insert(tk.END, f"Infected: {'Yes' if result['infected'] else 'No'}\n")
        text_area.insert(tk.END, f"File Size: {result['size']} bytes\n")
        text_area.insert(tk.END, f"Creation Time: {result['creation_time']}\n")
        text_area.insert(tk.END, f"Modification Time: {result['modification_time']}\n")
        text_area.insert(tk.END, f"Permissions: {result['permissions']}\n")
        if result['infected']:
            text_area.insert(tk.END, f"Number of Sections: {result['number_of_sections']}\n")
            text_area.insert(tk.END, f"Section Names: {', '.join(result['section_names'])}\n")
            text_area.insert(tk.END, f"Image Base: {result['image_base']}\n")
            text_area.insert(tk.END, f"Entry Point: {result['entry_point']}\n")
            text_area.insert(tk.END, f"Size of Image: {result['size_of_image']}\n")
            text_area.insert(tk.END, f"Imported DLLs: {', '.join(result['imported_dlls'])}\n")
            text_area.insert(tk.END, f"Exported Functions: {', '.join(result['exported_functions'])}\n")
            text_area.insert(tk.END, f"Resource Entries: {', '.join(map(str, result['resource_entries']))}\n")
            text_area.insert(tk.END, f"Digital Signature: {result['digital_signature']}\n")
        text_area.insert(tk.END, f"{'='*40}\n")

    def _animate_text_area(self, text):
        self.text_area.insert(tk.END, text)
        self.text_area.update_idletasks()
        time.sleep(0.05)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
