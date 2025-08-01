import tkinter as tk
from tkinter import messagebox, simpledialog, Listbox, Scrollbar, Toplevel, Text
import sqlite3
import os
from datetime import datetime
from cryptography.fernet import Fernet

# --- 1. ENCRYPTION SETUP ---
# Corresponds to: Security: cryptography (Fernet/AES) [cite: 28]
KEY_FILE = "secret.key"

def generate_key():
    """Generates a new key and saves it to a file."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    """Loads the encryption key from the file."""
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

# Load the key and initialize the Fernet suite
key = load_key()
cipher_suite = Fernet(key)

def encrypt_message(message: str) -> bytes:
    """Encrypts a string message."""
    return cipher_suite.encrypt(message.encode('utf-8'))

def decrypt_message(encrypted_message: bytes) -> str:
    """Decrypts an encrypted message and returns a string."""
    try:
        decrypted_bytes = cipher_suite.decrypt(encrypted_message)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        return f"Decryption Error: {e}"

# --- 2. DATABASE SETUP ---
# Corresponds to: Database: SQLite or JSON-based vault [cite: 29]
def setup_database():
    """Sets up the SQLite database and tables."""
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    # Table for encrypted notes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL UNIQUE,
            encrypted_content BLOB NOT NULL
        )
    ''')
    # Table for logging access attempts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# --- 3. MAIN APPLICATION CLASS ---
# Corresponds to: Frontend: Tkinter [cite: 25]
class SecureAIVault(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure AI Vault")
        self.geometry("600x450")
        
        # This password simulates the "Voice Unlock" feature [cite: 21] for demonstration
        self.master_password = "admin" 

        self.show_login_screen()

    def log_access(self, status: str):
        """Logs an access attempt to the database."""
        conn = sqlite3.connect("vault.db")
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO access_logs (timestamp, status) VALUES (?, ?)", (timestamp, status))
        conn.commit()
        conn.close()

    def show_login_screen(self):
        self.login_frame = tk.Frame(self)
        self.login_frame.pack(pady=20, padx=10, fill="both", expand=True)

        tk.Label(self.login_frame, text="Enter Master Password", font=("Helvetica", 16)).pack(pady=10)
        
        self.password_entry = tk.Entry(self.login_frame, show="*", width=30)
        self.password_entry.pack(pady=5)
        self.password_entry.focus_set()
        self.password_entry.bind("<Return>", self.check_password)

        tk.Button(self.login_frame, text="Unlock", command=self.check_password).pack(pady=10)

    def check_password(self, event=None):
        """Checks the password and grants access."""
        password = self.password_entry.get()
        if password == self.master_password:
            self.log_access("Success")
            self.login_frame.destroy()
            self.setup_main_ui()
        else:
            self.log_access("Failure")
            messagebox.showerror("Access Denied", "Incorrect password.")
            self.password_entry.delete(0, 'end')
            
    def setup_main_ui(self):
        """Sets up the main UI after successful login."""
        # --- MENU ---
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)
        
        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="View Access Logs", command=self.view_access_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        
        # --- NOTES FRAME ---
        notes_frame = tk.Frame(self, padx=10, pady=10)
        notes_frame.pack(fill="both", expand=True)

        # Left side: List of notes
        list_frame = tk.Frame(notes_frame)
        list_frame.pack(side="left", fill="y", padx=(0, 10))
        
        tk.Label(list_frame, text="Saved Notes").pack()
        self.notes_listbox = Listbox(list_frame, width=25)
        self.notes_listbox.pack(fill="y", expand=True)
        self.notes_listbox.bind("<<ListboxSelect>>", self.load_selected_note)

        # Right side: Note entry and content
        entry_frame = tk.Frame(notes_frame)
        entry_frame.pack(side="right", fill="both", expand=True)

        tk.Label(entry_frame, text="Title:").pack(anchor="w")
        self.title_entry = tk.Entry(entry_frame, width=50)
        self.title_entry.pack(fill="x", pady=(0, 5))

        tk.Label(entry_frame, text="Content:").pack(anchor="w")
        self.content_text = Text(entry_frame, height=10)
        self.content_text.pack(fill="both", expand=True)
        
        # --- BUTTONS ---
        button_frame = tk.Frame(entry_frame)
        button_frame.pack(fill="x", pady=10)
        
        tk.Button(button_frame, text="Save Note", command=self.save_note).pack(side="left", padx=5)
        tk.Button(button_frame, text="Delete Note", command=self.delete_note).pack(side="left", padx=5)
        tk.Button(button_frame, text="Clear Fields", command=self.clear_fields).pack(side="left", padx=5)

        self.refresh_notes_list()

    def refresh_notes_list(self):
        """Fetches notes from DB and updates the listbox."""
        self.notes_listbox.delete(0, 'end')
        conn = sqlite3.connect("vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT title FROM notes ORDER BY title ASC")
        for row in cursor.fetchall():
            self.notes_listbox.insert('end', row[0])
        conn.close()

    def save_note(self):
        """Encrypts and saves the note to the database."""
        title = self.title_entry.get()
        content = self.content_text.get("1.0", "end-1c")

        if not title or not content:
            messagebox.showwarning("Input Error", "Title and content cannot be empty.")
            return

        encrypted_content = encrypt_message(content)
        
        conn = sqlite3.connect("vault.db")
        cursor = conn.cursor()
        try:
            # Using INSERT OR REPLACE to handle both new and existing titles
            cursor.execute("INSERT OR REPLACE INTO notes (title, encrypted_content) VALUES (?, ?)", 
                           (title, encrypted_content))
            conn.commit()
            messagebox.showinfo("Success", f"Note '{title}' saved securely.")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to save note: {e}")
        finally:
            conn.close()
            
        self.clear_fields()
        self.refresh_notes_list()

    def load_selected_note(self, event=None):
        """Loads a selected note from the list into the entry fields."""
        selected_indices = self.notes_listbox.curselection()
        if not selected_indices:
            return
            
        selected_title = self.notes_listbox.get(selected_indices[0])
        
        conn = sqlite3.connect("vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_content FROM notes WHERE title = ?", (selected_title,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            decrypted_content = decrypt_message(row[0])
            self.clear_fields()
            self.title_entry.insert(0, selected_title)
            self.content_text.insert("1.0", decrypted_content)

    def delete_note(self):
        """Deletes the selected note from the database."""
        selected_indices = self.notes_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Selection Error", "Please select a note to delete.")
            return
        
        selected_title = self.notes_listbox.get(selected_indices[0])
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{selected_title}'?"):
            conn = sqlite3.connect("vault.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM notes WHERE title = ?", (selected_title,))
            conn.commit()
            conn.close()
            
            self.clear_fields()
            self.refresh_notes_list()
            messagebox.showinfo("Success", f"Note '{selected_title}' deleted.")

    def clear_fields(self):
        """Clears the title and content entry fields."""
        self.title_entry.delete(0, 'end')
        self.content_text.delete("1.0", 'end')
        self.notes_listbox.selection_clear(0, 'end')
        
    def view_access_logs(self):
        """Displays access logs in a new window."""
        # Corresponds to: View all access attempts with time and result [cite: 33]
        log_window = Toplevel(self)
        log_window.title("Access Logs")
        log_window.geometry("400x300")
        
        log_listbox = Listbox(log_window)
        log_listbox.pack(pady=10, padx=10, fill="both", expand=True)

        conn = sqlite3.connect("vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, status FROM access_logs ORDER BY id DESC")
        logs = cursor.fetchall()
        conn.close()
        
        if not logs:
            log_listbox.insert('end', "No access logs found.")
        else:
            for timestamp, status in logs:
                log_listbox.insert('end', f"{timestamp} - {status}")

# --- 4. RUN THE APPLICATION ---
if __name__ == "__main__":
    setup_database()
    app = SecureAIVault()
    app.mainloop()