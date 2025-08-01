import tkinter as tk
from tkinter import filedialog, messagebox, font
import os
import shutil
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# --- Constants ---
WINDOW_BG = "#212121"
FRAME_BG = "#2c2c2c"
TEXT_COLOR = "#FFFFFF"
ENTRY_BG = "#373737"
BUTTON_BG = "#007BFF"
BUTTON_FG = "#FFFFFF"
SUCCESS_COLOR = "#28a745"
ERROR_COLOR = "#c9302c"
FONT_FAMILY = "Helvetica"
VAULT_DIR = "SecureAI_Vault" # Name of the vault directory

class FileEncryptorUI(tk.Toplevel):
    """
    A UI window for encrypting and decrypting files using a password.
    """
    def __init__(self, master):
        super().__init__(master)
        self.title("File Encryptor")
        self.geometry("600x450")
        self.configure(bg=WINDOW_BG)
        self.resizable(False, False)

        # Create the vault directory if it doesn't exist
        if not os.path.exists(VAULT_DIR):
            os.makedirs(VAULT_DIR)
        
        # Center the window
        x = (self.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.winfo_screenheight() // 2) - (450 // 2)
        self.geometry(f"600x450+{x}+{y}")

        self.selected_file_path = tk.StringVar()

        # --- Fonts ---
        self.title_font = font.Font(family=FONT_FAMILY, size=20, weight="bold")
        self.label_font = font.Font(family=FONT_FAMILY, size=12)
        self.button_font = font.Font(family=FONT_FAMILY, size=12, weight="bold")
        self.status_font = font.Font(family=FONT_FAMILY, size=10, slant="italic")

        # --- UI Layout ---
        main_frame = tk.Frame(self, bg=WINDOW_BG)
        main_frame.pack(pady=20, padx=30, fill="both", expand=True)

        title_label = tk.Label(main_frame, text="File Encryptor / Decryptor", font=self.title_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        title_label.pack(pady=(0, 25))

        # --- File Selection ---
        file_frame = tk.Frame(main_frame, bg=FRAME_BG, relief="solid", borderwidth=1)
        file_frame.pack(fill="x", pady=10)

        select_btn = tk.Button(file_frame, text="Select File", font=self.label_font, bg="#444", fg=TEXT_COLOR, command=self.select_file)
        select_btn.pack(side="left", padx=10, pady=10)

        self.file_label = tk.Label(file_frame, textvariable=self.selected_file_path, font=self.label_font, bg=FRAME_BG, fg="#cccccc", wraplength=400)
        self.file_label.pack(side="left", padx=10, pady=10)
        self.selected_file_path.set("No file selected...")

        # --- Password Entry ---
        password_label = tk.Label(main_frame, text="Enter Password:", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        password_label.pack(anchor="w", pady=(15, 5))

        self.password_entry = tk.Entry(main_frame, show="*", font=self.label_font, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat")
        self.password_entry.pack(fill="x", ipady=8)

        # --- Action Buttons ---
        button_frame = tk.Frame(main_frame, bg=WINDOW_BG)
        button_frame.pack(pady=30, fill="x", expand=True)

        encrypt_button = tk.Button(button_frame, text="Encrypt & Vault", font=self.button_font, bg=SUCCESS_COLOR, fg=BUTTON_FG, command=self.encrypt_file_action)
        encrypt_button.pack(side="left", expand=True, ipady=10, padx=(0, 10))
        
        decrypt_button = tk.Button(button_frame, text="Decrypt from Vault", font=self.button_font, bg=BUTTON_BG, fg=BUTTON_FG, command=self.decrypt_file_action)
        decrypt_button.pack(side="right", expand=True, ipady=10, padx=(10, 0))

        # --- Status Label ---
        self.status_label = tk.Label(main_frame, text="", font=self.status_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        self.status_label.pack(pady=(10, 0))

    def select_file(self):
        """Opens a dialog to select a file."""
        filepath = filedialog.askopenfilename()
        if filepath:
            self.selected_file_path.set(os.path.basename(filepath))
            self.file_path = filepath
            self.status_label.config(text=f"Selected: {os.path.basename(filepath)}", fg=TEXT_COLOR)
        else:
            self.status_label.config(text="File selection cancelled.", fg=ERROR_COLOR)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a key from the password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_file_action(self):
        """Handles the file encryption process."""
        if not hasattr(self, 'file_path') or not self.file_path:
            messagebox.showerror("Error", "Please select a file first.")
            return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        try:
            # Read file content
            with open(self.file_path, 'rb') as f:
                file_data = f.read()

            # Generate a random salt
            salt = os.urandom(16)
            
            # Derive key and encrypt
            key = self.derive_key(password, salt)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(file_data)
            
            # Save the encrypted file to the vault
            base_filename = os.path.basename(self.file_path)
            new_filepath = os.path.join(VAULT_DIR, base_filename + ".enc")
            with open(new_filepath, 'wb') as f:
                f.write(salt)
                f.write(encrypted_data)

            # Delete the original file
            os.remove(self.file_path)
            
            self.status_label.config(text=f"Success! File encrypted and original deleted.", fg=SUCCESS_COLOR)
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved to vault and original file deleted.")
            self.selected_file_path.set("No file selected...")
            self.file_path = None


        except Exception as e:
            self.status_label.config(text=f"Error: {e}", fg=ERROR_COLOR)
            messagebox.showerror("Encryption Failed", f"An error occurred: {e}")

    def decrypt_file_action(self):
        """Handles the file decryption process."""
        # Prompt user to select a file from the vault
        filepath_to_decrypt = filedialog.askopenfilename(
            initialdir=VAULT_DIR,
            title="Select a file to decrypt from the vault",
            filetypes=(("Encrypted files", "*.enc"), ("All files", "*.*"))
        )

        if not filepath_to_decrypt:
            self.status_label.config(text="Decryption cancelled.", fg=ERROR_COLOR)
            return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        try:
            # Read the salt and the encrypted data
            with open(filepath_to_decrypt, 'rb') as f:
                salt = f.read(16)
                encrypted_data = f.read()
            
            # Derive key and decrypt
            key = self.derive_key(password, salt)
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)

            # Ask user where to save the decrypted file
            original_filename = os.path.basename(filepath_to_decrypt).rsplit('.enc', 1)[0]
            save_path = filedialog.asksaveasfilename(
                initialfile=original_filename,
                title="Save decrypted file as...",
                defaultextension="." + original_filename.split('.')[-1] if '.' in original_filename else ""
            )

            if not save_path:
                self.status_label.config(text="Save location not chosen. Decryption cancelled.", fg=ERROR_COLOR)
                return

            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.status_label.config(text=f"Success! File decrypted to {os.path.basename(save_path)}", fg=SUCCESS_COLOR)
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {save_path}")

        except InvalidToken:
            self.status_label.config(text="Decryption failed. Invalid password or corrupted file.", fg=ERROR_COLOR)
            messagebox.showerror("Decryption Failed", "Invalid password or the file is corrupted.")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}", fg=ERROR_COLOR)
            messagebox.showerror("Decryption Failed", f"An error occurred: {e}")

if __name__ == '__main__':
    # This is for testing the UI independently
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    app = FileEncryptorUI(root)
    app.mainloop()

    
# i want this window to be at hte center of thee screen and i can upload the files and store it in encrypted format but first i want a window to save it into the vault or access the vaults content so when save it goes in to the vault and displays the files and you can open them and in the save option i wnat a place where files can be inserted also all the window should pop up in the center of the screen