import tkinter as tk
from tkinter import messagebox, font
import json
import hashlib
import os

# --- Constants and Configuration ---
WINDOW_BG = "#212121"
FRAME_BG = "#2c2c2c"
TEXT_COLOR = "#FFFFFF"
ENTRY_BG = "#373737"
BUTTON_BG = "#007BFF"
BUTTON_FG = "#FFFFFF"
FONT_FAMILY = "Helvetica"
CREDENTIALS_FILE = "credentials.json"

class SetupApp(tk.Tk):
    """
    A one-time setup application to create user credentials.
    """
    def __init__(self):
        super().__init__()

        # --- Check if setup has already been run ---
        if os.path.exists(CREDENTIALS_FILE):
            if messagebox.askyesno("Setup Already Complete", 
                                   f"'{CREDENTIALS_FILE}' already exists.\n"
                                   "Do you want to overwrite it and create new credentials?"):
                pass # Continue with setup
            else:
                self.destroy() # Exit if user says no
                return

        self.title("First-Time Setup")
        self.geometry("450x700")
        self.configure(bg=WINDOW_BG)
        self.resizable(False, False)

        # --- Font Definitions ---
        self.title_font = font.Font(family=FONT_FAMILY, size=20, weight="bold")
        self.label_font = font.Font(family=FONT_FAMILY, size=12)
        self.entry_font = font.Font(family=FONT_FAMILY, size=12)
        self.button_font = font.Font(family=FONT_FAMILY, size=14, weight="bold")

        # --- Main Frame ---
        main_frame = tk.Frame(self, bg=WINDOW_BG)
        main_frame.pack(pady=20, padx=40, fill="both", expand=True)

        tk.Label(main_frame, text="Create Your Credentials", font=self.title_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(pady=(0, 20))

        # --- Password ---
        tk.Label(main_frame, text="Create Password", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(anchor="w")
        self.password_entry = self.create_entry(main_frame, show="*")
        
        tk.Label(main_frame, text="Confirm Password", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(anchor="w", pady=(10,0))
        self.confirm_password_entry = self.create_entry(main_frame, show="*")

        # --- Magic Word ---
        tk.Label(main_frame, text="Set Magic Word (for voice login)", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(anchor="w", pady=(20,0))
        self.magic_word_entry = self.create_entry(main_frame)

        # --- Security Questions ---
        self.security_questions = [
            "In what city were you born?",
            "What is the name of your first pet?"
        ]

        tk.Label(main_frame, text="Security Question 1:", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(anchor="w", pady=(20,0))
        tk.Label(main_frame, text=self.security_questions[0], font=self.label_font, bg=WINDOW_BG, fg="#cccccc").pack(anchor="w")
        self.answer1_entry = self.create_entry(main_frame)

        tk.Label(main_frame, text="Security Question 2:", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(anchor="w", pady=(10,0))
        tk.Label(main_frame, text=self.security_questions[1], font=self.label_font, bg=WINDOW_BG, fg="#cccccc").pack(anchor="w")
        self.answer2_entry = self.create_entry(main_frame)
        
        # --- Save Button ---
        save_button = tk.Button(
            main_frame, text="Save Credentials", font=self.button_font, bg=BUTTON_BG, fg=BUTTON_FG,
            relief="flat", cursor="hand2", command=self.save_credentials
        )
        save_button.pack(fill="x", pady=(30, 10), ipady=10)

    def create_entry(self, parent, show=None):
        """Helper function to create a styled entry widget."""
        entry = tk.Entry(
            parent, show=show, font=self.entry_font, bg=ENTRY_BG, fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR, borderwidth=2, relief="flat"
        )
        entry.pack(fill="x", pady=5, ipady=8)
        return entry

    def save_credentials(self):
        """Validates input and saves credentials to a JSON file."""
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        magic_word = self.magic_word_entry.get().lower() # Store magic word in lowercase
        answer1 = self.answer1_entry.get()
        answer2 = self.answer2_entry.get()

        # --- Input Validation ---
        if not all([password, confirm_password, magic_word, answer1, answer2]):
            messagebox.showerror("Error", "All fields must be filled out.")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        # --- Hashing for Security ---
        # We never store plain text passwords or answers.
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        hashed_answer1 = hashlib.sha256(answer1.encode()).hexdigest()
        hashed_answer2 = hashlib.sha256(answer2.encode()).hexdigest()
        
        credentials = {
            "password": hashed_password,
            "magic_word": magic_word,
            "security_questions": self.security_questions,
            "security_answers": [hashed_answer1, hashed_answer2]
        }

        # --- Write to File ---
        try:
            with open(CREDENTIALS_FILE, "w") as f:
                json.dump(credentials, f, indent=4)
            messagebox.showinfo("Success", "Credentials saved successfully!\nYou can now use the main application.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Could not save credentials file: {e}")

if __name__ == "__main__":
    # Advise user to run this script if credentials don't exist
    if not os.path.exists(CREDENTIALS_FILE):
        print(f"'{CREDENTIALS_FILE}' not found. Starting first-time setup...")
        app = SetupApp()
        app.mainloop()
    else:
        print(f"'{CREDENTIALS_FILE}' already exists. To run setup again, please delete the file first or confirm overwrite in the dialog.")
        app = SetupApp()
        app.mainloop()