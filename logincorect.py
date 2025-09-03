import tkinter as tk
from tkinter import messagebox, font
from PIL import Image, ImageTk
import speech_recognition as sr
import threading
import json
import hashlib
import os
from phishing_detector import PhishingDetectorUI
from file_encryptor import FileEncryptorUI

# --- Constants and Configuration ---
WINDOW_BG = "#212121"
FRAME_BG = "#2c2c2c"
TEXT_COLOR = "#FFFFFF"
ENTRY_BG = "#373737"
BUTTON_BG = "#007BFF"
BUTTON_FG = "#FFFFFF"
SUCCESS_COLOR = "#28a745" # Green for success
LISTENING_COLOR = "#ffc107" # Yellow for listening
CLOSE_BUTTON_BG = "#c9302c" # Red for close button
FONT_FAMILY = "Helvetica"
CREDENTIALS_FILE = "credentials.json"

# --- MainDashboard Class (No changes needed here) ---
class MainDashboard(tk.Toplevel):
    """
    The main dashboard of the security application.
    This window appears after a successful login.
    """
    def __init__(self, master):
        super().__init__(master)
        self.title("Security Dashboard")
        self.geometry("800x800") # Increased height for the new button
        self.configure(bg=WINDOW_BG)

        # --- Font Definitions ---
        self.title_font = font.Font(family=FONT_FAMILY, size=28, weight="bold")
        self.button_font = font.Font(family=FONT_FAMILY, size=14)
        self.desc_font = font.Font(family=FONT_FAMILY, size=10, slant="italic")

        # --- Main Container ---
        main_frame = tk.Frame(self, bg=WINDOW_BG)
        main_frame.pack(pady=40, padx=60, fill="both", expand=True)

        # --- Header ---
        header_label = tk.Label(
            main_frame,
            text="Security Toolkit",
            font=self.title_font,
            bg=WINDOW_BG,
            fg=TEXT_COLOR
        )
        header_label.pack(pady=(0, 40))

        # --- Grid for Feature Buttons ---
        features_grid = tk.Frame(main_frame, bg=WINDOW_BG)
        features_grid.pack(fill="both", expand=True)
        features_grid.grid_columnconfigure((0, 1), weight=1) # Make columns responsive
        features_grid.grid_rowconfigure((0, 1), weight=1) # Make rows responsive

        # --- Feature Buttons Data ---
        features = [
            {"icon": "📁", "title": "File Encryptor", "desc": "Securely encrypt and decrypt your files.", "command": self.open_file_encryptor},
            {"icon": "🎣", "title": "Phishing Detector", "desc": "Analyze emails for phishing attempts.", "command": self.open_phishing_detector},
            {"icon": "🔗", "title": "Link Analyzer", "desc": "Check URLs for malicious content.", "command": self.open_link_analyzer},
            {"icon": "📞", "title": "Scam Call Check", "desc": "Verify phone numbers for potential scams.", "command": self.open_scam_checker}
        ]

        # --- Create and place feature buttons ---
        for i, feature in enumerate(features):
            row, col = divmod(i, 2)
            button_frame = self.create_feature_button(features_grid, feature)
            button_frame.grid(row=row, column=col, padx=20, pady=20, sticky="nsew")
            
        # --- Close Button ---
        close_button = tk.Button(
            main_frame,
            text="Close Application",
            font=self.button_font,
            bg=BUTTON_BG,
            fg=TEXT_COLOR,
            activebackground=CLOSE_BUTTON_BG,
            activeforeground=TEXT_COLOR,
            relief="flat",
            cursor="hand2",
            command=self.master.destroy # This will call destroy() on the root SecurityApp window
        )
        close_button.pack(side="bottom", pady=(30, 0), ipady=10, fill='x')


    def create_feature_button(self, parent, feature_data):
        """Helper function to create a styled button for a feature."""
        frame = tk.Frame(parent, bg=FRAME_BG, relief="raised", borderwidth=2, highlightbackground=BUTTON_BG, highlightthickness=1)
        
        icon_label = tk.Label(frame, text=feature_data["icon"], font=("Arial", 40), bg=FRAME_BG, fg=BUTTON_BG)
        icon_label.pack(pady=(20, 10))

        title_label = tk.Label(frame, text=feature_data["title"], font=self.button_font, bg=FRAME_BG, fg=TEXT_COLOR)
        title_label.pack(pady=(0, 5))

        desc_label = tk.Label(frame, text=feature_data["desc"], font=self.desc_font, bg=FRAME_BG, fg="#cccccc", wraplength=200)
        desc_label.pack(pady=(0, 20), padx=10)

        # Make the entire frame clickable
        for widget in [frame, icon_label, title_label, desc_label]:
            widget.bind("<Button-1>", lambda e, cmd=feature_data["command"]: cmd())
            widget.config(cursor="hand2")

        return frame

    def open_file_encryptor(self):
        encryptor_window = FileEncryptorUI(self)
        encryptor_window.grab_set()

    def open_phishing_detector(self):
        phishing_window = PhishingDetectorUI(self)
        phishing_window.grab_set()

    def open_link_analyzer(self):
        messagebox.showinfo("Coming Soon", "The Link Analyzer feature is under construction.")

    def open_scam_checker(self):
        messagebox.showinfo("Coming Soon", "The Scam Call Check feature is under construction.")


class SecurityApp(tk.Tk):
    """
    The main application class for the security app.
    Handles loading credentials and the voice-activated login screen.
    """
    def __init__(self):
        super().__init__()
        
        # --- Load Credentials ---
        self.credentials = self.load_credentials()
        if not self.credentials:
            self.destroy()
            return

        self.title("Security App - Voice Login")
        self.geometry("400x650") # Increased height for forgot password
        self.configure(bg=WINDOW_BG)
        self.resizable(False, False)

        self.transcribed_word = tk.StringVar()

        self.title_font = font.Font(family=FONT_FAMILY, size=20, weight="bold")
        self.label_font = font.Font(family=FONT_FAMILY, size=12)
        self.entry_font = font.Font(family=FONT_FAMILY, size=12)
        self.button_font = font.Font(family=FONT_FAMILY, size=14, weight="bold")
        self.status_font = font.Font(family=FONT_FAMILY, size=10, slant="italic")
        self.link_font = font.Font(family=FONT_FAMILY, size=10, underline=True)

        try:
            logo_image = Image.open("logo.png").resize((100, 100), Image.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(logo_image)
            logo_label = tk.Label(self, image=self.logo_photo, bg=WINDOW_BG)
            logo_label.pack(pady=(20, 10))
        except FileNotFoundError:
            placeholder_label = tk.Label(self, text="🛡️", font=("Arial", 60), bg=WINDOW_BG, fg=BUTTON_BG)
            placeholder_label.pack(pady=(20, 10))

        login_frame = tk.Frame(self, bg=WINDOW_BG)
        login_frame.pack(pady=10, padx=40, fill="both", expand=True)

        title_label = tk.Label(login_frame, text="Secure Access", font=self.title_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        title_label.pack(pady=(0, 20))

        magic_word_label = tk.Label(login_frame, text="Magic Word", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        magic_word_label.pack(anchor="w")

        self.speak_button = tk.Button(
            login_frame, text="🎤 Speak Magic Word", font=self.label_font, bg="#555555",
            fg=TEXT_COLOR, cursor="hand2", relief="flat", command=self.start_listening_thread
        )
        self.speak_button.pack(fill="x", pady=(5, 5), ipady=8)

        self.status_label = tk.Label(
            login_frame, text="Status: Waiting for you to speak...", font=self.status_font, bg=WINDOW_BG, fg=TEXT_COLOR
        )
        self.status_label.pack(anchor="w", pady=(0, 15))

        password_label = tk.Label(login_frame, text="Password", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        password_label.pack(anchor="w")

        self.password_entry = tk.Entry(
            login_frame, show="*", font=self.entry_font, bg=ENTRY_BG, fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR, borderwidth=2, relief="flat"
        )
        self.password_entry.pack(fill="x", pady=5, ipady=8)
        self.password_entry.focus_set()

        login_button = tk.Button(
            login_frame, text="Unlock", font=self.button_font, bg=BUTTON_BG, fg=BUTTON_FG,
            activebackground=BUTTON_BG, activeforeground=BUTTON_FG, borderwidth=0,
            relief="flat", cursor="hand2", command=self.attempt_login
        )
        login_button.pack(fill="x", pady=(20, 10), ipady=10)
        
        # --- NEW: Forgot Password Button ---
        forgot_password_button = tk.Label(
            login_frame, text="Forgot Password?", font=self.link_font, bg=WINDOW_BG,
            fg="#cccccc", cursor="hand2"
        )
        forgot_password_button.pack(pady=10)
        forgot_password_button.bind("<Button-1>", lambda e: self.show_forgot_password_window())


        self.bind("<Return>", lambda event: self.attempt_login())

    def load_credentials(self):
        """Loads credentials from the JSON file."""
        if not os.path.exists(CREDENTIALS_FILE):
            messagebox.showerror("Error", f"'{CREDENTIALS_FILE}' not found.\nPlease run the setup.py script first.")
            return None
        try:
            with open(CREDENTIALS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            messagebox.showerror("Error", f"Failed to load or parse credentials: {e}")
            return None

    def start_listening_thread(self):
        self.speak_button.config(state=tk.DISABLED, text="🎤 Listening...")
        self.status_label.config(text="Status: Listening...", fg=LISTENING_COLOR)
        threading.Thread(target=self.listen_for_magic_word, daemon=True).start()

    def listen_for_magic_word(self):
        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            recognizer.adjust_for_ambient_noise(source, duration=1)
            try:
                audio = recognizer.listen(source, timeout=5, phrase_time_limit=5)
                self.status_label.config(text="Status: Processing...", fg=LISTENING_COLOR)
                recognized_text = recognizer.recognize_google(audio).lower()
                self.transcribed_word.set(recognized_text)
                self.status_label.config(text=f"Status: Word '{recognized_text}' captured!", fg=SUCCESS_COLOR)
            except sr.WaitTimeoutError:
                self.status_label.config(text="Status: No speech detected. Try again.", fg="red")
            except sr.UnknownValueError:
                self.status_label.config(text="Status: Could not understand audio. Try again.", fg="red")
            except sr.RequestError:
                self.status_label.config(text="Status: API unavailable. Check connection.", fg="red")
            finally:
                self.speak_button.config(state=tk.NORMAL, text="🎤 Speak Magic Word")

    def attempt_login(self):
        magic_word = self.transcribed_word.get()
        password = self.password_entry.get()
        # or not magic_word
        if not password:
            messagebox.showerror("Login Failed", "Magic word and password are required.")
            return

        # Hash the entered password for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        # magic_word == self.credentials['magic_word'] and 
        if hashed_password == self.credentials['password']:
            self.open_main_dashboard()
        else:
            messagebox.showerror("Login Failed", "Invalid magic word or password.")
            self.password_entry.delete(0, tk.END)
            self.status_label.config(text="Status: Waiting for you to speak...", fg=TEXT_COLOR)
            self.transcribed_word.set("")

    def show_forgot_password_window(self):
        """Creates a new window to handle password recovery."""
        recovery_window = tk.Toplevel(self)
        recovery_window.title("Password Recovery")
        recovery_window.geometry("400x350")
        recovery_window.configure(bg=WINDOW_BG)
        recovery_window.resizable(False, False)
        recovery_window.grab_set() # Modal window

        frame = tk.Frame(recovery_window, bg=WINDOW_BG, padx=20, pady=20)
        frame.pack(fill="both", expand=True)
        
        tk.Label(frame, text="Answer Security Questions", font=self.title_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(pady=(0, 20))
        
        # Display questions
        q1_label = tk.Label(frame, text=self.credentials['security_questions'][0], font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        q1_label.pack(anchor="w", pady=(10, 5))
        answer1_entry = tk.Entry(frame, font=self.entry_font, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat")
        answer1_entry.pack(fill="x", ipady=8)
        
        q2_label = tk.Label(frame, text=self.credentials['security_questions'][1], font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        q2_label.pack(anchor="w", pady=(10, 5))
        answer2_entry = tk.Entry(frame, font=self.entry_font, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat")
        answer2_entry.pack(fill="x", ipady=8)
        
        submit_button = tk.Button(
            frame, text="Submit Answers", font=self.button_font, bg=BUTTON_BG, fg=BUTTON_FG, relief="flat",
            command=lambda: self.verify_security_answers(recovery_window, answer1_entry.get(), answer2_entry.get())
        )
        submit_button.pack(fill="x", pady=20, ipady=10)

    def verify_security_answers(self, window, answer1, answer2):
        """Hashes and verifies the provided security answers."""
        if not answer1 or not answer2:
            messagebox.showerror("Error", "Both answers are required.", parent=window)
            return
            
        hashed_answer1 = hashlib.sha256(answer1.encode()).hexdigest()
        hashed_answer2 = hashlib.sha256(answer2.encode()).hexdigest()

        if (hashed_answer1 == self.credentials['security_answers'][0] and
            hashed_answer2 == self.credentials['security_answers'][1]):
            window.destroy()
            self.show_reset_password_window()
        else:
            messagebox.showerror("Verification Failed", "One or more answers are incorrect.", parent=window)

    def show_reset_password_window(self):
        """Shows a window to reset the password."""
        reset_window = tk.Toplevel(self)
        reset_window.title("Reset Password")
        reset_window.geometry("400x300")
        reset_window.configure(bg=WINDOW_BG)
        reset_window.grab_set()

        frame = tk.Frame(reset_window, bg=WINDOW_BG, padx=20, pady=20)
        frame.pack(fill="both", expand=True)
        
        tk.Label(frame, text="Create New Password", font=self.title_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(pady=(0, 20))

        tk.Label(frame, text="New Password", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(anchor="w", pady=(10, 5))
        new_pass_entry = tk.Entry(frame, show="*", font=self.entry_font, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat")
        new_pass_entry.pack(fill="x", ipady=8)

        tk.Label(frame, text="Confirm New Password", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR).pack(anchor="w", pady=(10, 5))
        confirm_pass_entry = tk.Entry(frame, show="*", font=self.entry_font, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat")
        confirm_pass_entry.pack(fill="x", ipady=8)
        
        reset_button = tk.Button(
            frame, text="Reset Password", font=self.button_font, bg=BUTTON_BG, fg=BUTTON_FG, relief="flat",
            command=lambda: self.perform_password_reset(reset_window, new_pass_entry.get(), confirm_pass_entry.get())
        )
        reset_button.pack(fill="x", pady=20, ipady=10)

    def perform_password_reset(self, window, new_password, confirm_password):
        """Resets the password and saves it."""
        if not new_password or not confirm_password:
            messagebox.showerror("Error", "Both fields are required.", parent=window)
            return
        
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.", parent=window)
            return
        
        # Hash and save the new password
        self.credentials['password'] = hashlib.sha256(new_password.encode()).hexdigest()
        try:
            with open(CREDENTIALS_FILE, 'w') as f:
                json.dump(self.credentials, f, indent=4)
            messagebox.showinfo("Success", "Password has been reset successfully.", parent=window)
            window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Could not save new password: {e}", parent=window)


    def open_main_dashboard(self):
        """Hides the login window and opens the main app dashboard."""
        self.withdraw()
        dashboard = MainDashboard(self)
        dashboard.protocol("WM_DELETE_WINDOW", self.destroy)

if __name__ == "__main__":
    app = SecurityApp()
    if app.credentials: # Only run mainloop if credentials loaded successfully
        app.mainloop()