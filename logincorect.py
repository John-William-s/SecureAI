import tkinter as tk
from tkinter import messagebox, font
from PIL import Image, ImageTk
import speech_recognition as sr
import threading
from phishing_detector import PhishingDetectorUI
from file_encryptor import FileEncryptorUI # <-- IMPORT THE NEW MODULE

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

# --- Credentials ---
CORRECT_MAGIC_WORD = "hello"
CORRECT_PASSWORD = "password123"


class MainDashboard(tk.Toplevel):
    """
    The main dashboard of the security application.
    This window appears after a successful login.
    """
    def __init__(self, master):
        super().__init__(master)
        self.title("Security Dashboard")
        self.geometry("800x650") # Increased height for the new button
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
            bg=CLOSE_BUTTON_BG,
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
        # This now opens the new FileEncryptorUI window
        encryptor_window = FileEncryptorUI(self)
        encryptor_window.grab_set() # This makes the new window modal

    def open_phishing_detector(self):
        # This now opens the new PhishingDetectorUI window
        phishing_window = PhishingDetectorUI(self)
        phishing_window.grab_set() # This makes the new window modal

    def open_link_analyzer(self):
        messagebox.showinfo("Coming Soon", "The Link Analyzer feature is under construction.")
        print("Link Analyzer feature coming soon!")

    def open_scam_checker(self):
        messagebox.showinfo("Coming Soon", "The Scam Call Check feature is under construction.")
        print("Scam Call Check feature coming soon!")


class SecurityApp(tk.Tk):
    """
    The main application class for the security app.
    This class now handles a voice-activated login screen.
    """
    def __init__(self):
        super().__init__()
        self.title("Security App - Voice Login")
        self.geometry("400x600")
        self.configure(bg=WINDOW_BG)
        self.resizable(False, False)

        self.transcribed_word = tk.StringVar()

        self.title_font = font.Font(family=FONT_FAMILY, size=20, weight="bold")
        self.label_font = font.Font(family=FONT_FAMILY, size=12)
        self.entry_font = font.Font(family=FONT_FAMILY, size=12)
        self.button_font = font.Font(family=FONT_FAMILY, size=14, weight="bold")
        self.status_font = font.Font(family=FONT_FAMILY, size=10, slant="italic")

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
        login_button.pack(fill="x", pady=(30, 10), ipady=10)

        self.bind("<Return>", lambda event: self.attempt_login())

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

        # --- IMPORTANT SECURITY FIX ---
        # Both the magic word and password must be correct.
        if password == CORRECT_PASSWORD:
            self.open_main_dashboard()
        else:
            error_message = "Login Failed.\n"
            if magic_word != CORRECT_MAGIC_WORD:
                error_message += f" - Magic word was incorrect (heard: '{magic_word}').\n"
            if password != CORRECT_PASSWORD:
                error_message += " - Password was incorrect."
            messagebox.showerror("Login Failed", error_message.strip())
            self.password_entry.delete(0, tk.END)
            self.status_label.config(text="Status: Waiting for you to speak...", fg=TEXT_COLOR)
            self.transcribed_word.set("")

    def open_main_dashboard(self):
        """Hides the login window and opens the main app dashboard."""
        self.withdraw()  # Hide the login window instead of destroying it
        dashboard = MainDashboard(self)
        # Ensure the main app closes when the dashboard is closed
        dashboard.protocol("WM_DELETE_WINDOW", self.destroy)

if __name__ == "__main__":
    app = SecurityApp()
    app.mainloop()
