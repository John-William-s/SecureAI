import tkinter as tk
from tkinter import messagebox, font
from PIL import Image, ImageTk
import speech_recognition as sr
import threading

# --- Constants and Configuration ---
WINDOW_BG = "#212121"
FRAME_BG = "#2c2c2c"
TEXT_COLOR = "#FFFFFF"
ENTRY_BG = "#373737"
BUTTON_BG = "#007BFF"
BUTTON_FG = "#FFFFFF"
SUCCESS_COLOR = "#28a745" # Green for success
LISTENING_COLOR = "#ffc107" # Yellow for listening
FONT_FAMILY = "Helvetica"

# --- Credentials ---
CORRECT_MAGIC_WORD = "abracadabra"
CORRECT_PASSWORD = "password123"


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

        # --- Instance Variables ---
        self.transcribed_word = tk.StringVar()

        # --- Font Definitions ---
        self.title_font = font.Font(family=FONT_FAMILY, size=20, weight="bold")
        self.label_font = font.Font(family=FONT_FAMILY, size=12)
        self.entry_font = font.Font(family=FONT_FAMILY, size=12)
        self.button_font = font.Font(family=FONT_FAMILY, size=14, weight="bold")
        self.status_font = font.Font(family=FONT_FAMILY, size=10, slant="italic")

        # --- Load and display the logo ---
        try:
            logo_image = Image.open("logo.png").resize((100, 100), Image.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(logo_image)
            logo_label = tk.Label(self, image=self.logo_photo, bg=WINDOW_BG)
            logo_label.pack(pady=(20, 10))
        except FileNotFoundError:
            placeholder_label = tk.Label(self, text="🛡️", font=("Arial", 60), bg=WINDOW_BG, fg=BUTTON_BG)
            placeholder_label.pack(pady=(20, 10))

        # --- Main Login Frame ---
        login_frame = tk.Frame(self, bg=WINDOW_BG)
        login_frame.pack(pady=10, padx=40, fill="both", expand=True)

        # --- Title Label ---
        title_label = tk.Label(login_frame, text="Secure Access", font=self.title_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        title_label.pack(pady=(0, 20))

        # --- Voice Recognition Section ---
        magic_word_label = tk.Label(login_frame, text="Magic Word", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        magic_word_label.pack(anchor="w")

        self.speak_button = tk.Button(
            login_frame,
            text="🎤 Speak the Word",
            font=self.label_font,
            bg="#555555",
            fg=TEXT_COLOR,
            cursor="hand2",
            relief="flat",
            command=self.start_listening_thread
        )
        self.speak_button.pack(fill="x", pady=(5, 5), ipady=8)

        self.status_label = tk.Label(
            login_frame, text="Status: Waiting for you to speak...", font=self.status_font, bg=WINDOW_BG, fg=TEXT_COLOR
        )
        self.status_label.pack(anchor="w", pady=(0, 15))

        # --- Password Entry ---
        password_label = tk.Label(login_frame, text="Password", font=self.label_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        password_label.pack(anchor="w")

        self.password_entry = tk.Entry(
            login_frame,
            show="*",
            font=self.entry_font,
            bg=ENTRY_BG,
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR,
            borderwidth=2,
            relief="flat"
        )
        self.password_entry.pack(fill="x", pady=5, ipady=8)
        self.password_entry.focus_set()

        # --- Login Button ---
        login_button = tk.Button(
            login_frame,
            text="Unlock",
            font=self.button_font,
            bg=BUTTON_BG,
            fg=BUTTON_FG,
            activebackground=BUTTON_BG,
            activeforeground=BUTTON_FG,
            borderwidth=0,
            relief="flat",
            cursor="hand2",
            command=self.attempt_login
        )
        login_button.pack(fill="x", pady=(30, 10), ipady=10)

        self.bind("<Return>", lambda event: self.attempt_login())

    def start_listening_thread(self):
        """
        Starts the voice recognition process in a separate thread to keep the GUI responsive.
        """
        self.speak_button.config(state=tk.DISABLED, text="🎤 Listening...")
        self.status_label.config(text="Status: Listening...", fg=LISTENING_COLOR)
        # The thread will call the listen_for_magic_word method
        threading.Thread(target=self.listen_for_magic_word, daemon=True).start()

    def listen_for_magic_word(self):
        """
        Listens for audio via the microphone and transcribes it using Google Web Speech API.
        This method is designed to run in a background thread.
        """
        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            # Adjust for ambient noise to improve accuracy
            recognizer.adjust_for_ambient_noise(source, duration=1)
            try:
                audio = recognizer.listen(source, timeout=5, phrase_time_limit=5)
                self.status_label.config(text="Status: Processing...", fg=LISTENING_COLOR)
                
                # Use Google's API to recognize the speech
                recognized_text = recognizer.recognize_google(audio).lower()
                self.transcribed_word.set(recognized_text)
                
                # Update UI to show the recognized word
                self.status_label.config(text=f"Status: Word '{recognized_text}' captured!", fg=SUCCESS_COLOR)
            
            except sr.WaitTimeoutError:
                self.status_label.config(text="Status: No speech detected. Try again.", fg="red")
            except sr.UnknownValueError:
                self.status_label.config(text="Status: Could not understand audio. Try again.", fg="red")
            except sr.RequestError:
                self.status_label.config(text="Status: API unavailable. Check connection.", fg="red")
            finally:
                # Re-enable the speak button regardless of the outcome
                self.speak_button.config(state=tk.NORMAL, text="🎤 Speak Magic Word")


    def attempt_login(self):
        """
        Checks the transcribed magic word and the entered password.
        """
        magic_word = self.transcribed_word.get()
        password = self.password_entry.get()

        if magic_word == CORRECT_MAGIC_WORD and password == CORRECT_PASSWORD:
            messagebox.showinfo("Success", "Login Successful! Welcome.")
            self.open_main_dashboard()
        else:
            error_message = "Login Failed.\n"
            if magic_word != CORRECT_MAGIC_WORD:
                error_message += f" - Magic word was incorrect (heard: '{magic_word}').\n"
            if password != CORRECT_PASSWORD:
                error_message += " - Password was incorrect."
            
            messagebox.showerror("Login Failed", error_message)
            self.password_entry.delete(0, tk.END)
            self.status_label.config(text="Status: Waiting for you to speak...", fg=TEXT_COLOR)
            self.transcribed_word.set("")


    def open_main_dashboard(self):
        """
        Closes the login window and will eventually open the main app dashboard.
        """
        print("Login successful. Main dashboard should open now.")
        self.destroy()


if __name__ == "__main__":
    app = SecurityApp()
    app.mainloop()