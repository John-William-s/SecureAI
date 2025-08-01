import tkinter as tk
from tkinter import font, messagebox
import nltk
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
import string
import pickle
import os

# --- Constants ---
WINDOW_BG = "#212121"
FRAME_BG = "#2c2c2c"
TEXT_COLOR = "#FFFFFF"
ENTRY_BG = "#373737"
BUTTON_BG = "#007BFF"
BUTTON_FG = "#FFFFFF"
FONT_FAMILY = "Helvetica"

class PhishingDetectorUI(tk.Toplevel):
    """
    A UI window for the Phishing Email Detector feature, powered by a Machine Learning model.
    """
    def __init__(self, master):
        super().__init__(master)
        self.title("Phishing Email Detector (ML)")

        # --- Set and center the window ---
        width, height = 700, 600
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.configure(bg=WINDOW_BG)
        self.resizable(False, False)

        # --- Load ML Model and Vectorizer ---
        try:
            if not os.path.exists("model.pkl") or not os.path.exists("vectorizer.pkl"):
                raise FileNotFoundError
            self.model = pickle.load(open('model.pkl', 'rb'))
            self.vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))
        except FileNotFoundError:
            messagebox.showerror("Error", "Model files not found!\nMake sure 'model.pkl' and 'vectorizer.pkl' are in the same folder.")
            self.destroy()
            return

        # --- Text Preprocessing Tools ---
        self.stemmer = PorterStemmer()
        try:
            self.stopwords_set = set(stopwords.words('english'))
        except LookupError:
            nltk.download('stopwords')
            self.stopwords_set = set(stopwords.words('english'))

        # --- Fonts ---
        self.title_font = font.Font(family=FONT_FAMILY, size=20, weight="bold")
        self.label_font = font.Font(family=FONT_FAMILY, size=12)
        self.button_font = font.Font(family=FONT_FAMILY, size=12, weight="bold")
        self.result_font = font.Font(family=FONT_FAMILY, size=14, weight="bold")

        # --- UI Layout ---
        main_frame = tk.Frame(self, bg=WINDOW_BG)
        main_frame.pack(pady=20, padx=30, fill="both", expand=True)

        title_label = tk.Label(main_frame, text="ML Phishing Analyzer", font=self.title_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        title_label.pack(pady=(0, 15))

        info_label = tk.Label(
            main_frame,
            text="Paste the full content of the suspicious email below and click 'Analyze'.",
            font=self.label_font,
            bg=WINDOW_BG,
            fg="#cccccc"
        )
        info_label.pack(pady=(0, 20))

        self.email_text = tk.Text(
            main_frame,
            height=15,
            bg=ENTRY_BG,
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR,
            font=self.label_font,
            borderwidth=2,
            relief="flat",
            wrap="word"
        )
        self.email_text.pack(fill="both", expand=True)

        analyze_button = tk.Button(
            main_frame,
            text="Analyze Email",
            font=self.button_font,
            bg=BUTTON_BG,
            fg=BUTTON_FG,
            cursor="hand2",
            command=self.analyze_email
        )
        analyze_button.pack(pady=20, ipady=8, fill='x')

    def preprocess_text(self, text):
        """
        Performs preprocessing: lowercasing, punctuation removal, stopwords removal, stemming.
        """
        text = text.lower()
        text = text.translate(str.maketrans('', '', string.punctuation))
        words = text.split()
        words = [self.stemmer.stem(word) for word in words if word not in self.stopwords_set]
        return ' '.join(words)

    def analyze_email(self):
        """
        Processes email and shows styled result with confidence.
        """
        email_content = self.email_text.get("1.0", tk.END)

        if not email_content.strip():
            messagebox.showwarning("Empty Input", "Please paste some email content to analyze.")
            return

        try:
            processed_email = self.preprocess_text(email_content)
            email_vector = self.vectorizer.transform([processed_email])

            # Predict and get confidence
            prediction = self.model.predict(email_vector)[0]
            confidence_scores = self.model.predict_proba(email_vector)[0]
            confidence = confidence_scores[prediction] * 100

            result_text = "✅ This email appears to be SAFE." if prediction == 0 else "⚠️ PHISHING/SPAM Detected!"
            result_color = "#28a745" if prediction == 0 else "#c9302c"

            # Show styled result popup
            self.show_result_window(result_text, confidence, result_color)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred:\n{e}")
            print("[ERROR]", e)

    def show_result_window(self, result_text, confidence, color):
        """
        Displays a styled result window with the detection result, centered.
        """
        result_win = tk.Toplevel(self)
        result_win.title("Detection Result")

        # Center the result window
        width, height = 400, 250
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        result_win.geometry(f"{width}x{height}+{x}+{y}")
        result_win.configure(bg=WINDOW_BG)
        result_win.resizable(False, False)

        # Center content
        center_frame = tk.Frame(result_win, bg=WINDOW_BG)
        center_frame.pack(expand=True)

        title = tk.Label(center_frame, text="Phishing Detection Result", font=self.title_font, bg=WINDOW_BG, fg=TEXT_COLOR)
        title.pack(pady=(20, 10))

        result_label = tk.Label(center_frame, text=result_text, font=self.result_font, bg=WINDOW_BG, fg=color)
        result_label.pack(pady=10)

        confidence_label = tk.Label(
            center_frame,
            text=f"Confidence: {confidence:.2f}%",
            font=self.label_font,
            bg=WINDOW_BG,
            fg="#cccccc"
        )
        confidence_label.pack(pady=(5, 20))

        close_btn = tk.Button(
            center_frame,
            text="Close",
            font=self.button_font,
            bg=BUTTON_BG,
            fg=BUTTON_FG,
            command=result_win.destroy,
            relief="flat",
            cursor="hand2"
        )
        close_btn.pack(ipady=6, ipadx=10)

if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()
    app = PhishingDetectorUI(root)
    app.mainloop()
