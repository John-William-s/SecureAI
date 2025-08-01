import string
import pandas as pd
import nltk
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
import pickle

def train_and_save():
    """
    This function trains the model based on the notebook's logic
    and saves the trained model and vectorizer to disk.
    """
    print("Starting model training process...")

    # --- 1. Load and Prepare Data ---
    try:
        df = pd.read_csv('spam_ham_dataset.csv')
    except FileNotFoundError:
        print("\nERROR: 'spam_ham_dataset.csv' not found.")
        print("Please make sure the dataset is in the same directory as this script.")
        return

    df['text'] = df['text'].apply(lambda x: x.replace('\r\n', " "))
    print("Data loaded and cleaned.")

    # --- 2. Preprocess Text (Stemming, Stopwords) ---
    stemmer = PorterStemmer()
    
    # Ensure stopwords are downloaded
    try:
        stopwords_set = set(stopwords.words('english'))
    except LookupError:
        print("NLTK 'stopwords' not found. Downloading...")
        nltk.download('stopwords')
        stopwords_set = set(stopwords.words('english'))

    corpus = []
    for i in range(len(df)):
        text = df['text'].iloc[i].lower()
        text = text.translate(str.maketrans('', '', string.punctuation))
        words = text.split()
        words = [stemmer.stem(word) for word in words if word not in stopwords_set]
        cleaned_text = ' '.join(words)
        corpus.append(cleaned_text)
    
    print("Text preprocessing complete.")

    # --- 3. Vectorize Text Data ---
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(corpus).toarray()
    y = df.label_num
    print("Text vectorization complete.")

    # --- 4. Train the RandomForest Model ---
    # Note: We train on the *entire* dataset now to make the final model as smart as possible.
    model = RandomForestClassifier(n_jobs=-1)
    model.fit(X, y)
    print("Model training complete.")

    # --- 5. Save the Vectorizer and Model ---
    with open('vectorizer.pkl', 'wb') as f:
        pickle.dump(vectorizer, f)
    
    with open('model.pkl', 'wb') as f:
        pickle.dump(model, f)
        
    print("\nSUCCESS! Model and vectorizer have been saved as 'model.pkl' and 'vectorizer.pkl'.")
    print("You can now use these in your main application.")


if __name__ == "__main__":
    train_and_save()
