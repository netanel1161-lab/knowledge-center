# utils.py
from bs4 import BeautifulSoup
from sentence_transformers import SentenceTransformer

_embedding_model = None

def extract_text_from_html(html_content: str) -> str:
    """
    Extracts plain text from HTML content using BeautifulSoup.
    """
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.get_text(separator=' ', strip=True)

def get_embedding_model():
    """
    Loads and returns the SentenceTransformer model for embedding.
    Caches the model after the first load.
    """
    global _embedding_model
    if _embedding_model is None:
        try:
            _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            print("Loaded SentenceTransformer model 'all-MiniLM-L6-v2'.")
        except Exception as e:
            print(f"Error loading SentenceTransformer model: {e}")
            print("Attempting to load from local cache or download. Ensure internet connection or model is pre-downloaded.")
            # Fallback for environments without direct internet access or if model not downloaded
            _embedding_model = SentenceTransformer('all-MiniLM-L6-v2', device='cpu')
            # If it still fails, we might need a more robust fallback or error handling
            if _embedding_model is None:
                raise RuntimeError("Could not load SentenceTransformer model 'all-MiniLM-L6-v2'.")
    return _embedding_model

def generate_embedding(text: str) -> list[float]:
    """
    Generates a vector embedding for the given text using SentenceTransformer.
    """
    model = get_embedding_model()
    # The encode method returns a numpy array, convert to list for consistency
    return model.encode(text).tolist()