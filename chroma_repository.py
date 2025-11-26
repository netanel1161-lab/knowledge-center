# chroma_repository.py
import chromadb
from chromadb.utils import embedding_functions
import os

class ChromaRepository:
    def __init__(self, collection_name="knowledge_items", persist_directory="chroma_db"):
        self.persist_directory = persist_directory
        os.makedirs(self.persist_directory, exist_ok=True)
        self.client = chromadb.PersistentClient(path=self.persist_directory)
        
        # Default embedding function (will be replaced by sentence-transformers later)
        # For now, we'll use a basic MiniLM-L6-V2 if the model is available
        try:
            self.ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        except Exception:
            print("Warning: SentenceTransformer 'all-MiniLM-L6-v2' not found. Using default 'all-MiniLM-L6-v2' from ChromaDB if available or falling back to a dummy embedding function.")
            # Fallback for environments without direct internet access or if model not downloaded
            self.ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2", device='cpu')
            if not self.ef: # If it still fails, use a dummy one
                print("Warning: Falling back to a dummy embedding function as SentenceTransformer is not available.")
                class DummyEmbeddingFunction:
                    def __call__(self, texts):
                        # Returns a list of dummy embeddings (e.g., zeros)
                        return [[0.0] * 384 for _ in texts] # MiniLM-L6-v2 outputs 384-dim vectors
                self.ef = DummyEmbeddingFunction()


        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            embedding_function=self.ef # Assign the embedding function here
        )

    def add_document(self, doc_id: str, document: str, metadata: dict = None):
        # ChromaDB automatically handles embedding if an embedding_function is provided to the collection
        self.collection.add(
            documents=[document],
            metadatas=[metadata if metadata else {}],
            ids=[doc_id]
        )
        print(f"Added document {doc_id} to ChromaDB.")

    def get_document(self, doc_id: str):
        return self.collection.get(ids=[doc_id], include=['documents', 'metadatas'])

    def query_documents(self, query_texts: list, n_results: int = 5):
        return self.collection.query(
            query_texts=query_texts,
            n_results=n_results,
            include=['documents', 'distances', 'metadatas']
        )

    def update_document(self, doc_id: str, new_document: str, new_metadata: dict = None):
        self.collection.update(
            ids=[doc_id],
            documents=[new_document],
            metadatas=[new_metadata if new_metadata else {}]
        )
        print(f"Updated document {doc_id} in ChromaDB.")

    def delete_document(self, doc_id: str):
        self.collection.delete(ids=[doc_id])
        print(f"Deleted document {doc_id} from ChromaDB.")

    def _clear_collection(self):
        """
        Clears all data from the collection. Use with caution.
        This is useful for development to reset the vector database.
        """
        self.client.delete_collection(name=self.collection.name)
        print(f"Collection '{self.collection.name}' cleared and recreated.")
        self.collection = self.client.get_or_create_collection(
            name=self.collection.name,
            embedding_function=self.ef
        )

    def get_collection_count(self):
        return self.collection.count()
