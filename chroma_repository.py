# chroma_repository.py
import chromadb
from chromadb.utils import embedding_functions
import os

class ChromaRepository:
    def __init__(self, collection_name="knowledge_items", persist_directory="chroma_db"):
        self.persist_directory = persist_directory
        os.makedirs(self.persist_directory, exist_ok=True)
        self.client = chromadb.PersistentClient(path=self.persist_directory)
        self.collection = None
        self._collection_name = collection_name
        self._ef = None

    def _get_embedding_function(self):
        if self._ef is not None:
            return self._ef
        try:
            self._ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        except Exception:
            print("Warning: SentenceTransformer 'all-MiniLM-L6-v2' not found. Falling back to CPU.")
            self._ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2", device='cpu')
        return self._ef

    def _get_collection(self):
        if self.collection is None:
            self.collection = self.client.get_or_create_collection(
                name=self._collection_name,
                embedding_function=self._get_embedding_function()
            )
        return self.collection

    def add_document(self, doc_id: str, document: str, metadata: dict = None):
        col = self._get_collection()
        col.add(
            documents=[document],
            metadatas=[metadata if metadata else {}],
            ids=[doc_id]
        )
        print(f"Added document {doc_id} to ChromaDB.")

    def get_document(self, doc_id: str):
        return self._get_collection().get(ids=[doc_id], include=['documents', 'metadatas'])

    def query_documents(self, query_texts: list, n_results: int = 5):
        return self._get_collection().query(
            query_texts=query_texts,
            n_results=n_results,
            include=['documents', 'distances', 'metadatas']
        )

    def update_document(self, doc_id: str, new_document: str, new_metadata: dict = None):
        self._get_collection().update(
            ids=[doc_id],
            documents=[new_document],
            metadatas=[new_metadata if new_metadata else {}]
        )
        print(f"Updated document {doc_id} in ChromaDB.")

    def delete_document(self, doc_id: str):
        self._get_collection().delete(ids=[doc_id])
        print(f"Deleted document {doc_id} from ChromaDB.")

    def _clear_collection(self):
        """
        Clears all data from the collection. Use with caution.
        This is useful for development to reset the vector database.
        """
        col = self._get_collection()
        self.client.delete_collection(name=col.name)
        print(f"Collection '{col.name}' cleared and recreated.")
        self.collection = self.client.get_or_create_collection(
            name=col.name,
            embedding_function=self._get_embedding_function()
        )

    def get_collection_count(self):
        return self._get_collection().count()
