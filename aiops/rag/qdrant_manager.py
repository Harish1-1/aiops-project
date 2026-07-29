from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct
)

class QdrantManager:

    def __init__(self):

        self.client = QdrantClient(
            host="localhost",
            port=6333
        )

        self.collection_name = "runbooks"

    def create_collection(self):

        collections = self.client.get_collections()

        existing = [
            c.name
            for c in collections.collections
        ]

        if self.collection_name not in existing:

            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(
                    size=768,
                    distance=Distance.COSINE
                )
            )

            print("Collection created")

    def recreate_collection(self):

        try:
            self.client.delete_collection(
                collection_name=self.collection_name
            )
            print("Old collection deleted")

        except Exception as e:
            print(f"No existing collection found: {e}")

        self.create_collection()

    def insert_document(
        self,
        doc_id,
        vector,
        payload
    ):

        self.client.upsert(
            collection_name=self.collection_name,
            points=[
                PointStruct(
                    id=doc_id,
                    vector=vector,
                    payload=payload
                )
            ]
        )

    def search(self, vector):

        results = self.client.query_points(
            collection_name=self.collection_name,
            query=vector,
            limit=3
        )

        return results.points