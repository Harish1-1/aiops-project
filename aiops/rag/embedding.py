import requests

OLLAMA_URL = "http://localhost:11434/api/embeddings"

def create_embedding(text):

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": "nomic-embed-text",
            "prompt": text
        }
    )

    response.raise_for_status()

    return response.json()["embedding"]