# test_embedding.py

from embedding import create_embedding

vector = create_embedding("OOMKilled")

print(type(vector))
print(len(vector))