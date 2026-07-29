from rag.query import retrieve_context

results = retrieve_context(
    "OOMKilled pod"
)

for r in results:

    print("=" * 50)
    print(r)