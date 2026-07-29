from llm_client import LLMClient

llm = LLMClient()

response = llm.generate(
    "Explain OOMKilled in Kubernetes"
)

print(response)