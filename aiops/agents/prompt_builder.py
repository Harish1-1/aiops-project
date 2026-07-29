def build_prompt(incident, context):

    context_text = "\n\n".join(context)

    return f"""
You are a Senior Site Reliability Engineer.

Incident:

{incident}

Relevant Runbooks:

{context_text}

Provide:

1. Root Cause Analysis
2. Confidence Score (0-100)
3. Immediate Fix
4. Prevention Strategy

Keep response concise and practical.
"""