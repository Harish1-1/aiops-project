from fastapi import FastAPI, Request
from collector import collect_incident

app = FastAPI()

@app.get("/")
def root():
    return {"status": "Incident Collector Running"}

@app.post("/alert")
async def alert(request: Request):
    data = await request.json()

    result = collect_incident(data)

    return {
        "status": "received",
        "incident": result
    }