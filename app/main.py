from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from app.routers import api

app = FastAPI(
    title="Unified Threat Detection and Response System",
    description="API for detecting and responding to cybersecurity threats",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(api.router)

@app.get("/")
async def root():
    return {"message": "Welcome to the Unified Threat Detection and Response System API"}

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
