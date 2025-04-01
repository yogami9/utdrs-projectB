from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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

# Mount static files (for dashboard)
app.mount("/dashboard", StaticFiles(directory="app/static", html=True), name="dashboard")

@app.get("/")
async def root():
    return {"message": "Welcome to the Unified Threat Detection and Response System API", 
            "dashboard_url": "/dashboard"}

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)