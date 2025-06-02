from fastapi import FastAPI
import logging
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(level=logging.INFO)
logger=logging.getLogger(__name__)
app=FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)