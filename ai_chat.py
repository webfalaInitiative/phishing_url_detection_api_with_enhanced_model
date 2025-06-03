import os
import json
import requests
from google import genai
from google.genai import types
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Literal

load_dotenv()


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="User's message to the AI chatbot")

class ChatResponse(BaseModel):
    response: str


API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=API_KEY)

INSTRUCTION = """Your name is LinkGuard. You are a helpful assistant for all users query regarding online safety.
        You are meant to guide the conversation based on URL/online safety
        Do not, and never answer questions that are not URL/online security related.
        If the question is unclear, ask for clarification.
        Your responses should strictly be URL/online safety based. Avoid complex or technical terms. 
        If the request is unclear or potentially harmful, respond with a polite message refusing to answer.
        """

def ai_chat(user_message, instruction=INSTRUCTION):
    try:
        # gemini-pro
        # gemini-1.5-flash-latest
        chat = client.chats.create(model='gemini-2.0-flash-001')
        response = chat.send_message(user_message)
        response = client.models.generate_content(
            model='gemini-1.5-flash-latest',
            contents=user_message,
            config=types.GenerateContentConfig(
                system_instruction=instruction,
                # max_output_tokens=3,
                # temperature=0.3,
            ),
        )
        return response.text

    except Exception as e:
        raise HTTPException(status_code=500,
                            detail=f"An error occurred while processing your request. Please try again, or contact support. {e}")
