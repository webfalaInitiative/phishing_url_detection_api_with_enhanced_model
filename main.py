import io
import re
import os
import csv
import tld
import joblib
import uvicorn
import numpy as np
import pandas as pd
from typing import List, Optional, Literal
from pydantic import BaseModel
from urllib.parse import urlparse
from sqlmodel import Session, select
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException

from feature_extraction import extract_features
from helper_functions import clean_url, is_valid_url, calculate_entropy
from database import init_db, save_url_record, engine, URLRecord


init_db()

app = FastAPI(
    title="The LinkGuard Phishing Link Detection API",
    description="""
        This API predicts whether a given URL is safe or unsafe using a trained Machine Learning model.
        
        It also stores every URL submitted into a database and provides endpoints to fetch and download predictions.
    """,
    version="1.0.0",
    contact={
        "name": "The Linkguard",
        "url": "https://thelinkguard.com/",
        "email": "linkguard1@gmail.com",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    }
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)

# cur_dir = os.path.dirname(__file__)
# model = joblib.load(os.path.join(cur_dir, 'models', 'rf_model.pkl'))


model = joblib.load("models/RandomForest.pkl")

trusted_domains = {
    # Social Media
    'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'pinterest.com',
    'reddit.com', 'tumblr.com', 'snapchat.com', 'tiktok.com',

    # Tech Giants
    'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'netflix.com', 'zoom.us', 'adobe.com', 'wordpress.com', 'github.com',
    'huggingface.co',

    # Email Services
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'protonmail.com',

    # E-commerce
    'ebay.com', 'walmart.com', 'etsy.com', 'shopify.com', 'paypal.com',

    # Cloud Services
    'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com', 'dropbox.com',
    'salesforce.com',

    # Banking (add major banks in your region)
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',

    # Media
    'cnn.com', 'bbc.com', 'nytimes.com', 'reuters.com', 'bloomberg.com'
}

class URLRequest(BaseModel):
    url: str

class FeedbackInput(BaseModel):
    feedback: Literal["correct", "incorrect"]


@app.get("/")
def root():
    return {"message": "The LinkGuard Phishing Link Detection API"}

@app.post("/analyze")
async def analyze_url(url_request: URLRequest):
    # Validate URL
    url = url_request.url
    feedback = "correct"  # Always assume correct first

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if not is_valid_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")

    try:
        url_features = extract_features(url)
        feature_df = pd.DataFrame(url_features, index=[0])

        url_domain = urlparse(clean_url(url.lower())).netloc
        if url_domain in trusted_domains:
            prediction = 0
            safe_score = 1.0
            phishing_score = 0.0
            label = 'Safe'
        else:
            prediction = model.predict(feature_df)[0]
            safe_score = model.predict_proba(feature_df)[0, 1]
            phishing_score = model.predict_proba(feature_df)[0, 0]
            label = 'Safe' if prediction == 0 else 'Unsafe'

        # 0 is Safe | 1 is Unsafe
        if prediction == 0:
            safety_score = f'{safe_score * 100:.1f}%'
        else:
            safety_score = f'{phishing_score * 100:.1f}%'

        features = [feature for feature in url_features.values()]
        # url_record =
        save_url_record(url=url, Have_IP=features[0], Have_At=features[1], URL_Length=features[2],
                        URL_Depth=features[3], Redirection=features[4], https_Domain=features[5],
                        TinyURL=features[6], Prefix_Suffix=features[7], DNS_Record=features[8],
                        Web_Traffic=features[9], Domain_Age=features[10], Domain_End=features[11],
                        iFrame=features[12], Mouse_Over=features[13], Right_Click=features[14],
                        Web_Forwards=features[15], Suspicious_Words=features[16], Suspicious_Patterns=features[17],
                        Have_Currency=features[18], GoogleIndex=features[19], label=int(prediction), feedback=feedback
                        )
        url_info = {
            'url_length': len(url),
            'domain_length': len(urlparse(url)[1]),
            'num_digits': sum(c.isdigit() for c in url),
            'num_special_chars': len(re.findall(r'[^a-zA-Z0-9]', url)),
            'excessive_delimiters': len(re.findall(r'[./-]', url)) > 5,
            'has_currency_symbol': bool(features[18]),
            'domain_entropy': calculate_entropy(url),
            'has_valid_tld': bool(tld.get_tld(url, fail_silently=True)),
            'is_ip_address': bool(features[0]),
            'suspicious_patterns_count': features[17],
        }

        context = {
            'url': url,
            'label': label,
            'safety_score': safety_score,
            'url_info': url_info,
        }
        return context
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {str(e)}")

@app.patch("/feedback/{prediction_id}", response_model=URLRecord)
def update_feedback(prediction_id: int, feedback_input: FeedbackInput):
    with Session(engine) as session:
        prediction = session.get(URLRecord, prediction_id)
        if not prediction:
            raise HTTPException(status_code=404, detail="Prediction not found")

        prediction.feedback = feedback_input.feedback
        session.add(prediction)
        session.commit()
        session.refresh(prediction)
        return prediction

def get_session():
    with Session(engine) as session:
        yield session

# @app.get("/saved_urls", response_model=List[URLRecord])
# def get_all_urls(session: Session = Depends(get_session)):
#     urls = session.exec(select(URLRecord).order_by(URLRecord.created_at.desc())).all()
#     return urls

@app.get("/logs")
def get_all_logs():
    with Session(engine) as session:
        records = session.exec(select(URLRecord).order_by(URLRecord.created_at.desc())).all()
        return records


@app.get("/download-urls_csv")
def download_urls_csv():
    """
    This is for training purpose
    """
    with Session(engine) as session:
        urls = session.exec(select(URLRecord)).all()

        # Create in-memory CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        headers = [
            'id', 'url',
            'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 'https_Domain',
            'TinyURL', 'Prefix_Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End',
            'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards', 'Suspicious_Words', 'Suspicious_Patterns',
            'Have_Currency', 'GoogleIndex', 'label', 'feedback', 'created_at'
        ]
        writer.writerow(headers)

        # Write rows
        for url in urls:
            writer.writerow([
                url.id, url.url,
                url.Have_IP, url.Have_At, url.URL_Length, url.URL_Depth, url.Redirection, url.https_Domain,
                url.TinyURL, url.Prefix_Suffix, url.DNS_Record, url.Web_Traffic, url.Domain_Age, url.Domain_End,
                url.iFrame, url.Mouse_Over, url.Right_Click, url.Web_Forwards, url.Suspicious_Words,
                url.Suspicious_Patterns, url.Have_Currency, url.GoogleIndex,
                url.label, url.feedback, url.created_at.isoformat()
            ])

        output.seek(0)

        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=linkguard_url_data.csv"
            }
        )

@app.get("/download-short_data")
def download_short_data():
    """
    This is for audit purpose
    """
    with Session(engine) as session:
        urls = session.exec(select(URLRecord)).all()

        # Create in-memory CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        headers = [
            'id', 'url', 'label', 'feedback', 'created_at'
        ]
        writer.writerow(headers)

        # Write rows
        for url in urls:
            writer.writerow([
                url.id, url.url, url.label, url.feedback, url.created_at.isoformat()
            ])

        output.seek(0)

        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=linkguard_short_urls.csv"
            }
        )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
