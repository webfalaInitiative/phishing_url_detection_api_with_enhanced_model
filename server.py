from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from main import URLFeatureExtractor, URLSecurityModel
from urllib.parse import urlparse
import uvicorn

class URLRequest(BaseModel):
    url: str

class URLResponse(BaseModel):
    url: str
    risk_score: str
    risk_classification: str
    features: dict

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)

feature_extractor = URLFeatureExtractor()
model = URLSecurityModel(feature_extractor)
model.load("./models/custom_model_domain_reps.joblib")

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def format_risk_score(score: float) -> str:
    return f"{score:.1f}%"

def classify_risk(risk_score: float) -> str:
    if risk_score >= 75.0:
        return "bad"
    elif risk_score >= 25.0:
        return "good"
    else:
        return "uncertain"

@app.get("/")
def read_root():
    return {"message": "Link Guard Phishing Link Detection API"}

@app.post("/analyze". response_model=URLResponse)
async def analyze_url(url_request: URLRequest):
    # Validate URL
    if not url_request.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    if not is_valid_url(url_request.url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    try:
        features = feature_extractor.extract_features(url_request.url)
        feature_vector = [[features[name] for name in model.feature_names]]
        # Convert probability to percentage (multiply by 100)
        risk_score = float(model.model.predict_proba(feature_vector)[0][1] * 100)
        risk_classification = classify_risk(risk_score)
        
        return {
            "url": url_request.url,
            "risk_score": format_risk_score(risk_score),
            "risk_classification": risk_classification,
            "features": features
        }
    except Exception as e:
        raise HTTPException(status_code=500, 
                          detail=f"Error analyzing URL: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)