from fastapi import FastAPI, HTTPException
from main import URLFeatureExtractor, URLSecurityModel
from urllib.parse import urlparse
import uvicorn

app = FastAPI()
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
    elif risk_score >= 50.0:
        return "good"
    else:
        return "uncertain"

@app.get("/")
def read_root():
    return {"message": "URL Security Analyzer API"}

@app.post("/analyze")
async def analyze_url(url: str):
    # Validate URL
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    if not is_valid_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    try:
        features = feature_extractor.extract_features(url)
        feature_vector = [[features[name] for name in model.feature_names]]
        # Convert probability to percentage (multiply by 100)
        risk_score = float(model.model.predict_proba(feature_vector)[0][1] * 100)
        risk_classification = classify_risk(risk_score)
        
        return {
            "url": url,
            "risk_score": format_risk_score(risk_score),
            "risk_classification": risk_classification,
            "features": features
        }
    except Exception as e:
        raise HTTPException(status_code=500, 
                          detail=f"Error analyzing URL: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)