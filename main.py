import io
import re
import os
import csv
import tld
import joblib
import uvicorn
import numpy as np
import pandas as pd
from typing import List
from pydantic import BaseModel
from urllib.parse import urlparse
from sqlmodel import Session, select
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException

from feature_extraction import FeatureExtraction
from helper_functions import is_valid_url, calculate_entropy
from database import init_db, save_url_record, engine, URLRecord


app = FastAPI()
init_db()

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


model = joblib.load("models/gradient_boost.pkl")
# with open("models/rf_model.pkl", "rb") as f:
#     model = pickle.load(f)

feature_list = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", "PrefixSuffix-",
    "SubDomains", "HTTPS", "DomainRegLen", "Favicon", "NonStdPort", "HTTPSDomainURL",
    "RequestURL", "AnchorURL", "LinksInScriptTags", "ServerFormHandler", "InfoEmail",
    "AbnormalURL", "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording", "WebsiteTraffic",
    "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport"
]
suspicious_patterns = [
            r'\d{4,}',  # Many numbers in domain
            r'[0-9a-f]{32}',  # MD5-like hash
            r'(secure|login|account|banking|update|verify|signin|security).*\.',  # Security keywords in wrong place
            r'\.(xyz|tk|ml|ga|cf|gq|pw)$',  # Common abuse TLDs
            r'([a-zA-Z0-9])\1{5,}',  # Character repetition
            r'[^a-zA-Z0-9-.]',  # Special characters in domain
            r'(-[a-zA-Z0-9]+){3,}'  # Excessive hyphens
        ]

class URLInput(BaseModel):
    url: str


@app.get("/")
def root():
    return {"message": "Link Guard Phishing Link Detection API"}

@app.post("/analyze")
async def analyze_url(data: URLInput):
    # Validate URL
    url = data.url.lower()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if not is_valid_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")

    try:
        feature_extractor = FeatureExtraction(url)
        features = np.array(feature_extractor.get_features_list()).reshape(1, 30)
        features_df = pd.DataFrame(features, columns=feature_list)
        prediction = model.predict(features_df)[0]

        # 1 is safe | -1 is unsafe
        label = 'Safe' if prediction == 1 else 'Unsafe'
        safe_score = model.predict_proba(features_df)[0, 1]
        phishing_score = model.predict_proba(features_df)[0, 0]
        if prediction == 1:
            safety_score = f'{safe_score * 100:.2f}%'
        else:
            safety_score = f'{(1 - phishing_score) * 100:.2f}%'
        features = FeatureExtraction(url).get_features_list()
        save_url_record(url=url, using_ip=features[0], long_url=features[1], short_url=features[2], symbol=features[3],
                        redirecting=features[4], prefix_suffix=features[5], subdomains=features[6], https=features[7],
                        domain_reg_len=features[8], favicon=features[9], non_std_port=features[10], https_domain_url=features[11],
                        request_url=features[12], anchor_url=features[13], links_in_script_tags=features[14],
                        server_form_handler=features[15], info_email=features[16], abnormal_url=features[17],
                        website_forwarding=features[18], status_bar_cust=features[19], disable_right_click=features[20],
                        using_popup_window=features[21], iframe_redirection=features[22], age_of_domain=features[23],
                        dns_recording=features[24], website_traffic=features[25], pagerank=features[26], google_index=features[27],
                        links_pointing_to_page=features[28], stats_report=features[29], label=int(prediction)
                        )
        try:
            tld_length = len(tld.get_tld(url, as_object=True).tld)
        except:
            tld_length = 0
        domain = tld.get_fld(url, fail_silently=True)

        suspicious_patterns_count = 0
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                suspicious_patterns_count += 1
        url_info = {
            'url_length': len(url),
            'domain_length': len(urlparse(url)[1]),
            'num_digits': sum(c.isdigit() for c in url),
            'num_special_chars': len(re.findall(r'[^a-zA-Z0-9]', url)),
            'excessive_delimiters': len(re.findall(r'[./-]', url)) > 5,
            'has_currency_symbol': bool(re.search(r'[₦$€£¥₹₽]', url)),
            'domain_entropy': calculate_entropy(url),
            'has_valid_tld': bool(tld.get_tld(url, fail_silently=True)),
            'tld_length': tld_length,
            'is_ip_address': bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain)),
            'suspicious_patterns_count': suspicious_patterns_count,
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


@app.get("/download-urls")
def download_urls_csv():
    with Session(engine) as session:
        urls = session.exec(select(URLRecord)).all()

        # Create in-memory CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        headers = [
            'url', 'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
            'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
            'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
            'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
            'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
            'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
            'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage',
            'StatsReport', 'label'
        ]
        writer.writerow(headers)

        # Write rows
        for url in urls:
            writer.writerow([
                url.id,
                url.url, url.using_ip, url.long_url, url.short_url, url.symbol, url.redirecting, url.prefix_suffix,
                url.subdomains, url.https, url.domain_reg_len, url.favicon, url.non_std_port, url.https_domain_url,
                url.request_url, url.anchor_url, url.links_in_script_tags, url.server_form_handler, url.info_email,
                url.abnormal_url, url.website_forwarding, url.status_bar_cust, url.disable_right_click,
                url.using_popup_window, url.iframe_redirection, url.age_of_domain, url.dns_recording,
                url.website_traffic, url.pagerank, url.google_index, url.links_pointing_to_page, url.stats_report,
                url.label, url.created_at.isoformat()
            ])

        output.seek(0)

        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=predicted_urls.csv"
            }
        )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
