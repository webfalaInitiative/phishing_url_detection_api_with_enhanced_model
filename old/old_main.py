from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
import numpy as np
from typing import List, Tuple, Set
import re
import tld
import nltk
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import pandas as pd
from datetime import datetime
import logging
import os
from urllib.parse import urlparse
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DomainReputation:
    """Handle domain reputation checking"""
    
    def __init__(self):
        self.trusted_domains = self._load_trusted_domains()
        self.suspicious_patterns = [
            r'\d{4,}',  # Many numbers in domain
            r'[0-9a-f]{32}',  # MD5-like hash
            r'(secure|login|account|banking|update|verify|signin|security).*\.',  # Security keywords in wrong place
            r'\.(xyz|tk|ml|ga|cf|gq|pw)$',  # Common abuse TLDs
            r'([a-zA-Z0-9])\1{5,}',  # Character repetition
            r'[^a-zA-Z0-9-.]',  # Special characters in domain
            r'(-[a-zA-Z0-9]+){3,}'  # Excessive hyphens
        ]
    
    def _load_trusted_domains(self) -> Set[str]:
        """Load list of trusted domains"""
        trusted = {
            # Social Media
            'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'pinterest.com',
            'reddit.com', 'tumblr.com', 'snapchat.com', 'tiktok.com',
            
            # Tech Giants
            'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'netflix.com', 'zoom.us', 'adobe.com', 'wordpress.com', 'github.com',
            
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
        
        # Add www. variants
        www_variants = {f'www.{domain}' for domain in trusted}
        trusted.update(www_variants)
        
        return trusted

    def analyze_domain(self, url: str) -> dict:
        """Analyze domain reputation and characteristics"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if not domain:
                domain = tld.get_fld(url, fail_silently=True)
            
            # Remove www. if present for comparison
            clean_domain = re.sub(r'^www\.', '', domain)
            
            analysis = {
                'is_trusted_domain': False,
                'suspicious_patterns_count': 0,
                'suspicious_patterns_found': [],
                'domain_length': len(domain),
                'subdomain_count': domain.count('.'),
                'is_ip_address': bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain)),
                'has_valid_tld': bool(tld.get_tld(url, fail_silently=True)),
                'domain_entropy': self._calculate_entropy(domain),
            }
            
            # Check if domain or its non-www version is trusted
            analysis['is_trusted_domain'] = (
                domain in self.trusted_domains or 
                clean_domain in self.trusted_domains
            )
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, domain):
                    analysis['suspicious_patterns_count'] += 1
                    analysis['suspicious_patterns_found'].append(pattern)
            
            return analysis
            
        except Exception as e:
            logger.warning(f"Error analyzing domain for URL {url}: {str(e)}")
            return {
                'is_trusted_domain': False,
                'suspicious_patterns_count': 0,
                'suspicious_patterns_found': [],
                'domain_length': 0,
                'subdomain_count': 0,
                'is_ip_address': False,
                'has_valid_tld': False,
                'domain_entropy': 0,
            }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text (high entropy often indicates randomness)"""
        if not text:
            return 0
        text = text.lower()
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0
        for count in freq.values():
            prob = count / len(text)
            entropy -= prob * np.log2(prob)
        return entropy

class URLFeatureExtractor:
    """Enhanced feature extraction for URLs"""
    
    def __init__(self):
        self.initialize_nlp()
        self.domain_reputation = DomainReputation()
    
    def initialize_nlp(self):
        """Initialize NLP components"""
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)
        self.stopwords = set(nltk.corpus.stopwords.words('english'))
        
    def extract_features(self, url: str) -> dict:
        """Extract comprehensive feature set from URL"""
        features = {}
        
        # Basic URL characteristics
        features['length'] = len(url)
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9]', url))
        
        # Get domain reputation analysis
        domain_analysis = self.domain_reputation.analyze_domain(url)
        
        # Add domain analysis features
        features.update({
            'is_trusted_domain': int(domain_analysis['is_trusted_domain']),
            'suspicious_patterns_count': domain_analysis['suspicious_patterns_count'],
            'domain_length': domain_analysis['domain_length'],
            'subdomain_count': domain_analysis['subdomain_count'],
            'is_ip_address': int(domain_analysis['is_ip_address']),
            'has_valid_tld': int(domain_analysis['has_valid_tld']),
            'domain_entropy': domain_analysis['domain_entropy'],
        })
        
        # Original feature extraction
        try:
            domain = tld.get_tld(url, as_object=True)
            features['tld_length'] = len(domain.tld)
        except:
            features['tld_length'] = 0
        
        # Suspicious patterns
        suspicious_keywords = {
            'login', 'signin', 'account', 'banking', 'secure', 'update',
            'verify', 'wallet', 'authenticate', 'password'
        }
        features['suspicious_keyword_count'] = sum(
            word in url.lower() for word in suspicious_keywords
        )
        features['multiple_tlds'] = len(re.findall(r'\.[a-z]{2,}', url.lower())) > 1
        features['excessive_delimiters'] = len(re.findall(r'[./-]', url)) > 5
        features['has_currency_symbol'] = bool(re.search(r'[$€£¥]', url))
        
        return features

class URLSecurityModel:
    """Class to handle model training and evaluation"""
    
    def __init__(self, feature_extractor: URLFeatureExtractor):
        self.feature_extractor = feature_extractor
        self.model = None
        self.feature_names = None
        
    def prepare_features(self, urls: List[str]) -> np.ndarray:
        """Convert URLs to feature matrix"""
        features = [self.feature_extractor.extract_features(url) for url in urls]
        self.feature_names = list(features[0].keys())
        return np.array([[f[name] for name in self.feature_names] for f in features])
    
    def train(self, urls: List[str], labels: List[int], test_size=0.2):
        """Train the model and evaluate performance"""
        logger.info(f"Preparing to train on {len(urls)} URLs")
        
        # Prepare features
        X = self.prepare_features(urls)
        
        # Split dataset
        X_train, X_test, y_train, y_test = train_test_split(
            X, labels, test_size=test_size, random_state=42, stratify=labels
        )
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            class_weight='balanced',
            random_state=42
        )
        self.model.fit(X_train, y_train)
        
        # Evaluate
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        y_pred = self.model.predict(X_test)
        report = classification_report(y_test, y_pred)
        conf_matrix = confusion_matrix(y_test, y_pred)
        
        logger.info(f"Training Score: {train_score:.4f}")
        logger.info(f"Test Score: {test_score:.4f}")
        logger.info("\nClassification Report:\n" + report)
        logger.info("\nConfusion Matrix:\n" + str(conf_matrix))
        
        # Feature importance analysis
        importance = sorted(zip(self.feature_names, 
                              self.model.feature_importances_),
                          key=lambda x: x[1], reverse=True)
        logger.info("\nTop 5 Important Features:")
        for feat, imp in importance[:5]:
            logger.info(f"{feat}: {imp:.4f}")
        
        return {
            'train_score': train_score,
            'test_score': test_score,
            'classification_report': report,
            'confusion_matrix': conf_matrix,
            'feature_importance': importance
        }
    
    def save(self, path: str):
        """Save the trained model"""
        if self.model is None:
            raise ValueError("No trained model to save")
        
        model_data = {
            'model': self.model,
            'feature_names': self.feature_names,
            'timestamp': datetime.now().isoformat()
        }
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")
    
    def load(self, path: str):
        """Load a trained model"""
        model_data = joblib.load(path)
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        logger.info(f"Model loaded from {path} (trained on {model_data['timestamp']})")

def train_from_csv(csv_path: str, url_column: str, label_column: str, model_output_path: str = "./models/url_security_model.joblib"):
    """Train model from CSV dataset"""
    # Load and prepare data
    logger.info(f"Loading data from {csv_path}")
    df = pd.read_csv(csv_path)
    
    # Basic data validation
    if url_column not in df.columns or label_column not in df.columns:
        raise ValueError(f"Required columns not found. Available columns: {df.columns.tolist()}")
    
    # Remove any rows with missing values
    df = df.dropna(subset=[url_column, label_column])
    
    # Convert labels to binary (0 for good, 1 for bad)
    label_mapping = {'good': 0, 'bad': 1}
    df[label_column] = df[label_column].map(lambda x: label_mapping.get(str(x).lower(), x))
    
    # Validate labels
    if not all(df[label_column].isin([0, 1])):
        raise ValueError("Labels must be either 'good'/'bad' or 0/1")
    
    # Print dataset statistics
    logger.info(f"Dataset statistics:")
    logger.info(f"Total URLs: {len(df)}")
    logger.info(f"Label distribution:\n{df[label_column].value_counts()}")
    
    # Initialize model components
    feature_extractor = URLFeatureExtractor()
    model = URLSecurityModel(feature_extractor)
    
    # Train model
    urls = df[url_column].tolist()
    labels = df[label_column].tolist()
    
    results = model.train(urls, labels)
    
    # Save model
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    model.save(model_output_path)
    
    return results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Train URL Security Model from CSV')
    parser.add_argument('--csv', required=True, help='Path to CSV file')
    parser.add_argument('--url-column', default='url', help='Name of URL column')
    parser.add_argument('--label-column', default='label', help='Name of label column')
    parser.add_argument('--model-output', default='./models/url_security_model.joblib', help='Path to save model')
    
    args = parser.parse_args()
    
    try:
        results = train_from_csv(
            args.csv,
            args.url_column,
            args.label_column,
            args.model_output
        )
        
        print("\nTraining completed successfully!")
        print(f"Model saved to: {args.model_output}")
        print("\nPerformance Metrics:")
        print(f"Training accuracy: {results['train_score']:.4f}")
        print(f"Testing accuracy: {results['test_score']:.4f}")
        print("\nClassification Report:")
        print(results['classification_report'])
        
    except Exception as e:
        logger.error(f"Error during training: {str(e)}")
        raise