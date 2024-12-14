#!/usr/bin/env python3
import whois
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify
from flask_cors import CORS
from time import sleep
from dotenv import load_dotenv
import os

app = Flask(__name__)

load_dotenv()  # load environment variables


# Configure logging
handler = RotatingFileHandler("whois_api.log", maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# Configure CORS
CORS(
    app,
    origins=["http://scamsniper.org", "https://www.scamsniper.org"],
    methods=["GET"],
)


API_KEY = os.getenv('API_KEY')
DEFAULT_DOMAIN = os.getenv('DEFAULT_DOMAIN', 'scamsniper.com')


@app.before_request
def before_request():
    # Log the request
    app.logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")

    # Skip API key check in development mode or for specific routes
    if os.getenv("FLASK_ENV") == "development" or request.path == "/health":
        return

    # Check API key
    api_key = request.headers.get("X-SCAMSNIPER-KEY")
    if api_key != API_KEY:
        app.logger.warning(f"Unauthorized request from {request.remote_addr}")
        return jsonify({"error": "Unauthorized"}), 403


# Health Check
@app.route("/health", methods=["GET"])
def health_check():
    try:
        whois.whois(DEFAULT_DOMAIN)
        return jsonify({"status": "healthy"})
    except Exception as e:
        app.logger.error(f"Health check failed: {e}")
        return jsonify({"status": "unhealthy"}), 500


# WHOIS Lookup Routes
@app.route("/<domain>", methods=["GET"])
def home_domain(domain):
    return jsonify(process_domain(domain))


@app.route("/", methods=["GET"])
def home():
    return jsonify(process_domain(DEFAULT_DOMAIN))


@app.route("/", methods=["POST"])
def home_post():
    sleep(0.25)
    submitted_domain = request.form.get("domain", DEFAULT_DOMAIN)
    return jsonify(process_domain(submitted_domain))


def process_domain(domain):
    try:
        domain_info = whois.whois(domain)
        return {"domain": domain, "info": domain_info}
    except Exception as e:
        app.logger.error(f"WHOIS lookup failed for domain {domain}: {e}")
        return {"domain": domain, "info": "Unable to perform domain WHOIS lookup, please try again."}


if __name__ == "__main__":
    app.run()
