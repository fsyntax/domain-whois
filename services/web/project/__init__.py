#!/usr/bin/env python3
import whois
import logging
import traceback
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify
from flask_cors import CORS
from time import sleep
from dotenv import load_dotenv
import os
import json

app = Flask(__name__)


# Enhanced Logging Configuration
def setup_logging():
    # Create a logger
    logger = logging.getLogger('whois_api')
    logger.setLevel(logging.DEBUG)  # Capture all log levels

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)

    # File Handler with Rotation
    file_handler = RotatingFileHandler(
        "whois_api.log",
        maxBytes=1_000_000,  # 1 MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    # Add handlers to the logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


# Initialize logging
logger = setup_logging()

# Rest of your existing imports and configurations...
load_dotenv()  # load environment variables

API_KEY = os.getenv('API_KEY')
DEFAULT_DOMAIN = os.getenv('DEFAULT_DOMAIN', 'scamsniper.com')


@app.before_request
def before_request():
    # Log detailed request information
    request_info = {
        'method': request.method,
        'path': request.path,
        'remote_addr': request.remote_addr,
        'user_agent': request.user_agent.string,
        'headers': dict(request.headers)
    }

    logger.info(f"Incoming Request: {json.dumps(request_info, indent=2)}")

    if request.path == "/health":
        return

    # Check API key
    api_key = request.headers.get("X-SCAMSNIPER-KEY")
    if api_key != API_KEY:
        logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
        return jsonify({"error": "Unauthorized"}), 403


# Health Check
@app.route("/health", methods=["GET"])
def health_check():
    try:
        whois.whois(DEFAULT_DOMAIN)
        logger.info("Health check successful")
        return jsonify({"status": "healthy"})
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return jsonify({"status": "unhealthy"}), 500


# WHOIS Lookup Routes
@app.route("/<domain>", methods=["GET"])
def home_domain(domain):
    logger.info(f"Processing domain: {domain}")
    return jsonify(process_domain(domain))


@app.route("/", methods=["GET"])
def home():
    logger.info(f"Processing default domain: {DEFAULT_DOMAIN}")
    return jsonify(process_domain(DEFAULT_DOMAIN))


@app.route("/", methods=["POST"])
def home_post():
    sleep(0.25)
    submitted_domain = request.form.get("domain", DEFAULT_DOMAIN)
    logger.info(f"Processing submitted domain: {submitted_domain}")
    return jsonify(process_domain(submitted_domain))


def process_domain(domain):
    try:
        logger.debug(f"Attempting WHOIS lookup for domain: {domain}")
        domain_info = whois.whois(domain)
        logger.info(f"Successfully retrieved WHOIS info for {domain}")
        return {"domain": domain, "info": domain_info}
    except Exception as e:
        logger.error(
            f"WHOIS lookup failed for domain {domain}",
            extra={
                'domain': domain,
                'error': str(e)
            },
            exc_info=True
        )
        return {"domain": domain, "info": "Unable to perform domain WHOIS lookup, please try again."}


if __name__ == "__main__":
    logger.info("Starting WHOIS API application")
    app.run()
