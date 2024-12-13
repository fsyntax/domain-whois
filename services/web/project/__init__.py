#!/usr/bin/env python3
import whois
from flask import Flask, request, jsonify
from time import sleep

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy"})


@app.route("/<domain>", methods=["GET"])
def home_domain(domain):
    return jsonify(process_domain(domain))


@app.route("/", methods=["GET"])
def home():
    domain = "scamsniper.org"
    return jsonify(process_domain(domain))


@app.route("/", methods=["POST"])
def home_post():
    domain = "scamsniper.org"
    sleep(0.25)
    submitted_domain = str(request.form["domain"])
    if submitted_domain == "":
        submitted_domain = domain
    return jsonify(process_domain(submitted_domain))


def process_domain(domain):
    try:
        domain_info = whois.whois(domain)
        return {"domain": domain, "info": domain_info}
    except Exception:
        return {"domain": domain, "info": "Unable to perform domain WHOIS lookup, please try again."}


if __name__ == "__main__":
    app.run()
