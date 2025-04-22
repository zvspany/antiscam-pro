# app.py
import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

# Import functions from api/endpoints.py
# check_link is assumed to handle VT internally and return combined result for 'link' key
from api.endpoints import check_message, check_phone, check_link
# Import Validators from api/validators.py - Needed for type detection
from api.validators import Validators

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Setting secret_key is crucial for session security. Change this in production!
app.secret_key = os.getenv("FLASK_SECRET_KEY", "domyslny_klucz_ktory_powinien_byc_zmieniony")

# Global statistics (since server start)
GLOBAL_STATS = {
    "messages_checked": 0,
    "phones_checked": 0,
    "links_checked": 0
}

def increment_stat(key):
    """Increments session and global stats."""
    # Session
    session[key] = session.get(key, 0) + 1
    # Global
    GLOBAL_STATS[key] += 1

# ZASTĄP CAŁĄ FUNKCJĘ index PONIŻSZYM KODEM
@app.route("/", methods=["GET", "POST"])
def index():
    """
    Handles the main page, processing form submissions (POST)
    and displaying results after redirect (GET).
    Implements Post/Redirect/Get (PRG) pattern.
    Processes a single input field, detecting data type (Link, Phone, Message).
    """
    user_ip = request.remote_addr

    # Initialize session stats if they don't exist
    if "messages_checked" not in session:
        session["messages_checked"] = 0
        session["phones_checked"] = 0
        session["links_checked"] = 0

    logger.info(f"Request to index ({request.method}) from IP: %s", user_ip)

    # --- Handle POST Request (Process & Store, then Redirect) ---
    if request.method == "POST":
        # Clear previous results from session before processing new ones
        session.pop('check_results', None)

        # Get data from the single input field named "input_data"
        input_data = request.form.get("input_data", "").strip() # Get and strip whitespace

        current_check_results = {}

        if input_data:
            logger.info(f"Received input data: '{input_data}'")

            # --- Type Detection Logic ---
            # Implement a simple prioritization: Link -> Phone -> Message
            # This order can be adjusted based on expected input types

            # 1. Check if it's a Link (URL) first
            # Use Validators.is_valid_url from api/validators.py
            if Validators.is_valid_url(input_data):
                logger.info(f"Input detected as URL: {input_data}")
                # Call check_link. Based on your endpoints.py, it returns the combined result dictionary for 'link'
                link_result = check_link(input_data)
                # Store the result dictionary under the 'link' key for the HTML template to read
                current_check_results["link"] = link_result
                increment_stat("links_checked") # Increment link stat
                logger.info(f"Processed link check. Result: {link_result.get('is_suspicious', 'N/A')}")

            # 2. Else, check if it's a Phone Number
            # Use Validators.is_valid_phone from api/validators.py
            elif Validators.is_valid_phone(input_data):
                 logger.info(f"Input detected as Phone: {input_data}")
                 phone_result = check_phone(input_data)
                 # Store the result dictionary under the 'phone' key for the HTML template
                 current_check_results["phone"] = phone_result
                 increment_stat("phones_checked") # Increment phone stat
                 logger.info(f"Processed phone check. Result: {phone_result.get('is_suspicious', 'N/A')}")

            # 3. Else, if it's neither a valid URL nor a valid phone number, assume it's a Message
            else:
                 logger.info(f"Input treated as Message: {input_data}")
                 message_result = check_message(input_data)
                 # Store the result dictionary under the 'message' key for the HTML template
                 current_check_results["message"] = message_result
                 increment_stat("messages_checked") # Increment message stat
                 logger.info(f"Processed message check. Result: {message_result.get('is_suspicious', 'N/A')}")

        else:
            logger.info("Received empty input data.")
            # If input is empty, current_check_results will be empty.
            # The HTML template is designed to handle this gracefully (no results displayed).

        # Store the results from this single check in the session to be retrieved by the subsequent GET request
        session['check_results'] = current_check_results

        # Redirect to the same URL with GET method to display results and prevent form re-submission on refresh
        logger.info("Redirecting after POST.")
        return redirect(url_for('index'))

    # --- Handle GET Request (Retrieve & Display) ---
    else: # request.method == "GET"
        # Retrieve the results from session if they exist (after a POST redirect)
        # Use session.pop to get the value and remove it in one step. Defaults to empty dict if no results in session.
        result = session.pop('check_results', {})
        logger.info(f"Handling GET request. Results retrieved from session: {bool(result)}")

        # Prepare session stats to pass to the template
        session_stats = {
            "messages_checked": session.get("messages_checked", 0),
            "phones_checked": session.get("phones_checked", 0),
            "links_checked": session.get("links_checked", 0)
        }

        # Render the template with the retrieved results (or empty result dict for a normal initial GET)
        # The 'result' dictionary will contain 'message', 'phone', or 'link' key based on input type detected in POST
        return render_template("index.html",
                               result=result, # Pass the result dictionary (can be empty or contain one check result)
                               global_stats=GLOBAL_STATS,
                               session_stats=session_stats)

# --- API ENDPOINTS ---
# These endpoints are designed for specific input types and typically return JSON.
# They remain unchanged as they are separate from the main single-input form.

@app.route("/api/check_message", methods=["POST"])
def api_check_message():
    """API endpoint for message check."""
    data = request.get_json()
    message = data.get("message", "")
    if not message:
        logger.warning("API check_message: Missing 'message' parameter.")
        return jsonify({"error": "Missing 'message' parameter."}), 400

    message_result = check_message(message)
    increment_stat("messages_checked") # Increment message stat for API
    logger.info(f"API check_message: Result: {message_result.get('is_suspicious', 'N/A')}")
    return jsonify(message_result)

@app.route("/api/check_phone", methods=["POST"])
def api_check_phone():
    """API endpoint for phone check."""
    data = request.get_json()
    phone = data.get("phone_number", "")
    if not phone:
         logger.warning("API check_phone: Missing 'phone_number' parameter.")
         return jsonify({"error": "Missing 'phone_number' parameter."}), 400

    phone_result = check_phone(phone)
    increment_stat("phones_checked") # Increment phone stat for API
    logger.info(f"API check_phone: Result: {phone_result.get('is_suspicious', 'N/A')}")
    return jsonify(phone_result)

@app.route("/api/check_link", methods=["POST"])
def api_check_link():
    """API endpoint for link check."""
    data = request.get_json()
    url = data.get("url", "")
    if not url:
        logger.warning("API check_link: Missing 'url' parameter.")
        return jsonify({"error": "Missing 'url' parameter."}), 400

    # Note: check_link in your endpoints.py handles VT internally and returns the combined dict
    link_result = check_link(url)

    increment_stat("links_checked") # Increment link stat for API
    logger.info(f"API check_link: Result: {link_result.get('is_suspicious', 'N/A')}, Source: {link_result.get('source', 'N/A')}")
    # Return the combined result dictionary from check_link
    return jsonify(link_result)


# --- Application Entry Point ---
if __name__ == "__main__":
    # Port from environment variable or default 5000
    port = int(os.environ.get("PORT", 5000))
    # host='0.0.0.0' allows external access (e.g., in Docker)
    # debug=True is useful during development
    app.run(host="0.0.0.0", port=port, debug=True)