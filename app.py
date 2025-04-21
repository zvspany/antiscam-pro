# app.py
import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for # Import redirect, url_for

# Import functions from api/endpoints.py
# Note: This version assumes check_link *does* call VT internally based on the original code provided by the user for app.py
# If you are using the reverted endpoints.py (local only), you'll need to adjust check_link logic below.
# Based on the user providing *this* app.py for modification, I'll stick to its implied structure.
from api.endpoints import check_message, check_phone, check_link

# Assume scan_url_with_virustotal is NOT called separately by app.py in this version,
# as the comment in the user's provided code suggests check_link handles VT.
# If you are using the reverted endpoints.py (local only), you'll need to import and call VT here.


# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Setting secret_key is crucial for session security.
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

@app.route("/", methods=["GET", "POST"])
def index():
    """
    Handles the main page, processing form submissions (POST)
    and displaying results after redirect (GET).
    Implements Post/Redirect/Get (PRG) pattern.
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

        message = request.form.get("message")
        phone = request.form.get("phone")
        link = request.form.get("link")

        # Store results from the current POST checks temporarily
        current_check_results = {}

        if message:
            message_result = check_message(message)
            current_check_results["message"] = message_result
            increment_stat("messages_checked") # Increment upon successful check process
            logger.info(f"Processed message check for POST. Result: {message_result.get('is_suspicious', 'N/A')}")

        if phone:
            phone_result = check_phone(phone)
            current_check_results["phone"] = phone_result
            increment_stat("phones_checked") # Increment upon successful check process
            logger.info(f"Processed phone check for POST. Result: {phone_result.get('is_suspicious', 'N/A')}")

        if link:
            # Note: This version assumes check_link handles VT internally
            link_result = check_link(link)
            current_check_results["link"] = link_result
            # If check_link returns VT data integrated, this is correct.
            # If using the reverted endpoints.py (local only), you'd call VT here:
            # virustotal_result = scan_url_with_virustotal(link)
            # current_check_results["virustotal"] = virustotal_result

            increment_stat("links_checked") # Increment upon successful check process
            logger.info(f"Processed link check for POST. Result: {link_result.get('is_suspicious', 'N/A')}, Source: {link_result.get('source', 'N/A')}")

        # Store the results in session to be retrieved by the subsequent GET request
        session['check_results'] = current_check_results

        # Redirect to the same URL with GET method
        # This prevents form re-submission on refresh
        logger.info("Redirecting after POST.")
        return redirect(url_for('index'))

    # --- Handle GET Request (Retrieve & Display) ---
    else: # request.method == "GET"
        # Retrieve the results from session if they exist (after a POST redirect)
        # Use session.pop to get the value and remove it in one step
        result = session.pop('check_results', {})
        logger.info(f"Handling GET request. Results retrieved from session: {bool(result)}")

        # Prepare session stats to pass to the template
        session_stats = {
            "messages_checked": session.get("messages_checked", 0),
            "phones_checked": session.get("phones_checked", 0),
            "links_checked": session.get("links_checked", 0)
        }

        # Render the template with the retrieved results (or empty result dict for a normal GET)
        return render_template("index.html",
                               result=result, # Will be empty for a normal GET, populated after POST+redirect
                               global_stats=GLOBAL_STATS,
                               session_stats=session_stats)

# --- API ENDPOINTS ---
# API endpoints typically do NOT use PRG, they return JSON directly.
# The stat incrementation here is correct (increments per valid POST to API).

@app.route("/api/check_message", methods=["POST"])
def api_check_message():
    """API endpoint for message check."""
    data = request.get_json()
    message = data.get("message", "")
    if not message:
        logger.warning("API check_message: Missing 'message' parameter.")
        return jsonify({"error": "Missing 'message' parameter."}), 400

    message_result = check_message(message)
    increment_stat("messages_checked") # Increment upon successful API check process
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
    increment_stat("phones_checked") # Increment upon successful API check process
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

    # Note: This version assumes check_link handles VT internally
    link_result = check_link(url)
    # If using the reverted endpoints.py (local only), you'd call VT here and combine results for the JSON response:
    # from api.virustotal import scan_url_with_virustotal
    # virustotal_result = scan_url_with_virustotal(url)
    # combined_response = {"link": link_result, "virustotal": virustotal_result} # Or integrate them differently

    increment_stat("links_checked") # Increment upon successful API check process
    logger.info(f"API check_link: Result: {link_result.get('is_suspicious', 'N/A')}, Source: {link_result.get('source', 'N/A')}")
    # If check_link integrates VT, return its result. If not, return a combined dict.
    # Assuming check_link integrates VT based on the user's previous app.py code structure:
    return jsonify(link_result)


# --- Application Entry Point ---
if __name__ == "__main__":
    # Port from environment variable or default 5000
    port = int(os.environ.get("PORT", 5000))
    # host='0.0.0.0' allows external access (e.g., in Docker)
    # debug=True is useful during development
    app.run(host="0.0.0.0", port=port, debug=True)