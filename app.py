import os
from flask import Flask, render_template, request, jsonify
from api.endpoints import check_message, check_phone, check_link

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    
    # Obsługuje POST z formularza
    if request.method == "POST":
        message = request.form.get("message")
        phone = request.form.get("phone")
        link = request.form.get("link")

        # Sprawdza wiadomość, numer telefonu i link
        if message:
            result["message"] = check_message(message)
        if phone:
            result["phone"] = check_phone(phone)
        if link:
            result["link"] = check_link(link)

    # Przekazuje wyniki do szablonu
    return render_template("index.html", result=result)

@app.route("/api/check_message", methods=["POST"])
def api_check_message():
    data = request.get_json()
    return jsonify(check_message(data.get("message", "")))

@app.route("/api/check_phone", methods=["POST"])
def api_check_phone():
    data = request.get_json()
    return jsonify(check_phone(data.get("phone_number", "")))

@app.route("/api/check_link", methods=["POST"])
def api_check_link():
    data = request.get_json()
    return jsonify(check_link(data.get("url", "")))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
