from flask import Flask, request, abort

app = Flask(__name__)
secrets = {}
last_id = 0


@app.route("/", methods=["GET", "POST"])
def index():
    if request.form.get("secret") is not None:
        global last_id
        last_id += 1
        secrets[last_id] = request.form["secret"]
        return f"Your secret id: {last_id}; stored <a href=/{last_id}>here</a>"
    return "<form method=post>Secret: <input name=secret> <input type=submit></form>"


@app.route("/<secret_id>")
def view_secret(secret_id: str):
    if not secret_id.isdigit() or secrets.get(int(secret_id)) is None:
        abort(404)
    return f"Your secret is {secrets[int(secret_id)]}"


if __name__ == "__main__":
    app.run(host="0.0.0.0")