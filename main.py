from flask import request, url_for, session, Response, redirect, Flask
from bokeh.util import session_id
import re
import os
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2 import InvalidGrantError, TokenExpiredError
import yaml

app = Flask(__name__)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

app_path = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(app_path, "config.yaml".format()), 'r') as stream:
    try:
        cfg = yaml.load(stream)
    except yaml.YAMLError as exc:
        print(exc)

GOOGLE_CLIENT_ID = cfg['GOOGLE_CLIENT_ID']  # your google client id
GOOGLE_CLIENT_SECRET = cfg['GOOGLE_CLIENT_SECRET']  # your google client secret
BOKEH_SECRET = cfg['BOKEH_SECRET']  # your bokeh secret
BOKEH_URL = cfg['BOKEH_URL']  # your bokeh url redirect
ALLOWED_DOMAIN = cfg['ALLOWED_DOMAIN']  # your domain
app.secret_key = cfg['APP_SECRET']  # your app secret key

blueprint = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    scope=[
        "https://www.googleapis.com/auth/plus.me",
        "https://www.googleapis.com/auth/userinfo.email",
    ]
)
app.register_blueprint(blueprint, url_prefix="/login")
app_path = os.path.dirname(os.path.realpath(__file__))


@app.route("/")
def index():
    if not google.authorized:
        return redirect(url_for("google.login"))
    try:
        resp = google.get("/oauth2/v2/userinfo")
        assert resp.ok, resp.text
        domain = re.search("@[\w.]+", resp.json()["email"])
        print(domain.group())
    except (InvalidGrantError, TokenExpiredError) as e:  # or maybe any OAuth2Error
        return redirect(url_for("google.login"))

    if domain.group() == ALLOWED_DOMAIN:
        s_id = session_id.generate_session_id(secret_key=BOKEH_SECRET, signed=True)
        return redirect("{url}/dashboard_simple/?bokeh-session-id={s_id}".format(s_id=s_id, url=BOKEH_URL), code=302)
    return "Hi {email} you are not allowed to login on this page".format(email=resp.json()["email"])


if __name__ == "__main__":
    app.run()
