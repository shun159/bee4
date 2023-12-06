from flask import Flask

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

data = {
    "enabler_name": "Internet Multifeed Co.",
    "service_name": "transix IPv4接続（DS-Lite）",
    "isp_name": "transix",
    "ttl": 86400,
    "order": [
        "dslite"
    ],
    "dslite": {
        "aftr": "2401:db00::3"
    }
}


@app.route("/config", methods=["GET"])
def config():
    return data


if __name__ == "__main__":
    app.run(host='::', port=443, ssl_context=('./scripts/server.crt', './scripts/server.key'))
