from flask import Flask

app = Flask(__name__)

@app.route('/')
def wakeup():
    return "Server awake"

if __name__ == '__main__':
    app.run()