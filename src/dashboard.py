from flask import Flask, render_template

app = Flask(
    __name__,
    template_folder = '../templates',
    static_folder = '../static'
)

@app.route('/')
def index():
    return render_template('index.html')

def start_dashboard(host = '0.0.0.0', port = 5000, debug = False):

    print(f"Starting dashboard on {host}:{port}...")
    app.run(host = host, port = port, debug = debug, threaded = True)

if __name__ == "__main__":
    start_dashboard()