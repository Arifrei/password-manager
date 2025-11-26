import os
import threading
from project import create_app
from project.utils import favicon_worker


if __name__ == "__main__":
    # This check prevents the worker from starting in the reloader's child process
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        worker_thread = threading.Thread(target=favicon_worker, daemon=True)
        worker_thread.start()
        print("Background favicon worker started.")

    app = create_app()
    # Use environment variable for debug mode (default: False for production)
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(host='0.0.0.0', port=5000, debug=True)
