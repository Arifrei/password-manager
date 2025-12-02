import os
import threading
from project import create_app
from project.utils import favicon_worker

app = create_app()


def start_favicon_worker():
    """Start the background favicon worker thread."""
    worker_thread = threading.Thread(target=favicon_worker, daemon=True)
    worker_thread.start()
    print("Background favicon worker started.")


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        start_favicon_worker()

    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(host="0.0.0.0", port=5001, debug=debug_mode)
