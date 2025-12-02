import os
import requests
from io import BytesIO
from PIL import Image
from queue import Queue
from urllib.parse import urlparse
from random import choice, randint, shuffle

from . import db
from .models import Passwords

# --- Favicon Setup ---
FAVICON_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'favicons')
os.makedirs(FAVICON_FOLDER, exist_ok=True)
favicon_queue = Queue()


def favicon_worker():
    """Worker thread that processes favicon fetching jobs from a queue."""
    from . import create_app
    app = create_app()  # Create a new app instance for the thread context
    with app.app_context():
        while True:
            entry_id, site_name = favicon_queue.get()
            if entry_id is None:
                break
            try:
                filename = fetch_and_save_favicon(site_name)
                if filename:
                    entry = db.session.get(Passwords, entry_id)
                    if entry:
                        entry.favicon = filename
                        db.session.commit()
            except Exception as e:
                print(f"Error in favicon worker for site '{site_name}': {e}")
                db.session.rollback()
            finally:
                favicon_queue.task_done()


# --- Favicon Fetching Functions ---

def extract_domain_from_site(site_name):
    site_name = site_name.lower().strip().replace(' login', '').replace(' account', '').replace(' app', '').strip()
    if '://' in site_name or site_name.startswith('www.'):
        parsed = urlparse(site_name if '://' in site_name else f'http://{site_name}')
        domain = (parsed.netloc or parsed.path).replace('www.', '')
        return domain
    if '.' in site_name and ' ' not in site_name:
        return site_name.replace('www.', '')
    return f"{site_name.split()[0]}.com"

def get_favicon_filename(site_name):
    domain = extract_domain_from_site(site_name)
    safe_name = domain.replace('.', '_').replace('/', '_').replace(':', '_')
    return f"{safe_name}.png"

def fetch_and_save_favicon(site_name):
    domain = extract_domain_from_site(site_name)
    filename = get_favicon_filename(site_name)
    filepath = os.path.join(FAVICON_FOLDER, filename)

    if os.path.exists(filepath):
        return filename

    favicon_urls = [
        f"https://www.google.com/s2/favicons?domain={domain}&sz=128",
        f"https://icons.duckduckgo.com/ip3/{domain}.ico",
        f"https://{domain}/favicon.ico",
        f"https://www.{domain}/favicon.ico",
    ]

    for url in favicon_urls:
        try:
            response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200 and len(response.content) > 0:
                try:
                    img = Image.open(BytesIO(response.content))
                    if img.size[0] < 10 or img.size[1] < 10:
                        continue
                    img = img.convert('RGBA').resize((32, 32), Image.Resampling.LANCZOS)
                    img.save(filepath, 'PNG')
                    return filename
                except Exception:
                    continue
        except Exception:
            continue
    return None


# --- Password Generator ---

def pass_generator():
    letters = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    numbers = list("0123456789")
    symbols = list("!#$%&()*+")
    password_list = [
        *(choice(letters) for _ in range(randint(8, 10))),
        *(choice(numbers) for _ in range(randint(2, 4))),
        *(choice(symbols) for _ in range(randint(2, 4))),
    ]
    shuffle(password_list)
    return "".join(password_list)
