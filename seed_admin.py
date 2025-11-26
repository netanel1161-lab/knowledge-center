from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
import os

# טוען את הערכים מה-.env
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "knowledge_db")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI is not set in .env")

client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
db = client[MONGO_DB_NAME]
users = db["users"]

# כאן מגדירים את פרטי האדמין שרוצים
username = "netanel"
raw_password = "0508504833"
role = "admin"

hashed_password = generate_password_hash(raw_password)

result = users.update_one(
    {"username": username},
    {
        "$set": {
            "username": username,
            "password": hashed_password,
            "role": role,
        }
    },
    upsert=True,
)

print(f"Created/updated admin user '{username}' with role '{role}'.")
