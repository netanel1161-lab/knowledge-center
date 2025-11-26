# models.py
from datetime import datetime, timedelta
from typing import Optional

from bson.objectid import ObjectId
from werkzeug.security import check_password_hash as werkzeug_check


class KnowledgeItemModel:
    def __init__(self, mongo_collection):
        self.collection = mongo_collection

    def create_item(self, item_type: str, title: str, content: str, metadata: dict, embedding_id: str):
        item_data = {
            "item_type": item_type,
            "title": title,
            "content": content,
            "metadata": metadata,
            "embedding_id": embedding_id,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        result = self.collection.insert_one(item_data)
        item_data['_id'] = result.inserted_id # Add the MongoDB ObjectId
        return item_data

    def get_all_items(self):
        return list(self.collection.find({}))

    def get_item_by_id(self, item_id: str):
        try:
            return self.collection.find_one({"_id": ObjectId(item_id)})
        except Exception:
            return None

    def search_items(self, criteria: dict, page: int, page_size: int):
        skip = (page - 1) * page_size
        cursor = (
            self.collection.find(criteria)
            .sort("updated_at", -1)
            .skip(skip)
            .limit(page_size)
        )
        items = list(cursor)
        total = self.collection.count_documents(criteria)
        return items, total

    def update_item(self, item_id: str, updates: dict):
        updates.pop('_id', None)
        updates['updated_at'] = datetime.utcnow()
        try:
            result = self.collection.update_one({"_id": ObjectId(item_id)}, {"$set": updates})
            return result.modified_count > 0
        except Exception:
            return False

    def delete_item(self, item_id: str):
        try:
            result = self.collection.delete_one({"_id": ObjectId(item_id)})
            return result.deleted_count > 0
        except Exception:
            return False

    def to_dict(self, item):
        if item and '_id' in item:
            item['id'] = str(item['_id'])
            del item['_id']
        if 'created_at' in item and isinstance(item['created_at'], datetime):
            item['created_at'] = item['created_at'].isoformat()
        if 'updated_at' in item and isinstance(item['updated_at'], datetime):
            item['updated_at'] = item['updated_at'].isoformat()
        return item


class UserModel:
    def __init__(self, mongo_collection, bcrypt):
        self.collection = mongo_collection
        self.bcrypt = bcrypt

    def create_user(self, username: str, password: str, role: str = "viewer", email: Optional[str] = None, email_verified: bool = False) -> Optional[dict]:
        if self.collection.find_one({"username": username}):
            return None
        password_hash = self.bcrypt.generate_password_hash(password).decode("utf-8")
        user_doc = {
            "username": username,
            "password_hash": password_hash,
            "role": role,
            "email": email,
            "email_verified": email_verified,
            "created_at": datetime.utcnow(),
            "failed_login_attempts": 0,
            "locked_until": None,
        }
        result = self.collection.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        return user_doc

    def create_user_from_google(self, google_id: str, email: str, name: Optional[str] = None, role: str = "viewer") -> dict:
        user_doc = {
            "username": name or email,
            "google_id": google_id,
            "email": email,
            "email_verified": True,
            "role": role,
            "created_at": datetime.utcnow(),
            "failed_login_attempts": 0,
            "locked_until": None,
        }
        result = self.collection.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        return user_doc

    def get_user_by_username(self, username: str) -> Optional[dict]:
        return self.collection.find_one({"username": username})

    def get_user_by_email(self, email: str) -> Optional[dict]:
        return self.collection.find_one({"email": email})

    def get_user_by_google_id(self, google_id: str) -> Optional[dict]:
        return self.collection.find_one({"google_id": google_id})

    def attach_google_id(self, user_id, google_id: str):
        return self.collection.update_one({"_id": user_id}, {"$set": {"google_id": google_id, "email_verified": True}})

    def set_email_verification_token(self, user_id, token: str):
        self.collection.update_one(
            {"_id": user_id},
            {
                "$set": {
                    "email_verification_token": token,
                    "email_verified": False,
                    "email_verification_created_at": datetime.utcnow(),
                }
            },
        )

    def verify_email_token(self, token: str) -> bool:
        doc = self.collection.find_one({"email_verification_token": token})
        if not doc:
            return False
        self.collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {"email_verified": True}, "$unset": {"email_verification_token": "", "email_verification_created_at": ""}},
        )
        return True

    def verify_user(self, username: str, password: str) -> Optional[dict]:
        user = self.get_user_by_username(username)
        if not user:
            return None

        stored_hash = user.get("password_hash", "")
        if not stored_hash:
            return None

        # Check for old werkzeug hash and migrate if it matches
        if stored_hash.startswith("pbkdf2:"):
            if werkzeug_check(stored_hash, password):
                # Password is correct, re-hash with bcrypt and update
                new_hash = self.bcrypt.generate_password_hash(password).decode("utf-8")
                self.collection.update_one({"_id": user["_id"]}, {"$set": {"password_hash": new_hash}})
                self.unlock_user(user["_id"])
                return user
            self.record_failed_login(user["_id"])
            return None  # Old hash, wrong password

        # Assume bcrypt, check password
        if self.bcrypt.check_password_hash(stored_hash, password):
            self.unlock_user(user["_id"])
            return user
        
        self.record_failed_login(user["_id"])
        return None

    def record_failed_login(self, user_id: ObjectId):
        self.collection.update_one({"_id": user_id}, {"$inc": {"failed_login_attempts": 1}})

    def lock_user(self, user_id: ObjectId, duration_minutes: int = 15):
        lock_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.collection.update_one(
            {"_id": user_id},
            {"$set": {"locked_until": lock_until, "failed_login_attempts": 0}}
        )

    def unlock_user(self, user_id: ObjectId):
        self.collection.update_one(
            {"_id": user_id},
            {"$set": {"failed_login_attempts": 0, "locked_until": None}}
        )

    def is_locked(self, user_id: ObjectId) -> bool:
        user = self.collection.find_one({"_id": user_id})
        if not user or not user.get("locked_until"):
            return False
        return datetime.utcnow() < user["locked_until"]
