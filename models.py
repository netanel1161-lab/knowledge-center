# models.py
from datetime import datetime
from typing import Optional

from bson.objectid import ObjectId  # For MongoDB ObjectId
from werkzeug.security import check_password_hash, generate_password_hash

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
            # MongoDB uses ObjectId for _id field
            return self.collection.find_one({"_id": ObjectId(item_id)})
        except Exception:
            # If item_id is not a valid ObjectId string
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
        # Remove _id from updates if present, as _id is immutable
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
        # Helper to convert MongoDB item (with ObjectId) to a JSON-serializable dict
        if item and '_id' in item:
            item['id'] = str(item['_id'])
            del item['_id']
        if 'created_at' in item and isinstance(item['created_at'], datetime):
            item['created_at'] = item['created_at'].isoformat()
        if 'updated_at' in item and isinstance(item['updated_at'], datetime):
            item['updated_at'] = item['updated_at'].isoformat()
        return item


class UserModel:
    def __init__(self, mongo_collection):
        self.collection = mongo_collection

    def create_user(self, username: str, password: str, role: str = "viewer") -> Optional[dict]:
        if self.collection.find_one({"username": username}):
            return None
        user_doc = {
            "username": username,
            "password_hash": generate_password_hash(password),
            "role": role,
            "created_at": datetime.utcnow(),
        }
        result = self.collection.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        return user_doc

    def get_user_by_username(self, username: str) -> Optional[dict]:
        return self.collection.find_one({"username": username})

    def verify_user(self, username: str, password: str) -> Optional[dict]:
        user = self.get_user_by_username(username)
        if not user:
            return None
        if not check_password_hash(user.get("password_hash", ""), password):
            return None
        return user
