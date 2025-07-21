from flask import Blueprint, request, jsonify
from bson import ObjectId
from datetime import datetime
from pymongo import DESCENDING

notifications_bp = Blueprint('notifications', __name__)

# These will be injected from main app
users_collection = None
notifications_collection = None
user_notifications_collection = None

def init_notifications_module(users_col, notifications_col, user_notifications_col):
    global users_collection, notifications_collection, user_notifications_collection
    users_collection = users_col
    notifications_collection = notifications_col
    user_notifications_collection = user_notifications_col

# Utility: Find users based on audience
def build_notification_targets(audience_type, audience_value=None, nickname=None):
    if audience_type == "all":
        query = {}
    elif audience_type == "level":
        if not audience_value:
            raise ValueError("Level value is required")
        query = {"level": audience_value.upper()}
    elif audience_type == "department":
        if not audience_value:
            raise ValueError("Department value is required")
        query = {"department": audience_value.upper()}
    elif audience_type == "user":
        if not nickname:
            raise ValueError("Nickname is required for user targeting")
        user = users_collection.find_one({"nickname": nickname})
        if not user:
            raise ValueError("Target user does not exist")
        return [user["_id"]]
    else:
        raise ValueError("Invalid audience_type")

    user_cursor = users_collection.find(query, {"_id": 1})
    return [user["_id"] for user in user_cursor]

# Create Notification
@notifications_bp.route('/api/notifications', methods=['POST'])
def create_notification():
    try:
        data = request.get_json()
        audience_type = data.get('audience_type')
        audience_value = data.get('audience_value')  # level, department, etc
        nickname = data.get('nickname')              # for user targeting
        title = data.get('title')
        message = data.get('message')
        popup = data.get('popup', False)

        if not all([audience_type, title, message]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400

        try:
            target_user_ids = build_notification_targets(audience_type, audience_value, nickname)
        except ValueError as ve:
            return jsonify({'success': False, 'error': str(ve)}), 400

        notif = {
            'title': title.strip(),
            'message': message.strip(),
            'popup': popup,
            'audience_type': audience_type,
            'audience_value': nickname if audience_type == "user" else audience_value,
            'created_at': datetime.utcnow()
        }

        notif_id = notifications_collection.insert_one(notif).inserted_id

        bulk_entries = [
            {
                'notification_id': notif_id,
                'user_id': user_id,
                'read': False,
                'dismissed': False,
                'created_at': datetime.utcnow()
            } for user_id in target_user_ids
        ]

        if bulk_entries:
            user_notifications_collection.insert_many(bulk_entries)

        return jsonify({'success': True, 'message': 'Notification created'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Get Notifications for a User
@notifications_bp.route('/api/notifications', methods=['GET'])
def get_user_notifications():
    try:
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'error': 'Missing user_id'}), 400

        try:
            user_id = ObjectId(user_id)
        except:
            return jsonify({'success': False, 'error': 'Invalid user_id'}), 400

        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        skip = (page - 1) * limit

        pipeline = [
            {"$match": {"user_id": user_id}},
            {"$sort": {"created_at": DESCENDING}},
            {"$skip": skip},
            {"$limit": limit},
            {
                "$lookup": {
                    "from": "notifications",
                    "localField": "notification_id",
                    "foreignField": "_id",
                    "as": "notification"
                }
            },
            {"$unwind": "$notification"},
            {
                "$project": {
                    "_id": 1,
                    "read": 1,
                    "dismissed": 1,
                    "notification._id": 1,
                    "notification.title": 1,
                    "notification.message": 1,
                    "notification.popup": 1,
                    "notification.created_at": 1
                }
            }
        ]

        notifications = list(user_notifications_collection.aggregate(pipeline))

        for n in notifications:
            n["_id"] = str(n["_id"])
            n["notification"]["_id"] = str(n["notification"]["_id"])
            n["notification"]["created_at"] = n["notification"]["created_at"].isoformat()

        return jsonify({'success': True, 'notifications': notifications})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Mark Notification as Read
@notifications_bp.route('/api/notifications/<notif_id>/read', methods=['POST'])
def mark_notification_as_read(notif_id):
    try:
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'error': 'Missing user_id'}), 400

        result = user_notifications_collection.update_one(
            {"_id": ObjectId(notif_id), "user_id": ObjectId(user_id)},
            {"$set": {"read": True}}
        )
        return jsonify({'success': True, 'updated': result.modified_count > 0})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Dismiss Popup
@notifications_bp.route('/api/notifications/<notif_id>/dismiss', methods=['POST'])
def dismiss_notification(notif_id):
    try:
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'error': 'Missing user_id'}), 400

        result = user_notifications_collection.update_one(
            {"_id": ObjectId(notif_id), "user_id": ObjectId(user_id)},
            {"$set": {"dismissed": True}}
        )
        return jsonify({'success': True, 'updated': result.modified_count > 0})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Admin: List All Notifications
@notifications_bp.route('/api/admin/notifications', methods=['GET'])
def admin_get_notifications():
    try:
        audience_type = request.args.get('audience_type')
        audience_value = request.args.get('audience_value')

        query = {}
        if audience_type:
            query['audience_type'] = audience_type
        if audience_value:
            query['audience_value'] = audience_value

        notifications = list(notifications_collection.find(query).sort("created_at", DESCENDING))
        for notif in notifications:
            notif['_id'] = str(notif['_id'])
            notif['created_at'] = notif['created_at'].isoformat()

        return jsonify({'success': True, 'notifications': notifications})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Admin: Delete a Notification
@notifications_bp.route('/api/admin/notifications/<notif_id>', methods=['DELETE'])
def delete_notification(notif_id):
    try:
        notif_id = ObjectId(notif_id)
        notifications_collection.delete_one({'_id': notif_id})
        user_notifications_collection.delete_many({'notification_id': notif_id})
        return jsonify({'success': True, 'message': 'Deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Admin: Search Users
@notifications_bp.route('/api/admin/search-users', methods=['GET'])
def search_users():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'success': False, 'error': 'Missing query'}), 400

    users = list(users_collection.find({
        "$or": [
            {"nickname": {"$regex": q, "$options": "i"}},
            {"department": {"$regex": q, "$options": "i"}}
        ]
    }, {"_id": 1, "nickname": 1, "department": 1}).limit(10))

    for u in users:
        u["_id"] = str(u["_id"])
    return jsonify({"success": True, "users": users})
