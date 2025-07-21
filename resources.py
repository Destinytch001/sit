import datetime
from flask import Blueprint, request, jsonify, send_file
from bson import ObjectId
from pymongo import DESCENDING
import cloudinary
import cloudinary.uploader
import requests
from io import BytesIO
import os
from werkzeug.utils import secure_filename
from extensions import db

resources_bp = Blueprint('resources_bp', __name__, url_prefix='/api/resources')
resources_collection = db.resources

# Cloudinary config (⚠️ Use environment variables in production)
cloudinary.config(
    cloud_name="dhndd1msa",
    api_key="337382597786761",
    api_secret="bEJ0sWFZi8yYzeP5lzVl_rmUtX8"
)

# Helper to serialize MongoDB _id
def serialize_resource(res):
    res['_id'] = str(res['_id'])
    return res

def get_file_extension(file_type):
    """Map file type to extension"""
    file_type = file_type.lower()
    if file_type == 'pdf':
        return '.pdf'
    elif file_type == 'doc':
        return '.doc'
    elif file_type == 'mp3':
        return '.mp3'
    elif file_type == 'mp4':
        return '.mp4'
    elif file_type == 'img':
        return '.jpg'  # Default to jpg for images
    return ''

def download_and_convert(url, original_filename, file_type):
    """Download file from Cloudinary and return as proper file type"""
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        # Create a file-like object from the response content
        file_data = BytesIO(response.content)
        
        # Generate a secure filename with proper extension
        filename = secure_filename(original_filename)
        base, ext = os.path.splitext(filename)
        if not ext or ext.lower() != get_file_extension(file_type):
            ext = get_file_extension(file_type)
            filename = f"{base}{ext}"
            
        return file_data, filename
    except Exception as e:
        print(f"Download error: {e}")
        raise

# -----------------------------
# ✅ Upload New Resource (with file)
# -----------------------------
@resources_bp.route('/upload', methods=['POST'])
def upload_resource():
    try:
        # Validate required fields
        required_fields = ['title', 'level', 'department', 'category', 'file_type']
        form_data = {field: request.form.get(field) for field in required_fields}
        file = request.files.get('file')
        
        if None in form_data.values() or not file:
            return jsonify(success=False, error="All fields are required"), 400

        # Upload to Cloudinary
        upload_result = cloudinary.uploader.upload(
            file,
            resource_type="auto",
            folder="naits_resources",
            use_filename=True,
            unique_filename=False
        )

        if not upload_result.get("secure_url"):
            return jsonify(success=False, error="Cloudinary upload failed"), 500

        # Create resource document
        new_resource = {
            'title': form_data['title'],
            'file_url': upload_result["secure_url"],
            'file_type': form_data['file_type'].lower(),
            'level': form_data['level'],
            'department': form_data['department'],
            'category': form_data['category'],
            'created_at': datetime.datetime.utcnow(),
            'cloudinary_public_id': upload_result.get('public_id'),
            'original_filename': secure_filename(file.filename)
        }

        # Insert into database
        inserted = resources_collection.insert_one(new_resource)
        new_resource['_id'] = str(inserted.inserted_id)

        return jsonify(success=True, resource=new_resource), 201

    except Exception as e:
        print(f"Upload Error: {e}")
        return jsonify(success=False, error="Something went wrong during upload"), 500

# -----------------------------
# ✅ Download Resource (with proper file type)
# -----------------------------
@resources_bp.route('/download/<resource_id>', methods=['GET'])
def download_resource(resource_id):
    try:
        resource = resources_collection.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            return jsonify(success=False, error='Resource not found'), 404

        # Download and convert the file
        file_data, filename = download_and_convert(
            resource['file_url'],
            resource.get('original_filename', resource['title']),
            resource['file_type']
        )

        # Send the file with proper headers
        return send_file(
            file_data,
            as_attachment=True,
            download_name=filename,
            mimetype=f"application/{resource['file_type']}"
        )

    except Exception as e:
        print(f"Download Error: {e}")
        return jsonify(success=False, error="Failed to download resource"), 500

# -----------------------------
# ✅ Get Resources for User (filtered)
# -----------------------------
@resources_bp.route('/user', methods=['GET'])
def get_user_resources():
    try:
        # Validate required parameters
        department = request.args.get('department')
        level = request.args.get('level')
        if not department or not level:
            return jsonify(success=False, error="Department and level are required"), 400

        # Build query
        query = {
            'department': department,
            'level': level
        }
        
        # Optional filters
        if request.args.get('category'):
            query['category'] = request.args.get('category')
        
        # Pagination
        page = max(1, int(request.args.get('page', 1)))
        limit = max(1, min(50, int(request.args.get('limit', 10))))
        skip = (page - 1) * limit

        # Query database
        cursor = resources_collection.find(query)\
            .sort('created_at', DESCENDING)\
            .skip(skip).limit(limit)

        resources = [serialize_resource(r) for r in cursor]
        return jsonify(success=True, resources=resources), 200

    except Exception as e:
        print(f"User Resource Error: {e}")
        return jsonify(success=False, error="Failed to fetch user resources"), 500

# -----------------------------
# ✅ Admin: Get All Resources (with filters + search)
# -----------------------------
@resources_bp.route('/', methods=['GET'])
def get_all_resources():
    try:
        query = {}
        
        # Add filters
        for key in ['department', 'level', 'category', 'file_type']:
            if value := request.args.get(key):
                query[key] = value
        
        # Add search
        if title := request.args.get('title'):
            query['title'] = {'$regex': title, '$options': 'i'}
        
        # Pagination
        page = max(1, int(request.args.get('page', 1)))
        limit = max(1, min(100, int(request.args.get('limit', 20))))
        skip = (page - 1) * limit

        # Query database
        cursor = resources_collection.find(query)\
            .sort('created_at', DESCENDING)\
            .skip(skip).limit(limit)
        
        resources = [serialize_resource(r) for r in cursor]
        return jsonify(success=True, resources=resources), 200

    except Exception as e:
        print(f"Get All Error: {e}")
        return jsonify(success=False, error="Failed to load resources"), 500

# -----------------------------
# ✅ Get Single Resource
# -----------------------------
@resources_bp.route('/<resource_id>', methods=['GET'])
def get_single_resource(resource_id):
    try:
        resource = resources_collection.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            return jsonify(success=False, error='Resource not found'), 404
        return jsonify(success=True, resource=serialize_resource(resource)), 200
    except Exception as e:
        print(f"Get Single Error: {e}")
        return jsonify(success=False, error='Invalid resource ID'), 400

# -----------------------------
# ✅ Update Resource (with optional file re-upload)
# -----------------------------
@resources_bp.route('/<resource_id>', methods=['PUT'])
def update_resource(resource_id):
    try:
        # Get existing resource
        resource = resources_collection.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            return jsonify(success=False, error="Resource not found"), 404

        # Prepare update data
        update_data = {}
        for key in ['title', 'category', 'level', 'department', 'file_type']:
            if value := request.form.get(key):
                update_data[key] = value

        # Handle file update if provided
        file = request.files.get('file')
        if file:
            # Delete old Cloudinary file
            if resource.get('cloudinary_public_id'):
                cloudinary.uploader.destroy(resource['cloudinary_public_id'], invalidate=True)

            # Upload new file
            upload_result = cloudinary.uploader.upload(
                file,
                resource_type="auto",
                folder="naits_resources",
                use_filename=True,
                unique_filename=False
            )
            
            update_data.update({
                'file_url': upload_result.get('secure_url'),
                'cloudinary_public_id': upload_result.get('public_id'),
                'original_filename': secure_filename(file.filename),
                'file_type': request.form.get('file_type', resource['file_type'])
            })

        # Update database
        resources_collection.update_one(
            {'_id': ObjectId(resource_id)},
            {'$set': update_data}
        )
        
        # Return updated resource
        updated = resources_collection.find_one({'_id': ObjectId(resource_id)})
        return jsonify(success=True, resource=serialize_resource(updated)), 200

    except Exception as e:
        print(f"Update Error: {e}")
        return jsonify(success=False, error="Failed to update resource"), 500

# -----------------------------
# ✅ Delete Resource (and Cloudinary file)
# -----------------------------
@resources_bp.route('/<resource_id>', methods=['DELETE'])
def delete_resource(resource_id):
    try:
        resource = resources_collection.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            return jsonify(success=False, error="Resource not found"), 404

        # Delete file from Cloudinary
        if resource.get('cloudinary_public_id'):
            cloudinary.uploader.destroy(resource['cloudinary_public_id'], invalidate=True)

        # Delete from database
        resources_collection.delete_one({'_id': ObjectId(resource_id)})
        return jsonify(success=True, message='Resource deleted successfully'), 200

    except Exception as e:
        print(f"Delete Error: {e}")
        return jsonify(success=False, error="Failed to delete resource"), 500