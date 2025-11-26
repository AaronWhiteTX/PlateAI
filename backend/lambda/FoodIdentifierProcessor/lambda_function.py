import json
import boto3
import base64
from datetime import datetime
import uuid
import hashlib
import urllib.request
import urllib.parse

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
s3_client = boto3.client('s3', region_name='us-east-1')
bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

table = dynamodb.Table('meals')
users_table = dynamodb.Table('users')
bucket = 'foodidentifier-730980070158-photos'
GOOGLE_CLIENT_ID = '763043938348-grfgm9oj02f2147ea2cmnd3q5qo243dv.apps.googleusercontent.com'

def lambda_handler(event, context):
    # Handle both direct invocation and API Gateway proxy
    if isinstance(event.get('body'), str):
        body = json.loads(event['body'])
    else:
        body = event
    
    action = body.get('action')
    
    if action == 'google_auth':
        return google_auth(body)
    elif action == 'create_user':
        return create_user(body)
    elif action == 'verify_user':
        return verify_user(body)
    elif action == 'analyze_food_photo':
        return analyze_food_photo(body)
    elif action == 'get_recipe':
        return get_recipe(body)
    elif action == 'save_meal':
        return save_meal(body)
    elif action == 'get_meals':
        return get_meals(body)
    else:
        return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid action'})}

def google_auth(body):
    """Validate Google token and create/retrieve user"""
    try:
        google_token = body.get('google_token')
        if not google_token:
            return error_response(400, 'No token provided')
        
        # Verify token with Google
        try:
            url = 'https://oauth2.googleapis.com/tokeninfo'
            params = urllib.parse.urlencode({'id_token': google_token})
            full_url = f"{url}?{params}"
            
            with urllib.request.urlopen(full_url) as response:
                token_data = json.loads(response.read().decode())
            
            email = token_data.get('email')
            name = token_data.get('name', email.split('@')[0])
            
        except Exception as e:
            return error_response(401, f'Token validation failed: {str(e)}')
        
        # Check if user exists
        user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
        
        try:
            response = users_table.get_item(Key={'userId': user_id})
            user = response.get('Item')
        except:
            user = None
        
        if not user:
            # Create new user
            user_data = {
                'userId': user_id,
                'email': email,
                'name': name,
                'auth_method': 'google',
                'created_at': datetime.utcnow().isoformat(),
                'last_login': datetime.utcnow().isoformat()
            }
            users_table.put_item(Item=user_data)
        else:
            # Update last login
            users_table.update_item(
                Key={'userId': user_id},
                UpdateExpression='SET last_login = :now',
                ExpressionAttributeValues={':now': datetime.utcnow().isoformat()}
            )
        
        return success_response({
            'success': True,
            'user_id': user_id,
            'email': email,
            'name': name
        })
    
    except Exception as e:
        return error_response(500, f'Google auth failed: {str(e)}')

def create_user(body):
    """Create user with email and password"""
    try:
        email = body.get('email', '').strip()
        password = body.get('password', '')
        
        if not email or not password:
            return error_response(400, 'Email and password required')
        
        if len(password) < 6:
            return error_response(400, 'Password must be at least 6 characters')
        
        if '@' not in email:
            return error_response(400, 'Invalid email format')
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
        
        # Check if user already exists
        try:
            response = users_table.get_item(Key={'userId': user_id})
            if 'Item' in response:
                return error_response(409, 'Email already registered')
        except:
            pass
        
        # Create user
        user_data = {
            'userId': user_id,
            'email': email,
            'password_hash': password_hash,
            'auth_method': 'email',
            'created_at': datetime.utcnow().isoformat(),
            'last_login': datetime.utcnow().isoformat()
        }
        users_table.put_item(Item=user_data)
        
        return success_response({
            'success': True,
            'user_id': user_id,
            'email': email,
            'message': 'Account created'
        })
    
    except Exception as e:
        return error_response(500, f'Sign up failed: {str(e)}')

def verify_user(body):
    """Verify email/password and return user"""
    try:
        email = body.get('email', '').strip()
        password = body.get('password', '')
        
        if not email or not password:
            return error_response(400, 'Email and password required')
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
        
        # Get user from DynamoDB
        try:
            response = users_table.get_item(Key={'userId': user_id})
            user = response.get('Item')
        except:
            user = None
        
        if not user:
            return error_response(401, 'Invalid email or password')
        
        # Verify password
        if user.get('password_hash') != password_hash:
            return error_response(401, 'Invalid email or password')
        
        # Update last login
        users_table.update_item(
            Key={'userId': user_id},
            UpdateExpression='SET last_login = :now',
            ExpressionAttributeValues={':now': datetime.utcnow().isoformat()}
        )
        
        return success_response({
            'success': True,
            'user_id': user_id,
            'email': email,
            'message': 'Signed in'
        })
    
    except Exception as e:
        return error_response(500, f'Sign in failed: {str(e)}')

def analyze_food_photo(body):
    try:
        image_base64 = body.get('image_base64')
        user_id = body.get('userId', 'anonymous')
        
        if not image_base64:
            return error_response(400, 'No image provided')
        
        req_body = json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 500,
            'messages': [
                {
                    'role': 'user',
                    'content': [
                        {
                            'type': 'image',
                            'source': {
                                'type': 'base64',
                                'media_type': 'image/jpeg',
                                'data': image_base64
                            }
                        },
                        {
                            'type': 'text',
                            'text': '''Analyze this food photo. Respond ONLY with valid JSON:
{
  "dish_name": "name",
  "confidence": 0.95,
  "ingredients": ["item1", "item2"],
  "estimated_portion_grams": 200,
  "calories": 350,
  "protein_g": 25,
  "carbs_g": 40,
  "fat_g": 12
}'''
                        }
                    ]
                }
            ]
        })
        
        response = bedrock.invoke_model(
            modelId='us.anthropic.claude-3-5-sonnet-20240620-v1:0',
            body=req_body,
            contentType='application/json',
            accept='application/json'
        )
        
        result = json.loads(response['body'].read().decode())
        analysis_text = result['content'][0]['text']
        analysis = json.loads(analysis_text)
        
        return success_response(analysis)
    except Exception as e:
        return error_response(500, str(e))

def get_recipe(body):
    try:
        dish_name = body.get('dish_name')
        dietary_restriction = body.get('dietary_restriction', '')
        
        prompt = f"Generate a detailed recipe for {dish_name}. {dietary_restriction} Respond in JSON with: ingredients (list), steps (list), cook_time_minutes, difficulty."
        
        req_body = json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 1000,
            'messages': [{'role': 'user', 'content': prompt}]
        })
        
        response = bedrock.invoke_model(
            modelId='us.anthropic.claude-3-5-sonnet-20240620-v1:0',
            body=req_body,
            contentType='application/json',
            accept='application/json'
        )
        
        result = json.loads(response['body'].read().decode())
        
        return success_response({'recipe': result['content'][0]['text']})
    except Exception as e:
        return error_response(500, str(e))

def save_meal(body):
    try:
        user_id = body.get('userId', 'anonymous')
        meal_id = str(uuid.uuid4())
        
        meal_data = {
            'userId': user_id,
            'mealId': meal_id,
            'timestamp': datetime.utcnow().isoformat(),
            'dish_name': body.get('dish_name'),
            'calories': body.get('calories'),
            'protein_g': body.get('protein_g'),
            'carbs_g': body.get('carbs_g'),
            'fat_g': body.get('fat_g'),
            'photo_url': body.get('photo_url', ''),
            'notes': body.get('notes', '')
        }
        
        table.put_item(Item=meal_data)
        
        return success_response({'mealId': meal_id, 'message': 'Meal saved'})
    except Exception as e:
        return error_response(500, str(e))

def get_meals(body):
    try:
        user_id = body.get('userId', 'anonymous')
        
        response = table.query(
            KeyConditionExpression='userId = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )
        
        return success_response({'meals': response.get('Items', [])})
    except Exception as e:
        return error_response(500, str(e))

def success_response(data):
    """Format successful API response with CORS headers"""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'
        },
        'body': json.dumps(data)
    }

def error_response(status_code, message):
    """Format error API response with CORS headers"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'
        },
        'body': json.dumps({'success': False, 'message': message})
    }
