import json
import boto3
import base64
from datetime import datetime, timedelta
import uuid
import hashlib
import urllib.request
import urllib.parse
import re

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
s3_client = boto3.client('s3', region_name='us-east-1')
bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')
cloudwatch = boto3.client('cloudwatch', region_name='us-east-1')

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_image_base64(image_base64, max_size_mb=10):
    if not image_base64:
        return False, "No image provided"
    size_bytes = len(image_base64) * 0.75
    size_mb = size_bytes / (1024 * 1024)
    if size_mb > max_size_mb:
        return False, f"Image too large: {size_mb:.1f}MB (max {max_size_mb}MB)"
    return True, None

def validate_question(question, max_length=500):
    if not question or len(question) > max_length:
        return False, f"Question must be 1-{max_length} characters"
    return True, None

def put_metric(metric_name, value, unit='Count'):
    try:
        cloudwatch.put_metric_data(
            Namespace='FoodIdentifier',
            MetricData=[{
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit,
                'Timestamp': datetime.utcnow()
            }]
        )
    except Exception as e:
        print(f"Failed to put metric: {str(e)}")

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
    elif action == 'ask_ai':
        return ask_ai(body)
    elif action == 'change_password':
        return change_password(body)
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
        
        if not validate_email(email):
            put_metric('ValidationError', 1)
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
        
        put_metric('UserCreated', 1)
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
        
        put_metric('UserLogin', 1)
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
        
        is_valid, error_msg = validate_image_base64(image_base64, max_size_mb=10)
        if not is_valid:
            put_metric('ValidationError', 1)
            return error_response(400, error_msg)
        
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
        
        put_metric('PhotoAnalyzed', 1)
        put_metric('BedrockTokensUsed', result.get('usage', {}).get('output_tokens', 0))
        
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

def ask_ai(body):
    """Answer questions about nutrition, meals, and health goals"""
    print(f"DEBUG: ask_ai called with question: {body.get('question')}")
    try:
        question = body.get('question', '')
        user_id = body.get('userId', 'anonymous')
        nutrition = body.get('nutrition', {})
        goals = body.get('goals', {})
        context = body.get('context', '')
        dish_name = body.get('dish_name', '')
        
        is_valid, error_msg = validate_question(question, max_length=500)
        if not is_valid:
            put_metric('ValidationError', 1)
            return error_response(400, error_msg)
        
        system_prompt = """You are a casual friend, not an AI.
Respond VERY SHORT:
- Greeting: 1 sentence max. Just say hi back.
- Short question: 1-2 sentences, direct answer
- Medium question: 2-3 sentences max
- Long question: 3-4 sentences max
Never suggest features, tracking, or goals. No lists or bullets. Sound human."""
        
        is_greeting = question.lower() in ['hello', 'hi', 'hey', 'what\'s up', 'sup', 'yo', 'nice', 'good', 'thanks', 'cool', 'lol', 'ok', 'kk']
        is_short = len(question) < 20
        is_medium = len(question) < 50
        
        if is_greeting:
            max_tokens = 40
        elif is_short:
            max_tokens = 80
        elif is_medium:
            max_tokens = 150
        else:
            max_tokens = 250
        
        # Get conversation history
        conversation_history = []
        try:
            response = dynamodb.Table('conversations').query(
                KeyConditionExpression='userId = :uid',
                ExpressionAttributeValues={':uid': user_id},
                ScanIndexForward=True,  # oldest first (chronological)
                Limit=20  # last 20 messages
            )
            conversation_history = response.get('Items', [])
        except Exception as e:
            print(f"DEBUG: Could not fetch conversation history: {str(e)}")
        
        # Build messages array with history
        messages = []
        
        # Add previous conversation
        for msg in conversation_history:
            if msg.get('role') == 'user':
                messages.append({'role': 'user', 'content': msg.get('content', '')})
            elif msg.get('role') == 'assistant':
                messages.append({'role': 'assistant', 'content': msg.get('content', '')})
        
        # Build current prompt based on context
        if nutrition and goals:
            # AI Coach mode - nutrition focused
            nutrition_info = f"Current nutrition: Calories: {nutrition.get('calories', 0)}, Protein: {nutrition.get('protein', 0)}g, Carbs: {nutrition.get('carbs', 0)}g, Fat: {nutrition.get('fat', 0)}g, Fiber: {nutrition.get('fiber', 0)}g"
            goals_info = f"Daily goals: Calories: {goals.get('calories', 2000)}, Protein: {goals.get('protein', 50)}g, Carbs: {goals.get('carbs', 250)}g, Fiber: {goals.get('fiber', 25)}g"
            prompt = f"{nutrition_info}\n{goals_info}\n\nUser question: {question}\n\nProvide helpful, personalized nutrition advice."
        elif dish_name:
            # Meal analysis mode
            nutrition_info = f"Nutrition info - Calories: {nutrition.get('calories', 0)}, Protein: {nutrition.get('protein', 0)}g, Carbs: {nutrition.get('carbs', 0)}g, Fat: {nutrition.get('fat', 0)}g"
            prompt = f"The user is asking about a meal: {dish_name}. {nutrition_info}. Their question: {question}. Provide a helpful, concise answer."
        else:
            # General question
            prompt = question
        
        # Add current message
        messages.append({'role': 'user', 'content': prompt})
        
        print(f"DEBUG: Built prompt with {len(messages)} total messages (including history)...")
        
        req_body = json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': max_tokens,
            'system': system_prompt,
            'messages': messages
        })
        
        print(f"DEBUG: Calling bedrock with max_tokens={max_tokens}...")
        response = bedrock.invoke_model(
            modelId='us.anthropic.claude-3-5-sonnet-20240620-v1:0',
            body=req_body,
            contentType='application/json',
            accept='application/json'
        )
        
        result = json.loads(response['body'].read().decode())
        ai_response = result['content'][0]['text']
        
        put_metric('AICoachQuery', 1)
        put_metric('BedrockTokensUsed', result.get('usage', {}).get('output_tokens', 0))
        
        # Save conversation to history
        try:
            conversations_table = dynamodb.Table('conversations')
            timestamp_user = datetime.utcnow().isoformat()
            timestamp_assistant = (datetime.utcnow().timestamp() + 0.001)
            expiry_time = int((datetime.utcnow() + timedelta(days=90)).timestamp())
            
            # Save user message
            conversations_table.put_item(Item={
                'userId': user_id,
                'timestamp': timestamp_user,
                'role': 'user',
                'content': question,
                'expiryTime': expiry_time
            })
            
            # Save assistant response
            conversations_table.put_item(Item={
                'userId': user_id,
                'timestamp': datetime.fromtimestamp(timestamp_assistant).isoformat(),
                'role': 'assistant',
                'content': ai_response,
                'expiryTime': expiry_time
            })
        except Exception as e:
            print(f"DEBUG: Could not save conversation history: {str(e)}")
        
        print(f"DEBUG: Got AI response: {ai_response[:100]}...")
        return success_response({'response': ai_response})
    except Exception as e:
        print(f"Error in ask_ai: {str(e)}")
        import traceback
        traceback.print_exc()
        return error_response(500, f"Error: {str(e)}")

def change_password(body):
    """Change user password for email-based accounts"""
    try:
        email = body.get('email')
        current_password = body.get('current_password')
        new_password = body.get('new_password')
        
        if not email or not current_password or not new_password:
            return error_response(400, 'Missing required fields')
        
        # Hash passwords
        current_hash = hashlib.sha256(current_password.encode()).hexdigest()
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        # Get user
        user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
        response = users_table.get_item(Key={'userId': user_id})
        
        if 'Item' not in response:
            return error_response(404, 'User not found')
        
        user = response['Item']
        
        # Check if user has password (email auth)
        if 'password_hash' not in user:
            return error_response(400, 'This account uses Google authentication. Password change not available.')
        
        # Verify current password
        if user['password_hash'] != current_hash:
            return error_response(401, 'Current password is incorrect')
        
        # Update password
        users_table.update_item(
            Key={'userId': user_id},
            UpdateExpression='SET password_hash = :new_hash, updated_at = :now',
            ExpressionAttributeValues={
                ':new_hash': new_hash,
                ':now': datetime.utcnow().isoformat()
            }
        )
        
        return success_response({'success': True, 'message': 'Password changed successfully'})
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
    print(f"DEBUG: success_response called with data: {data}")
    response = {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'
        },
        'body': json.dumps(data)
    }
    print(f"DEBUG: returning response with headers: {response['headers']}")
    return response

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