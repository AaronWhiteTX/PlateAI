import json
import boto3
import base64
from datetime import datetime, timedelta
from decimal import Decimal
import uuid
import hashlib
import urllib.request
import urllib.parse
import re

# Custom JSON encoder for DynamoDB Decimal types
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

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

meals_table = dynamodb.Table('meals')
users_table = dynamodb.Table('users')
recipes_table = dynamodb.Table('recipes')
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
    elif action == 'correct_meal':
        return correct_meal(body)
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
    elif action == 'save_recipe':
        return save_recipe(body)
    elif action == 'get_recipes':
        return get_recipes(body)
    elif action == 'delete_recipe':
        return delete_recipe(body)
    elif action == 'delete_meal':
        return delete_meal(body)
    elif action == 'get_plan':
        return get_plan(body)
    elif action == 'save_plan':
        return save_plan(body)
    elif action == 'initialize_user':
        return initialize_user(body)
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
            # Create new user and initialize with example recipe
            user_data = {
                'userId': user_id,
                'email': email,
                'name': name,
                'auth_method': 'google',
                'created_at': datetime.utcnow().isoformat(),
                'last_login': datetime.utcnow().isoformat()
            }
            users_table.put_item(Item=user_data)
            
            # Initialize with pecan pie example in recipe history
            initialize_user({'userId': user_id})
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
        
        # Initialize with pecan pie example in recipe history
        initialize_user({'userId': user_id})
        
        put_metric('UserCreated', 1)
        return success_response({
            'success': True,
            'user_id': user_id,
            'email': email,
            'message': 'Account created'
        })
    
    except Exception as e:
        return error_response(500, f'Sign up failed: {str(e)}')

def initialize_user(body):
    """Initialize new user with example recipe (pecan pie)"""
    try:
        user_id = body.get('userId')
        if not user_id:
            return error_response(400, 'userId required')
        
        # Add pecan pie example to recipe history
        pecan_pie_recipe = {
            'userId': user_id,
            'recipeId': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'title': 'Pecan Pie Slice',
            'type': 'healthy',
            'dish_name': 'Pecan Pie Slice',
            'content': '''Healthy Pecan Pie Slice Recipe

Ingredients per slice:
- Pecans: 1.5 oz (42g)
- Almond flour crust
- Natural sweetener (honey/maple syrup)
- Eggs or flax eggs
- Coconut oil
- Vanilla extract

Nutrition Facts (per slice):
- Calories: 450
- Protein: 5g
- Carbs: 45g
- Fat: 28g
- Fiber: 2g

Instructions:
1. Make a healthier crust using almond flour and coconut oil
2. Use natural sweeteners instead of refined sugar
3. Toast pecans for enhanced flavor
4. Bake at 350°F for 35-40 minutes
5. Let cool before slicing

Health Benefits:
- High in healthy fats from pecans and coconut oil
- Rich in vitamin E and antioxidants
- Good source of minerals like magnesium and zinc''',
            'calories': 450,
            'protein': 5,
            'carbs': 45,
            'fat': 28,
            'fiber': 2,
            'photo_url': 'https://foodidentifier-730980070158-photos.s3.amazonaws.com/example/pecan-pie.jpg',
            'source': 'Example Recipe',
            'created_at': datetime.utcnow().isoformat()
        }
        
        recipes_table.put_item(Item=pecan_pie_recipe)
        
        return success_response({
            'success': True,
            'message': 'User initialized with example recipe'
        })
    except Exception as e:
        return error_response(500, f'Initialization failed: {str(e)}')

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
        
        # Check password
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
            'name': user.get('name', email.split('@')[0])
        })
    
    except Exception as e:
        return error_response(500, f'Verification failed: {str(e)}')

def analyze_food_photo(body):
    try:
        image_base64 = body.get('image')
        user_id = body.get('userId', 'anonymous')
        
        is_valid, error_msg = validate_image_base64(image_base64)
        if not is_valid:
            return error_response(400, error_msg)
        
        # Remove data URL prefix if present
        if ',' in image_base64:
            image_base64 = image_base64.split(',')[1]
        
        # Upload photo to S3
        photo_key = f"meals/{user_id}/{uuid.uuid4()}.jpg"
        try:
            s3_client.put_object(
                Bucket=bucket,
                Key=photo_key,
                Body=base64.b64decode(image_base64),
                ContentType='image/jpeg'
            )
            photo_url = f"https://{bucket}.s3.amazonaws.com/{photo_key}"
        except Exception as s3_error:
            print(f"S3 upload warning: {str(s3_error)}")
            photo_url = ''
        
        # Call Claude Bedrock for food analysis
        req_body = json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 500,
            'messages': [{
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
                        'text': '''Analyze this food image and provide JSON with:
{
    "dish_name": "exact name",
    "confidence": 0.0-1.0,
    "calories": number,
    "protein_g": number,
    "carbs_g": number,
    "fat_g": number,
    "fiber_g": number,
    "ingredients": ["ingredient1", "ingredient2"],
    "notes": "any special notes about nutrition estimation"
}

Be specific about portion size visible in image. For pecan pie slice: typically 450 calories per slice.'''
                    }
                ]
            }]
        })
        
        response = bedrock.invoke_model(
            modelId='us.anthropic.claude-3-5-sonnet-20240620-v1:0',
            body=req_body,
            contentType='application/json',
            accept='application/json'
        )
        
        result = json.loads(response['body'].read().decode())
        analysis_text = result['content'][0]['text']
        
        # Parse JSON from response
        try:
            # Find JSON in the response
            json_start = analysis_text.find('{')
            json_end = analysis_text.rfind('}') + 1
            if json_start != -1 and json_end > json_start:
                analysis_json = json.loads(analysis_text[json_start:json_end])
            else:
                analysis_json = json.loads(analysis_text)
        except:
            analysis_json = {
                'dish_name': 'Unknown Dish',
                'confidence': 0.5,
                'calories': 0,
                'protein_g': 0,
                'carbs_g': 0,
                'fat_g': 0,
                'fiber_g': 0,
                'ingredients': [],
                'notes': 'Could not parse nutrition data'
            }
        
        # Add photo URL to response
        analysis_json['photo_url'] = photo_url
        
        put_metric('FoodAnalyzed', 1)
        put_metric('BedrockTokensUsed', result.get('usage', {}).get('output_tokens', 0))
        
        return success_response(analysis_json)
    except Exception as e:
        print(f"Error in analyze_food_photo: {str(e)}")
        return error_response(500, f"Analysis failed: {str(e)}")

def correct_meal(body):
    """Allow user to manually correct meal analysis"""
    try:
        user_id = body.get('userId')
        original_analysis = body.get('original_analysis')
        correction = body.get('correction')
        
        if not user_id or not original_analysis or not correction:
            return error_response(400, 'userId, original_analysis, and correction required')
        
        # Create corrected analysis by merging
        corrected_analysis = {
            'original_dish': original_analysis.get('dish_name'),
            'corrected_dish': correction.get('dish_name', original_analysis.get('dish_name')),
            'original_calories': original_analysis.get('calories'),
            'corrected_calories': correction.get('calories', original_analysis.get('calories')),
            'original_protein': original_analysis.get('protein_g'),
            'corrected_protein': correction.get('protein_g', original_analysis.get('protein_g')),
            'original_carbs': original_analysis.get('carbs_g'),
            'corrected_carbs': correction.get('carbs_g', original_analysis.get('carbs_g')),
            'original_fat': original_analysis.get('fat_g'),
            'corrected_fat': correction.get('fat_g', original_analysis.get('fat_g')),
            'timestamp': datetime.utcnow().isoformat(),
            'userId': user_id
        }
        
        return success_response({
            'success': True,
            'corrected_analysis': corrected_analysis,
            'message': 'Meal corrected successfully'
        })
    except Exception as e:
        return error_response(500, f'Correction failed: {str(e)}')

def get_recipe(body):
    try:
        dish_name = body.get('dish_name')
        dietary_restriction = body.get('dietary_restriction', '')
        
        if not dish_name:
            return error_response(400, 'dish_name required')
        
        prompt = f'''Generate a detailed recipe for {dish_name}.
        
Dietary restriction: {dietary_restriction}

Provide ONLY the recipe text, including:
1. Ingredients list with exact quantities
2. Step-by-step instructions
3. Final nutrition info (calories, protein, carbs, fat)

Format cleanly with line breaks.'''
        
        req_body = json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 600,
            'messages': [{
                'role': 'user',
                'content': prompt
            }]
        })
        
        response = bedrock.invoke_model(
            modelId='us.anthropic.claude-3-5-sonnet-20240620-v1:0',
            body=req_body,
            contentType='application/json',
            accept='application/json'
        )
        
        result = json.loads(response['body'].read().decode())
        recipe_text = result['content'][0]['text']
        
        put_metric('RecipeGenerated', 1)
        
        return success_response({'recipe': recipe_text})
    except Exception as e:
        print(f"Error in get_recipe: {str(e)}")
        return error_response(500, f"Recipe generation failed: {str(e)}")

def ask_ai(body):
    try:
        user_id = body.get('userId')
        question = body.get('question')
        nutrition = body.get('nutrition', {})
        goals = body.get('goals', {})
        dish_name = body.get('dish_name', '')
        saved_meals = body.get('saved_meals', [])
        recipe_history = body.get('recipe_history', [])
        
        is_valid, error_msg = validate_question(question)
        if not is_valid:
            return error_response(400, error_msg)
        
        # Build system prompt with context awareness
        context_prompt = ""
        if saved_meals:
            meals_list = ', '.join([f"{m.get('dish_name', 'Meal')} ({m.get('calories', 0)} cal)" for m in saved_meals[:5]])
            context_prompt += f"\nUser's saved meals: {meals_list}"
        
        if recipe_history:
            recipes_list = ', '.join([f"{r.get('title', 'Recipe')}" for r in recipe_history[:5]])
            context_prompt += f"\nUser's recipe history: {recipes_list}"
        
        system_prompt = f"""You are a knowledgeable nutrition AI Coach. You provide personalized nutrition advice based on user's dietary preferences, goals, and history.
        
You have access to:
- User's saved meals and their nutrition info
- User's recipe history
- User's daily nutrition goals

Be encouraging, specific, and evidence-based in your recommendations.{context_prompt}"""
        
        # Determine response length
        is_short = len(question) < 30
        is_medium = len(question) < 100
        
        if is_short:
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
                ScanIndexForward=True,
                Limit=20
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
    """Save analyzed meal to user's saved meals"""
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
            'fiber_g': body.get('fiber_g', 0),
            'photo_url': body.get('photo_url', ''),
            'notes': body.get('notes', '')
        }
        
        meals_table.put_item(Item=meal_data)
        
        return success_response({'mealId': meal_id, 'message': 'Meal saved'})
    except Exception as e:
        return error_response(500, str(e))

def get_meals(body):
    """Get all saved meals for user"""
    try:
        user_id = body.get('userId', 'anonymous')
        
        response = meals_table.query(
            KeyConditionExpression='userId = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )
        
        return success_response({'meals': response.get('Items', [])})
    except Exception as e:
        return error_response(500, str(e))

def save_recipe(body):
    """Save generated recipe to user's recipe history"""
    try:
        user_id = body.get('userId')
        if not user_id:
            return error_response(400, 'userId required')
        
        recipe_id = str(uuid.uuid4())
        recipe_data = {
            'userId': user_id,
            'recipeId': recipe_id,
            'timestamp': datetime.utcnow().isoformat(),
            'title': body.get('title'),
            'type': body.get('type'),
            'dish_name': body.get('dish_name'),
            'content': body.get('content'),
            'calories': body.get('calories'),
            'protein': body.get('protein'),
            'carbs': body.get('carbs'),
            'fat': body.get('fat'),
            'fiber': body.get('fiber', 0),
            'photo_url': body.get('photo_url', ''),
            'source': 'Generated Recipe'
        }
        
        recipes_table.put_item(Item=recipe_data)
        
        return success_response({'recipeId': recipe_id, 'message': 'Recipe saved to history'})
    except Exception as e:
        return error_response(500, str(e))

def get_recipes(body):
    """Get all recipes in user's recipe history"""
    try:
        user_id = body.get('userId')
        if not user_id:
            return error_response(400, 'userId required')
        
        response = recipes_table.query(
            KeyConditionExpression='userId = :uid',
            ExpressionAttributeValues={':uid': user_id},
            ScanIndexForward=False
        )
        
        return success_response({'recipes': response.get('Items', [])})
    except Exception as e:
        return error_response(500, str(e))

def delete_recipe(body):
    """Delete a recipe from recipe history"""
    try:
        user_id = body.get('userId')
        recipe_id = body.get('recipeId')
        
        if not user_id or not recipe_id:
            return error_response(400, 'userId and recipeId required')
        
        recipes_table.delete_item(
            Key={'userId': user_id, 'recipeId': recipe_id}
        )
        
        return success_response({'success': True, 'message': 'Recipe deleted'})
    except Exception as e:
        return error_response(500, str(e))

def delete_meal(body):
    """Delete a meal from saved meals"""
    try:
        user_id = body.get('userId')
        meal_id = body.get('mealId')
        
        if not user_id or not meal_id:
            return error_response(400, 'userId and mealId required')
        
        meals_table.delete_item(
            Key={'userId': user_id, 'mealId': meal_id}
        )
        
        return success_response({'success': True, 'message': 'Meal deleted'})
    except Exception as e:
        return error_response(500, str(e))

def get_plan(body):
    """Get daily meal plan for a specific date"""
    try:
        user_id = body.get('userId')
        date = body.get('date')
        
        if not user_id or not date:
            return error_response(400, 'userId and date required')
        
        daily_plans_table = dynamodb.Table('dailyPlans')
        response = daily_plans_table.get_item(
            Key={'userId': user_id, 'date': date}
        )
        
        if 'Item' in response:
            return success_response(response['Item'])
        else:
            # Return empty plan if none exists
            return success_response({
                'userId': user_id,
                'date': date,
                'meals': {
                    'breakfast': [],
                    'lunch': [],
                    'dinner': [],
                    'snacks': []
                }
            })
    except Exception as e:
        return error_response(500, str(e))

def save_plan(body):
    """Save daily meal plan for a specific date"""
    try:
        user_id = body.get('userId')
        date = body.get('date')
        meals = body.get('meals')
        
        if not user_id or not date or not meals:
            return error_response(400, 'userId, date, and meals required')
        
        daily_plans_table = dynamodb.Table('dailyPlans')
        plan_data = {
            'userId': user_id,
            'date': date,
            'meals': meals,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        daily_plans_table.put_item(Item=plan_data)
        
        return success_response({'success': True, 'message': 'Plan saved'})
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
        'body': json.dumps(data, cls=DecimalEncoder)
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