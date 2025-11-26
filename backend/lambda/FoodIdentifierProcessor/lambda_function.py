import json
import boto3
import base64
from datetime import datetime
import uuid

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
s3_client = boto3.client('s3', region_name='us-east-1')
bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

table = dynamodb.Table('meals')
bucket = 'foodidentifier-730980070158-photos'

def lambda_handler(event, context):
    # Handle both direct invocation and API Gateway proxy
    if isinstance(event.get('body'), str):
        body = json.loads(event['body'])
    else:
        body = event
    
    action = body.get('action')
    
    if action == 'analyze_food_photo':
        return analyze_food_photo(body)
    elif action == 'get_recipe':
        return get_recipe(body)
    elif action == 'save_meal':
        return save_meal(body)
    elif action == 'get_meals':
        return get_meals(body)
    else:
        return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid action'})}

def analyze_food_photo(body):
    try:
        image_base64 = body.get('image_base64')
        user_id = body.get('userId', 'anonymous')
        
        if not image_base64:
            return {'statusCode': 400, 'body': json.dumps({'error': 'No image provided'})}
        
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
        
        return {'statusCode': 200, 'body': json.dumps(analysis)}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

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
        
        return {'statusCode': 200, 'body': result['content'][0]['text']}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

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
        
        return {'statusCode': 200, 'body': json.dumps({'mealId': meal_id, 'message': 'Meal saved'})}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def get_meals(body):
    try:
        user_id = body.get('userId', 'anonymous')
        
        response = table.query(
            KeyConditionExpression='userId = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )
        
        return {'statusCode': 200, 'body': json.dumps({'meals': response.get('Items', [])})}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
