# PlateAI - AI-Powered Nutrition Tracking & Meal Planning

A production-grade serverless web application that uses AWS Bedrock (Claude AI) to identify foods from photos, generate healthy recipe alternatives, track nutrition, and provide personalized meal planning.

**Live Demo:** [plateai.cloud](https://plateai.cloud)

---

## System Architecture

```mermaid
graph TB
    subgraph "Frontend"
        UI[PlateAI Dashboard]
    end

    subgraph "API Layer"
        APIGW[API Gateway<br/>Rate Limits: 2 photos, 3 AI questions, 3 recipes/day]
    end

    subgraph "Compute"
        Lambda[Lambda Function<br/>Python 3.12]
    end

    subgraph "AI - Bedrock"
        Claude[Claude 3.5 Sonnet<br/>Vision + Text]
    end

    subgraph "Storage"
        Users[(users)]
        Meals[(meals)]
        Recipes[(recipes)]
        Plans[(dailyPlans)]
        Convos[(conversations<br/>90-day TTL)]
        S3[S3 Photos<br/>Public Bucket]
    end

    UI -->|Upload Photo| APIGW
    APIGW --> Lambda
    Lambda -->|Store Image| S3
    Lambda -->|Analyze| Claude
    Lambda -->|Save| Meals
    Lambda --> Users
    Lambda --> Recipes
    Lambda --> Plans
    Lambda --> Convos
    
    style Claude fill:#8B5CF6
    style Lambda fill:#FF9900
    style S3 fill:#3B82F6
    style Users fill:#3B82F6
    style Meals fill:#3B82F6
    style Recipes fill:#3B82F6
    style Plans fill:#3B82F6
    style Convos fill:#3B82F6
Project OverviewPlateAI solves the problem of manual food logging and meal planning by leveraging Generative AI for image recognition and nutritional context.Core Functions:Photo-to-Nutrition: Upload a food photo to have Claude Vision identify the dish and estimate macros.Recipe Generation: Get Vegan, Keto, or Healthy alternatives for any meal with AI-generated recipes.Daily Meal Planner: Plan meals for any date with nutrition tracking and goal monitoring.AI Coach: Ask nutrition questions with full conversation context preserved.Meal History: Save meals and recipes for quick future planning.Key Stats:Monthly Cost: ~$1-3 (optimized via strict rate limiting)Latency: <2 seconds for most requestsRate Limits: 2 photos, 3 AI questions, 3 recipes per day (implemented for cost protection)Cost Protection & Rate LimitingTo maintain a low-cost serverless footprint, strict logic controls usage frequency per user.Daily Limits (per user)2 photo uploads per day3 AI coach questions per day3 recipe generations per dayLimits reset automatically at midnightState stored in localStorage with backend validationCost ImplicationsPer user (at limit):2 photos x $0.015 = $0.033 AI questions x $0.009 = $0.0273 recipes x $0.03 = $0.09Total: Approx $0.15 per user/day at max capacity.Without limits: Heavy usage could spike costs to $50-100/month. The current implementation ensures the project remains within the $1-3/month range for portfolio demonstration purposes.Key Features & Data Flow1. Food Photo AnalysisThe system uses S3 for persistent image storage and Bedrock for analysis.Data Flow:User upload -> Lambda (base64) -> S3 (Storage) -> Bedrock Claude Vision -> DynamoDBAnalysis Response Example:JSON{
  "dish_name": "Pecan Pie Slice",
  "confidence": 0.95,
  "calories": 450,
  "protein_g": 5,
  "carbs_g": 45,
  "fat_g": 28,
  "fiber_g": 2,
  "photo_url": "[https://s3.amazonaws.com/](https://s3.amazonaws.com/)..."
}
2. AI Recipe GenerationGenerates healthier alternatives for any analyzed meal (Vegan, Keto, Healthy, or Original). Recipes are auto-saved to history with photo references.3. AI Coach with ContextThe system queries conversation history from DynamoDB before calling Bedrock, allowing Claude to respond naturally to follow-up questions. Conversations have a 90-day TTL.Technical DecisionsWhy Bedrock Claude?Vision API: Native ability to analyze food photos.Context Windows: Handles conversation history for the AI coach.Pay-per-token: No fixed costs (unlike provisioned instances), making it ideal for variable traffic.Why DynamoDB?On-demand billing: Costs are zero when traffic is low.TTL: Automatic cleanup of old conversation logs reduces storage costs.Performance: Single-digit millisecond latency for user queries.Why S3 for Photos?Persistence: More efficient than storing base64 strings in a database.Public Access: Easy integration with the frontend via direct URLs.Cost: Significantly cheaper storage ($0.023/GB) compared to database storage.Security & LimitationsImplemented SecurityHTTPS: Enforced via API Gateway and CloudFront.Input Validation: Strict type checking on photos and text inputs.Rate Limiting: Logic-based daily limits to prevent abuse.Data Hygiene: Password hashing (SHA-256) and CORS configuration.Known Gaps & Cost Trade-offsTo keep the monthly operating cost of this portfolio project under $5, the following trade-offs were made:WAF (Web Application Firewall): Omitted to avoid the fixed monthly fee (approx. $5/rule/month).Encryption at Rest: Standard AWS managed encryption is used. Customer-managed keys (KMS) were not implemented to avoid key management costs.Request Signing: The architecture relies on API Gateway keys and logic-based rate limits rather than signed requests to simplify the frontend demonstration.API ArchitectureThe application exposes a RESTful API via AWS API Gateway.EndpointMethodDescription/analyze_food_photoPOSTAccepts base64 image, returns dish name and macros./generate_recipePOSTGenerates diet-specific recipe variants (Keto, Vegan, etc)./save_mealPOSTSaves analyzed food data to DynamoDB./get_mealsPOSTRetrieves meal history by UserID./save_planPOSTSaves a daily meal plan structure./get_planPOSTRetrieves meal plan for a specific date.Portfolio CompetenciesThis project demonstrates the following engineering capabilities:Cloud-Native Development: Multi-service integration (Lambda, Bedrock, DynamoDB, S3, API Gateway).FinOps & Cost Awareness: Engineering architectural decisions specifically to control cloud spend (rate limits, resource selection).Production Readiness: Implementation of error handling, input validation, and TTL data cleanup.AI Integration: Applied usage of Vision and LLM models in a practical, user-facing context.Full Stack Implementation: Complete development from backend Python logic to frontend integration.Last Updated: November 28, 2024Status: Production-ReadyMonthly Cost: $1-3 (with rate limits)