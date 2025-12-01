# PlateAI Deployment Guide

Complete guide to deploy PlateAI to your own AWS account.

## Prerequisites
- AWS account with admin access
- AWS CLI installed and configured
- Terraform >= 1.0 installed
- Domain name (optional, for custom domain)

## Cost Estimate
- **With rate limits (2/3/3 per day)**: $1-3/month
- **Without rate limits**: $20-50/month (Bedrock usage)
- First year: Mostly covered by AWS free tier

## Step 1: Enable Bedrock Access
1. Go to AWS Console → Bedrock (us-east-1 region)
2. Request access to "Claude 3.5 Sonnet" model
3. Wait for approval (usually instant)

## Step 2: Clone Repositories
```bash
git clone https://github.com/AaronWhiteTX/plateai.git
git clone https://github.com/AaronWhiteTX/plateai-terraform.git
cd plateai-terraform
```

## Step 3: Configure Infrastructure

### Edit main.tf
Update these values to make them unique:
```hcl
# S3 buckets (must be globally unique)
resource "aws_s3_bucket" "photos" {
  bucket = "YOUR-NAME-plateai-photos"  # Change this
}

resource "aws_s3_bucket" "frontend" {
  bucket = "YOUR-NAME-plateai-frontend"  # Change this
}
```

### Option A: With Custom Domain
Keep CloudFront and ACM sections, update domain:
```hcl
resource "aws_cloudfront_distribution" "plateai" {
  aliases = ["yourdomain.com", "www.yourdomain.com"]
  # ...
}

resource "aws_acm_certificate" "plateai" {
  domain_name = "yourdomain.com"
  subject_alternative_names = ["www.yourdomain.com"]
  # ...
}
```

### Option B: Without Custom Domain
Remove or comment out these resources in main.tf:
- `aws_cloudfront_distribution.plateai`
- `aws_acm_certificate.plateai`

## Step 4: Deploy Infrastructure
```bash
terraform init
terraform plan  # Review changes
terraform apply  # Type 'yes' to confirm
```

Save these outputs:
- API Gateway URL: `https://XXXXXXX.execute-api.us-east-1.amazonaws.com/prod`
- S3 Frontend URL: `http://YOUR-BUCKET.s3-website-us-east-1.amazonaws.com`

## Step 5: Update Frontend Configuration

### Update dashboard.html
```javascript
// Line ~15
const API_ENDPOINT = 'YOUR-API-GATEWAY-URL';  // From step 4
```

### Update lambda_function.py CORS (if using custom domain)
```python
# Line ~870
'Access-Control-Allow-Origin': 'https://yourdomain.com'
```

## Step 6: Deploy Lambda Code
```bash
cd ../plateai
zip lambda.zip lambda_function.py

aws lambda update-function-code \
  --function-name FoodIdentifierProcessor \
  --zip-file fileb://lambda.zip
```

## Step 7: Upload Frontend
```bash
aws s3 cp index.html s3://YOUR-BUCKET/
aws s3 cp dashboard.html s3://YOUR-BUCKET/
```

## Step 8: DNS Configuration (Custom Domain Only)

### Get CloudFront Domain
```bash
terraform output cloudfront_domain
# Example: d1abc123def.cloudfront.net
```

### Configure DNS
Add CNAME records in your DNS provider:
```
Type: CNAME
Name: www
Value: d1abc123def.cloudfront.net

Type: CNAME  
Name: @
Value: d1abc123def.cloudfront.net
```

### Validate ACM Certificate
Check email or DNS validation records from ACM console.

## Step 9: Test Deployment
1. Visit your S3 URL or custom domain
2. Create account
3. Upload a food photo
4. Verify AI analysis works
5. Check rate limits (2 photos max today)

## Troubleshooting

### "Access Denied" on S3
```bash
aws s3api put-bucket-policy --bucket YOUR-BUCKET --policy file://bucket-policy.json
```

### Lambda can't access Bedrock
Check IAM role has `AmazonBedrockFullAccess` policy attached.

### CORS errors
Verify API_ENDPOINT in dashboard.html matches actual API Gateway URL.

### Rate limits not working
Check browser localStorage is enabled. Try incognito mode.

## Cleanup (Delete Everything)
```bash
cd plateai-terraform

# Empty S3 buckets first
aws s3 rm s3://YOUR-PHOTOS-BUCKET --recursive
aws s3 rm s3://YOUR-FRONTEND-BUCKET --recursive

# Destroy infrastructure
terraform destroy  # Type 'yes' to confirm
```

## Architecture
See main [README.md](README.md) for architecture diagram and technical details.

## Support
Open an issue on GitHub for deployment problems.
