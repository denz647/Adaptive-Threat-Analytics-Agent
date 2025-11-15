# AWS Migration Notes
- Ingestion: replace local CSV with S3 + Lambda/Kinesis to push logs.
- Training: use SageMaker training jobs with the same scikit-learn code (containerize).
- Serving: deploy detection as SageMaker endpoint or Lambda invoking model.
- Feedback store: move SQLite -> DynamoDB (or RDS) and FAISS -> Chroma hosted on ECS (or use managed vector DB).
- LLM: use Amazon Bedrock (if available) or host Llama in EC2/GPU, or use OpenAI/other API.
- Dashboard: run Streamlit on ECS Fargate behind ALB or AWS Amplify + static frontend that calls backend API (FastAPI).
