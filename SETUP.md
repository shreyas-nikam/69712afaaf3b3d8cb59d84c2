# Setup Instructions

## Local Development

1. Create a secrets file for Azure OpenAI credentials:
   ```bash
   cp .streamlit/secrets.toml.example .streamlit/secrets.toml
   ```

2. Edit `.streamlit/secrets.toml` with your Azure OpenAI credentials:
   ```toml
   azure_endpoint = "https://your-resource-name.openai.azure.com/"
   azure_api_key = "your-azure-api-key-here"
   azure_api_version = "2024-08-01-preview"
   ```

3. Install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

4. Run the app:
   ```bash
   streamlit run app.py
   ```

## Docker Build

To build the Docker image with Azure credentials:

```bash
docker build \
  --build-arg AZURE_ENDPOINT="https://your-resource-name.openai.azure.com/" \
  --build-arg AZURE_API_KEY="your-azure-api-key" \
  --build-arg AZURE_API_VERSION="2024-08-01-preview" \
  -t your-image-name .
```

## GitHub Actions

The workflow automatically builds and pushes to Docker Hub when you create a version tag.

**Required GitHub Secrets:**
- `DOCKERHUB_USERNAME` - Your Docker Hub username
- `DOCKERHUB_PASSWORD` - Your Docker Hub password
- `AZURE_ENDPOINT` - Azure OpenAI endpoint URL
- `AZURE_API_KEY` - Azure OpenAI API key
- `AZURE_API_VERSION` - Azure OpenAI API version (e.g., "2024-08-01-preview")

To deploy:
```bash
git tag v1.0.0
git push origin v1.0.0
```

## User Options

Users can choose between:
1. **Default Azure (gpt-5-nano)** - Uses the preconfigured Azure OpenAI endpoint
2. **Custom OpenAI** - Users can provide their own OpenAI API key for models like gpt-4o, gpt-4o-mini, etc.
