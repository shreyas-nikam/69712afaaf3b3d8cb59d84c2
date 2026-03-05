# Use Python base image
FROM python:3.12-slim

# Set working directory in the container
WORKDIR /app

# Copy requirements (adjust file name if needed)
COPY requirements.txt /app/

# Install dependencies
RUN pip install --upgrade pip     && pip install -r requirements.txt

# Copy the rest of the application code
COPY . /app

# Accept build arguments for Azure credentials
ARG AZURE_ENDPOINT
ARG AZURE_API_KEY
ARG AZURE_API_VERSION=2024-05-01-preview

# Create .streamlit directory if it doesn't exist and write secrets.toml
RUN mkdir -p /app/.streamlit && \
    echo "azure_endpoint = \"${AZURE_ENDPOINT}\"" > /app/.streamlit/secrets.toml && \
    echo "azure_api_key = \"${AZURE_API_KEY}\"" >> /app/.streamlit/secrets.toml && \
    echo "azure_api_version = \"${AZURE_API_VERSION}\"" >> /app/.streamlit/secrets.toml

# Set the port number via build-time or run-time environment
# We'll default it to 8501, but you can override later.
ENV PORT=8501

# Expose the port so Docker maps it
EXPOSE $PORT

# Run Streamlit
CMD ["bash", "-c", "streamlit run app.py --server.port=$PORT --server.headless=true"]
