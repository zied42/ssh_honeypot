# Use a lightweight Python image
FROM python:3.11-slim

# Prevent Python buffering (better logs)
ENV PYTHONUNBUFFERED=1

# Set working directory inside container
WORKDIR /app

# Copy all project files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir paramiko

# Expose the SSH port your honeypot uses
EXPOSE 2222

# Run the honeypot
CMD ["python", "main1.py"]
