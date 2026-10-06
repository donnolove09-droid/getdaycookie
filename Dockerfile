FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

# Cài Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright đã cài sẵn trong base image + có sẵn deps
# Chỉ cần cài Chromium (không cần install-deps vì base image có rồi)
RUN playwright install chromium

# Copy code
COPY . .

# Render sẽ tự inject $PORT
ENV PORT=8080

CMD ["gunicorn", "-b", "0.0.0.0:$PORT", "-w", "1", "--threads", "4", "--timeout", "300", "app:app"]
