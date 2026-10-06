FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium

COPY . .

ENV PORT=8080

CMD ["sh", "-c", "gunicorn -b 0.0.0.0:$PORT -w 1 --threads 4 --timeout 300 app:app"]
