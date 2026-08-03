FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install \
    --no-cache-dir \
    -r requirements.txt

COPY src/app.py ./src/app.py

COPY models/multiclass.pkl ./models/multiclass.pkl
COPY models/label.pkl ./models/label.pkl

ENV PORT=8080

CMD streamlit run src/app.py \
    --server.port=$PORT \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --server.enableCORS=false \
    --browser.gatherUsageStats=false