FROM python:3.11-slim

# Không chạy dashboard bằng root. Streamlit là tiến trình đối mặt Internet,
# nên nếu có lỗ hổng RCE trong Streamlit hoặc trong một dependency thì việc
# chạy dưới UID không đặc quyền là lớp ngăn cách cuối cùng còn lại.
RUN useradd --create-home --uid 10001 socuser

WORKDIR /app

COPY requirements.txt .

RUN pip install \
    --no-cache-dir \
    -r requirements.txt

COPY src/app.py ./src/app.py

# app.py imports the shared feature contract
COPY src/features.py ./src/features.py

COPY models/multiclass.pkl ./models/multiclass.pkl
COPY models/label.pkl ./models/label.pkl

RUN chown -R socuser:socuser /app

USER socuser

ENV PORT=8080

# enableXsrfProtection phải bật. Đi kèm enableCORS=false, Streamlit sẽ cảnh
# báo nhưng vẫn giữ được lớp chống CSRF trên các endpoint upload/websocket.
CMD streamlit run src/app.py \
    --server.port=$PORT \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --server.enableCORS=false \
    --server.enableXsrfProtection=true \
    --browser.gatherUsageStats=false
