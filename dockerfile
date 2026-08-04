# Dockerfile — تیم آزادی Gateway
# این فایل رو توی ریشه‌ی ریپازیتوری timazadi/TimAzadi قرار بده.

FROM python:3.12-slim

WORKDIR /app

# نصب وابستگی‌ها (لایه‌ی جدا برای کش بهتر)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی کل سورس
COPY . .

# Railway مقدار PORT رو خودش موقع اجرا ست می‌کنه
ENV PORT=8000
EXPOSE 8000

# ⚠️ نکته: اگه اپلیکیشن FastAPI‌ت توی main.py با متغیر دیگه‌ای غیر از "app"
# تعریف شده (مثلاً app = FastAPI() ولی توی فایل دیگه‌ای)، این خط رو مطابقش کن.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
