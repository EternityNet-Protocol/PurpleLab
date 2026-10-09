FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY backend ./backend
COPY scenarios ./scenarios
COPY fixtures ./fixtures
COPY rules ./rules
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -e .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]