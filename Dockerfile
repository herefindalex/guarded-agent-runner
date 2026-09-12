FROM node:24-alpine AS frontend
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////data/guarded_agent_runner.db
WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app
COPY pyproject.toml README.md ./
COPY guarded_agent_runner/ guarded_agent_runner/
RUN pip install --no-cache-dir .
COPY --from=frontend /build/frontend/dist frontend/dist
RUN mkdir /data && chown app:app /data
USER app
EXPOSE 8000
CMD ["uvicorn", "guarded_agent_runner.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
