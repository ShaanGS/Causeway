FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY causeway ./causeway
COPY ventriloquist ./ventriloquist
COPY server ./server
RUN pip install --no-cache-dir ".[server]"
EXPOSE 8788
CMD ["causeway", "serve", "--host", "0.0.0.0", "--port", "8788"]
