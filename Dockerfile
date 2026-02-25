FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.7 /uv /usr/local/bin/uv

# Copy project files
COPY pyproject.toml server.py ./

# Install pinned dependencies into the system python (no venv needed in container)
RUN uv pip install --system "mcp[cli]==1.26.0" "python-dotenv==1.2.1" "uvicorn==0.34.0"

# Run as non-root user for security
RUN useradd -r -s /bin/false appuser
USER appuser

# server.py reads PORT env var directly (Railway sets it automatically)
CMD ["python", "server.py", "--transport", "streamable-http", "--host", "0.0.0.0"]
