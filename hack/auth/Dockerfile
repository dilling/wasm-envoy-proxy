# Use the latest Python 3.12 image from Docker Hub
FROM python:3.13-slim

# Install uv.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy the application into the container.
COPY . /app

ENV PYTHONUNBUFFERED=1

# Install the application dependencies.
WORKDIR /app
RUN uv sync --frozen --no-cache

# Run the application.
CMD ["/app/.venv/bin/fastapi", "run", "app.py", "--port", "8080", "--host", "0.0.0.0"]
