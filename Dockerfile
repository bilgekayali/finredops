FROM python:3.12-slim

RUN useradd --create-home --uid 10001 finredops
WORKDIR /app

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
COPY examples ./examples

RUN python -m pip install --no-cache-dir .

USER finredops
EXPOSE 8080

ENTRYPOINT ["python", "-m", "finredops"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]

