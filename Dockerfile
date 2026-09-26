FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 hp
COPY honeypot.py .
COPY static ./static
RUN mkdir -p /app/data && chown -R hp:hp /app
USER hp
EXPOSE 8080 2323 2222
CMD ["python","honeypot.py","run"]
