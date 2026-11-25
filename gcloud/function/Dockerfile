FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/appuser \
    PORT=8080

WORKDIR /app

RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g 10001 --create-home --shell /sbin/nologin appuser

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=0:0 . /app
RUN chmod -R a+rX /app

USER 10001:10001
EXPOSE 8080

CMD ["functions-framework", "--target=quicksand_combined", "--port=8080"]
