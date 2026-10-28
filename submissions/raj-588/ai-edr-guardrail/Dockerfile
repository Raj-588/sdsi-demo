FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt onnxruntime tokenizers
COPY . .
RUN python demo/make_poisoned_files.py
# Bake the classifier into the image so air-gapped deployments need no runtime download:
#   RUN ./scripts/download_model.sh
EXPOSE 8080
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
