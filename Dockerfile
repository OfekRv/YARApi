FROM python:3
WORKDIR /YARApi
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . ./
EXPOSE 8080
CMD ["python", "YARApi.py"]