import requests

url = "http://localhost:8000/api/v1/auth/login"
data = {"username": "admin", "password": "wrongpassword"}

for i in range(1, 135):
    r = requests.post(url, json=data)
    print(f"Request {i}: HTTP {r.status_code}")
    if r.status_code == 429:
        print(f"  --> RATE LIMITED at request {i}!")
        print(f"  --> Response: {r.text}")
        break