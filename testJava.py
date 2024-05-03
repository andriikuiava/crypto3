from locust import HttpUser, task, between

class AccountUser(HttpUser):
    wait_time = between(0.001, 0.002)

    @task
    def create_account(self):
        account_data = {
            "customerId": 1,
            "currencies": ["USD"],
            "country": "Estonia"
        }
        self.client.post("/accounts/create", json=account_data)

# Run the test with:
# locust -f testJava.py