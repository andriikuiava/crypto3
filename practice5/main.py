import hashlib

# Define your username
username = "ankuia"

# Hash the username using SHA-256
hashed_username = hashlib.sha256(username.encode()).hexdigest()

# Print the hashed version
print("Hashed username:", hashed_username)
