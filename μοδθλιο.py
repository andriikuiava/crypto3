from sympy import factorint

# Modulus (replace this with your actual modulus)
modulus = 60075706484530187385580279213441299974231196675614117426294438577081087670919

# Factorize the modulus
factors = factorint(modulus)

# Print the prime factors
print("Prime factors:", list(factors.keys()))
