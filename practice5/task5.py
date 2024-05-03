import hashlib

sha256 = "2898afd63742afe3e3a11ca6eebcd6227d3e024f948e366d7ce9aacedb460bf7"

target_hashes = set()

def sha256_hash(string):
    return hashlib.sha256(string.encode()).hexdigest()


for i in range(10000000, 100000000):
    code_hash = sha256_hash(str(i))
    if code_hash == sha256:
        print(i)
        break
    target_hashes.add(code_hash)

ranges = {
    'AS/OÜ': range(10000000, 20000000),
    'public': range(70000000, 80000000),
    'MTÜ': range(80000000, 90000000),
    'sihtasutus': range(90000000, 100000000)
}

for org_type, org_range in ranges.items():
    for code in org_range:
        code_hash = sha256_hash(str(code))
        if code_hash in target_hashes:
            print(org_type)
            break
