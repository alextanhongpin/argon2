from argon2 import PasswordHasher
ph = PasswordHasher()

hash = ph.hash('123456')
print('hash:', hash)


isValid = ph.verify(hash, '123456')
print('isValid:', isValid)