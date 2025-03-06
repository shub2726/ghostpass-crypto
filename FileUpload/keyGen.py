from Crypto.PublicKey import RSA

# Generate RSA key pair
key = RSA.generate(2048)

# Save the private key (for the server)
with open("server_private.key", "wb") as private_file:
    private_file.write(key.export_key())

# Save the public key (for the client)
with open("server_public.pem", "wb") as public_file:
    public_file.write(key.publickey().export_key())

print("Server RSA keys generated successfully!")
print("Private key: 'server_private.key'")
print("Public key: 'server_public.pem' (Give this to the client!)")
