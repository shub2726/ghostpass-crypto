# ghostpass-crypto
Our submission for Cryptography Course (CS352). A secure identity verification system where users generate encrypted tokens to verify their details anonymously, ensuring privacy using tokenization, encryption, and digital signatures.

# how to run
Run server, upload_server, thirdparty, client. 
register or login.
type the name of the pdfs (make sure its in that directory) and itll show up in the uploads folder.
if a user has already uploaded, it doesn't ask again. 

server will now generate a JWT token based on uploaded documents of user and will send it to client.
client has to enter it manually (it will show up in client terminal)
third party will use it and verify with server..if token mismatches or 15 seconds pass.. token will be invalid.
