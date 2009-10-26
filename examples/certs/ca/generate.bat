openssl req -new -keyout neukey.pem -out neureq.pem -days 720

openssl x509 -req -days 720 -in neureq.pem -signkey neukey.pem -out neu.crt

openssl pkcs12 -inkey neukey.pem -in neu.crt -out neu.pfx -export

openssl rsa -in neukey.pem -out neu.key