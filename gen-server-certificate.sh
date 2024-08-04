#!/bin/bash

openssl req -x509 -nodes -days 36500 -newkey ec:<(openssl ecparam -name prime256v1) -keyout tls/serverkey.pem -out tls/servercert.pem -subj "/C=JP/O=RasPython3 Org./CN=raspython3.org"