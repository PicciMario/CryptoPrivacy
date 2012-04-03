Two level CA simulation software
================================

(c)opyright 2012 Mario Piccinelli <mario.piccinelli@gmail.com>

Released under MIT License

This software was developed as a mean to test a two-level CA approach for securing the exchange and management of personal data. This software works with certificates put in a predefined directory structure, and relies on the OpenSSL command line software to perform cryptographic operations. 

<hr>

Setup
-----
The software needs to be run in a path which also contains the following directories. They must exist and be initialized as described.

- root-ca: data for the root certification authority, described below.
- users: initialized empty.
- crls: initialized empty. When you receive a signed file, you must put here the CRL file of the sender to be checked.
- tmp: initialized empty.
- config: should have been already initialized.
- cadir: should contain root cert and root CRL. It must be hashed with the "c_rehash" utility provided with OpenSSL any time content is added or changed.

<hr>

Init root CA
------------
The root CA should be already initialized (this is not managed by the software). The files must be copied (if they already exist) or be generated (for example with the OpenSSL utility) and put in the following paths with the following file names:

- root-CA/ (root CA)
- - private/
- - - root.pem (public root key)
- - public/
- - - root.pem (private root key)
- - - root-crl.pem (root crl)

<hr>

Standard directory structure:
-----------------------------
- users/ (all first level users)
- - username/
- - - public/
- - - - cert.crl (user certificare revocation list)
- - - - cert.crt (user cert)
- - - private/
- - - - cert.key (user private key)
- - - conf/
- - - - openssl.conf (configuration file for requests)
- - - - username / usermail (name and mail, used to streamline end certs requests)
- - - - index
- - - - serial
- - - certs/
- - - - end-cert name/
- - - - - cert.crt (end certificate)
- - - - - cert.key (end private key)

- cadir/ (hosting root cert for checking)

- crls/ (third parties crls, for checking received files)

- root-ca/ (root CA)
- - private/
- - - root.pem (public root key)
- - public/
- - - root.pem (private root key)
- - - root-crl.pem (root crl)
- - conf/
- - - openssl.cnf
- - - index
- - - serial
- - - signed_keys/
