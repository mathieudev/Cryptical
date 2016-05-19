# Cryptical

[![Python 2.7](https://img.shields.io/badge/python-2.7-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](https://raw.githubusercontent.com/mathieudev/Cryptical/master/LICENSE)

This python program provides a secure container for your files using AES 256 with PKCS#7 padding for the files encryption, RSA-OAEP for the AES key encryption and RSA-PSS for the signature of the archive. It is also an API you can use for encryption, decryption and signature operations.

Locking mechanism :

![alt tag](https://raw.githubusercontent.com/mathieudev/Cryptical/master/img/lock.png)

Unlocking mechanism :

![alt tag](https://raw.githubusercontent.com/mathieudev/Cryptical/master/img/unlock.png)

## Getting Started

### Prerequisities

This tool works with Python 2.7 and the library [pycrypto](https://pypi.python.org/pypi/pycrypto).

```
pip install pycrypto
```

### Examples

Generate RSA key pair if you need one :

```
python cryptical.py --gen 4096
```
Lock your files in a secure container :

```
python cryptical.py --lock file1.txt file2.txt --keys priv.pem pub.pem --output archive
```

Lock your files in a secure container and securely delete them :

```
python cryptical.py --lock file1.txt file2.txt --keys priv.pem pub.pem --output archive --delete
```

Unlock your secure container :

```
python cryptical.py --unlock archive.lkd --keys priv.pem pub.pem
```

## Authors

* **Hakan Küsne** - *Initial work* - [hakankusne](https://github.com/hakankusne)
* **Mathieu Devaud** - *Initial work* - [mathieudev](https://github.com/mathieudev)


## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details
