# Cryptical

## Synopsis

This python program provides a secure container for your files using AES 256 with PKCS#7 padding for the files encryption, RSA-OAEP for the AES key encryption and RSA-PSS for the signature of the archive. It is also an API you can use for encryption, decryption and signature operations.

Locking mechanism :

![alt tag](https://raw.githubusercontent.com/mathieudev/Cryptical/master/img/lock.png)

Unlocking mechanism :

![alt tag](https://raw.githubusercontent.com/mathieudev/Cryptical/master/img/unlock.png)

## Getting Started

### Prerequisities

[pycrypto](https://pypi.python.org/pypi/pycrypto)

### Examples

Generate RSA key pair if you need one :

```
python cryptical --gen 4096
```
Lock your files in a secure container :

```
python cryptical --lock file1.txt file2.txt --keys priv.pem pub.pem --output archive
```

Unlock your secure container :

```
python cryptical --unlock archive.lkd --keys priv.pem pub.pem
```

## Authors

* **Hakan Küsne** - *Initial work* - [hakankusne](https://github.com/hakankusne)
* **Mathieu Devaud** - *Initial work* - [mathieudev](https://github.com/mathieudev)


## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details
