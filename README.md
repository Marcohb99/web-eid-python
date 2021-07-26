# Marco Antonio Hurtado Bandrés <br/> Trabajo Fin de Grado 2021 <br/> Final Year Dissertation  


# WebEidPython
This is one of the components that for my final year dissertation, which is a replacement of the original [C++ web eid native app](https://github.com/web-eid/web-eid-app).

## Table of contents
* [Introduction](#introduction)
* [Modifications](#modifications)
* [Requirements](#requirements)
* [Installation](#installation)
    * [Windows](#windows)
    * [Linux](#linux)
* [Requirements](#requirements)
* [Usage](#usage)

## Introduction

This native app works mainly the same way as the [C++ web eid native app](https://github.com/web-eid/web-eid-app). In fact, the structure (controller and command handlers) as well as lots of the names are the same.

Note that this native app is a **proof of concept**, therefore, some things may be missing, but it has been tested with the rest of the components and they work well. The components of this project are:
* This **modified python native application**
* The [**modified spring boot example**](https://webeidspringexsamplemodified.herokuapp.com/), only modified to accept spanish AC-FNMT Usuarios and seg-social ACGISS eID certificates.
* The **modified Web eID extension**, only modified to fit the new structure with the record server added.
* The [**eID record server**](https://eidrecordserver.herokuapp.com/): a new web application made from the original Web eID spring boot example which will track all the activity made with eID certificates and allows users to see a list of usages, download them and receive email notifications when their certificates are used. This component has been developed to add secure digital signature delegation.


## Modifications
This component has been developed to use **eID certificate files instead of eID smart cards**, this is because the main goal of this dissertation is to make the eID delegation process more secure, and eID cards in a personal context are rarely delegated. Certificate files are the things being delegated normally.

This modification **doesn't support the command line usage**, like the original native app does, but adds some functionality for digital signature delegation:
1. It stores record files in json format, with info about the digital identity activity (see the structure in [this file](/app/registry/record_structure.json.dist)).
2. It stores metadata of the signed file, because what the app signs is the container metadata that will have the file to sign and the detached signature.
3. It sends a POST request to the eID record server to store the eID activity, and if the request fails, it stops the authentication or signing process.

Just to mention, at first it also was going to send the emails, but due to the security issues of storing the email acount credentials, the functionality was moved to the server itself. However, the command handler is kept [here](/app/src/controller/command_handler/sendMail.py).

## Requirements
In order to make the native app work, the following is needed.

### Python and pip
This native app has been developed and tested with **python 3.9.2** but it should work with a 3.7+ version. In order to install the python libraries, pip is required.

Please, check these things before installing any libraries, because changing the python version after installing them will require resintalling.

### Browser
This native app and the installation scripts have only been tested and developed to work in **Firefox**.

### Libraries
The python libraries used are:
* [Cryptography](https://cryptography.io/en/latest/)
    - Note that in some linux systems, the library is installed, but the version may be old (version 3.0 or lower) and cause errors. To avoid that:
        1. Upgrade the library (install pip if it wasn\'t installed) and use one of this commands:
        ```bash
        $ python3 -m pip install -U cryptography
        $ python3 -m pip3 install -U cryptography
        ````
        2. Check the cryptography version is 3.1 or higher:
        ```bash
        $ pip freeze | grep cryptography
        cryptography==3.1
        ````

* [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
* [Aenum](https://pypi.org/project/aenum/)
* [Dotenv](https://pypi.org/project/python-dotenv/)
* [PyJWT](https://pyjwt.readthedocs.io/en/stable/)
* [Requests](https://pypi.org/project/requests/)
* [Validators](https://pypi.org/project/validators/)

### Certificates
This native app has been tested with both .pfx and .p12 certificates, mainly with the algorithm *sha256withRSA*. However it should support more algorithms. Note that:
* **SHA1 certificates are not supported** because PyJwt does not support it.
* **ECDSA certificate are not supported** because cryptography does not suppor signing with them.

There are several test certificates to test. Usage explained in the [usage section](#usage).

## Installation
The common installation process just requires intalling the libraries. After that, it depends on the OS.

### Windows
**Note:** Tested in Windows 10 64 bits <br/>
After installing the libraries and checking the Python version, do the following:
1. Execute the script `web_eid_bat_setup.bat` : this will create the file `/app/webeidPython.bat` that will be used to execute [webeidPython.py](app/webeidPython.py) (the whole native app).
2. Execute the script `web_eid_json_setup.ps1` with powershell: this will modify the file `/app/webeidPython.json`, changing the "path" value to the previously created bat path.
3. Execute the script `web_eid_modified_regedit_setup.bat` : this will ask for admin privileges and then add the necessary reg keys to allow communication between the web extension and the native app.
4. Change the first line in [webeidPython.py](app/webeidPython.py) to `#!/usr/bin/env python`

If after these steps the app doens't work, you should **check all the values are okay** and after that trying a **manual installation**.

The **things to check** are:
* First of all, that `webeidPython.bat` has been created in the `/app` folder.
* The `call python` argument inside `webeidPython.bat`: it should be the full right path to `webeidPython.py` with single backlash.
* The path value in `webeidPython.json`: it should be the full path to `webeidPython.bat`, between double quotes (" ") and with double backlashes (\\\\).
* The reg keys have the right value:
    1. Type `regedit` in the windows search bar.
    2. Go to both `HKEY_LOCAL_MACHINE\SOFTWARE\Mozilla\NativeMessagingHosts` and `HKEY_CURRENT_USER\SOFTWARE\Mozilla\NativeMessagingHosts` and check there is a folder named `webeidPython` and the value is the full path to `webeidPython.json` with single backlash (\\).

If this still doesn't work, check these sources:
* The file [firefox_extension_setup.md](firefox_extension_setup.md) which has been adapted from the original native messaging example in firefox and has useful info.
* [MDN article about native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging) covers from setup to troubleshooting.
* [Web-eid-app in github](https://github.com/web-eid/web-eid-app) has the original native app setup.
* [Web-eid-webextension in github](https://github.com/web-eid/web-eid-webextension) has the original extension setup.

Also, info, debug and error logs are saved to the [logs folder](app/logs) and may be useful.

### Linux
**Note**: tested in ubuntu 20.04 LTS and 18.04 LTS (this one may require updating the python and node versions as explained before).
1. Give execution permissions to [webeidPython.py](app/webeidPython.py) 
```bash
 $ chmod +x app/webeidPython.py
````
2. Execute [web_eid_setup_linux.sh](web_eid_setup_linux.sh) with sudo. This will locate the main python file, edit the manifest [webeidPython.json](/app/webeidPython.json) and copy it to the folder `/usr/lib/mozilla/native-messaging-hosts`.
    - It may require to install `jq` before.
    - If the folder `/usr/lib/mozilla/native-messaging-hosts` does not exist, create it before running the script.
```bash
 $ sudo apt-get install jq
 $ sudo mkdir /usr/lib/mozilla/native-messaging-hosts
 $ sudo ./web_eid_setup_linux.sh
````
3. Change the first line in [webeidPython.py](app/webeidPython.py) to `#!/usr/bin/env python3` or to your global python3 executable location.

If after these steps the app doens\'t work, you should **check all the values are okay** and after that trying a **manual installation**.

The **things to check** are:
* First of all, that `webeidPython.py` has execution permissions.
* That the `webeidPython.json` has been created in the right manifest folder (`/usr/lib/mozilla/native-messaging-hosts`).
* The path value in `webeidPython.json`: it should be the full path to `webeidPython.py`, between double quotes (" ") and with (/).
* The python3 path: if by typing `/usr/bin/env python3` in the command line, the python console doesn\'t show, it means the file cannot be executed with that command. Check where python3 is installed and change the first line with the proper value. Other line that could work is
`#!/usr/bin/python3`

If this still doesn\'t work, check these sources:
* The file [firefox_extension_setup.md](firefox_extension_setup.md) which has been adapted from the original native messaging example in firefox and has useful info.
* [MDN article about native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging) covers from setup to troubleshooting.
* [Web-eid-app in github](https://github.com/web-eid/web-eid-app) has the original native app setup.
* [Web-eid-webextension in github](https://github.com/web-eid/web-eid-webextension) has the original extension setup.

Also, info, debug and error logs are saved to the [logs folder](app/logs) and may be useful.

## Usage
To use the native app, you can either use the testing certificates provided in the [certs](app/certs) folder.
To change the usage way, first you will need to rename the `.env.dist` file to just `.env` . After that:
* For using **testing certificates**:
    1. Set the `USE_PERSONAL_CERT` variable to `False`.
    2. Set the `TEST_CERT_NAME` to one of the names of the cert files in the [certs](app/certs) folder (extension included).
* For using **personal certificates**:
    1. Set the `USE_PERSONAL_CERT` variable to `True`.
    2. Set the `PERSONAL_CERT_PATH` value to the full path to yout personal certificate, between double quotes (" ") and with double backlashes (\\\\).
    3. Set the `PERSONAL_CERT_PW` value to the certificate password.

All the eID records are stored in the [registry](app/registry) folder. You can check them out after each eID certificate action.

**Note:** all the lines in the `.env` file MUST be without spaces between the `=` , the key and the value, like for example `PERSONAL_CERT_PW="password"`.