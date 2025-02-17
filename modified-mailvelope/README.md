# Project 2
# Added or Modified Functions
 # aesGcmEncrypt (in crypto.js file)
 # aesGcmDecrypt (in crypto.js file)
 # generateAesKey (in crypto.js file)
 # rsaEncryptAesKey (in openpgpjs.js file)
 # rsaDecryptAesKey (in openpgpjs.js file)
 # generateHmac (in pgpModel.js file)
 # verifyHmac (in pgpModel.js file)
 # encryptMessage (in pgpModel.js file)
 # decryptMessage (in pgpModel.js file)

# How to Run the Extension
 # First, follow original Mailvelope process.
  # upload 'mailvelope.firefox.zip' file in a 'dist' folder to firefox.
  # Then, generate key with your name and email address in 'Key Management' section.
 # Next, go to your email and send a message through email.
  # Here, make sure the recipient also generate/synced their key with their email.
  # So, I recommend to send a message to yourself.
 # After sending an email (encryption), open console log window and see encrypting validation.
 # After decryption, you can also check console logs for decrypting validation and see the error also.

# ------------------------------------------------------------------------------------------------------

# Mailvelope

[![Build Status](https://travis-ci.org/mailvelope/mailvelope.svg?branch=master)](https://travis-ci.org/mailvelope/mailvelope)

Mailvelope is a browser extension for Google Chrome and Firefox that allows secure email communication based on the OpenPGP standard. It can be configured to work with arbitrary Webmail provider.

## OpenPGP backends

Mailvelope uses the following OpenPGP implementation

  - [OpenPGP.js](http://openpgpjs.org/) for the Chrome Extension and for the Firefox Addon

## Installation

Mailvelope is available in the Chrome Web Store:
https://chrome.google.com/webstore/detail/kajibbejlbohfaggdiogboambcijhkke

For Firefox you can get it from addons.mozilla.org:
https://addons.mozilla.org/en/firefox/addon/mailvelope/

Or check the [releases](https://github.com/mailvelope/mailvelope/releases) section for latest builds of Firefox and Chrome installation packages.

## Client API

You can find the current [API Documentation](https://mailvelope.github.io/mailvelope) on GitHub pages. The version will correspond to the current master branch. A demo page with unit tests is available at: [https://demo.mailvelope.com](https://demo.mailvelope.com).

## Build instructions

If you don’t have grunt installed, yet:

    npm install -g grunt-cli

and then get and build the sources:

    git clone https://github.com/mailvelope/mailvelope.git
    cd mailvelope
    npm ci && grunt prod

#### Chrome

    grunt dist-cr

The Chrome extension will be in `dist/mailvelope.chrome.zip`.

#### Firefox

    grunt dist-ff

The Firefox web extension will be in `dist/mailvelope.firefox.zip`.

#### Development

Update your local repository:

    # inside mailvelope folder
    git checkout dev
    git pull origin dev && grunt
    # continue with 'grunt dist-cr' or 'grunt dist-ff'

There are a few more tasks/tools available:

* watch source code for changes and recompile if needed

    `grunt watch`

* test the firefox plugin

  ```
  node_modules/web-ext/bin/web-ext run --source-dir=./build/firefox
  ```

  It is possible to reload the plugin on changes, run the `grunt watch` task on another console terminal

* reset repository

    `grunt clean`

## Website

https://www.mailvelope.com

## Licence

Use of this source code is governed by the GNU AFFERO GENERAL PUBLIC LICENSE that can be found in the LICENSE file.

## About

Contact: Thomas Oberndörfer <thomas@mailvelope.com>
Twitter: [@mailvelope](https://twitter.com/mailvelope)
Contributors: see [list on GitHub](https://github.com/mailvelope/mailvelope/graphs/contributors)
