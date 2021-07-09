# AEGIS128L for C++

AEGIS is an AEAD cipher family as specified in [AEGIS: A Fast Authenticated
Encryption Algorithm](http://competitions.cr.yp.to/round1/aegisv1.pdf).

This library is a low-level implementation of the AEGIS128L cipher. Please look
at other libraries such as [Tink](https://github.com/google/tink) when you need
a safe cryptographic API.

This library is intended to be used by cryptographic frameworks that wrap this
library in a safe API. Alternatively, this library is also useful for streaming
operations, but this is in general unsafe. It can be made safe, if you follow
the implementator's guide carefully. Please consult aegis128L.h for an API
documentation.

This is not an officially supported Google product.

## Building

Under Ubuntu/Debian:

```
sudo apt-get install libgtest-dev libabsl-dev libjsoncpp-dev
cmake .
make
./aegis128L_test
```
