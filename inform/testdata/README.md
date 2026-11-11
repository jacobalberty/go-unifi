# Test data

`aes_snappy.dat` is an inform packet captured from a UniFi UAP-AC-Pro-Gen2
(MAC f0:9f:c2:79:63:90, firmware 3.9.27.8537), AES-CBC encrypted and snappy
compressed, with device key `e2c930683af3945e4d0d58d37a78c2a6`.

`gcm_zlib.dat` is an inform packet captured from a UniFi UAP-AC-Pro-Gen2
(MAC fc:ec:da:fc:c5:35, firmware 4.0.66.10832), AES-GCM encrypted and zlib
compressed, with device key `05223125e6b44aca0a0599551168d766`. It is the
only capture here that exercises GCM against a real device.

Both come from [dmke/inform-inspect](https://github.com/dmke/inform-inspect)
(via the jacobalberty/inform-inspect fork), used under the MIT License:

    Copyright (c) 2018 Dominik Menke
