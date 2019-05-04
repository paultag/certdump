certdump
========

This is a very simple (maybe overly so!) x.509 Certificate reader.

`certdump` contains U.S. Government PIV Certificate support through the
`pault.ag/go/piv` library, and will extract a few PIV specific fields
out of the x.509 Certificate.

This is intended to replace basically all usage where you wind up running
something like `openssl x509 -in something.crt -inform der|pem -noout -text`.

Additionally, this contains a `json` output format, helpful when quickly
scripting something over a large number of Certificates.
