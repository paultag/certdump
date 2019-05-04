certdump(1) -- read x509 Certificates
=====================================

SYNOPSIS
--------

`certdump` [global options] [arguments...]

DESCRIPTION
-----------

`certdump` is a very simple x.509 Certificate reader. `certdump` contains
U.S. Government PIV Certificate support through the `pault.ag/go/piv`
library, and will extract a few PIV specific fields
out of the x.509 Certificate as well as standard x.509 fields.

This is intended to replace basically all usage where you wind up running
something like `openssl x509 -in something.crt -inform der|pem -noout -text`.

Additionally, this contains a `json` output format, helpful when quickly
scripting something over a large number of Certificates.

OPTIONS
-------

    --ca        path on the filesystem to find a file with concatinated PEM x.509 CAs
                that are trusted to issue Certificates you're dumping. This is used to
                ensure the Certificate is both valid, as well as print the CA chain
                at the head of the output. This should also contain all known
                intermediaries.

    --json      output the x.509 Certificate as a JSON object. This (internally)
                is using Go's default `encoding/json` to dump the Go x509.Certificate
                type, so the keys and values contained in this object may change
                as the Go standard library changes. Be careful about breakge!

    --text      output text describing the x.509 Certificates passed. This is
                the default mode. If --json is provided, this is ignored.

    --validate  attempt ot validate the Certificates passed. If --text is
                provided, this will output the CA chain before the rest of
                the output.

AUTHOR
------

Paul Tagliamonte <paultag@gmail.com>

SEE ALSO
--------

openssl(1)
