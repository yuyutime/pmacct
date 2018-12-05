HTTP server addon for PMACCT
=============================

Prerequisites:
--------------

This addon is using embedded code from MONGOOSE project (https://github.com/cesanta/mongoose).
Only two files from Mongoose code base are needed: `mongoose.h` and `mongoose.c`.
For simplicity both are included into pmacct source tree here.

To update get fresh versions of files from Github:
```
wget https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.c
wget https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.h
```
or
```
git clone https://github.com/cesanta/mongoose.git
```
to some folder and copy these two files here from the root of Mongoose folder.

Building notes:
---------------

To build pmacct with embedded http functtionality add `--enable-web` to `configure` options.
