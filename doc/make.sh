#!/bin/sh
rm -f oictest*
sphinx-apidoc -F -o ../doc/ ../src/oictest
make clean
make html