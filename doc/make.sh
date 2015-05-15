#This file is subject to the Apache License version 2.0 available at http://apache.org/licenses/LICENSE-2.0.
#!/bin/sh
rm -f oictest*
sphinx-apidoc -F -o ../doc/ ../src/oictest
make clean
make html
