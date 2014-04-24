
.. _install:

*******************
Quick install guide
*******************

Installing OICTest should be straight forward

The code you can get from github from my site.

If you have git installed you should be able to do::

    $ git clone git://github.com/rohe/pyoidc.git
    $ git clone git://github.com/rohe/pyjwkest.git
    $ git clone git://github.com/rohe/oictest.git

Given that you have a Python version >= 2.6 and < 3.0 you should
be able to install by doing::

    $ cd pyjwkest
    $ python setup.py install
    $ cd pyoidc
    $ python setup.py install
    $ cd ../oictest
    $ python setup.py install

Prerequisites
-------------

There are a number of other packages needed but they are listed in the
setup.py files and should be installed automatically.



