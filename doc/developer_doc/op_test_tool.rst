****************
Dev doc - OPtest
****************

.. image:: ../_static/oprp.png

1. The user creates a new test instance
2. After filling in all the necessary information a new test instance (oprp) is created. Every test instance is a independent web server which runs on a specified port.
3. Using the test instance a user can run a number of tests on a OpenID connect provider.

Code structure
""""""""""""""

The code could be found in the path /oictest/test/oic_op

configuration server
--------------------
The config_server folder contains **config_server.py** which will start the the configuration server.
It is responsible for creating configuration file and starting new test instances.

Oictest contains a package called configuration_server which contains the business logic.
**configurations.py**: Is responsible for converting data between the GUI configuration structure and the configuration file format
**response_encoder.py**: Is responsible for creating the responses returned to the client
**shell_commands.py**: Is responsible for executing shell commands like killing test instance and identifying if any process is using a specific port.
**test_instance_database.py**: Is responsible for storing information in a database

Test instance
-------------
The rp folder contains oprp2.py which is the test instance used to run the all openid connect tests. It consumes a configuration file created by the

Exception handling
""""""""""""""""""
The configuration server is a CherryPyWSGIServer. In the application method all unhandled exceptions are catched.

Every exception gets an uuid which is presented to the user.

Normally the trace stack of every un handled exception is printed in the log file. In some cases
exceptions are raised but the trace stack should not be printed in the log. There are a class
called UserFriendlyException which makes it possible to not print the stack trace in the log.
This class also makes it possible to send a user friendly error message to the user and print a
separate message in the log file which may contain more detailed information.

Back up
"""""""
The configuration server creates a configuration file which is consumed by the oprp2.py (test instance).
When a configuration file is updated the overwritten configuration is backed up in the folder:
/oictest/test/oic_op/rp/config_backup

The configuration information is also stored in the database as a safety precaution. It could be
restored using the port_database_editor.py in the configuration_server package.

Port database editor:
"""""""""""""""""""""
The port_database_editor.py could be found in the configuration_server package. It's a command line
script which primary task is to keep the configuration files and the database synchronized. A
standard operation is to generate a new database file based on the configuration files in a specific
folder.

The script is built to detect differences in the database and the configuration files the
user has to specify. For example if a configuration file has been remove but the information still
exists in the database the script will prompt the user whether to restore the configuration file or
remove the information.

If for example a change where made to a configuration file by for some reason the change where
not made in the database the script will prompt the user for which version to use. The other
configuration will be overwritten.



