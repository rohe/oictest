# Operational Maintenance

*Version 1.0 - March 1st, 2017*

This document describes operational maintenance procedures for the (old) OpenID Connect OP certification environment
that the OpenID Foundation provides. It lists important directory/file structures and the steps one would have to take
to update the code, documentation and/or configuration of these environments.

For regular maintanance go directly to the [Deployment](#Deployment) section.

### SSH Login

Make sure you have an account on the machine that is allowed to `su` into the `oictest` user. Login to the server with:
````shell
ssh <username>@op.certification.openid.net
````

Change to the oictest user with the right permissions:
````shell
sudo su oictest
````

### Directories/Files Layout
The directories and files that are important for the OP test environment.

Home directory:
````
/home/oictest
````

Toplevel directory:
````
~/projects
````
Dependencies are in library directories, should stay as is on old OP, **DON’T TOUCH**
````
~/projects/pyjwkest/
~/projects/pyoidc/
````

Dependency versions:

- pyjwkest - JWK,JWE,JWS,JWT library - 1.0.7beta 
- pyoidc - OpenID Connect library - 0.7.8.beta

The other directories are not important:
````
~/projects/dirg-util
~/projects/its_oictest
````
Main toplevel test dir:
````
~/projects/oictest/
````

Sources for the main test dir can be found at:
````
https://github.com/rohe/oictest
````

Installation script:
````
~/projects/oictest/setup.py
````

About:
````
    packages=["oictest", "rrtest", "oauth2test", "umatest", "configuration_server"],
````

Only `oictest` and `configuration_server` are important for the OP.

Main OP test dir:
````
/home/oictest/projects/oictest/test/oic_op
````

Configuration of the configuration_server:
````
~/projects/oictest/test/oic_op/config_server/config.py
````
Configuration of RPs:
````
/home/oictest/projects/oictest/test/oic_op/rp
````
Restart script in there:
````
~/projects/oictest/test/oic_op/rp/restart.py
````

### Notes
OLD VERSION=OP  
Is called `oictest`  
NEW VERSION=OP,RP(uma)  
Is called `oidctest`  

- Old version is about to be replaced.
- New version is built on common framework across different test suites (SAML/ OIDC etc.)
- RP test instances are separated instances spawned on their own port
- One OP may use one RP instance or several because they require different OP URLs/ports for different tests, e.g. they cannot change the reponse_type on the same OP URL
- 2 log files per RP instance: test output, to be included in certification submissions, and python debug logs for troubleshooting

### Deployment
These are the actual commands one would give to update the code/configuration and make it available in the production environment.

###### INSTALL
NB: not needed on OP machine itself anymore, see:  
[https://github.com/rohe/oictest/blob/master/INSTALL.txt](https://github.com/rohe/oictest/blob/master/INSTALL.txt)

###### UPDATE
Pulls down source code, needs deploy after that:
````	
cd oictest
sudo git pull
<Already up-to-date>
````

###### DEPLOY
````
cd oictest
sudo python setup.py install
````
One of two services may have changed:
- Configuration server: go to section [Restart Config Server](#RESTART-CONFIG-SERVER)
- OP Test tool instance that is an RP: go to section [Restart RP](#RESTART-RP)

###### RESTART RP
````
cd test/oic_op/rp/
sudo ./restart.py rp_conf_*.py
````
You can also restart a specific instance by typing:
````
sudo ./restart.py rp_conf_<port>.py
````
need to get port number from the OP tester, probably better at US night time or weekend.  
After restart, log files can be found in:
````
/home/oictest/projects/oictest/test/oic_op/rp/server_log
````

###### RESTART CONFIG SERVER
````
cd /home/oictest/projects/oictest/test/oic_op/config_server
ps -aef | grep config_server

root     25158     1  0 Feb17 ?        00:00:00 sudo python ./config_server.py config
root     25159 25158  0 Feb17 ?        00:02:29 python ./config_server.py config
oictest  35884 35602  0 09:24 pts/2    00:00:00 grep --color=auto config_server

sudo killl -9 both python processes
````

Restart with:
````
sudo python ./config_server.py config 2> err.log &
````

Look at logs:
````
tail config_server.log
tail err.log
````
Exceptions in there are bad: need fix, SSL certificate errors are not bad: ignore
