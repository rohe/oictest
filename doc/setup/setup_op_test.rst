******
OPtest
******

This is the simple how-to description. For those that just wants to test
there OpenId provider (OP) using a pre-defined set of test flows.

There will eventually be more documentation for those that wants to build
their own test flows.

Currently there are two different implementation of the OP test tool.

OICC
====
The first released version where OICC which is a commando line based test tool. One limitation with OICC where the fact
that it had to handle user interactions. In other words an action which requires an end-user for example entering user
credentials to a login form. In most cases this could be solved by adding so called "interaction blocks" to the configuration.
By using "interaction blocks" it is possible to tell the script in which input fields to enter the necessary user credentials.
Later on a web interface where developed which could often parse interaction blocks automatically, read more about the
web interfacce `here <https://dirg.org.umu.se/page/oictestgui>`_. But if the login form contained javascript it could not be handled by OICC.

OPRP
====
In order to solve the problem a new OP test tool where implemented named OPRP. This version acts as an web server.
The big difference between the two OP test tools is that OICC downloads the login form enters the user credentials and posts
the form while OPRP gets redirected to the actual login form. As a consequence OPRP can only run tests sequentially.

We recommend you to use OPRP since it is under continues development. We are also providing OPRP as a service, for more
information on how to use the service visit `fed-lab.org <www.fed-lab.org>`_

If you want to setup an OPRP instance visit :doc:`oprp`

If you want to setup an OICC instance visit :doc:`oicc`
