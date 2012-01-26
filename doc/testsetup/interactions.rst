.. _interactions:

*****************************
How to deal with interactions
*****************************

Certain interactions between the partners in a conversation are not matter
for standardisation. One typical such thing is how the authentication is done.

For this to be handled this package allows for defining an action depending on
the response from the other part.

Dealing with forms
==================

This is the most common case where you need interaction while communicating
with a server.
You, that is the user, is expected to fill in username/password or to give
consent or similar actions.

A couple of examples:

A simple form
-------------

.. code-block:: html

    <form method="POST" action="/abop/op.php/login">
      Username:<input type="text" name="username" value="=alice">(or =bob)<br />
      Password:<input type="password" name="password" value="wonderland">(or underland)<br />
      <input type="checkbox" name="persist">Keep me logged in. <br />
      <input type="submit">
     </form>

Here you would expect to use the defaults hence it's just a matter of
submitting the form. This is expressed in JSON as::

    "https://connect.openid4.us/abop/op.php/auth": ["select_form", null]


More then one form
------------------

.. code-block:: html
    :emphasize-lines: 3,13

    <form method="POST" action="/abop/op.php/confirm_userinfo">
    <input type="hidden" name="mode" value="ax_confirm">
    <input type="hidden" name="persona" value="Default">
    <table cellspacing="0" cellpadding="0" width="600">
    <thead><tr><th>Attribute</th><th>Value</th><th>Confirm</th></tr></thead>
    <tr><td>Full Name</td><td><input id='inputtext' name='ax.name' type='text' value='Alice Yamada'></td>
    <td><input type='checkbox' name='conf_ax.name' value='1' checked></td></tr>
    <tr><td><input type="submit" name="confirm" value="confirmed">
    <input type="submit" name="confirm" value="cancel" title="title"></td></tr></table>
    </form>
    <form method="POST" action="/abop/op.php/confirm_userinfo">
    <input type="hidden" name="mode" value="ax_confirm">
    <input type="hidden" name="persona" value="Browsing">
    <table cellspacing="0" cellpadding="0" width="600">
    <thead><tr><th>Attribute</th><th>Value</th><th>Confirm</th></tr></thead>
    <tr><td>Full Name</td><td><input id='inputtext' name='ax.name' type='text' value='Alice Yamada'></td>
    <td><input type='checkbox' name='conf_ax.name' value='1' checked></td></tr>
    <tr><td colspan="3"><input type="submit" name="confirm" value="confirmed">
    <input type="submit" name="confirm" value="cancel" title="title"></td></tr></table>
    </form>

First you need to pick the right form and then in this case just submit it.
The difficulty is to pick the right form. The action is the same so is
the method in both forms. What turns out to be different between the two forms
is the value of a hidden control ("persona")::

    "https://connect.openid4.us/abop/op.php/login": ["select_form",
                          {"_form_pick_": {"control": ("persona", "Default")}}]

More then one form with different actions
-----------------------------------------



The opfunc module
=================

.. automodule:: oictest.opfunc
   :members:
