Install
=======

Windows
^^^^^^^

*Python app and Library*

For those that don't yet have Python 3 installed, follow these simple steps.

#. Download `Python 3.7`_ or later (select *Windows x86-64 executable installer*)
#. It is recommended that you leave installation options on default but (optionally) also select...
   * Select Install for All Users
   * Select Precompile standard library
#. Open a command prompt and type 'python'. This will send you in to a Python interpreter and also display the version you have installed. This should be 3.7 or later.


Now issue the 'pip' command to install Cryptonice::

    pip install cryptonice

.. _Python 3.7: https://www.python.org/downloads/


Mac
^^^
Mac OS comes with Python 2 pre-installed. Since Cryptonice requires Python 3.7 or later and you will need
to ensure that this is installed.

#. Download `Python 3.7`_ or later (select *macOS 64-bit installer*)
#. Open the downloaded file and follow the installation prompts
#. The install will pop open a file window. Double-click the file *Install Certificates.command* in order to install default root certificates
#. Open up a new terminal window so that we can install Cryptonice

Finally, make sure to use 'pip3' so that the Python 3 version is used. If you issue the 'pip' command then
Python 2 will be used and Cryptonice will fail::

    pip3 install cryptonice


Ubuntu
^^^^^^
Install instructions to come.
