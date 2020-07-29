Install
=======

Windows
^^^^^^^
*Requirements*
Cryptonice for Windows depends on `Visual C++ Redistributable for Visual Studio 2015`_. Most people are likely to have this installed but if you receive an error about missing
file **vcruntime140.dll** then make sure this is installed first.

.. Visual C++ Redistributable for Visual Studio 2015_ : https://www.microsoft.com/en-us/download/details.aspx?id=48145

**Standalone executable**

If you do not have Python installed, and can't or won't install it, you may be able to use the standalone Windows executable.

#. Head over to the `Cryptonice Releases`_ section of the Github repo and download the latest version you find.
#. Once the file has downloaded open it to begin installation (we recommend you install in to a folder that your user has write access to, e.g. C:/\Cryptonice)
#. After installation, open a terminal window and navigate in to the installation folder and the version folder found within (e.g. c:/\Cryptonice\cryptonice-1.0.6)

You may now use Cryptonice by entering the name of the executable and any parameters you need. For example::

  c:\cryptonice\cryptonice-1.0.6\cryptonice.exe example.com

In order to run Cryptonice from any directory you may want to add the installation location to your path, for example::

  set path=%path%;c:\cryptonice\cryptonice-1.0.6


.. _Cryptonice Releases: https://github.com/F5-Labs/cryptonice/releases


**Python app and Library**

Installing Cryptonice via pip ensures that you can easily update the tool whenever new versions are released. The other advantage is that Cryptonice should be available to be executed
from any directory that you are currently in without modifying your path.

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

**Python app and Library**

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
Cryptonice currently supports Ubuntu 20.04. Since this distribution comes with Python 3.8.2 preinstalled we need only install PIP and one dependency manually::

  sudo apt install python3-pip
  sudo apt install python3-pycurl
  pip3 install cryptonice
