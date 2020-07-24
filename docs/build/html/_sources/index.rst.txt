.. cryptonice documentation master file, created by
   sphinx-quickstart on Tue Jul 14 11:19:14 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Cryptonice |version| documentation
==================================
.. image:: Cryptonice-icons-pink-hexagon.png
  :width: 100px
  :align: right
  :height: 100px
  :alt: Cryptonice logo

*Making crypto... nice!*

Cryptonice is a command-line tool and Python library that allows a user to examine the TLS configuration,
certificate information, web application headers and DNS records for one or more supplied domain names.
Cryptonice is built heavily upon the excellent `SSLyze`_ and `Cryptography`_ Python libraries.

Using default arguments Cryptonice will scan the target site on port 443, check for port 80 to 443 redirects,
look for DNS CAA records, test the TLS connection and certificate and check for the availability of HTTP/2,
HSTS and other security headers.

*Currently Supported:*

* Windows Python app and library
* Mac Python app and library

*Coming Soon:*

* Linux support
* Standalone executables

.. _SSLyze: https://github.com/nabla-c0d3/sslyze
.. _Cryptography: https://github.com/pyca/cryptography


**Sample output of Cryptonice command line usage**:
::
  cryptonice untrusted-root.badssl.com

.. image:: cryptonice_example.png
  :width: 568px
  :align: center
  :height: 552px
  :alt: Cryptonice sample output


For more ideas on how to use Cryptonice view the Examples pages.

Getting help
============
Need some help? Start here...

* `Introducing Cryptonice`_ on F5 Labs
* View the code, fork the project and submit issues on the `Cryptonice Github repo`_.

.. _Introducing Cryptonice: https://www.f5.com/labs/cryptonice
.. _Cryptonice Github repo: https://github.com/F5-Labs/cryptonice


Getting Started
^^^^^^^^^^^^^^^

.. toctree::
   :maxdepth: 3
   :hidden:

   intro/overview
   intro/install
   intro/commandline
   intro/examples

:doc:`intro/overview`
   Understand what Cryptonice is and how it can help you.

:doc:`intro/install`
   Get Cryptonice installed on your computer.

:doc:`intro/commandline`
 Learn the different command line parameters to customize your scan.

:doc:`intro/examples`
   See some examples of basic command line usage of Cryptonice.


Advanced API Use
^^^^^^^^^^^^^^^^

.. toctree::
  :maxdepth: 1
  :hidden:

  api/advanced
  api/modules

:doc:`api/advanced`
  Using the Cryptonice library in your own code.

:doc:`api/modules`
  A description of each of the scanning and testing modules within Cryptonice.


Indices and tables
==================

* :ref:`genindex`
