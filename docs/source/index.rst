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

.. _SSLyze: https://github.com/nabla-c0d3/sslyze
.. _Cryptography: https://github.com/pyca/cryptography

Getting help
============
Need some help? Start here...

* `Introduction Cryptonice` on F5 Labs
* View the code, fork the project and submit issues on the `Cryptonice Github repo`_.
* Ask or search questions on the `Cryptonice Slack channel`_.

.. _Introduction Cryptonice: https://www.f5.com/labs/cryptonice
.. _Cryptonice Github repo: https://github.com/F5-Labs/cryptonice
.. _Cryptonice Slack channel: https://f5.com


Getting Started
^^^^^^^^^^^^^^^

.. toctree::
   :caption: Getting Started
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


Advanced Usage
^^^^^^^^^^^^^^

.. toctree::
  :caption: Advanced Usage
  :maxdepth: 3
  :hidden:

  api/modules

:doc:`api/modules`
  Get Cryptonice installed on your computer.


Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
