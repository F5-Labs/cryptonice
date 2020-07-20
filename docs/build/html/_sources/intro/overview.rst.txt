Overview
========

Why Use Cryptonice?
^^^^^^^^^^^^^^^^^^^

There are many tools available for scanning and analysing the results of TLS and HTTPS configurations.
In fact, many of them are web based and do not need to be downloaded. So why use Cryptonice over these services?
Cryptonice is aimed at solving these sorts of problems:

*Scan multiple sites*

Many of the hosted services, such as `SSL Labs`_ and `Hardenize`_ require you to submit individual sites
for sequential scanning. This is ideal for occassional ad-hoc scans, but it's not efficient if you need to
scan multiple sites at the same time or continuously scan the same site on a frequent basis. Using either
the command line version of Cryptonice, or using its libraries in your own code, you can schedule or
programatically scan multiple sites as often as you need to.

*Testing internal sites*

Externally hosted TLS and security testing sites require that your web app is publicly accessible. For
intranet sites or other internal sites, this is of no use. Cryptonice can be run from anywhere and can
target internal hostname or IP addresses just as easily as it can scan public facing websites.

*Audit the entire HTTPS deployment*

A secure HTTPS configuration depends on a lot more than a good certificate and strong ciphers. Cryptonice
goes beyond basic TLS scans but also testing your DNS configuration, looking for newer protocols (such as HTTP/2)
and also checking for web app headers, such as HTTP strict transport security (HSTS).

*Learn how to improve*

Cryptonice not only provides a detailed report of the scan results but also shows Critical, High, Medium and low recommendations
for how you might be able to make improvements. So you need not be an expert with TLS to understand how to improve the
security of your website.

*Integrating HTTPS checks in to CI/CD pipeline*

More than ever, infrastructure is deployed as code and attackers are equally adept at automating their attacks. Performing
automated and regular checks on HTTPS deployments for every code change is essential to ensure accidental configuration changes
don't inadvertently weaken the security of the site. By leveraging Cryptonice API's you can build your own checks in to the development
workflow.

.. _SSL Labs: https://www.ssllabs.com/ssltest/
.. _Hardenize: https://www.hardenize.com/
