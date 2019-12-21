.. _admin-guide:

Administration Guide
====================

HOLD UP
-------

This particular page is woefully out of date. Come back later when I've got this updated.


Concepts
--------

There are several concepts crucial to understanding how ACE works and how to use ACE. For the analyst, it’s important to understand observables, tagging, and dispositioning. The administrator and developer needs to understand those concepts as well, but additionally must understand ACE’s dependencies and its engine and modular architecture.

The ACE system is named after the system's core engine, the Analysis Correlation Engine. 

Modules
+++++++

ACE modules automate something that an analyst has previously done manually. These modules do all the analysis on observables, and each module knows which types of observables it works with and knows what to do with those types of observables. Modules can be built to do anything that you can automate.


Recursive Analysis
++++++++++++++++++

.. role:: strike
   :class: strike

With the introduction of observables and modules, you can begin to understand how ACE performs its recursive analysis and correlation.  

For example, given observable type 'file', each ACE module that acts on an observable of type file will be called to perform its analysis.  From the output of each module’s analysis ACE will discover and create new observables which kicks off more modules to perform analysis.  This recursive process will continue until all observables are discovered, analyzed, and correlated or until a specified alert correlation timeout is reached. ACE’s default timeout limit for recursive alert analysis is 15 minutes, however, a warning will be logged if alert analysis exceeds five minutes. These values are configurable under ACE's 'global' configuration section.


Turning on the Engine
------------------

::

  $ ace service start engine --daemon

.. _email-scanning:

Email Scanner
+++++++++++++

TODO

::

  $ ace service start email_scanner --daemon


Enabling Modules
----------------

Yara Scanner
++++++++++++

First, make sure the **analysis_module_yara_scanner_v3_4** section in ``/opt/ace/etc/saq.ini`` is enabled. Then create a ``/opt/signatures`` directory::

  $ mkdir /opt/signatures
  $ cd /opt/signatures
  
Now place your yara signature directories in `/opt/signatures/<your yara directories>`.

Create a symlink for ACE to find your signatures::

  $ ln -s /opt/signatures $SAQ_HOME/etc/yara

Start the yara scanner::

  $ ace service start yara --daemon

Live Renderer
+++++++++++++

The live browser rendering module will try to render a png image of any html file it's given. This can be particularly helpful for viewing email html content. Keep security in-mind when implementing this module.

To configure the module, execute the following commands. NOTE: The following instructions explain how to set up the renderer on localhost, but you can set up the rendered on a dedicated server as well.

Create a user named "cybersecurity"::

  $ sudo adduser cybersecurity

Generate a ssh key as the ace user::

  $ ssh-keygen -t rsa -b 4096

Add this entry to your ace ssh config::

  $ cd /home/ace
  $ vim .ssh/config

  Host render-server
    HostName localhost
    port 22
    User cybersecurity
    IdentityFile /home/ace/.ssh/id_rsa

Set up the cybersecurity account::

  $ sudo su - cybersecurity
  $ cd && mkdir .ssh && mkdir tmp
  $ cat /home/ace/.ssh/id_rsa.pub >> .ssh/authorized_keys
  $ ln -s /opt/ace/render render
  $ exit

Add localhost as a known ssh host for the ace user::

  $ ssh-keyscan -H localhost >> .ssh/known_hosts

Run the ``install`` script::

  $ cd /opt/ace/render/ && ./install

Download the most recent Chrome driver from https://sites.google.com/a/chromium.org/chromedriver/downloads::

  $ cd /opt/ace/render 
  $ wget https://chromedriver.storage.googleapis.com/<version number goes here>/chromedriver_linux64.zip
  $ unzip chromedriver_linux64.zi

Finally, make sure the following (at a minimum) is in your ``saq.ini`` file::

  [analysis_module_live_browser_analyzer]
  remote_server = render-server
  enabled = yes

Now, restart the correlation engine and render away.
