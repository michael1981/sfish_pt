# This script was automatically generated from the dsa-380
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15217);
 script_version("$Revision: 1.13 $");
 script_xref(name: "DSA", value: "380");
 script_cve_id("CVE-2002-0164", "CVE-2003-0063", "CVE-2003-0071", "CVE-2003-0730");
 script_bugtraq_id(4396, 6940, 6950, 8514);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-380 security update');
 script_set_attribute(attribute: 'description', value:
'Four vulnerabilities have been discovered in XFree86.
The xterm package provides a terminal escape sequence that reports
  the window title by injecting it into the input buffer of the
  terminal window, as if the user had typed it.  An attacker can craft
  an escape sequence that sets the title of a victim\'s xterm window to
  an arbitrary string (such as a shell command) and then reports that
  title.  If the victim is at a shell prompt when this is done, the
  injected command will appear on the command line, ready to be run.
  Since it is not possible to embed a carriage return in the window
  title, the attacker would have to convince the victim to press Enter
  (or rely upon the victim\'s careless or confusion) for the shell or
  other interactive process to interpret the window title as user
  input.  It is conceivable that the attacker could craft other escape
  sequences that might convince the victim to accept the injected
  input, however.  The Common Vulnerabilities and Exposures project at
  cve.mitre.org has assigned the name
  CVE-2003-0063
  to this issue.
To determine whether your version of xterm is vulnerable to abuse of
  the window title reporting feature, run the following command at a
  shell prompt from within an xterm window:
(The terminal bell may ring, and the window title may be prefixed
  with an "l".)
This flaw is exploitable by anything that can send output to a
  terminal window, such as a text document.  The xterm user has to
  take action to cause the escape sequence to be sent, however (such
  as by viewing a malicious text document with the "cat" command).
  Whether you are likely to be exposed to it depends on how you use
  xterm.  Consider the following:
Debian has resolved this problem by disabling the window title
  reporting escape sequence in xterm; it is understood but ignored.
  The escape sequence to set the window title has not been disabled.
A future release of the xterm package will have a configuration
  option to permit the user to turn the window title reporting feature
  back on, but it will default off.
The xterm package, since it emulates DEC VT-series text terminals,
  emulates a feature of DEC VT terminals known as "User-Defined Keys"
  (UDK for short).  There is a bug in xterm\'s handling of DEC UDK
  escape sequences, however, and an ill-formed one can cause the xterm
  process to enter a tight loop.  This causes the process to "spin",
  consuming CPU cycles uselessly, and refusing to handle signals (such
  as efforts to kill the process or close the window).
To determine whether your version of xterm is vulnerable to this
  attack, run the following command at a shell prompt from within a
  "sacrificial" xterm window (i.e., one that doesn\'t have anything in
  the scrollback buffer you might need to see later):
This flaw is exploitable by anything that can send output to a
  terminal window, such as a text document.  The xterm user has to
  take action to cause the escape sequence to be sent, however (such
  as by viewing a malicious text document with the "cat" command).
  Whether you are likely to be exposed to it depends on how you use
  xterm.
Debian has resolv
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-380');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-380
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA380] DSA-380-1 xfree86");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-380-1 xfree86");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lbxproxy', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'libdps-dev', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'libdps1', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'libdps1-dbg', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'libxaw6', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'libxaw6-dbg', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'libxaw6-dev', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'libxaw7', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'libxaw7-dbg', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'libxaw7-dev', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'proxymngr', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'twm', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'x-window-system', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'x-window-system-core', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xbase-clients', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xdm', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfonts-100dpi', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfonts-100dpi-transcoded', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfonts-75dpi', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfonts-75dpi-transcoded', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfonts-base', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfonts-base-transcoded', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfonts-cyrillic', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfonts-pex', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfonts-scalable', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfree86-common', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfs', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfwp', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlib6g', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlib6g-dev', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibmesa-dev', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibmesa3', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibmesa3-dbg', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibosmesa-dev', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibosmesa3', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibosmesa3-dbg', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibs', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibs-dbg', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibs-dev', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xlibs-pic', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xmh', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xnest', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xprt', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xserver-common', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xserver-xfree86', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xspecs', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xterm', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xutils', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xvfb', release: '3.0', reference: '4.1.0-16woody1');
deb_check(prefix: 'xfree86', release: '3.0', reference: '4.1.0-16woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
