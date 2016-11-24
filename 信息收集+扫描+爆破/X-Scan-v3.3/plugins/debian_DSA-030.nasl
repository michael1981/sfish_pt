# This script was automatically generated from the dsa-030
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14867);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "030");
 script_bugtraq_id(1430, 2924, 2925);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-030 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans, Joseph S. Myers, Michal Zalewski, Alan Cox,
and others have noted a number of problems in several components of the X
Window System sample implementation (from which XFree86 is derived). While
there are no known reports of real-world malicious exploits of any of these
problems, it is nevertheless suggested that you upgrade your XFree86 packages
immediately.


The scope of this advisory is XFree86 3.3.6 only, since that is the version
released with Debian GNU/Linux 2.2 ("potato"); Debian packages of XFree86 4.0
and later have not been released as part of a Debian distribution.


Several people are responsible for authoring the fixes to these problems,
including Aaron Campbell, Paulo Cesar Pereira de Andrade, Keith Packard, David
Dawes, Matthieu Herrb, Trevor Johnson, Colin Phipps, and Branden Robinson.


The X servers are vulnerable to a denial-of-service attack during
XC-SECURITY protocol negotiation.
X clients based on Xlib (which is most of them) are subject to potential
buffer overflows in the _XReply() and _XAsyncReply() functions if they connect
to a maliciously-coded X server that places bogus data in its X protocol
replies. NOTE: This is only an effective attack against X clients running
with elevated privileges (setuid or setgid programs), and offers potential
access only to the elevated privilege. For instance, the most common setuid X
client is probably xterm. On many Unix systems, xterm is setuid root; in Debian
2.2, xterm is only setgid utmp, which means that an effective exploit is
limited to corruption of the lastlog, utmp, and wtmp files --
not general
root access. Also note that the attacker must already have sufficient
privileges to start such an X client and successfully connect to the X server.
There is a buffer overflow (not stack-based) in xdm\'s XDMCP code.
There is a one-byte overflow in Xtrans.c.
Xtranssock.c is also subject to buffer overflow problems.
There is a buffer overflow with the -xkbmap X server flag.
The MultiSrc widget in the Athena widget library handle temporary files
insecurely.
The imake program handles temporary files insecurely when executing install
rules.
The ICE library is subject to buffer overflow attacks.
The xauth program handles temporary files insecurely.
The XauLock() function in the Xau library handles temporary files
insecurely.
The gccmakedep and makedepend programs handle temporary files insecurely.

All of the above issues are resolved by this security release.

There are several other XFree86 security issues commonly discussed in conjunction with the above, to which an up-to-date Debian 2.2 system is
NOT vulnerable:


There are 4 distinct problems with Xlib\'s XOpenDisplay() function in which
a maliciously coded X server could cause a denial-of-service attack or buffer
overflow. As before, this is only an effective attack against X clients running
with elevated privileges, and the attacker must already have sufficient
privileges to start such an X client and successfully connect to the X server.
Debian 2.2 and 2.2r1 are only vulnerable to one of these problems, because we
applied patches to XFree86 3.3.6 to correct the other three. An additional
patch a
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-030');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-030
and install the recommended updated packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA030] DSA-030-2 xfree86");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-030-2 xfree86");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rstart', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'rstartd', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'twm', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xbase', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xbase-clients', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xdm', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xext', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xf86setup', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xfree86-common', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xlib6g', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xlib6g-dev', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xlib6g-static', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xmh', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xnest', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xproxy', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xprt', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-3dlabs', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-common', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-fbdev', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-i128', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-mach64', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-mono', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-p9000', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-s3', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-s3v', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-svga', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-tga', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xserver-vga16', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xsm', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xterm', release: '2.2', reference: '3.3.6-11potato32');
deb_check(prefix: 'xvfb', release: '2.2', reference: '3.3.6-11potato32');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
