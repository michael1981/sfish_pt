# This script was automatically generated from the dsa-042
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14879);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "042");
 script_cve_id("CVE-2001-0191");
 script_bugtraq_id(2333);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-042 security update');
 script_set_attribute(attribute: 'description', value:
'Klaus Frank has found a vulnerability in the way gnuserv
handled remote connections.  Gnuserv is a remote control facility for Emacsen
which is available as standalone program as well as included in XEmacs21.
Gnuserv has a buffer for which insufficient boundary checks were made.
Unfortunately this buffer affected access control to gnuserv which is using a
MIT-MAGIC-COOCKIE based system.  It is possible to overflow the buffer
containing the cookie and foozle cookie comparison.

Gnuserv was derived from emacsserver which is part of GNU Emacs.  It was
reworked completely and not much is left over from its time as part of
GNU Emacs.  Therefore the versions of emacsserver in both Emacs19 and Emacs20
doesn\'t look vulnerable to this bug, they don\'t even provide a MIT-MAGIC-COOKIE
based mechanism.

This could lead into a remote user issue commands under the UID of the
person running gnuserv.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-042');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-042
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA042] DSA-042-1 gnuserv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-042-1 gnuserv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnuserv', release: '2.2', reference: '2.1alpha-5.1');
deb_check(prefix: 'xemacs21', release: '2.2', reference: '21.1.10-5');
deb_check(prefix: 'xemacs21-bin', release: '2.2', reference: '21.1.10-5');
deb_check(prefix: 'xemacs21-mule', release: '2.2', reference: '21.1.10-5');
deb_check(prefix: 'xemacs21-mule-canna-wnn', release: '2.2', reference: '21.1.10-5');
deb_check(prefix: 'xemacs21-nomule', release: '2.2', reference: '21.1.10-5');
deb_check(prefix: 'xemacs21-support', release: '2.2', reference: '21.1.10-5');
deb_check(prefix: 'xemacs21-supportel', release: '2.2', reference: '21.1.10-5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
