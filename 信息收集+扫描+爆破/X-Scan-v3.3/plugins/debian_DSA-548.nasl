# This script was automatically generated from the dsa-548
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15385);
 script_version("$Revision: 1.13 $");
 script_xref(name: "DSA", value: "548");
 script_cve_id("CVE-2004-0817");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-548 security update');
 script_set_attribute(attribute: 'description', value:
'Marcus Meissner discovered a heap overflow error in imlib, an imaging
library for X and X11, that could be abused by an attacker to execute
arbitrary code on the victim\'s machine.  The updated packages we have
provided in DSA 548-1 did not seem to be sufficient, which should be
fixed by this update.
For the old stable distribution (woody) this problem has been fixed in
version 1.9.14-2woody3.
For the stable distribution (sarge) this problem has been fixed in
version 1.9.14-16.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-548');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your imlib1 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA548] DSA-548-2 imlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-548-2 imlib");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gdk-imlib-dev', release: '3.0', reference: '1.9.14-2woody3');
deb_check(prefix: 'gdk-imlib1', release: '3.0', reference: '1.9.14-2woody3');
deb_check(prefix: 'imlib-base', release: '3.0', reference: '1.9.14-2woody3');
deb_check(prefix: 'imlib-dev', release: '3.0', reference: '1.9.14-2woody3');
deb_check(prefix: 'imlib-progs', release: '3.0', reference: '1.9.14-2woody3');
deb_check(prefix: 'imlib1', release: '3.0', reference: '1.9.14-2woody3');
deb_check(prefix: 'imlib', release: '3.1', reference: '1.9.14-16.2');
deb_check(prefix: 'imlib', release: '3.0', reference: '1.9.14-2woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
