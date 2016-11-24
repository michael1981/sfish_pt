# This script was automatically generated from the dsa-058
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14895);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "058");
 script_cve_id("CVE-2001-0690");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-058 security update');
 script_set_attribute(attribute: 'description', value:
'Megyer Laszlo found a printf format bug in the exim mail transfer
agent. The code that checks the header syntax of an email logs
an error without protecting itself against printf format attacks.
It\'s only exploitable locally with the -bS switch
(in batched SMTP mode).

This problem has been fixed in version 3.12-10.1. Since that code is
not turned on by default a standard installation is not vulnerable,
but we still recommend to upgrade your exim package.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-058');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-058
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA058] DSA-058-1 exim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-058-1 exim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'exim', release: '2.2', reference: '3.12-10.1');
deb_check(prefix: 'eximon', release: '2.2', reference: '3.12-10.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
