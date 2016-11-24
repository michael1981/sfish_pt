# This script was automatically generated from the dsa-545
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15382);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "545");
 script_cve_id("CVE-2004-0558");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-545 security update');
 script_set_attribute(attribute: 'description', value:
'Alvaro Martinez Echevarria discovered a problem in CUPS, the Common
UNIX Printing System.  An attacker can easily disable browsing in CUPS
by sending a specially crafted UDP datagram to port 631 where cupsd is
running.
For the stable distribution (woody) this problem has been fixed in
version 1.1.14-5woody6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-545');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cups packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA545] DSA-545-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-545-1 cupsys");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody6');
deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5woody6');
deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5woody6');
deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5woody6');
deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5woody6');
deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5woody6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
