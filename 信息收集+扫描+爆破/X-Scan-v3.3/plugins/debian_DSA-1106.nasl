# This script was automatically generated from the dsa-1106
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22648);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1106");
 script_cve_id("CVE-2006-2194");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1106 security update');
 script_set_attribute(attribute: 'description', value:
'Marcus Meissner discovered that the winbind plugin in pppd does not
check whether a setuid() call has been successful when trying to drop
privileges, which may fail with some PAM configurations.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.4.3-20050321+2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1106');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ppp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1106] DSA-1106-1 ppp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1106-1 ppp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ppp', release: '3.1', reference: '2.4.3-20050321+2sarge1');
deb_check(prefix: 'ppp-dev', release: '3.1', reference: '2.4.3-20050321+2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
