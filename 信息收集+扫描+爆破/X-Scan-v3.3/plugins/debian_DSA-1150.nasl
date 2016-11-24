# This script was automatically generated from the dsa-1150
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22692);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1150");
 script_cve_id("CVE-2006-3378");
 script_bugtraq_id(18850);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1150 security update');
 script_set_attribute(attribute: 'description', value:
'A bug has been discovered in several packages that execute the
setuid() system call without checking for success when trying to drop
privileges, which may fail with some PAM configurations.
For the stable distribution (sarge) this problem has been fixed in
version 4.0.3-31sarge8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1150');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your passwd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1150] DSA-1150-1 shadow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1150-1 shadow");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'login', release: '3.1', reference: '4.0.3-31sarge8');
deb_check(prefix: 'passwd', release: '3.1', reference: '4.0.3-31sarge8');
deb_check(prefix: 'shadow', release: '3.1', reference: '4.0.3-31sarge8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
