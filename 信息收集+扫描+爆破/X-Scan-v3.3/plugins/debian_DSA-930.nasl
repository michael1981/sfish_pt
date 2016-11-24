# This script was automatically generated from the dsa-930
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22796);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "930");
 script_cve_id("CVE-2006-0083");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-930 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar from the Debian Security Audit project discovered a
format string attack in the logging code of smstools, which may be
exploited to execute arbitrary code with root privileges.
The original advisory for this issue said that the old stable
distribution (woody) was not affected because it did not contain
smstools. This was incorrect, and the only change in this updated
advisory is the inclusion of corrected packages for woody.
For the old stable distribution (woody) this problem has been fixed in
version 1.5.0-2woody0.
For the stable distribution (sarge) this problem has been fixed in
version 1.14.8-1sarge0.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-930');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your smstools package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA930] DSA-930-2 smstools");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-930-2 smstools");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'smstools', release: '3.0', reference: '1.5.0-2woody0');
deb_check(prefix: 'smstools', release: '3.1', reference: '1.14.8-1sarge0');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
