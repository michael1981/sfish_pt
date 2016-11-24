# This script was automatically generated from the dsa-1121
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22663);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1121");
 script_cve_id("CVE-2005-1127");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1121 security update');
 script_set_attribute(attribute: 'description', value:
'Peter Bieringer discovered that postgrey, a greylisting
implementation for Postfix, is vulnerable to a format string attack
that allows remote attackers to cause a denial of service to the daemon.
For the stable distribution (sarge) this problem has been fixed in
version 1.21-1sarge1.
For the stable distribution (sarge) this problem has also been fixed
in version 1.21-1volatile4 in the volatile archive.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1121');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your postgrey package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1121] DSA-1121-1 postgrey");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1121-1 postgrey");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'postgrey', release: '3.1', reference: '1.21-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
