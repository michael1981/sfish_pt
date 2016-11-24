# This script was automatically generated from the dsa-1394
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27549);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1394");
 script_cve_id("CVE-2007-4739");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1394 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that reprepro, a tool to create a repository of Debian
packages, only checks the validity of known signatures when updating
from a remote site, and thus does not reject packages with only unknown
signatures. This allows an attacker to bypass this authentication
mechanism.
The oldstable distribution (sarge) is not affected by this problem.
For the stable distribution (etch) this problem has been fixed in
version 1.3.1+1-1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1394');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your reprepro package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1394] DSA-1394-1 reprepro");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1394-1 reprepro");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'reprepro', release: '4.0', reference: '1.3.1+1-1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
