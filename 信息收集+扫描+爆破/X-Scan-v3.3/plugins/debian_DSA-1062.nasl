# This script was automatically generated from the dsa-1062
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22604);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1062");
 script_cve_id("CVE-2006-2442");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1062 security update');
 script_set_attribute(attribute: 'description', value:
'Sven Dreyer discovered that KPhone, a Voice over IP client for KDE,
creates a configuration file world-readable, which could leak sensitive
information like SIP passwords.
The old stable distribution (woody) doesn\'t contain kphone packages.
For the stable distribution (sarge) this problem has been fixed in
version 4.1.0-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1062');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kphone package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1062] DSA-1062-1 kphone");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1062-1 kphone");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kphone', release: '3.1', reference: '4.1.0-2sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
