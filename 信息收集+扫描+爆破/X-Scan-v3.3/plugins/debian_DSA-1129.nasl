# This script was automatically generated from the dsa-1129
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22671);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1129");
 script_cve_id("CVE-2006-3120");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1129 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar and Max Vozeler from the Debian Security Audit Project
have found several format string security bugs in osiris, a
network-wide system integrity monitor control interface.  A remote
attacker could exploit them and cause a denial of service or execute
arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 4.0.6-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1129');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your osiris packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1129] DSA-1129-1 osiris");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1129-1 osiris");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'osiris', release: '3.1', reference: '4.0.6-1sarge1');
deb_check(prefix: 'osirisd', release: '3.1', reference: '4.0.6-1sarge1');
deb_check(prefix: 'osirismd', release: '3.1', reference: '4.0.6-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
