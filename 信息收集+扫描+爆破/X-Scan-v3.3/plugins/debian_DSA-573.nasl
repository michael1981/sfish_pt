# This script was automatically generated from the dsa-573
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15671);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "573");
 script_cve_id("CVE-2004-0888");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-573 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans discovered several integer overflows in xpdf, that are
also present in CUPS, the Common UNIX Printing System, which can be
exploited remotely by a specially crafted PDF document.
For the stable distribution (woody) these problems have been fixed in
version 1.1.14-5woody10.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-573');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your CUPS packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA573] DSA-573-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-573-1 cupsys");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody10');
deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5woody10');
deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5woody10');
deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5woody10');
deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5woody10');
deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5woody10');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
