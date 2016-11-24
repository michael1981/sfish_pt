# This script was automatically generated from the dsa-950
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22816);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "950");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-950 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" and Chris Evans discovered several heap based buffer
overflows in xpdf which are also present in CUPS, the Common UNIX
Printing System, and which can lead to a denial of service by crashing
the application or possibly to the execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 1.1.14-5woody14.
CUPS doesn\'t use the xpdf source anymore since 1.1.22-7, when it switched
to using xpdf-utils for PDF processing.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-950');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your CUPS packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA950] DSA-950-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-950-1 cupsys");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody14');
deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5woody14');
deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5woody14');
deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5woody14');
deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5woody14');
deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5woody14');
deb_check(prefix: 'cupsys', release: '3.1', reference: '1.1.23-10sarge1');
deb_check(prefix: 'cupsys-bsd', release: '3.1', reference: '1.1.23-10sarge1');
deb_check(prefix: 'cupsys-client', release: '3.1', reference: '1.1.23-10sarge1');
deb_check(prefix: 'libcupsimage2', release: '3.1', reference: '1.1.23-10sarge1');
deb_check(prefix: 'libcupsimage2-dev', release: '3.1', reference: '1.1.23-10sarge1');
deb_check(prefix: 'libcupsys2', release: '3.1', reference: '1.1.23-10sarge1');
deb_check(prefix: 'libcupsys2-dev', release: '3.1', reference: '1.1.23-10sarge1');
deb_check(prefix: 'libcupsys2-gnutls10', release: '3.1', reference: '1.1.23-10sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
