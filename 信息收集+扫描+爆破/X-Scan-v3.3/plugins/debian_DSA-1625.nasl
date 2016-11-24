# This script was automatically generated from the dsa-1625
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33774);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1625");
 script_cve_id("CVE-2008-0053", "CVE-2008-1373", "CVE-2008-1722");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1625 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Common Unix
Printing System (CUPS). The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2008-0053
    Buffer overflows in the HP-GL input filter allowed to possibly run
    arbitrary code through crafted HP-GL files.
CVE-2008-1373
    Buffer overflow in the GIF filter allowed to possibly run arbitrary
    code through crafted GIF files.
CVE-2008-1722
    Integer overflows in the PNG filter allowed to possibly run arbitrary
    code through crafted PNG files.
For the stable distribution (etch), these problems have been fixed in
version 1.2.7-4etch4 of package cupsys.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1625');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cupsys package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1625] DSA-1625-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1625-1 cupsys");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cupsys', release: '4.0', reference: '1.2.7-4etch4');
deb_check(prefix: 'cupsys-bsd', release: '4.0', reference: '1.2.7-4etch4');
deb_check(prefix: 'cupsys-client', release: '4.0', reference: '1.2.7-4etch4');
deb_check(prefix: 'cupsys-common', release: '4.0', reference: '1.2.7-4etch4');
deb_check(prefix: 'cupsys-dbg', release: '4.0', reference: '1.2.7-4etch4');
deb_check(prefix: 'libcupsimage2', release: '4.0', reference: '1.2.7-4etch4');
deb_check(prefix: 'libcupsimage2-dev', release: '4.0', reference: '1.2.7-4etch4');
deb_check(prefix: 'libcupsys2', release: '4.0', reference: '1.2.7-4etch4');
deb_check(prefix: 'libcupsys2-dev', release: '4.0', reference: '1.2.7-4etch4');
deb_check(prefix: 'libcupsys2-gnutls10', release: '4.0', reference: '1.2.7-4etch4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
