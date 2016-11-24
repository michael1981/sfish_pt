# This script was automatically generated from the dsa-1284
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25151);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "1284");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1284 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the QEMU processor
emulator, which may lead to the execution of arbitrary code or denial of
service. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-1320
    Tavis Ormandy discovered that a memory management routine of the Cirrus
    video driver performs insufficient bounds checking, which might
    allow the execution of arbitrary code through a heap overflow.
CVE-2007-1321
    Tavis Ormandy discovered that the NE2000 network driver and the socket
    code perform insufficient input validation, which might allow the
    execution of arbitrary code through a heap overflow.
CVE-2007-1322
    Tavis Ormandy discovered that the <q>icebp</q> instruction can be abused to
    terminate the emulation, resulting in denial of service.
CVE-2007-1323
    Tavis Ormandy discovered that the NE2000 network driver and the socket
    code perform insufficient input validation, which might allow the
    execution of arbitrary code through a heap overflow.
CVE-2007-1366
    Tavis Ormandy discovered that the <q>aam</q> instruction can be abused to
    crash qemu through a division by zero, resulting in denial of
    service.
For the oldstable distribution (sarge) these problems have been fixed in
version 0.6.1+20050407-1sarge1.
For the stable distribution (etch) these problems have been fixed
in version 0.8.2-4etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1284');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your qemu packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1284] DSA-1284-1 qemu");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-1322", "CVE-2007-1366", "CVE-2007-2893");
 script_summary(english: "DSA-1284-1 qemu");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'qemu', release: '3.1', reference: '0.6.1+20050407-1sarge1');
deb_check(prefix: 'qemu', release: '4.0', reference: '0.8.2-4etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
