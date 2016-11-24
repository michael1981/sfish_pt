# This script was automatically generated from the dsa-1799
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38747);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1799");
 script_cve_id("CVE-2008-0928", "CVE-2008-1945", "CVE-2008-4539");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1799 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the QEMU processor
emulator. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2008-0928
    Ian Jackson discovered that range checks of file operations on 
    emulated disk devices were insufficiently enforced.
CVE-2008-1945
    It was discovered that an error in the format auto detection of
    removable media could lead to the disclosure of files in the
    host system.
CVE-2008-4539
    A buffer overflow has been found in the emulation of the Cirrus
    graphics adaptor.
For the old stable distribution (etch), these problems have been fixed in
version 0.8.2-4etch3.
For the stable distribution (lenny), these problems have been fixed in
version 0.9.1-10lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1799');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your qemu packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1799] DSA-1799-1 qemu");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1799-1 qemu");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'qemu', release: '4.0', reference: '0.8.2-4etch3');
deb_check(prefix: 'qemu', release: '5.0', reference: '0.9.1-10lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
