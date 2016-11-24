# This script was automatically generated from the dsa-332
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15169);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "332");
 script_cve_id("CVE-2002-0429", "CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248");
 script_bugtraq_id(4259, 6535, 7112, 7600, 7601, 7791, 7793);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-332 security update');
 script_set_attribute(attribute: 'description', value:
'A number of vulnerabilities have been discovered in the Linux kernel.
This advisory provides corrected source code for Linux 2.4.17, and
corrected binary kernel images for the mips and mipsel architectures.
Other versions and architectures will be covered by separate
advisories.
For the stable distribution (woody), these problems have been fixed in
kernel-source-2.4.17 version 2.4.17-1woody1 and
kernel-patch-2.4.17-mips version 2.4.17-0.020226.2.woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-332');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-332
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA332] DSA-332-1 linux-kernel-2.4.17");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-332-1 linux-kernel-2.4.17");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-doc-2.4.17', release: '3.0', reference: '2.4.17-1woody1');
deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-0.020226.2.woody2');
deb_check(prefix: 'kernel-image-2.4.17-r3k-kn02', release: '3.0', reference: '2.4.17-0.020226.2.woody2');
deb_check(prefix: 'kernel-image-2.4.17-r4k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody2');
deb_check(prefix: 'kernel-image-2.4.17-r4k-kn04', release: '3.0', reference: '2.4.17-0.020226.2.woody2');
deb_check(prefix: 'kernel-image-2.4.17-r5k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody2');
deb_check(prefix: 'kernel-patch-2.4.17-mips', release: '3.0', reference: '2.4.17-0.020226.2.woody2');
deb_check(prefix: 'kernel-source-2.4.17', release: '3.0', reference: '2.4.17-1woody1');
deb_check(prefix: 'mips-tools', release: '3.0', reference: '2.4.17-0.020226.2.woody2');
deb_check(prefix: 'mkcramfs', release: '3.0', reference: '2.4.17-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
