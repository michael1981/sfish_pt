# This script was automatically generated from the dsa-336
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15173);
 script_version("$Revision: 1.14 $");
 script_xref(name: "DSA", value: "336");
 script_bugtraq_id(4259);
 script_bugtraq_id(6420);
 script_bugtraq_id(6535);
 script_bugtraq_id(7112);
 script_bugtraq_id(7600);
 script_bugtraq_id(7601);
 script_bugtraq_id(7791);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-336 security update');
 script_set_attribute(attribute: 'description', value:
'A number of vulnerabilities have been discovered in the Linux kernel.
This advisory provides updated 2.2.20 kernel source, and binary kernel
images for the i386 architecture.  Other architectures and kernel
versions will be covered by separate advisories.
For the stable distribution (woody) on the i386 architecture, these
problems have been fixed in kernel-source-2.2.20 version
2.2.20-5woody2 and kernel-image-i386 version 2.2.20-5woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-336');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-336
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA336] DSA-336-1 linux-kernel-2.2.20");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2002-0429", "CVE-2002-1380", "CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247");
 script_summary(english: "DSA-336-1 linux-kernel-2.2.20");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-doc-2.2.20', release: '3.0', reference: '2.2.20-5woody2');
deb_check(prefix: 'kernel-headers-2.2.20', release: '3.0', reference: '2.2.20-5woody3');
deb_check(prefix: 'kernel-headers-2.2.20-compact', release: '3.0', reference: '2.2.20-5woody3');
deb_check(prefix: 'kernel-headers-2.2.20-idepci', release: '3.0', reference: '2.2.20-5woody3');
deb_check(prefix: 'kernel-image-2.2.20', release: '3.0', reference: '2.2.20-5woody3');
deb_check(prefix: 'kernel-image-2.2.20-compact', release: '3.0', reference: '2.2.20-5woody3');
deb_check(prefix: 'kernel-image-2.2.20-idepci', release: '3.0', reference: '2.2.20-5woody3');
deb_check(prefix: 'kernel-source-2.2.20', release: '3.0', reference: '2.2.20-5woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
