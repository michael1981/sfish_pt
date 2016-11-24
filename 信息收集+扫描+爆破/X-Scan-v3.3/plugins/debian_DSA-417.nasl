# This script was automatically generated from the dsa-417
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15254);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "417");
 script_cve_id("CVE-2003-0961", "CVE-2003-0985");
 script_bugtraq_id(9356);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-417 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Starzetz discovered a flaw in bounds checking in mremap() in the
Linux kernel (present in version 2.4.x and 2.6.x) which may allow a
local attacker to gain root privileges.  Version 2.2 is not affected
by this bug.
Andrew Morton discovered a missing boundary check for the brk system
call which can be used to craft a local root exploit.
For the stable distribution (woody) these problems have been fixed in
version 2.4.18-12 for the alpha architecture and in
version 2.4.18-1woody3 for the powerpc architecture.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-417');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA417] DSA-417-1 linux-kernel-2.4.18-powerpc+alpha");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-417-1 linux-kernel-2.4.18-powerpc+alpha");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-doc-2.4.18', release: '3.0', reference: '2.4.18-14.1');
deb_check(prefix: 'kernel-headers-2.4.18', release: '3.0', reference: '2.4.18-1woody3');
deb_check(prefix: 'kernel-headers-2.4.18-1', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-headers-2.4.18-1-generic', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-headers-2.4.18-1-smp', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-image-2.4.18-1-generic', release: '3.0', reference: '2.4.18-11');
deb_check(prefix: 'kernel-image-2.4.18-1-smp', release: '3.0', reference: '2.4.18-11');
deb_check(prefix: 'kernel-image-2.4.18-newpmac', release: '3.0', reference: '2.4.18-1woody3');
deb_check(prefix: 'kernel-image-2.4.18-powerpc', release: '3.0', reference: '2.4.18-1woody3');
deb_check(prefix: 'kernel-image-2.4.18-powerpc-smp', release: '3.0', reference: '2.4.18-1woody3');
deb_check(prefix: 'kernel-patch-2.4.18-powerpc', release: '3.0', reference: '2.4.18-1woody3');
deb_check(prefix: 'kernel-source-2.4.18', release: '3.0', reference: '2.4.18-14.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
