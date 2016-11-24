# This script was automatically generated from the dsa-276
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15113);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "276");
 script_cve_id("CVE-2003-0127");
 script_bugtraq_id(7112);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-276 security update');
 script_set_attribute(attribute: 'description', value:
'The kernel module loader in Linux 2.2 and Linux 2.4 kernels has a flaw
in ptrace.  This hole allows local users to obtain root privileges by
using ptrace to attach to a child process that is spawned by the
kernel.  Remote exploitation of this hole is not possible.
This advisory only covers kernel packages for the S/390 architecture.
Other architectures will be covered by separate advisories.
For the stable distribution (woody) this problem has been fixed in the
following versions:
The old stable distribution (potato) is not affected by this problem
for this architecture since s390 was first released with Debian
GNU/Linux 3.0 (woody).
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-276');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel-images packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA276] DSA-276-1 linux-kernel-s390");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-276-1 linux-kernel-s390");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-2.woody.2.2');
deb_check(prefix: 'kernel-image-2.4.17-s390', release: '3.0', reference: '2.4.17-2.woody.2.2');
deb_check(prefix: 'kernel-patch-2.4.17-s390', release: '3.0', reference: '0.0.20020816-0.woody.1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
