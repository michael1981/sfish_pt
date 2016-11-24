# This script was automatically generated from the dsa-403
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15240);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "403");
 script_cve_id("CVE-2003-0961");
 script_bugtraq_id(9138);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-403 security update');
 script_set_attribute(attribute: 'description', value:
'Recently multiple servers of the Debian project were compromised using a
Debian developers account and an unknown root exploit. Forensics
revealed a burneye encrypted exploit. Robert van der Meulen managed to
decrypt the binary which revealed a kernel exploit. Study of the exploit
by the Red Hat and SuSE kernel and security teams quickly revealed that
the exploit used an integer overflow in the brk system call. Using
this bug it is possible for a userland program to trick the kernel into
giving access to the full kernel address space. This problem was found
in September by Andrew Morton, but unfortunately that was too late for
the 2.4.22 kernel release.
This bug has been fixed in kernel version 2.4.23 for the 2.4 tree and
2.6.0-test6 kernel tree. For Debian it has been fixed in version
2.4.18-14 of the kernel source packages, version 2.4.18-12 of the i386
kernel images and version 2.4.18-11 of the alpha kernel images.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-403');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-403
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA403] DSA-403-1 kernel-image-2.4.18-1-alpha, kernel-image-2.4.18-1-i386, kernel-source-2.4.18");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-403-1 kernel-image-2.4.18-1-alpha, kernel-image-2.4.18-1-i386, kernel-source-2.4.18");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-doc-2.4.18', release: '3.0', reference: '2.4.18-14');
deb_check(prefix: 'kernel-headers-2.4.18-1', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-headers-2.4.18-1-386', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-headers-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-headers-2.4.18-1-686', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-headers-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-headers-2.4.18-1-generic', release: '3.0', reference: '2.4.18-11');
deb_check(prefix: 'kernel-headers-2.4.18-1-k6', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-headers-2.4.18-1-k7', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-headers-2.4.18-1-smp', release: '3.0', reference: '2.4.18-11');
deb_check(prefix: 'kernel-image-2.4.18-1-386', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-image-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-image-2.4.18-1-686', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-image-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-image-2.4.18-1-generic', release: '3.0', reference: '2.4.18-11');
deb_check(prefix: 'kernel-image-2.4.18-1-k6', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-image-2.4.18-1-k7', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-image-2.4.18-1-smp', release: '3.0', reference: '2.4.18-11');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-386', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-686', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-k6', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-k7', release: '3.0', reference: '2.4.18-12');
deb_check(prefix: 'kernel-source-2.4.18', release: '3.0', reference: '2.4.18-14');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
