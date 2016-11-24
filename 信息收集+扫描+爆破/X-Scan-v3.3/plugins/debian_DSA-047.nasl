# This script was automatically generated from the dsa-047
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38953);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "047");
 script_cve_id("CVE-2001-1390", "CVE-2001-1391", "CVE-2001-1392", "CVE-2001-1393", "CVE-2001-1394", "CVE-2001-1395", "CVE-2001-1396");
 script_bugtraq_id(2529);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-047 security update');
 script_set_attribute(attribute: 'description', value:
'The kernels used in Debian GNU/Linux 2.2 have been found to have 
multiple security problems. This is a list of problems based 
on the 2.2.19 release notes as found on 
http://www.linux.org.uk/:


binfmt_misc used user pages directly
the CPIA driver had an off-by-one error in the buffer code which made
  it possible for users to write into kernel memory
the CPUID and MSR drivers had a problem in the module unloading code
  which could cause a system crash if they were set to automatically load
  and unload (please note that Debian does not automatically unload kernel
  modules)
There was a possible hang in the classifier code
The getsockopt and setsockopt system calls did not handle sign bits
  correctly which made a local DoS and other attacks possible
The sysctl system call did not handle sign bits correctly which allowed
  a user to write in kernel memory
ptrace/exec races that could give a local user extra privileges
possible abuse of a boundary case in the sockfilter code
SYSV shared memory code could overwrite recently freed memory which might
  cause problems
The packet length checks in the masquerading code were a bit lax
  (probably not exploitable)
Some x86 assembly bugs caused the wrong number of bytes to be copied.
A local user could deadlock the kernel due to bugs in the UDP port
  allocation.


All these problems are fixed in the 2.2.19 kernel, and it is highly
recommend that you upgrade machines to this kernel.

Please note that kernel upgrades are not done automatically. You will
have to explicitly tell the packaging system to install the right kernel
for your system.


');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-047');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-047
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA047] DSA-047-1 kernel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-047-1 kernel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-doc-2.2.19', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-headers-2.2.19', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-headers-2.2.19-compact', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-headers-2.2.19-ide', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-headers-2.2.19-idepci', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-headers-2.2.19-sparc', release: '2.2', reference: '6');
deb_check(prefix: 'kernel-image-2.2.19', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-image-2.2.19-amiga', release: '2.2', reference: '2.2.19-1');
deb_check(prefix: 'kernel-image-2.2.19-atari', release: '2.2', reference: '2.2.19-1');
deb_check(prefix: 'kernel-image-2.2.19-bvme6000', release: '2.2', reference: '2.2.19-1');
deb_check(prefix: 'kernel-image-2.2.19-chrp', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-image-2.2.19-compact', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-image-2.2.19-generic', release: '2.2', reference: '2.2.19-1');
deb_check(prefix: 'kernel-image-2.2.19-ide', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-image-2.2.19-idepci', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-image-2.2.19-jensen', release: '2.2', reference: '2.2.19-1');
deb_check(prefix: 'kernel-image-2.2.19-mac', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-image-2.2.19-mvme147', release: '2.2', reference: '2.2.19-1');
deb_check(prefix: 'kernel-image-2.2.19-mvme16x', release: '2.2', reference: '2.2.19-1');
deb_check(prefix: 'kernel-image-2.2.19-nautilus', release: '2.2', reference: '2.2.19-1');
deb_check(prefix: 'kernel-image-2.2.19-pmac', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-image-2.2.19-prep', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-image-2.2.19-riscpc', release: '2.2', reference: '20010414');
deb_check(prefix: 'kernel-image-2.2.19-smp', release: '2.2', reference: '2.2.19-1');
deb_check(prefix: 'kernel-image-2.2.19-sun4cdm', release: '2.2', reference: '6');
deb_check(prefix: 'kernel-image-2.2.19-sun4dm-pci', release: '2.2', reference: '6');
deb_check(prefix: 'kernel-image-2.2.19-sun4dm-smp', release: '2.2', reference: '6');
deb_check(prefix: 'kernel-image-2.2.19-sun4u', release: '2.2', reference: '6');
deb_check(prefix: 'kernel-image-2.2.19-sun4u-smp', release: '2.2', reference: '6');
deb_check(prefix: 'kernel-patch-2.2.19-arm', release: '2.2', reference: '20010414');
deb_check(prefix: 'kernel-patch-2.2.19-m68k', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-patch-2.2.19-powerpc', release: '2.2', reference: '2.2.19-2');
deb_check(prefix: 'kernel-source-2.2.19', release: '2.2', reference: '2.2.19-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
