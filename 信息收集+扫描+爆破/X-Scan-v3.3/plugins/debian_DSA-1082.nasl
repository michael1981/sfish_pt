# This script was automatically generated from the dsa-1082
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22624);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1082");
 script_cve_id("CVE-2003-0984", "CVE-2004-0138", "CVE-2004-0394", "CVE-2004-0427", "CVE-2004-0447", "CVE-2004-0554", "CVE-2004-0565");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1082 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2004-0427
     A local denial of service vulnerability in do_fork() has been found.
CVE-2005-0489
     A local denial of service vulnerability in proc memory handling has
     been found.
CVE-2004-0394
     A buffer overflow in the panic handling code has been found.
CVE-2004-0447
     A local denial of service vulnerability through a null pointer
     dereference in the IA64 process handling code has been found.
CVE-2004-0554
     A local denial of service vulnerability through an infinite loop in
     the signal handler code has been found.
CVE-2004-0565
     An information leak in the context switch code has been found on
     the IA64 architecture.
CVE-2004-0685
     Unsafe use of copy_to_user in USB drivers may disclose sensitive
     information.
CVE-2005-0001
     A race condition in the i386 page fault handler may allow privilege
     escalation.
CVE-2004-0883
     Multiple vulnerabilities in the SMB filesystem code may allow denial
     of service or information disclosure.
CVE-2004-0949
     An information leak discovered in the SMB filesystem code.
CVE-2004-1016
     A local denial of service vulnerability has been found in the SCM layer.
CVE-2004-1333
     An integer overflow in the terminal code may allow a local denial of
     service vulnerability.
CVE-2004-0997
     A local privilege escalation in the MIPS assembly code has been found.
CVE-2004-1335
     A memory leak in the ip_options_get() function may lead to denial of
     service.
CVE-2004-1017
     Multiple overflows exist in the io_edgeport driver which might be usable
     as a denial of service attack vector.
CVE-2005-0124
     Bryan Fulton reported a bounds checking bug in the coda_pioctl function
     which may allow local users to execute arbitrary code or trigger a denial
     of service attack.
CVE-2003-0984
     Inproper initialization of the RTC may disclose information.
CVE-2004-1070
     Insufficient input sanitising in the load_elf_binary() function may
     lead to privilege escalation.
CVE-2004-1071
     Incorrect error handling in the binfmt_elf loader may lead to privilege
     escalation.
CVE-2004-1072
     A buffer overflow in the binfmt_elf loader may lead to privilege
     escalation or denial of service.
CVE-2004-1073
     The open_exec function may disclose information.
CVE-2004-1074
     The binfmt code is vulnerable to denial of service through malformed
     a.out binaries.
CVE-2004-0138
     A denial of service vulnerability in the ELF loader has been found.
CVE-2004-1068
     A programming error in the unix_dgram_recvmsg() function may lead to
     privilege escalation.
CVE-2004-1234
     The ELF loader is vulnerable to denial of service through malformed
     binaries.
CVE-2005-0003
     Crafted ELF binaries may lead to privilege escalation, due to 
     insufficient checking of overlapping memory regions.
CVE-2004-1235
     A race condition in the load_elf_library() and binfmt_aout()
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1082');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1082] DSA-1082-1 kernel-source-2.4.17");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1082-1 kernel-source-2.4.17");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-doc-2.4.17', release: '3.0', reference: '2.4.17-1woody4');
deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-0.020226.2.woody7');
deb_check(prefix: 'kernel-headers-2.4.17-apus', release: '3.0', reference: '2.4.17-6');
deb_check(prefix: 'kernel-headers-2.4.17-hppa', release: '3.0', reference: '32.5');
deb_check(prefix: 'kernel-headers-2.4.17-ia64', release: '3.0', reference: '011226.18');
deb_check(prefix: 'kernel-image-2.4.17-32', release: '3.0', reference: '32.5');
deb_check(prefix: 'kernel-image-2.4.17-32-smp', release: '3.0', reference: '32.5');
deb_check(prefix: 'kernel-image-2.4.17-64', release: '3.0', reference: '32.5');
deb_check(prefix: 'kernel-image-2.4.17-64-smp', release: '3.0', reference: '32.5');
deb_check(prefix: 'kernel-image-2.4.17-apus', release: '3.0', reference: '2.4.17-6');
deb_check(prefix: 'kernel-image-2.4.17-itanium', release: '3.0', reference: '011226.18');
deb_check(prefix: 'kernel-image-2.4.17-itanium-smp', release: '3.0', reference: '011226.18');
deb_check(prefix: 'kernel-image-2.4.17-mckinley', release: '3.0', reference: '011226.18');
deb_check(prefix: 'kernel-image-2.4.17-mckinley-smp', release: '3.0', reference: '011226.18');
deb_check(prefix: 'kernel-image-2.4.17-r3k-kn02', release: '3.0', reference: '2.4.17-0.020226.2.woody7');
deb_check(prefix: 'kernel-image-2.4.17-r4k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody7');
deb_check(prefix: 'kernel-image-2.4.17-r4k-kn04', release: '3.0', reference: '2.4.17-0.020226.2.woody7');
deb_check(prefix: 'kernel-image-2.4.17-r5k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody7');
deb_check(prefix: 'kernel-image-2.4.17-s390', release: '3.0', reference: '2.4.17-2.woody.5');
deb_check(prefix: 'kernel-image-apus', release: '3.0', reference: '2.4.17-6');
deb_check(prefix: 'kernel-patch-2.4.17-apus', release: '3.0', reference: '2.4.17-6');
deb_check(prefix: 'kernel-patch-2.4.17-mips', release: '3.0', reference: '2.4.17-0.020226.2.woody7');
deb_check(prefix: 'kernel-patch-2.4.17-s390', release: '3.0', reference: '0.0.20020816-0.woody.4');
deb_check(prefix: 'kernel-source-2.4.17', release: '3.0', reference: '2.4.17-1woody4');
deb_check(prefix: 'kernel-source-2.4.17-hppa', release: '3.0', reference: '32.5');
deb_check(prefix: 'kernel-source-2.4.17-ia64', release: '3.0', reference: '011226.18');
deb_check(prefix: 'mips-tools', release: '3.0', reference: '2.4.17-0.020226.2.woody7');
deb_check(prefix: 'mkcramfs', release: '3.0', reference: '2.4.17-1woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
