
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37509);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:162: qemu");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:162 (qemu).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities have been found in Qemu.
Multiple heap-based buffer overflows in the cirrus_invalidate_region
function in the Cirrus VGA extension in QEMU 0.8.2, as used in Xen and
possibly other products, might allow local users to execute arbitrary
code via unspecified vectors related to attempting to mark non-existent
regions as dirty, aka the bitblt heap overflow. (CVE-2007-1320)
Integer signedness error in the NE2000 emulator in QEMU 0.8.2,
as used in Xen and possibly other products, allows local users to
trigger a heap-based buffer overflow via certain register values
that bypass sanity checks, aka QEMU NE2000 receive integer signedness
error. (CVE-2007-1321)
QEMU 0.8.2 allows local users to halt a virtual machine by executing
the icebp instruction. (CVE-2007-1322)
QEMU 0.8.2 allows local users to crash a virtual machine via the
divisor operand to the aam instruction, as demonstrated by aam 0x0,
which triggers a divide-by-zero error. (CVE-2007-1366)
The NE2000 emulator in QEMU 0.8.2 allows local users to execute
arbitrary code by writing Ethernet frames with a size larger than
the MTU to the EN0_TCNT register, which triggers a heap-based
buffer overflow in the slirp library, aka NE2000 mtu heap
overflow. (CVE-2007-5729)
Heap-based buffer overflow in QEMU 0.8.2, as used in Xen and possibly
other products, allows local users to execute arbitrary code via
crafted data in the net socket listen option, aka QEMU net socket
heap overflow. (CVE-2007-5730)
QEMU 0.9.0 allows local users of a Windows XP SP2 guest operating
system to overwrite the TranslationBlock (code_gen_buffer) buffer,
and probably have unspecified other impacts related to an overflow,
via certain Windows executable programs, as demonstrated by
qemu-dos.com. (CVE-2007-6227)
Qemu 0.9.1 and earlier does not perform range checks for block
device read or write requests, which allows guest host users with
root privileges to access arbitrary memory and escape the virtual
machine. (CVE-2008-0928)
Changing removable media in QEMU could trigger a bug similar to
CVE-2008-2004, which would allow local guest users to read arbitrary
files on the host by modifying the header of the image to identify
a different format. (CVE-2008-1945) See the diskformat: parameter to
the -usbdevice option.
The drive_init function in QEMU 0.9.1 determines the format of
a raw disk image based on the header, which allows local guest
users to read arbitrary files on the host by modifying the header
to identify a different format, which is used when the guest is
restarted. (CVE-2008-2004) See the -format option.
The updated packages have been patched to fix these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:162");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-1322", "CVE-2007-1366", "CVE-2007-5729", "CVE-2007-5730", "CVE-2007-6227", "CVE-2008-0928", "CVE-2008-1945", "CVE-2008-2004");
script_summary(english: "Check for the version of the qemu package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dkms-kqemu-1.3.0-0.pre11.13.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qemu-0.9.0-16.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qemu-img-0.9.0-16.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dkms-kqemu-1.3.0-0.pre11.15.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qemu-0.9.0-18.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qemu-img-0.9.0-18.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"qemu-", release:"MDK2008.0")
 || rpm_exists(rpm:"qemu-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2007-1320", value:TRUE);
 set_kb_item(name:"CVE-2007-1321", value:TRUE);
 set_kb_item(name:"CVE-2007-1322", value:TRUE);
 set_kb_item(name:"CVE-2007-1366", value:TRUE);
 set_kb_item(name:"CVE-2007-5729", value:TRUE);
 set_kb_item(name:"CVE-2007-5730", value:TRUE);
 set_kb_item(name:"CVE-2007-6227", value:TRUE);
 set_kb_item(name:"CVE-2008-0928", value:TRUE);
 set_kb_item(name:"CVE-2008-1945", value:TRUE);
 set_kb_item(name:"CVE-2008-2004", value:TRUE);
}
exit(0, "Host is not affected");
