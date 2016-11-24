
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23897);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:151: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:151 (kernel).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
Prior to and including 2.6.16-rc2, when running on x86_64 systems with
preemption enabled, local users can cause a DoS (oops) via multiple
ptrace tasks that perform single steps (CVE-2006-1066).
Prior to 2.6.16, a directory traversal vulnerability in CIFS could
allow a local user to escape chroot restrictions for an SMB-mounted
filesystem via '..\' sequences (CVE-2006-1863).
Prior to 2.6.16, a directory traversal vulnerability in smbfs could
allow a local user to escape chroot restrictions for an SMB-mounted
filesystem via '..\' sequences (CVE-2006-1864).
Prior to to 2.6.16.23, SCTP conntrack in netfilter allows remote
attackers to cause a DoS (crash) via a packet without any chunks,
causing a variable to contain an invalid value that is later used to
dereference a pointer (CVE-2006-2934).
The dvd_read_bca function in the DVD handling code assigns the wrong
value to a length variable, which could allow local users to execute
arbitrary code via a crafted USB storage device that triggers a buffer
overflow (CVE-2006-2935).
Prior to 2.6.17, the ftdi_sio driver could allow local users to cause
a DoS (memory consumption) by writing more data to the serial port than
the hardware can handle, causing the data to be queued (CVE-2006-2936).
The 2.6 kernel, when using both NFS and EXT3, allowed remote attackers
to cause a DoS (file system panic) via a crafted UDP packet with a V2
lookup procedure that specifies a bad file handle (inode number),
triggering an error and causing an exported directory to be remounted
read-only (CVE-2006-3468).
The 2.6 kernel's SCTP was found to cause system crashes and allow for
the possibility of local privilege escalation due to a bug in the
get_user_iov_size() function that doesn't properly handle overflow when
calculating the length of iovec (CVE-2006-3745).
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.
In addition to these security fixes, other fixes have been included
such as:
- added support for new devices:
o Testo products in usb-serial
o ATI SB600 IDE
o ULI M-1573 south Bridge
o PATA and SATA support for nVidia MCP55, MCP61, MCP65, and AMD CS5536
o Asus W6A motherboard in snd-hda-intel
o bcm 5780
- fixed ip_gre module unload OOPS
- enabled opti621 driver for x86 and x86_64
- fixed a local DoS introduced by an imcomplete fix for CVE-2006-2445
- updated to Xen 3.0.1 with selected fixes
- enable hugetlbfs
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:151");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-1066", "CVE-2006-1863", "CVE-2006-1864", "CVE-2006-2445", "CVE-2006-2934", "CVE-2006-2935", "CVE-2006-2936", "CVE-2006-3468", "CVE-2006-3745");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.25mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1066", value:TRUE);
 set_kb_item(name:"CVE-2006-1863", value:TRUE);
 set_kb_item(name:"CVE-2006-1864", value:TRUE);
 set_kb_item(name:"CVE-2006-2445", value:TRUE);
 set_kb_item(name:"CVE-2006-2934", value:TRUE);
 set_kb_item(name:"CVE-2006-2935", value:TRUE);
 set_kb_item(name:"CVE-2006-2936", value:TRUE);
 set_kb_item(name:"CVE-2006-3468", value:TRUE);
 set_kb_item(name:"CVE-2006-3745", value:TRUE);
}
exit(0, "Host is not affected");
