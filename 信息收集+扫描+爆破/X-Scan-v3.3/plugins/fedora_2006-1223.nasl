
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-1223
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24054);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2006-1223: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-1223 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

This updates to the latest upstream stable kernel
(2.6.18.2), and also fixes a number of security issues.

MOKB-05-11-2006: Linux 2.6.x ISO9660 __find_get_block_slow()
denial of service
[8]http://projects.info-pull.com/mokb/MOKB-05-11-2006.html
(CVE-2006-5757)

MOKB-07-11-2006: Linux 2.6.x zlib_inflate memory corruption
[9]http://projects.info-pull.com/mokb/MOKB-07-11-2006.html

MOKB-09-11-2006: Linux 2.6.x ext3fs_dirhash denial of service
[10]http://projects.info-pull.com/mokb/MOKB-10-11-2006.html

Herbert Xu found a security issue in the Xen hypervisor,
which would allow a malicious guest to access a freed grant
table page after freeing and possibly having it reallocated
to another guest.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-5757");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.18-1.2849.fc6", prefix:"kernel-", release:"FC6") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
