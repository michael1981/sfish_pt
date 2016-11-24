#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16134);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-1235");
 
 name["english"] = "Fedora Core 2 2005-014: kernel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-014 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of
any Linux operating system. The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

This update rebases the kernel to match the upstream 2.6.10 release,
and adds a number of security fixes by means of adding the latest -ac
patch." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=262" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.6.10-   Release : 1.8_FC2", prefix:"kernel-", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-1235", value:TRUE);
}
