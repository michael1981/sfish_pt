#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19868);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-2492");
 
 name["english"] = "Fedora Core 3 2005-905: kernel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-905 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.


* Wed Sep 14 2005 Dave Jones <davej redhat com> [2.6.12-1.1378_FC3]
- Fixes for CVE-2005-2490 and CVE-2005-2492

* Mon Sep  5 2005 Dave Jones <davej redhat com>
- Fix aic7xxx issue with >4GB. (#167049)

* Fri Sep  2 2005 Dave Jones <davej redhat com> [2.6.12-1.1377_FC3]
- Various post 2.6.13 ACPI updates. (20050902)

* Mon Aug 29 2005 Dave Jones <davej redhat com>
- Fix local builds when '-' is in the hostname.
- Update ALPS driver to 2.6.13 level" );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
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
if ( rpm_check( reference:"kernel-2.6.12-1.1378_FC3", prefix:"kernel-", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2492", value:TRUE);
}
