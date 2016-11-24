#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15544);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0888");
 
 name["english"] = "Fedora Core 2 2004-348: xpdf";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-348 (xpdf).

Xpdf is an X Window System based viewer for Portable Document Format
(PDF) files. Xpdf is a small and efficient program which uses
standard X fonts.

Update Information:

Xpdf is an X Window System based viewer for Portable Document Format
(PDF) files.

During a source code audit, Chris Evans and others discovered a number
of integer overflow bugs that affected all versions of xpdf. An
attacker could construct a carefully crafted PDF file that could cause
xpdf to crash or possibly execute arbitrary code when opened. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0888 to this issue.

Users of xpdf are advised to upgrade to this errata package, which contains
a backported patch correcting these issues." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-348.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the xpdf package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"xpdf-3.00-3.4", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-debuginfo-3.00-3.4", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"xpdf-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
}
