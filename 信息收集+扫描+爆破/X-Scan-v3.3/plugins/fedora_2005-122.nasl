#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16351);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0888");
 
 name["english"] = "Fedora Core 2 2005-122: cups";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-122 (cups).

The Common UNIX Printing System provides a portable printing layer for
UNIX operating systems. It has been developed by Easy Software
Products
to promote a standard printing solution for all UNIX vendors and
users.
CUPS provides the System V and Berkeley command-line interfaces.

Update Information:

A problem with PDF handling was discovered by Chris Evans, and has
been fixed. The Common Vulnerabilities and Exposures project
(www.mitre.org) has assigned the name CVE-2004-0888 to this issue.

FEDORA-2004-337 attempted to correct this but the patch was
incomplete." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=376" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the cups package";
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
if ( rpm_check( reference:"cups-1.1.20-11.11", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.20-11.11", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.20-11.11", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-debuginfo-1.1.20-11.11", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"cups-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
}
