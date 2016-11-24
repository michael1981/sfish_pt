#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14764);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0786");
 
 name["english"] = "Fedora Core 1 2004-307: apr-util";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-307 (apr-util).

The mission of the Apache Portable Runtime (APR) is to provide a
free library of C data structures and routines.  This library
contains additional utility interfaces for APR; including support
for XML, LDAP, database interfaces, URI parsing and more.

Update Information:

Testing using the Codenomicon HTTP Test Tool performed by the Apache
Software Foundation security group and Red Hat uncovered an input
validation issue in the IPv6 URI parsing routines in the apr-util
library.  If a remote attacker sent a request including a carefully
crafted URI, an httpd child process could be made to crash.  The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0786 to this issue.

This update includes a backported patch for this issue." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-307.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the apr-util package";
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
if ( rpm_check( reference:"apr-util-0.9.4-2.1", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-0.9.4-2.1", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-debuginfo-0.9.4-2.1", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"apr-util-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0786", value:TRUE);
}
