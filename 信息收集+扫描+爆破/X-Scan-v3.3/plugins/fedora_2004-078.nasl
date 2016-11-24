#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13678);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0097");
 
 name["english"] = "Fedora Core 1 2004-078: pwlib";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-078 (pwlib).


PWLib is a cross-platform class library designed to support the OpenH323
project.  OpenH323 provides an implementation of the ITU H.323
teleconferencing protocol, used by packages such as Gnome Meeting.

Update Information:

A test suite for the H.225 protocol (part of the H.323 family) provided
by the NISCC uncovered bugs in PWLib prior to version 1.6.0.  An
attacker could trigger these bugs by sending carefully crafted messages
to an application.  The effects of such an attack can vary depending on
the application, but would usually result in a Denial of Service. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0097 to this issue.

Users are advised to upgrade to the update packages, which contain
backported security fixes and are not vulnerable to these issues.

Red Hat would like to thank Craig Southeren of the OpenH323 project for
providing the fixes for these issues." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-078.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the pwlib package";
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
if ( rpm_check( reference:"pwlib-1.5.0-4", prefix:"pwlib-", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"pwlib-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0097", value:TRUE);
}
