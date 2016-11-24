
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-11710
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42849);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 12 2009-11710: wordpress");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-11710 (wordpress)");
 script_set_attribute(attribute: "description", value: "Wordpress is an online publishing / weblog package that makes it very easy,
almost trivial, to get information out to people on the web.

-
Update Information:

2.8.6 fixes two security problems that can be exploited by registered, logged i
n
users who have posting privileges.  If you have untrusted authors on your blog,
upgrading to 2.8.6 is recommended.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the wordpress package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"wordpress-2.8.6-2.fc12", release:"FC12") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
