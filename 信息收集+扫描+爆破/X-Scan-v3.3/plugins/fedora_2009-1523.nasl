
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1523
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37920);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-1523: squidGuard");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1523 (squidGuard)");
 script_set_attribute(attribute: "description", value: "squidGuard can be used to
- limit the web access for some users to a list of accepted/well known
web servers and/or URLs only.
- block access to some listed or blacklisted web servers and/or URLs
for some users.
- block access to URLs matching a list of regular expressions or words
for some users.
- enforce the use of domainnames/prohibit the use of IP address in
URLs.
- redirect blocked URLs to an 'intelligent' CGI based info page.
- redirect unregistered user to a registration form.
- redirect popular downloads like Netscape, MSIE etc. to local copies.
- redirect banners to an empty GIF.
- have different access rules based on time of day, day of the week,
date etc.
- have different rules for different user groups.
- and much more..

Neither squidGuard nor Squid can be used to
- filter/censor/edit text inside documents
- filter/censor/edit embeded scripting languages like JavaScript or
VBscript inside HTML

-
Update Information:

Update to 1.2.1, and patch for SG-2008-06-13
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the squidGuard package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"squidGuard-1.2.1-2.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
