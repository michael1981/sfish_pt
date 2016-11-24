
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-5509
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38918);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-5509: jetty");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-5509 (jetty)");
 script_set_attribute(attribute: "description", value: "Jetty is a 100% Java HTTP Server and Servlet Container.
This means that you do not need to configure and run a
separate web server (like Apache) in order to use java,
servlets and JSPs to generate dynamic content. Jetty is
a fully featured web server for static and dynamic content.
Unlike separate server/container solutions, this means
that your web server and web application run in the same
process, without interconnection overheads and complications.
Furthermore, as a pure java component, Jetty can be simply
included in your application for demonstration, distribution
or deployment. Jetty is available on all Java supported
platforms.

-
Update Information:

This build upgrades jetty to 5.1.15 which addresses CVE-2009-1523.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1523", "CVE-2009-1524");
script_summary(english: "Check for the version of the jetty package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"jetty-5.1.15-4.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
