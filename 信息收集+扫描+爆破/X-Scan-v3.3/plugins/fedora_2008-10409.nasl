
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-10409
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37932);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2008-10409: php-Smarty");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-10409 (php-Smarty)");
 script_set_attribute(attribute: "description", value: "Although Smarty is known as a 'Template Engine', it would be more accurately
described as a 'Template/Presentation Framework.' That is, it provides the
programmer and template designer with a wealth of tools to automate tasks
commonly dealt with at the presentation layer of an application. I stress the
word Framework because Smarty is not a simple tag-replacing template engine.
Although it can be used for such a simple purpose, its focus is on quick and
painless development and deployment of your application, while maintaining
high-performance, scalability, security and future growth.

-
Update Information:

CVE-2008-4811
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-4811");
script_summary(english: "Check for the version of the php-Smarty package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"php-Smarty-2.6.20-2.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
