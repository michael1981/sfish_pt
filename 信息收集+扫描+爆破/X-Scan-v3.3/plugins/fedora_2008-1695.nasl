
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1695
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31103);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-1695: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1695 (httpd)");
 script_set_attribute(attribute: "description", value: "The Apache HTTP Server is a powerful, efficient, and extensible
web server.

-
Update Information:

This update includes the latest release of httpd 2.2, which fixes a number of
minor security issues and other bugs.    A flaw was found in the mod_imagemap
module. On sites where mod_imagemap was enabled and an imagemap file was
publicly available, a cross-site scripting attack was possible. (CVE-2007-5000)
A flaw was found in the mod_status module. On sites where mod_status was enable
d
and the status pages were publicly accessible, a cross-site scripting attack wa
s
possible. (CVE-2007-6388)    A flaw was found in the mod_proxy_balancer module.
On sites where  mod_proxy_balancer was enabled, a cross-site scripting attack
against an authorized user was possible. (CVE-2007-6421)    A flaw was found in
the mod_proxy_balancer module. On sites where  mod_proxy_balancer was enabled,
an authorized user could send a carefully crafted request that would cause the
Apache child process handling that request to crash. This could lead to a denia
l
of service if using a threaded Multi-Processing Module. (CVE-2007-6422)    A
flaw was found in the mod_proxy_ftp module. On sites where  mod_proxy_ftp was
enabled and a forward proxy was configured, a  cross-site scripting attack was
possible against browsers which do not correctly derive the response character
set following the rules in RFC 2616. (CVE-2008-0005)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5000", "CVE-2007-6388", "CVE-2007-6421", "CVE-2007-6422", "CVE-2008-0005");
script_summary(english: "Check for the version of the httpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"httpd-2.2.8-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
