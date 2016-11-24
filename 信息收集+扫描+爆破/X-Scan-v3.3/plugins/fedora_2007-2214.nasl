
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2214
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27758);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2214: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2214 (httpd)");
 script_set_attribute(attribute: "description", value: "The Apache HTTP Server is a powerful, efficient, and extensible
web server.

-
Update Information:

This update includes the latest stable release of the Apache HTTP Server.

A flaw was found in the Apache HTTP Server mod_proxy module. On sites where a r
everse proxy is configured, a remote attacker could send a carefully crafted re
quest that would cause the Apache child process handling that request to crash.
On sites where a forward proxy is configured, an attacker could cause a simila
r crash if a user could be persuaded to visit a
malicious site using the proxy. This could lead to a denial of service if using
a threaded Multi-Processing Module. (CVE-2007-3847)

A flaw was found in the mod_autoindex module.  On sites where directory listing
s are used, and the AddDefaultCharset directive has been removed from the confi
guration, a cross-site-scripting attack may be possible against browsers which
do not correctly derive the response character set following the rules in RFC 2
616. (CVE-2007-4465)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-5752", "CVE-2007-1862", "CVE-2007-3304", "CVE-2007-3847", "CVE-2007-4465");
script_summary(english: "Check for the version of the httpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"httpd-2.2.6-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
