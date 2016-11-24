
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8812
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40833);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-8812: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8812 (httpd)");
 script_set_attribute(attribute: "description", value: "The Apache HTTP Server is a powerful, efficient, and extensible
web server.

-
Update Information:

This update includes the latest release of the Apache HTTP Server, version
2.2.13, fixing several security issues:    * Fix a potential Denial-of-Service
attack against mod_deflate or other modules, by forcing the server to consume
CPU time in compressing a large file after a client disconnects.
(CVE-2009-1891)    * Prevent the 'Includes' Option from being enabled in an
.htaccess file if the AllowOverride restrictions do not permit it.
(CVE-2009-1195)    * Fix a potential Denial-of-Service attack against mod_proxy
in a reverse proxy configuration, where a remote attacker can force a proxy
process to consume CPU time indefinitely. (CVE-2009-1890)    * mod_proxy_ajp:
Avoid delivering content from a previous request which failed to send a request
body.  (CVE-2009-1191)    Many bug fixes are also included; see the upstream
changelog for further details:
[9]http://www.apache.org/dist/httpd/CHANGES_2.2.13
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1191", "CVE-2009-1195", "CVE-2009-1890", "CVE-2009-1891");
script_summary(english: "Check for the version of the httpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"httpd-2.2.13-1.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
