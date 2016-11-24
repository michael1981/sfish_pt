
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-615
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25716);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-615: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-615 (httpd)");
 script_set_attribute(attribute: "description", value: "The Apache HTTP Server is a powerful, efficient, and extensible
web server.

Update Information:

The Apache HTTP Server did not verify that a process was an
Apache child process before sending it signals. A local
attacker with the ability to run scripts on the Apache HTTP
Server could manipulate the scoreboard and cause arbitrary
processes to be terminated which could lead to a denial of
service (CVE-2007-3304). This issue is not exploitable on
Fedora if using the default SELinux targeted policy.

A flaw was found in the Apache HTTP Server mod_status
module. On sites where the server-status page is publicly
accessible and ExtendedStatus is enabled this could lead to
a cross-site scripting attack. On Fedora the server-status
page is not enabled by default and it is best practice to
not make this publicly available. (CVE-2006-5752)

A bug was found in the Apache HTTP Server mod_cache module.
On sites where caching is enabled, a remote attacker could
send a carefully crafted request that would cause the Apache
child process handling that request to crash. This could
lead to a denial of service if using a threaded
Multi-Processing Module. (CVE-2007-1863)

A bug was found in the mod_mem_cache module. On sites where
caching is enabled using this module, an information leak
could occur which revealed portions of sensitive memory to
remote users. (CVE-2007-1862)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-5752", "CVE-2007-1862", "CVE-2007-1863", "CVE-2007-3304");
script_summary(english: "Check for the version of the httpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mod_ssl-2.2.4-2.1.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-2.2.4-2.1.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
