
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7663
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34140);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-7663: awstats");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7663 (awstats)");
 script_set_attribute(attribute: "description", value: "Advanced Web Statistics is a powerful and featureful tool that generates
advanced web server graphic statistics. This server log analyzer works
from command line or as a CGI and shows you all information your log contains,
in graphical web pages. It can analyze a lot of web/wap/proxy servers like
Apache, IIS, Weblogic, Webstar, Squid, ... but also mail or ftp servers.

This program can measure visits, unique vistors, authenticated users, pages,
domains/countries, OS busiest times, robot visits, type of files, search
engines/keywords used, visits duration, HTTP errors and more...
Statistics can be updated from a browser or your scheduler.
The program also supports virtual servers, plugins and a lot of features.

With the default configuration, the statistics are available:
[9]http://localhost/awstats/awstats.pl

-
Update Information:

Add upstream patch for CVE-2008-3714
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3714");
script_summary(english: "Check for the version of the awstats package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"awstats-6.8-2.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
