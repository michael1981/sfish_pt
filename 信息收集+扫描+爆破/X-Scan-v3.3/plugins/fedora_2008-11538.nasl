
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11538
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35232);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-11538: rsyslog");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11538 (rsyslog)");
 script_set_attribute(attribute: "description", value: "Rsyslog is an enhanced multi-threaded syslogd supporting, among others, MySQL,
syslog/tcp, RFC 3195, permitted sender lists, filtering on any message part,
and fine grain output format control. It is quite compatible to stock sysklogd
and can be used as a drop-in replacement. Its advanced features make it
suitable for enterprise-class, encryption protected syslog relay chains while
at the same time being very easy to setup for the novice user.

-
Update Information:

Security fixes for CVE-2008-5617 and CVE-2008-5618, detailed in:
[9]http://www.rsyslog.com/Article322.phtml  [10]http://secunia.com/Advisories/3
2857/
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5617", "CVE-2008-5618");
script_summary(english: "Check for the version of the rsyslog package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"rsyslog-3.20.2-2.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
