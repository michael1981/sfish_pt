
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3010
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31824);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-3010: pdns-recursor");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3010 (pdns-recursor)");
 script_set_attribute(attribute: "description", value: "PowerDNS Recursor is a non authoritative/recursing DNS server. Use this
package if you need a dns cache for your network.

-
ChangeLog:


Update information :

* Wed Apr  2 2008 Ruben Kerkhof <ruben rubenkerkhof com> 3.1.5-1
- Upstream released new version
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1637");
script_summary(english: "Check for the version of the pdns-recursor package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"pdns-recursor-3.1.5-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
