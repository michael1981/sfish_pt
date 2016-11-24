
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8595
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34377);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-8595: postfix");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8595 (postfix)");
 script_set_attribute(attribute: "description", value: "Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
TLS

-
Update Information:

New upstream patch level version 2.5.5, including multiple security fixes
detailed in upstream announcements:
[9]http://www.postfix.org/announcements/20080814.html
[10]http://www.postfix.org/announcements/20080902.html
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2936", "CVE-2008-2937", "CVE-2008-3889");
script_summary(english: "Check for the version of the postfix package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"postfix-2.5.5-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
