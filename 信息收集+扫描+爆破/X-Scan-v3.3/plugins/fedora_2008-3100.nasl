
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3100
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31979);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-3100: otrs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3100 (otrs)");
 script_set_attribute(attribute: "description", value: "OTRS is an Open source Ticket Request System (also well known as trouble ticket
system) with many features to manage customer telephone calls and e-mails. The
system is built to allow your support, sales, pre-sales, billing, internal IT,
helpdesk, etc. department to react quickly to inbound inquiries.

-
Update Information:

Security update: Add upstream patch for CVE-2008-1515 / OSA-2008-01
(Vulnerability in OTRS SOAP interface allowing remote access without  valid SOA
P
user - [9]http://otrs.org/advisory/OSA-2008-01-en/ )
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1515");
script_summary(english: "Check for the version of the otrs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"otrs-2.1.5-4.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
