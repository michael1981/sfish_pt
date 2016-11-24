
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3543
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33144);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-3543: kronolith");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3543 (kronolith)");
 script_set_attribute(attribute: "description", value: "Kronolith is the Horde calendar application.  It provides repeating
events, all-day events, custom fields, keywords, and managing multiple
users through Horde Authentication.  The calendar API that Kronolith
uses is abstracted; MCAL and SQL drivers are currently provided.

The Horde Project writes web applications in PHP and releases them under
Open Source licenses.  For more information (including help with Kronolith)
please visit [9]http://www.horde.org/.

READ /usr/share/doc/kronolith-2.1.8/README.Fedora AFTER INSTALLING FOR
MORE INSTRUCTIONS!

-
ChangeLog:

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1974");
script_summary(english: "Check for the version of the kronolith package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kronolith-2.1.8-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
