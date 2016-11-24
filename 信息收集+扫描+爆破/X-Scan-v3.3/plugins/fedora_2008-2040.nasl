
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2040
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31311);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-2040: horde");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2040 (horde)");
 script_set_attribute(attribute: "description", value: "The Horde Framework provides a common structure and interface for Horde
applications (such as IMP, a web-based mail program). This RPM is
required for all other Horde module RPMs.

The Horde Project writes web applications in PHP and releases them under
Open Source licenses. For more information (including help with Horde
and its modules) please visit [9]http://www.horde.org/.

READ /usr/share/doc/horde-3.1.6/README.Fedora AFTER INSTALLING FOR
INSTRUCTIONS AND SECURITY!

For additional functionality, also install horde-enhanced

-
ChangeLog:


Update information :

* Fri Jan 11 2008 Brandon Holbrook <fedora at theholbrooks.org> 3.1.6-1
- Update to 3.1.6
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-6018", "CVE-2008-0807");
script_summary(english: "Check for the version of the horde package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"horde-3.1.6-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
