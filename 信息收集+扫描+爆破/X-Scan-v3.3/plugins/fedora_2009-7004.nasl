
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-7004
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40828);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-7004: irssi");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-7004 (irssi)");
 script_set_attribute(attribute: "description", value: "Irssi is a modular IRC client with Perl scripting. Only text-mode
frontend is currently supported. The GTK/GNOME frontend is no longer
being maintained.

-
ChangeLog:


Update information :

* Tue Jun 23 2009 Huzaifa Sidhpurwala <huzaifas redhat com> - 0.8.13-3
- Resolve CVE-2009-1959
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1959");
script_summary(english: "Check for the version of the irssi package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"irssi-0.8.13-3.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
