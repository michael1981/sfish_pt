
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24211);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0011: libgsf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0011");
 script_set_attribute(attribute: "description", value: '
  Updated libgsf packages that fix a buffer overflow flaw are now available.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  The GNOME Structured File Library is a utility library for reading and
  writing structured file formats.

  A heap based buffer overflow flaw was found in the way GNOME Structured
  File Library processes and certain OLE documents. If an person opened a
  specially crafted OLE file, it could cause the client application to crash
  or
  execute arbitrary code. (CVE-2006-4514)

  Users of GNOME Structured File Library should upgrade to these updated
  packages, which contain a backported patch that resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0011.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4514");
script_summary(english: "Check for the version of the libgsf packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libgsf-1.6.0-7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgsf-devel-1.6.0-7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgsf-1.10.1-2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgsf-devel-1.10.1-2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
