
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36015);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0336: glib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0336");
 script_set_attribute(attribute: "description", value: '
  Updated glib2 packages that fix several security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  GLib is the low-level core library that forms the basis for projects such
  as GTK+ and GNOME. It provides data structure handling for C, portability
  wrappers, and interfaces for such runtime functionality as an event loop,
  threads, dynamic loading, and an object system.

  Diego Pettenò discovered multiple integer overflows causing heap-based
  buffer overflows in GLib\'s Base64 encoding and decoding functions. An
  attacker could use these flaws to crash an application using GLib\'s Base64
  functions to encode or decode large, untrusted inputs, or, possibly,
  execute arbitrary code as the user running the application. (CVE-2008-4316)

  Note: No application shipped with Red Hat Enterprise Linux 5 uses the
  affected functions. Third-party applications may, however, be affected.

  All users of glib2 should upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0336.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4316");
script_summary(english: "Check for the version of the glib packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"glib2-2.12.3-4.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glib2-devel-2.12.3-4.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
