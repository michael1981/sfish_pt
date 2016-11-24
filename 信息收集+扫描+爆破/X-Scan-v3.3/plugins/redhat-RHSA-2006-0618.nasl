
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22202);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0618: apache");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0618");
 script_set_attribute(attribute: "description", value: '
  Updated Apache httpd packages that correct a security issue are now
  available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server available for free.

  A bug was found in Apache where an invalid Expect header sent to the server
  was returned to the user in an unescaped error message. This could
  allow an attacker to perform a cross-site scripting attack if a victim was
  tricked into connecting to a site and sending a carefully crafted Expect
  header. (CVE-2006-3918)

  While a web browser cannot be forced to send an arbitrary Expect header by
  a third-party attacker, it was recently discovered that certain versions of
  the Flash plugin can manipulate request headers. If users running such
  versions can be persuaded to load a web page with a malicious Flash applet,
  a cross-site scripting attack against the server may be possible.

  Users of Apache should upgrade to these updated packages, which contain a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0618.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-3918");
script_summary(english: "Check for the version of the apache packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache-1.3.27-11.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.27-11.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.27-11.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
