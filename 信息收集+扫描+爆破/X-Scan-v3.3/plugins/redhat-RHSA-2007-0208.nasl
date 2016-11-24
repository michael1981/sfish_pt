
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25136);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0208: w");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0208");
 script_set_attribute(attribute: "description", value: '
  Updated w3c-libwww packages that fix a security issue and a bug are now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  w3c-libwww is a general-purpose web library.

  Several buffer overflow flaws in w3c-libwww were found. If a client
  application that uses w3c-libwww connected to a malicious HTTP server, it
  could trigger an out of bounds memory access, causing the client
  application to crash (CVE-2005-3183).

  This updated version of w3c-libwww also fixes an issue when computing MD5
  sums on a 64 bit machine.

  Users of w3c-libwww should upgrade to these updated packages, which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0208.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3183");
script_summary(english: "Check for the version of the w packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"w3c-libwww-5.4.0-10.1.RHEL4.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-apps-5.4.0-10.1.RHEL4.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-devel-5.4.0-10.1.RHEL4.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
