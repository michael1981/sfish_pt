
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35181);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-1023: finch");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-1023");
 script_set_attribute(attribute: "description", value: '
  Updated Pidgin packages that fix several security issues and bugs are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Pidgin is a multi-protocol Internet Messaging client.

  A denial-of-service flaw was found in Pidgin\'s MSN protocol handler. If a
  remote user was able to send, and the Pidgin user accepted, a
  carefully-crafted file request, it could result in Pidgin crashing.
  (CVE-2008-2955)

  A denial-of-service flaw was found in Pidgin\'s Universal Plug and Play
  (UPnP) request handling. A malicious UPnP server could send a request to
  Pidgin, causing it to download an excessive amount of data, consuming all
  available memory or disk space. (CVE-2008-2957)

  A flaw was found in the way Pidgin handled SSL certificates. The NSS SSL
  implementation in Pidgin did not properly verify the authenticity of SSL
  certificates. This could have resulted in users unknowingly connecting to a
  malicious SSL service. (CVE-2008-3532)

  In addition, this update upgrades pidgin from version 2.3.1 to version
  2.5.2, with many additional stability and functionality fixes from the
  Pidgin Project.

  Note: the Secure Internet Live Conferencing (SILC) chat network protocol
  has recently changed, affecting all versions of pidgin shipped with Red Hat
  Enterprise Linux.

  Pidgin cannot currently connect to the latest version of the SILC server
  (1.1.14): it fails to properly exchange keys during initial login. This
  update does not correct this. Red Hat Bugzilla #474212 (linked to in the
  References section) has more information.

  Note: after the errata packages are installed, Pidgin must be restarted for
  the update to take effect.

  All Pidgin users should upgrade to these updated packages, which contains
  Pidgin version 2.5.2 and resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-1023.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2955", "CVE-2008-2957", "CVE-2008-3532");
script_summary(english: "Check for the version of the finch packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"finch-2.5.2-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"finch-devel-2.5.2-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-2.5.2-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-devel-2.5.2-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-perl-2.5.2-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-tcl-2.5.2-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-2.5.2-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-devel-2.5.2-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-perl-2.5.2-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"finch-2.5.2-6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-2.5.2-6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-perl-2.5.2-6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-tcl-2.5.2-6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-2.5.2-6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-perl-2.5.2-6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
