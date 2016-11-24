
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41031);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1452: neon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1452");
 script_set_attribute(attribute: "description", value: '
  Updated neon packages that fix two security issues are now available for
  Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  neon is an HTTP and WebDAV client library, with a C interface. It provides
  a high-level interface to HTTP and WebDAV methods along with a low-level
  interface for HTTP request handling. neon supports persistent connections,
  proxy servers, basic, digest and Kerberos authentication, and has complete
  SSL support.

  It was discovered that neon is affected by the previously published "null
  prefix attack", caused by incorrect handling of NULL characters in X.509
  certificates. If an attacker is able to get a carefully-crafted certificate
  signed by a trusted Certificate Authority, the attacker could use the
  certificate during a man-in-the-middle attack and potentially confuse an
  application using the neon library into accepting it by mistake.
  (CVE-2009-2474)

  A denial of service flaw was found in the neon Extensible Markup Language
  (XML) parser. A remote attacker (malicious DAV server) could provide a
  specially-crafted XML document that would cause excessive memory and CPU
  consumption if an application using the neon XML parser was tricked into
  processing it. (CVE-2009-2473)

  All neon users should upgrade to these updated packages, which contain
  backported patches to correct these issues. Applications using the neon
  HTTP and WebDAV client library, such as cadaver, must be restarted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1452.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2473", "CVE-2009-2474");
script_summary(english: "Check for the version of the neon packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"neon-0.25.5-10.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"neon-devel-0.25.5-10.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"neon-0.24.7-4.el4_8.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"neon-devel-0.24.7-4.el4_8.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"neon-0.24.7-4.el4_8.2", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"neon-devel-0.24.7-4.el4_8.2", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"neon-0.25.5-10.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"neon-devel-0.25.5-10.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
