
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25986);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0795: cyrus");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0795");
 script_set_attribute(attribute: "description", value: '
  An updated cyrus-sasl package that addresses a security issue and fixes
  various other bugs is now available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The cyrus-sasl package contains the Cyrus implementation of SASL. SASL is
  the Simple Authentication and Security Layer, a method for adding
  authentication support to connection-based protocols.

  A bug was found in cyrus-sasl\'s DIGEST-MD5 authentication mechanism. As
  part of the DIGEST-MD5 authentication exchange, the client is expected to
  send a specific set of information to the server. If one of these items
  (the "realm") was not sent or was malformed, it was possible for a remote
  unauthenticated attacker to cause a denial of service (segmentation fault)
  on the server. (CVE-2006-1721)

  This errata also fixes the following bugs:

  * the Kerberos 5 library included in Red Hat Enterprise Linux 4 was not
  thread safe. This update adds functionality which allows it to be used
  safely in a threaded application.

  * several memory leak bugs were fixed in cyrus-sasl\'s DIGEST-MD5
  authentication plug-in.

  * /dev/urandom is now used by default on systems which don\'t support
  hwrandom. Previously, dev/random was the default.

  * cyrus-sasl needs zlib-devel to build properly. This dependency
  information is now included in the package.

  Users are advised to upgrade to this updated cyrus-sasl package, which
  resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0795.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-1721");
script_summary(english: "Check for the version of the cyrus packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cyrus-sasl-2.1.19-14", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-devel-2.1.19-14", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-gssapi-2.1.19-14", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-md5-2.1.19-14", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-ntlm-2.1.19-14", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-plain-2.1.19-14", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-sql-2.1.19-14", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
