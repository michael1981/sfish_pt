
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35971);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0341: curl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0341");
 script_set_attribute(attribute: "description", value: '
  Updated curl packages that fix a security issue are now available for Red
  Hat Enterprise Linux 2.1, 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and Dict
  servers, using any of the supported protocols. cURL is designed to work
  without user interaction or any kind of interactivity.

  David Kierznowski discovered a flaw in libcurl where it would not
  differentiate between different target URLs when handling automatic
  redirects. This caused libcurl to follow any new URL that it understood,
  including the "file://" URL type. This could allow a remote server to force
  a local libcurl-using application to read a local file instead of the
  remote one, possibly exposing local files that were not meant to be
  exposed. (CVE-2009-0037)

  Note: Applications using libcurl that are expected to follow redirects to
  "file://" protocol must now explicitly call curl_easy_setopt(3) and set the
  newly introduced CURLOPT_REDIR_PROTOCOLS option as required.

  cURL users should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running applications using
  libcurl must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0341.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0037");
script_summary(english: "Check for the version of the curl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"curl-7.15.5-2.1.el5_3.4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.15.5-2.1.el5_3.4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-7.8-3.rhel2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.8-3.rhel2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-7.10.6-9.rhel3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.10.6-9.rhel3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-7.12.1-11.1.el4_7.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.12.1-11.1.el4_7.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
