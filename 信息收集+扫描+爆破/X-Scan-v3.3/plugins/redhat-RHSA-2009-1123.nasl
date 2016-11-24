
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39526);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1123: gstreamer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1123");
 script_set_attribute(attribute: "description", value: '
  Updated gstreamer-plugins-good packages that fix multiple security issues
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  GStreamer is a streaming media framework, based on graphs of filters which
  operate on media data. GStreamer Good Plug-ins is a collection of
  well-supported, good quality GStreamer plug-ins.

  Multiple integer overflow flaws, that could lead to a buffer overflow, were
  found in the GStreamer Good Plug-ins PNG decoding handler. An attacker
  could create a specially-crafted PNG file that would cause an application
  using the GStreamer Good Plug-ins library to crash or, potentially, execute
  arbitrary code as the user running the application when parsed.
  (CVE-2009-1932)

  All users of gstreamer-plugins-good are advised to upgrade to these updated
  packages, which contain a backported patch to correct these issues. After
  installing the update, all applications using GStreamer Good Plug-ins (such
  as some media playing applications) must be restarted for the changes to
  take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1123.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1932");
script_summary(english: "Check for the version of the gstreamer packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gstreamer-plugins-good-0.10.9-1.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer-plugins-good-devel-0.10.9-1.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer-plugins-good-0.10.9-1.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer-plugins-good-devel-0.10.9-1.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
