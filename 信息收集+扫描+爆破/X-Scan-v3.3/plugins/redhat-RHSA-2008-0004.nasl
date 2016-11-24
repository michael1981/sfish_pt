
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29974);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0004: apache");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0004");
 script_set_attribute(attribute: "description", value: '
  Updated apache packages that fix several security issues are now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server.

  A flaw was found in the mod_imap module. On sites where mod_imap was
  enabled and an imagemap file was publicly available, a cross-site scripting
  attack was possible. (CVE-2007-5000)

  A flaw was found in the mod_autoindex module. On sites where directory
  listings are used, and the "AddDefaultCharset" directive has been removed
  from the configuration, a cross-site scripting attack was possible against
  Web browsers which did not correctly derive the response character set
  following the rules in RFC 2616. (CVE-2007-4465)

  A flaw was found in the mod_status module. On sites where mod_status was
  enabled and the status pages were publicly available, a cross-site
  scripting attack was possible. (CVE-2007-6388)

  A flaw was found in the mod_proxy_ftp module. On sites where mod_proxy_ftp
  was enabled and a forward proxy was configured, a cross-site scripting
  attack was possible against Web browsers which did not correctly derive the
  response character set following the rules in RFC 2616. (CVE-2008-0005)

  Users of Apache should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Users should restart Apache
  after installing this update.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0004.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2008-0005");
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

if ( rpm_check( reference:"apache-1.3.27-14.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.27-14.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.27-14.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
