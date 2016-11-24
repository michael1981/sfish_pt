
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17165);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-025: exim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-025");
 script_set_attribute(attribute: "description", value: '
  Updated exim packages that resolve security issues are now available for
  Red
  Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  Exim is a mail transport agent (MTA) developed at the University of
  Cambridge for use on Unix systems connected to the Internet.

  A buffer overflow was discovered in the spa_base64_to_bits function in
  Exim, as originally obtained from Samba code. If SPA authentication is
  enabled, a remote attacker may be able to exploit this vulnerability to
  execute arbitrary code as the \'exim\' user. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0022 to
  this issue. Please note that SPA authentication is not enabled by default
  in Red Hat Enterprise Linux 4.

  Buffer overflow flaws were discovered in the host_aton and
  dns_build_reverse functions in Exim. A local user can trigger these flaws
  by executing exim with carefully crafted command line arguments and may be
  able to gain the privileges of the \'exim\' account. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0021 to this issue.

  Users of Exim are advised to update to these erratum packages which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-025.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0021", "CVE-2005-0022");
script_summary(english: "Check for the version of the exim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"exim-4.43-1.RHEL4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-doc-4.43-1.RHEL4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-mon-4.43-1.RHEL4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-sa-4.43-1.RHEL4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
