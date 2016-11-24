#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17590);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0387", "CVE-2004-0550", "CVE-2005-0189", "CVE-2005-0191", "CVE-2005-0455", "CVE-2005-0611");

 script_name(english: "RHSA-2005-299: realplayer");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2005-299");
script_set_attribute(attribute:"description", value: 
'  Updated realplayer packages that fix a number of security issues are now
  available for Red Hat Enterprise Linux 3 Extras.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The realplayer package contains RealPlayer, a media format player.

  A number of security issues have been discovered in RealPlayer 8 of which a
  subset are believed to affect the Linux version as shipped with Red Hat
  Enterprise Linux 3 Extras. RealPlayer 8 is no longer supported by
  RealNetworks.

  Users of RealPlayer are advised to upgrade to this erratum package which
  contains RealPlayer 10.');
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute: "solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute: "see_also", value:
"http://rhn.redhat.com/errata/RHSA-2005-299.html");
 script_end_attributes();

 
 script_summary(english: "Check for the version of the realplayer packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"realplayer-10.0.3-1.rhel3", release:"RHEL3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host in not affected");
