
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12349);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2003-008: mgetty");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-008");
 script_set_attribute(attribute: "description", value: '
  Updated Mgetty packages are now available to fix a possible buffer overflow
  and a permissions problem.

  Mgetty is a getty replacement for use with data and fax modems.

  Mgetty can be configured to run an external program to decide whether or
  not to answer an incoming call based on Caller ID information. Versions of
  Mgetty prior to 1.1.29 would overflow an internal buffer if the caller name
  reported by the modem was too long.

  Additionally, the faxspool script supplied with versions of Mgetty prior to
  1.1.29 used a simple permissions scheme to allow or deny fax transmission
  privileges. This scheme was easily circumvented because the spooling
  directory used for outgoing faxes was world-writable.

  All users of Mgetty should upgrade to these errata packages, which
  contain Mgetty 1.1.30 and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-008.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1391", "CVE-2002-1392");
script_summary(english: "Check for the version of the mgetty packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mgetty-1.1.30-0.7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mgetty-sendfax-1.1.30-0.7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mgetty-viewfax-1.1.30-0.7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mgetty-voice-1.1.30-0.7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
