
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12426);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-297: stunnel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-297");
 script_set_attribute(attribute: "description", value: '
  Updated stunnel packages are now available. These updates address problems
  stemming from improper use of non-reentrant functions in signal handlers.

  Stunnel is a wrapper for network connections. It can be used to tunnel an
  unencrypted network connection over an encrypted connection (encrypted
  using SSL or TLS) or to provide an encrypted means of connecting to
  services that do not natively support encryption.

  A previous advisory provided updated packages to address re-entrancy
  problems in stunnel\'s signal-handling routines. These updates did not
  address other bugs that were found by Steve Grubb, and introduced an
  additional bug, which was fixed in stunnel 3.26.

  All users should upgrade to these errata packages, which address these
  issues by updating stunnel to version 3.26.

  NOTE: After upgrading, any instances of stunnel configured to run in daemon
  mode should be restarted, and any active network connections that are
  currently being serviced by stunnel should be terminated and reestablished.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-297.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0740");
script_summary(english: "Check for the version of the stunnel packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"stunnel-3.26-1.7.3", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
