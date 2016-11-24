
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12406);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-223: stunnel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-223");
 script_set_attribute(attribute: "description", value: '
  Updated stunnel packages are now available. These updates correct a
  potential vulnerability in stunnel\'s signal handling.

  Stunnel is a wrapper for network connections. It can be used to tunnel an
  unencrypted network connection over a secure connection (encrypted using
  SSL or TLS) or to provide a secure means of connecting to services that do
  not natively support encryption.

  When configured to listen for incoming connections (instead of being
  invoked by xinetd), stunnel can be configured to either start a thread or a
  child process to handle each new connection. If Stunnel is configured to
  start a new child process to handle each connection, it will receive a
  SIGCHLD signal when that child exits.

  Stunnel versions prior to 4.04 would perform tasks in the SIGCHLD signal
  handler which, if interrupted by another SIGCHLD signal, could be unsafe.
  This could lead to a denial of service.

  All users are urged to upgrade to these errata packages, which modify
  stunnel\'s signal handler so that it is not vulnerable to this issue.

  NOTE: After upgrading, any instances of stunnel configured to run in daemon
  mode should be restarted, and any active network connections that are
  currently being serviced by stunnel should be terminated and reestablished.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-223.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1563");
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

if ( rpm_check( reference:"stunnel-3.22-5.7.3", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
