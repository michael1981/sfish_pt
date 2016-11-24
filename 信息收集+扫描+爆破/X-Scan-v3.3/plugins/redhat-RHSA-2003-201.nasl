
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12404);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-201: ypserv");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-201");
 script_set_attribute(attribute: "description", value: '
  Updated ypserv packages fixing a denial of service vulnerability are now
  available.

  The ypserv package contains the Network Information Service (NIS) server.

  A vulnerability has been discovered in the ypserv NIS server prior to
  version 2.7. If a malicious client queries ypserv via TCP and subsequently
  ignores the server\'s response, ypserv will block attempting to send the
  reply. This results in ypserv failing to respond to other client requests.

  Versions 2.7 and above of ypserv have been altered to fork a child for each
  client request, thus preventing any one request from causing the server to
  block.

  Red Hat recommends that users of NIS upgrade to these packages, which
  contain version 2.8.0 of ypserv and are therefore not vulnerable to this
  issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-201.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0251");
script_summary(english: "Check for the version of the ypserv packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ypserv-2.8-0.AS21E", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
