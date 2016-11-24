
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12455);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-033: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-033");
 script_set_attribute(attribute: "description", value: '
  Updated Gaim packages that fix a number of serious vulnerabilities are now
  available.

  Gaim is an instant messenger client that can handle multiple protocols.

  Stefan Esser audited the Gaim source code and found a number of bugs that
  have security implications. Due to the nature of instant messaging many of
  these bugs require man-in-the-middle attacks between client and server.
  However at least one of the buffer overflows could be exploited by an
  attacker sending a carefully-constructed malicious message through a
  server.

  The issues include:

  Multiple buffer overflows that affect versions of Gaim 0.75 and earlier.
  1) When parsing cookies in a Yahoo web connection, 2) YMSG protocol
  overflows parsing the Yahoo login webpage, 3) a YMSG packet overflow, 4)
  flaws in the URL parser, and 5) flaws in HTTP Proxy connect. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0006 to these issues.

  A buffer overflow in Gaim 0.74 and earlier in the Extract Info
  Field Function used for MSN and YMSG protocol handlers. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0007 to this issue.

  An integer overflow in Gaim 0.74 and earlier, when allocating
  memory for a directIM packet results in heap overflow.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0008 to this issue.

  All users of Gaim should upgrade to these erratum packages, which contain
  backported security patches correcting these issues.

  Red Hat would like to thank Steffan Esser for finding and reporting these
  issues and Jacques A. Vidrine for providing initial patches.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-033.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");
script_summary(english: "Check for the version of the gaim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gaim-0.75-3.2.0", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
