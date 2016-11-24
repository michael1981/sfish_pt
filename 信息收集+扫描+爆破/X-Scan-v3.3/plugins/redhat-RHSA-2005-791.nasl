
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19995);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-791: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-791");
 script_set_attribute(attribute: "description", value: '
  An updated thunderbird package that fixes various bugs is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  A bug was found in the way Thunderbird processes certain international
  domain names. An attacker could create a specially crafted HTML mail, which
  when viewed by the victim would cause Thunderbird to crash or possibly
  execute arbitrary code. Thunderbird as shipped with Red Hat Enterprise
  Linux 4 must have international domain names enabled by the user in order
  to be vulnerable to this issue. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-2871 to this issue.

  A bug was found in the way Thunderbird processes certain Unicode sequences.
  It may be possible to execute arbitrary code as the user running
  Thunderbird if the user views a specially crafted HTML mail containing
  Unicode sequences. (CAN-2005-2702)

  A bug was found in the way Thunderbird makes XMLHttp requests. It is
  possible that a malicious HTML mail could leverage this flaw to exploit
  other proxy or server flaws from the victim\'s machine. It is also possible
  that this flaw could be leveraged to send XMLHttp requests to hosts other
  than the originator; the default behavior of Thunderbird is to disallow
  such actions. (CAN-2005-2703)

  A bug was found in the way Thunderbird implemented its XBL interface. It
  may be possible for a malicious HTML mail to create an XBL binding in such
  a way that would allow arbitrary JavaScript execution with chrome
  permissions. Please note that in Thunderbird 1.0.6 this issue is not
  directly exploitable and will need to leverage other unknown exploits.
  (CAN-2005-2704)

  An integer overflow bug was found in Thunderbird\'s JavaScript engine. Under
  favorable conditions, it may be possible for a malicious mail message to
  execute arbitrary code as the user running Thunderbird. Please note that
  JavaScript support is disabled by default in Thunderbird. (CAN-2005-2705)

  A bug was found in the way Thunderbird displays about: pages. It is
  possible for a malicious HTML mail to open an about: page, such as
  about:mozilla, in such a way that it becomes possible to execute JavaScript
  with chrome privileges. (CAN-2005-2706)

  A bug was found in the way Thunderbird opens new windows. It is possible
  for a malicious HTML mail to construct a new window without any user
  interface components, such as the address bar and the status bar. This
  window could then be used to mislead the user for malicious purposes.
  (CAN-2005-2707)

  A bug was found in the way Thunderbird processes URLs passed to it on the
  command line. If a user passes a malformed URL to Thunderbird, such as
  clicking on a link in an instant messaging program, it is possible to
  execute arbitrary commands as the user running Thunderbird. (CAN-2005-2968)

  Users of Thunderbird are advised to upgrade to this updated package, which
  contains Thunderbird version 1.0.7 and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-791.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871", "CVE-2005-2968");
script_summary(english: "Check for the version of the thunderbird packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"thunderbird-1.0.7-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
