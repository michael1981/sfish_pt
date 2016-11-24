
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12478);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2004-110: galeon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-110");
 script_set_attribute(attribute: "description", value: '
  Updated Mozilla packages that fix vulnerabilities in S/MIME parsing as well
  as other issues and bugs are now available.

  Mozilla is a Web browser and mail reader, designed for standards
  compliance, performance and portability. Network Security Services (NSS)
  is a set of libraries designed to support cross-platform development of
  security-enabled server applications.

  NISCC testing of implementations of the S/MIME protocol uncovered a number
  of bugs in NSS versions prior to 3.9. The parsing of unexpected ASN.1
  constructs within S/MIME data could cause Mozilla to crash or consume large
  amounts of memory. A remote attacker could potentially trigger these bugs
  by sending a carefully-crafted S/MIME message to a victim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0564 to this issue.

  Andreas Sandblad discovered a cross-site scripting issue that affects
  various versions of Mozilla. When linking to a new page it is still
  possible to interact with the old page before the new page has been
  successfully loaded. Any Javascript events will be invoked in the context
  of the new page, making cross-site scripting possible if the different
  pages belong to different domains. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0191 to
  this issue.

  Flaws have been found in the cookie path handling between a number of Web
  browsers and servers. The HTTP cookie standard allows a Web server
  supplying a cookie to a client to specify a subset of URLs on the origin
  server to which the cookie applies. Web servers such as Apache do not
  filter returned cookies and assume that the client will only send back
  cookies for requests that fall within the server-supplied subset of URLs.
  However, by supplying URLs that use path traversal (/../) and character
  encoding, it is possible to fool many browsers into sending a cookie to a
  path outside of the originally-specified subset. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0594 to this issue.

  Users of Mozilla are advised to upgrade to these updated packages, which
  contain Mozilla version 1.4.2 and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-110.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0564", "CVE-2003-0594", "CVE-2004-0191");
script_summary(english: "Check for the version of the galeon packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"galeon-1.2.13-0.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.2-2.1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.2-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.2-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.2-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.2-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.2-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.2-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.2-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.2-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.2-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
