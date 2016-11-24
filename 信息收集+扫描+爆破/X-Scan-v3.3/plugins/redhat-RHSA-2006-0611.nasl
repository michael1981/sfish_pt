
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22122);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2006-0611: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0611");
 script_set_attribute(attribute: "description", value: '
  Updated thunderbird packages that fix several security bugs are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  The Mozilla Foundation has discontinued support for the Mozilla Thunderbird
  1.0 branch. This update deprecates the Mozilla Thunderbird 1.0 branch in
  Red Hat Enterprise Linux 4 in favor of the supported Mozilla Thunderbird
  1.5 branch.

  This update also resolves a number of outstanding Thunderbird security issues:

  Several flaws were found in the way Thunderbird processed certain
  javascript actions. A malicious mail message could execute arbitrary
  javascript instructions with the permissions of "chrome", allowing the page
  to steal sensitive information or install browser malware. (CVE-2006-2776,
  CVE-2006-2784, CVE-2006-2785, CVE-2006-2787, CVE-2006-3807, CVE-2006-3809)

  Several denial of service flaws were found in the way Thunderbird processed
  certain mail messages. A malicious web page could crash the browser or
  possibly execute arbitrary code as the user running Thunderbird.
  (CVE-2006-2779, CVE-2006-2780, CVE-2006-3801, CVE-2006-3677,
  CVE-2006-3113, CVE-2006-3803, CVE-2006-3805, CVE-2006-3806, CVE-2006-3811)

  Several flaws were found in the way Thunderbird processed certain
  javascript actions. A malicious mail message could conduct a cross-site
  scripting attack or steal sensitive information (such as cookies owned by
  other domains). (CVE-2006-3802, CVE-2006-3810)

  A form file upload flaw was found in the way Thunderbird handled javascript
  input object mutation. A malicious mail message could upload an arbitrary
  local file at form submission time without user interaction. (CVE-2006-2782)

  A denial of service flaw was found in the way Thunderbird called the
  crypto.signText() javascript function. A malicious mail message could crash
  the browser if the victim had a client certificate loaded. (CVE-2006-2778)

  A flaw was found in the way Thunderbird processed Proxy AutoConfig scripts.
  A malicious Proxy AutoConfig server could execute arbitrary javascript
  instructions with the permissions of "chrome", allowing the page to steal
  sensitive information or install client malware. (CVE-2006-3808)

  Note: Please note that JavaScript support is disabled by default in
  Thunderbird. The above issues are not exploitable with JavaScript disabled.

  Two flaws were found in the way Thunderbird displayed malformed inline
  vcard attachments. If a victim viewed an email message containing a
  carefully crafted vcard it was possible to execute arbitrary code as the
  user running Thunderbird. (CVE-2006-2781, CVE-2006-3804)

  A cross site scripting flaw was found in the way Thunderbird processed
  Unicode Byte-order-Mark (BOM) markers in UTF-8 mail messages. A malicious
  web page could execute a script within the browser that a web input
  sanitizer could miss due to a malformed "script" tag. (CVE-2006-2783)

  Two HTTP response smuggling flaws were found in the way Thunderbird
  processed certain invalid HTTP response headers. A malicious web site could
  return specially crafted HTTP response headers which may bypass HTTP proxy
  restrictions. (CVE-2006-2786)

  A double free flaw was found in the way the nsIX509::getRawDER method was
  called. If a victim visited a carefully crafted web page, it was possible
  to crash Thunderbird. (CVE-2006-2788)

  Users of Thunderbird are advised to upgrade to this update, which contains
  Thunderbird version 1.5.0.5 that corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0611.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787", "CVE-2006-2788", "CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811");
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

if ( rpm_check( reference:"thunderbird-1.5.0.5-0.el4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
