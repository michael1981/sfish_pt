
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-3414
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28230);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-3414: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-3414 (thunderbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

-
Update Information:

Updated thunderbird packages that fix several security bugs are now available f
or Fedora Core 8.

This update has been rated as having moderate security impact by the Fedora Sec
urity Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the way in which Thunderbird processed certain malf
ormed HTML mail content. An HTML mail message containing malicious content coul
d cause Thunderbird to crash or potentially execute arbitrary code as the user
running Thunderbird. JavaScript support is disabled by default in Thunderbird;
these issues are not exploitable unless the user has enabled JavaScript. (CVE-2
007-5338, CVE-2007-5339, CVE-2007-5340)

Several flaws were found in the way in which Thunderbird displayed malformed HT
ML mail content. An HTML mail message containing specially-crafted content coul
d potentially trick a user into surrendering sensitive information. (CVE-2007-1
095, CVE-2007-3844, CVE-2007-3511, CVE-2007-5334)

A flaw was found in the Thunderbird sftp protocol handler. A malicious HTML mai
l message could access data from a remote sftp site, possibly stealing sensitiv
e user data. (CVE-2007-5337)

A request-splitting flaw was found in the way in which Thunderbird generates a
digest authentication request. If a user opened a specially-crafted URL, it was
possible to perform cross-site scripting attacks, web cache poisoning, or othe
r, similar exploits. (CVE-2007-2292)

Users of Thunderbird are advised to upgrade to these erratum packages, which co
ntain backported patches that correct these issues.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2292", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5340");
script_summary(english: "Check for the version of the thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"thunderbird-2.0.0.9-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
