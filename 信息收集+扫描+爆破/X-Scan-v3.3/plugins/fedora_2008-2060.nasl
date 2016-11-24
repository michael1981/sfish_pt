
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2060
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31314);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-2060: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2060 (thunderbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

-
Update Information:

Mozilla Thunderbird is a standalone mail and newsgroup client.    Several flaws
were found in the way Thunderbird processed certain malformed HTML mail content
.
A HTML mail message containing malicious content could cause Thunderbird to
crash, or potentially execute arbitrary code as the user running Thunderbird.
(CVE-2008-0412, CVE-2008-0413, CVE-2008-0415, CVE-2008-0419)    Several flaws
were found in the way Thunderbird displayed malformed HTML mail content. A HTML
mail message containing specially-crafted content could trick a user into
surrendering sensitive information. (CVE-2008-0591, CVE-2008-0593)    A flaw wa
s
found in the way Thunderbird handles certain chrome URLs. If a user has certain
extensions installed, it could allow a malicious HTML mail message to steal
sensitive session data. Note: this flaw does not affect a default installation
of Thunderbird. (CVE-2008-0418)    Note: JavaScript support is disabled by
default in Thunderbird; the above issues are not exploitable unless JavaScript
is enabled.    A flaw was found in the way Thunderbird saves certain text files
.
If a remote site offers a file of type 'plain/text', rather than 'text/plain',
Thunderbird will not show future 'text/plain' content to the user, forcing them
to save those files locally to view the content. (CVE-2008-0592)    Users of
thunderbird are advised to upgrade to these updated packages, which contain
backported patches to resolve these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0304", "CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0415", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593");
script_summary(english: "Check for the version of the thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"thunderbird-2.0.0.12-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
