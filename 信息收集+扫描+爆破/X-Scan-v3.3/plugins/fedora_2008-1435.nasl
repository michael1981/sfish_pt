
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1435
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31060);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-1435: kazehakase");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1435 (kazehakase)");
 script_set_attribute(attribute: "description", value: "Kazehakase is a Web browser which aims to provide
a user interface that is truly user-friendly & fully customizable.

-
Update Information:

Mozilla Firefox is an open source Web browser.    Several flaws were found in
the way Firefox processed certain malformed web content. A webpage containing
malicious content could cause Firefox to crash, or potentially execute arbitrar
y
code as the user running Firefox. (CVE-2008-0412, CVE-2008-0413, CVE-2008-0415,
CVE-2008-0419)    Several flaws were found in the way Firefox displayed
malformed web content. A webpage containing specially-crafted content could
trick a user into surrendering sensitive information. (CVE-2008-0591,
CVE-2008-0593)    A flaw was found in the way Firefox stored password data. If
a
user saves login information for a malicious website, it could be possible to
corrupt the password database, preventing the user from properly accessing save
d
password data. (CVE-2008-0417)    A flaw was found in the way Firefox handles
certain chrome URLs. If a user has certain extensions installed, it could allow
a malicious website to steal sensitive session data. Note: this flaw does not
affect a default installation of Firefox. (CVE-2008-0418)    A flaw was found i
n
the way Firefox saves certain text files. If a website offers a file of type
'plain/text', rather than 'text/plain', Firefox will not show future
'text/plain' content to the user in the browser, forcing them to save those
files locally to view the content. (CVE-2008-0592)    Users of firefox are
advised to upgrade to these updated packages, which contain updated packages to
resolve these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
script_summary(english: "Check for the version of the kazehakase package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kazehakase-0.5.2-1.fc7.2", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
