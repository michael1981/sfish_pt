
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3557
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32206);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-3557: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3557 (thunderbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

-
Update Information:

Mozilla Thunderbird is a standalone mail and newsgroup client.    Several flaws
were found in the processing of some malformed HTML mail  content. An HTML mail
message containing such malicious content could cause  Thunderbird to crash or,
potentially, execute arbitrary code as the user  running Thunderbird.
(CVE-2008-1233, CVE-2008-1235, CVE-2008-1236,  CVE-2008-1237)    Several flaws
were found in the display of malformed web content. An HTML  mail message
containing specially-crafted content could, potentially, trick  a user into
surrendering sensitive information. (CVE-2008-1234)    A flaw was found in the
processing of malformed JavaScript content. An HTML  mail message containing
such malicious content could cause Thunderbird to  crash or, potentially,
execute arbitrary code as the user running  Thunderbird. (CVE-2008-1380)
Note: JavaScript support is disabled by default in Thunderbird; the above  issu
e
is not exploitable unless JavaScript is enabled.    All Thunderbird users shoul
d
upgrade to these updated packages, which  contain backported patches to resolve
these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1380");
script_summary(english: "Check for the version of the thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"thunderbird-2.0.0.14-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
