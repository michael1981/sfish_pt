
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-1192
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24045);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2006-1192: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-1192 (thunderbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

Update Information:

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the way Thunderbird processes
certain malformed Javascript code. A malicious HTML mail
message could cause the execution of Javascript code in such
a way that could cause Thunderbird to crash or execute
arbitrary code as the user running Thunderbird.
(CVE-2006-5463, CVE-2006-5747, CVE-2006-5748)

Several flaws were found in the way Thunderbird renders HTML
mail messages. A malicious HTML mail message could cause the
mail client to crash or possibly execute arbitrary code as
the user running Thunderbird. (CVE-2006-5464)

Users of Thunderbird are advised to upgrade to this update,
which contains Thunderbird version 1.5.0.8 that corrects
these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-5464", "CVE-2006-5748");
script_summary(english: "Check for the version of the thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"thunderbird-1.5.0.8-1.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
