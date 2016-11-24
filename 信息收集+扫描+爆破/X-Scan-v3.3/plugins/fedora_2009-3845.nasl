
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3845
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36211);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-3845: moin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3845 (moin)");
 script_set_attribute(attribute: "description", value: "MoinMoin is an advanced, easy to use and extensible WikiEngine with a large
community of users. Said in a few words, it is about collaboration on easily
editable web pages.

-
Update Information:

Update moin to 1.6.4. Fix the following CVEs: CVE-2008-0781 (again),
CVE-2008-3381, CVE-2009-0260, CVE-2009-0312. Fix AttachFile escaping problems,
upstream 1.7 changeset 5f51246a4df1 backported.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0781", "CVE-2008-3381", "CVE-2009-0260", "CVE-2009-0312");
script_summary(english: "Check for the version of the moin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"moin-1.6.4-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
