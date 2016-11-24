
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7987
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34186);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-7987: ipa");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7987 (ipa)");
 script_set_attribute(attribute: "description", value: "IPA is an integrated solution to provide centrally managed Identity (machine,
user, virtual machines, groups, authentication credentials), Policy
(configuration settings, access control information) and Audit (events,
logs, analysis thereof).

-
Update Information:

Security update to address Kerberos master password disclosure flaw
(CVE-2008-3274).    A simple update is not sufficient to resolve the security
issue.  Please *carefully* follow the upgrade instructions at:
[9]http://freeipa.org/page/CVE-2008-3274
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3274");
script_summary(english: "Check for the version of the ipa package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ipa-1.1.0-4.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
