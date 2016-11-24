
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27452);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  squid: Fix for two denial-of-service bugs in conjunction with ftp URLs and external ACLs (squid-2504)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch squid-2504");
 script_set_attribute(attribute: "description", value: "This update fixes a remotely exploitable denial-of-service
bug in squid, that can be triggered by using special ftp://
URLs. (CVE-2007-0247)
 Additionally the 10.2 package needed
a fix for another DoS bug (CVE-2007-0248) and for
max_user_ip handling in ntlm_auth.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch squid-2504");
script_end_attributes();

script_cve_id("CVE-2007-0247", "CVE-2007-0248");
script_summary(english: "Check for the squid-2504 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"squid-2.6.STABLE6-0.4", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
