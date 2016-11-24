
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27354);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  mutt: APOP vulnerable to password guessing (mutt-3702)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch mutt-3702");
 script_set_attribute(attribute: "description", value: "This update of mutt fixes a vulnerability in the APOP
implementation that allows an active attacker to guess
three bytes of the password. (CVE-2007-1558)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch mutt-3702");
script_end_attributes();

script_cve_id("CVE-2007-1558");
script_summary(english: "Check for the mutt-3702 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"mutt-1.5.13-34", release:"SUSE10.2") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
