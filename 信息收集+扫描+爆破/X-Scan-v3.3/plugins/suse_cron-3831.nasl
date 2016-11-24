
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29408);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for cron (cron-3831)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch cron-3831");
 script_set_attribute(attribute: "description", value: "By setting hard links to /etc/crontab users were able to
prevent cron from running scheduled jobs (CVE-2007-1856).

A re-emerged symlink bug allowed users to edit the crontab
of other users (CVE-2005-1038).

This is a reissue of the SLES10 update after Service Pack
1, since Service Pack 1 merge lost some of the fixes in the
cron package.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch cron-3831");
script_end_attributes();

script_cve_id("CVE-2005-1038", "CVE-2007-1856");
script_summary(english: "Check for the cron-3831 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"cron-4.1-45.18", release:"SLES10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cron-4.1-45.18", release:"SLED10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
