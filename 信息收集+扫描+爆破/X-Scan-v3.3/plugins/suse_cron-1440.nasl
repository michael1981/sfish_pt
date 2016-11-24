
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27189);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Local privilege escalation in Cron. (cron-1440)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch cron-1440");
 script_set_attribute(attribute: "description", value: "A missing check on the return value of setuid() in 
vixie-cron could be used by a local user to gain root 
privileges by exhausting resource limits and waiting for a 
cronjob to trigger.  This is tracked by the Mitre CVE ID 
CVE-2006-2607.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch cron-1440");
script_end_attributes();

script_cve_id("CVE-2006-2607");
script_summary(english: "Check for the cron-1440 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"cron-4.1-45.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
