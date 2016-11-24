
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41252);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for yast2-backup (12279)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12279");
 script_set_attribute(attribute: "description", value: 'This updated of yast2-backup fixes a sellcode injection vulnerability and improves handling of symlinks for the backup process. (CVE-2008-4636)
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 12279");
script_end_attributes();

script_cve_id("CVE-2008-4636");
script_summary(english: "Check for the security advisory #12279");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"yast2-backup-2.9.22-0.1", release:"SUSE9", cpu: "noarch") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
