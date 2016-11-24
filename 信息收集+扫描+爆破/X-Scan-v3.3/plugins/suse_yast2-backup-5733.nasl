
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(34991);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  yast2-backup: Fix for arbitrary shell code injection and improvemnt for handling symlinks (yast2-backup-5733)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch yast2-backup-5733");
 script_set_attribute(attribute: "description", value: "This updated of yast2-backup fixes a sellcode injection
vulnerability and improves handling of symlinks for the
backup process.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch yast2-backup-5733");
script_end_attributes();

script_summary(english: "Check for the yast2-backup-5733 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"yast2-backup-2.15.7-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
