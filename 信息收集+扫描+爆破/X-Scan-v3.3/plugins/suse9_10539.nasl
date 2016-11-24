
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41081);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for permissions and filesystem (10539)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 10539");
 script_set_attribute(attribute: "description", value: 'It is technically impossible to change permissions files in
of world writeable directories that don\'t have the sticky
bit set in a secure way. This update therefore removes
/var/lib/xmcd/discog from /etc/permissions*. Furthermore
permissions handling of files below /var/games is removed.
To be able to change permissions of directories in world
writeable directories in a secure way a slash must be
appended to the path in the /etc/permssions* file. This
update corrects missing slashes amongst others for
/usr/src/packages/*.
');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch 10539");
script_end_attributes();

script_summary(english: "Check for the security advisory #10539");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"filesystem-9-29.8", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"permissions-2005.10.20-0.2", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
