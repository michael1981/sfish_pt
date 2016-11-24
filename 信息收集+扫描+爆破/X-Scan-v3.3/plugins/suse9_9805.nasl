
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41344);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for ncpfs (9805)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 9805");
 script_set_attribute(attribute: "description", value: 'This update fixes the following security issues:
* a buffer overflow in ncplogin and ncpmap. Both
applications are installed setuid-root on SuSE Linux,
but only users of group \'trusted\' are allowed to execute
the binaries. If successfully exploited this
vulnerabilities could be used to gain local root access.
* missing file permisions checks for ~/.nwclient
(CVE-2005-0013)
* a buffer overflow in ncplogin (CVE-2005-0014)
This update also fixes the following non-security issues:
* On SLES9 translations for several languages have been
added
');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch 9805");
script_end_attributes();

script_summary(english: "Check for the security advisory #9805");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ncpfs-2.2.4-25.7", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ncpfs-devel-2.2.4-25.7", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
