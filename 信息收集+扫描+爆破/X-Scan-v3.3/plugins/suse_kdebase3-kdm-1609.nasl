
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27285);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  kdm security update (kdebase3-kdm-1609)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kdebase3-kdm-1609");
 script_set_attribute(attribute: "description", value: "KDM stores the type of the previously used session in the 
user's home directory. By using a symlink users could trick 
kdm into also storing content of files that are normally 
not accesible by users (CVE-2006-2449).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch kdebase3-kdm-1609");
script_end_attributes();

script_cve_id("CVE-2006-2449");
script_summary(english: "Check for the kdebase3-kdm-1609 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kdebase3-kdm-3.5.1-69.23", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
