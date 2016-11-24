#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19292);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-1852");
 
 name["english"] = "Fedora Core 4 2005-624: kdenetwork";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-624 (kdenetwork).

Networking applications for the K Desktop Environment.

Update Information:

Multiple integer overflow flaws were found in the way Kopete processes
Gadu-Gadu messages. A remote attacker could send a specially crafted
Gadu-Gadu message which would cause Kopete to crash or possibly execute
arbitrary code. The Common Vulnerabilities and Exposures project
assigned the name CVE-2005-1852 to this issue.

Users of Kopete should update to these packages which contain a
patch to correct this issue." );
 script_set_attribute(attribute:"solution", value:
"http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_kdenetwork-3.4.1-0.fc4.2" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the kdenetwork package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdenetwork-3.4.1-0.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-devel-3.4.1-0.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"kdenetwork-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-1852", value:TRUE);
}
