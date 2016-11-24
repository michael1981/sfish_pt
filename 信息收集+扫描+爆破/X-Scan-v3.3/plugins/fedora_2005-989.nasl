#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20024);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-2972");
 
 name["english"] = "Fedora Core 3 2005-989: abiword";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-989 (abiword).

AbiWord is a cross-platform Open Source word processor. The goal is to make
AbiWord full-featured, and remain lean.

Update Information:

CVE-2005-2972 abiword multiple buffer overflows" );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the abiword package";
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
if ( rpm_check( reference:"abiword-2.0.12-11", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"abiword-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2972", value:TRUE);
}
