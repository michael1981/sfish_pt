#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20191);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CAN-2005-2104");
 
 name["english"] = "Fedora Core 4 2005-1071: sysreport";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-1071 (sysreport).

Sysreport is a utility that gathers information about a system's
hardware and configuration. The information can then be used for
diagnostic purposes and debugging. Sysreport is commonly used to help
support technicians and developers by providing a 'snapshot' of a
system's current layout.

Update Information:

It is possible for a local attacker to cause a race
condition and trick sysreport into writing its output to a
directory the attacker can read.

The new sysreport fixes this security issue" );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the sysreport package";
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
if ( rpm_check( reference:"sysreport-1.4.1-5", prefix:"sysreport-", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"sysreport-", release:"FC4") )
{
 set_kb_item(name:"CAN-2005-2104", value:TRUE);
}
