#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20101);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CAN-2005-1704", "CAN-2005-1705");
 
 name["english"] = "Fedora Core 4 2005-1033: gdb";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-1033 (gdb).

GDB, the GNU debugger, allows you to debug programs written in C, C++,
Java, and other languages, by executing them in a controlled fashion
and printing their data.

Update Information:

This is an fc4 update for gdb that includes security issues:

CAN-2005-1704 Integer Overflow in gdb

This problem is that gdb's internal copy of bfd
does not protect against heap-based overflow.

CAN-2005-1705 gdb arbitrary command execution

This problem allows unprotected .gdbinit files
to execute arbitrary commands during gdb startup.

Fixes for both problems are found in:

gdb-6.3.0.0-1.84

This release also contains some additional fixes
from the last update." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the gdb package";
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
if ( rpm_check( reference:"gdb-6.3.0.0-1.84", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"gdb-", release:"FC4") )
{
 set_kb_item(name:"CAN-2005-1704", value:TRUE);
 set_kb_item(name:"CAN-2005-1705", value:TRUE);
}
