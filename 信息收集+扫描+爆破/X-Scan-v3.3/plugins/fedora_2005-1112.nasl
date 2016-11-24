#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20287);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2005-2933");
 
 name["english"] = "Fedora Core 3 2005-1112: libc-client";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-1112 (libc-client).

C-client is a common API for accessing mailboxes. It is used internally by
the popular PINE mail reader, the University of Washington's IMAP server
and PHP.

Update Information:

The c-client library provides an API which allows
applications to access and manipulate remote mail boxes.

The library contains a bug in its mail_valid_net_parse()
function.  If an application allows untrusted input to be
supplied to this function, its stack may become corrupted.
This update backports the fix from imap-2004g which resolves
this issue." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the libc-client package";
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
if ( rpm_check( reference:"libc-client-2002e-13", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libc-client-devel-2002e-13", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"libc-client-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2933", value:TRUE);
}
