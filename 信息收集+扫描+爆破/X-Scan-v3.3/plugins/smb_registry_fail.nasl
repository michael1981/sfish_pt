#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(26917);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SMB registry can not be accessed by the scanner";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Nessus is not able to access the remote Windows Registry." );
 script_set_attribute(attribute:"description", value:
"It was not possible to connect to PIPE\winreg on the remote host.

If you intend to use Nessus to perform registry-based checks, the
registry checks will not work because the 'Remote Registry Access'
service (winreg) has been disabled on the remote host or can not be
connected to with the supplied credentials." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();
 
 summary["english"] = "Determines whether the remote registry is accessible";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_registry_access.nasl");
 script_require_keys("SMB/registry_not_accessible");
 exit(0);
}

port = get_kb_item("SMB/transport");
val = get_kb_item("SMB/registry_not_accessible");

if (val)
  security_note(port);
