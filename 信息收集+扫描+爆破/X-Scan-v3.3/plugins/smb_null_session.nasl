#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(26920);
 script_bugtraq_id(494);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-1117");
 name["english"] = "SMB NULL session";
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote Windows host with a NULL
session." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Windows, and it was possible to
log into it using a NULL session (ie, with no login or password).  An
unauthenticated remote attacker can leverage this issue to get
information about the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/support/kb/articles/Q143/4/74.ASP" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/support/kb/articles/Q246/2/61.ASP" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_name(english:name["english"]);
 
script_end_attributes();

 
 summary["english"] = "Attempts to log into the remote host using a NULL session";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_login.nasl");
 script_require_keys("SMB/null_session_enabled");
 exit(0);
}

include("smb_func.inc");

val = get_kb_item("SMB/null_session_enabled");

if (val)
  security_note(kb_smb_transport());
