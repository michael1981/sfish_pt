#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(26919);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-1999-0505");

 name["english"] = "SMB guest account for all users";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running one of the Microsoft Windows operating
systems.  It was possible to log into it as a guest user using a 
random account." );
 script_set_attribute(attribute:"solution", value:
"In the group policy change the setting for 
'Network access: Sharing and security model for local accounts' from
'Guest only - local users authenticate as Guest' to
'Classic - local users authenticate as themselves'." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();

 
 summary["english"] = "Attempts to log into the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_login.nasl");
 script_require_keys("SMB/guest_enabled");
 exit(0);
}

include("smb_func.inc");

val = get_kb_item("SMB/guest_enabled");

if (val)
  security_warning(kb_smb_transport());
