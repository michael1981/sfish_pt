#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(26918);
 script_bugtraq_id(990, 11199);
 script_version ("$Revision: 1.3 $");
 script_cve_id(
   "CVE-1999-0504",
   "CVE-1999-0505",
   "CVE-1999-0506",
   "CVE-2000-0222",
   "CVE-2005-3595"
 );
 script_xref(name:"OSVDB", value:"297");
 script_xref(name:"OSVDB", value:"10050");
 name["english"] = "SMB blank administrator password";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running one of the Microsoft Windows operating
systems.  It was possible to log into it using the administrator
account with a blank password." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_set_attribute(attribute:"solution", value: "Set a password to the administrator account");
 script_end_attributes();
 
 summary["english"] = "Attempts to log into the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_login.nasl");
 script_require_keys("SMB/blank_admin_password");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

val = get_kb_item("SMB/blank_admin_password");

if (val)
  security_hole(kb_smb_transport());

