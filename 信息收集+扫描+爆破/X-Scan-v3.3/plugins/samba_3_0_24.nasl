#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24685);
 script_bugtraq_id(22395, 22403, 22410);
 script_xref(name:"OSVDB", value:"33098");
 script_xref(name:"OSVDB", value:"33100");
 script_xref(name:"OSVDB", value:"33101");
 script_cve_id("CVE-2007-0452", "CVE-2007-0453", "CVE-2007-0454");
 script_version ("$Revision: 1.6 $");
 name["english"] = "Samba < 3.0.24 Multiple Flaws";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is vulnerable to multiple vulnerabilies which
might lead to remote code execution" );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Samba server is affected
by several flaws :

- A denial of service issue occuring if an authenticated attacker sends
a large number of CIFS session requests which will cause an infinite loop 
to occur in the smbd daemon, thus utilizing CPU resources and denying access 
to legitimate users ;

- A remote format string vulnerability which may be exploited by an attacker
with write access to a remote share by sending a malformed request to
the remote service (this issue only affects installations sharing an
AFS file system when the afsacl.so VFS module is loaded)

- A remote buffer overflow vulnerability affecting the NSS lookup capability
of the remote winbindd daemon" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 3.0.24 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks the version of Samba";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

#
# Many distributions backported the fixes so this check
# is unreliable
#
if ( report_paranoia < 2 ) exit(0);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 3\.0\.([0-9]|1[0-9]|2[0-3])[^0-9]*$", string:lanman, icase:TRUE))
   security_hole(get_kb_item("SMB/transport"));
}
