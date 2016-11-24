#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(17611);
 script_bugtraq_id(12890);
 script_version("$Revision: 1.6 $");

 name["english"] = "Trillian Multiple HTTP Responses Buffer Overflow Vulnerabilities";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"An attacker may be able to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host has the Trillian program installed.  Trillian is a
Peer2Peer client that allows users to chat and share files with other
users across the world. 

The remote version of this software is vulnerable to several buffer
overflows when processing malformed responses. 

An attacker could exploit these flaws to execute arbitrary code on the
remote host.  To exploit these flaws, an attacker would need to divert
several HTTP requests made by the remote host (through DNS poisoning)
to a rogue HTTP server sending malformed data." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version newer than 3.1.0.121." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the version of Trillian.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
  script_dependencies("trillian_installed.nasl");
  script_require_keys("SMB/Trillian/Version");

  exit(0);
}


ver = get_kb_item("SMB/Trillian/Version");
if (ver)
{
  ver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("3.1.0.122", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      security_hole(get_kb_item("SMB/transport"));
      break;
    }
    else if (ver[i] > fix[i])
      break;
}

