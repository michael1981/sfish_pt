#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(28228);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2007-4572", "CVE-2007-5398");
  script_bugtraq_id(26454, 26455);
  script_xref(name:"OSVDB", value:"39179");
  script_xref(name:"OSVDB", value:"39180");

  script_name(english:"Samba < 3.0.27 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

 script_set_attribute(attribute:"synopsis", value:
"The remote Samba server may be affected one or more vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server on the remote
host contains a boundary error in the 'reply_netbios_packet()'
function in 'nmbd/nmbd_packets.c' when sending NetBIOS replies. 
Provided the server is configured to run as a WINS server, a remote
attacker can exploit this issue by sending multiple specially-crafted
WINS 'Name Registration' requests followed by a WINS 'Name Query'
request, leading to a stack-based buffer overflow and allow for
execution of arbitrary code. 

There is also a stack buffer overflow in nmbd's logon request
processing code that can be triggered by means of specially-crafted
GETDC mailslot requests when the affected server is configured as a
Primary or Backup Domain Controller.  Note that the Samba security
team currently does not believe this particular can be exploited to
execute arbitrary code remotely." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-90/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483744" );
 script_set_attribute(attribute:"see_also", value:"http://us1.samba.org/samba/security/CVE-2007-4572.html" );
 script_set_attribute(attribute:"see_also", value:"http://us1.samba.org/samba/security/CVE-2007-5398.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483742" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483743" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 3.0.27 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager");

  exit(0);
}


include("global_settings.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
  if (ereg(pattern:"Samba 3\.0\.([0-9]|1[0-9]|2[0-6])[^0-9]*$", string:lanman, icase:TRUE))
    security_hole(get_kb_item("SMB/transport"));
}
