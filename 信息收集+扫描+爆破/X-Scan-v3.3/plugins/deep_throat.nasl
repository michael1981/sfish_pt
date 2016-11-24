#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10053);
 script_version ("$Revision: 1.22 $");
 
 # There was a CVE for this (CVE-1999-0660), but it got rejected
 script_xref(name:"OSVDB", value:"20");

 script_name(english:"DeepThroat Backdoor Detection");
 script_summary(english:"Checks for the presence of DeepThroat");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"A backdoor is installed on the remote Windows host."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "DeepThroat is installed on the remote host.  This backdoor allows\n",
     "anyone to perform actions such as reading files, reading the registry\n",
     "and executing programs.  A remote attacker could use this to\n",
     "completely control the system."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://xforce.iss.net/xforce/xfdb/2290"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Use regedit or regedt32, and find 'SystemDLL32' in\n",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n",
     "This value's data is the path of the file.  If you are infected by\n",
     "DeepThroat 2 or 3, then the registry value is named 'SystemTray'.\n\n",
     "After cleaning the infected machine, you should manually find the root\n",
     "cause of the initial infection.  Alternatively, you may wish to\n",
     "completely rebuild the system, as the backdoor may have been used to\n",
     "create other backdoors into the system."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ThoroughTests");
 
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

port = 2140;
if(get_udp_port_state(port))
{
 data = raw_string(0x00,0x00);
 soc = open_sock_udp(port);
 if(soc)
 {
 send(socket:soc, data:data, length:2);
 result = recv(socket:soc, length:4096);
 if("My Mouth is Open" >< result)security_hole(port);
 close(soc);
 }
}
