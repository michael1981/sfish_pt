#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title, fixed VDB refs, enhanced description (1/28/2009)


include("compat.inc");

if(description)
{
   script_id(10760);
   script_version ("$Revision: 1.16 $");

   script_cve_id("CVE-2001-1424");
   script_bugtraq_id(2568);
   script_xref(name:"OSVDB", value:"429");

   script_name(english:"Alcatel ADSL Modem Unrestricted Remote Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The Alcatel modem can be accessed remotely." );
 script_set_attribute(attribute:"description", value:
"On the Alcatel Speed Touch Pro ADSL modem, a protection mechanism 
feature is available to ensure that nobody can gain remote access 
to the modem (via the WAN/DSL interface). This mechanism guarantees 
that nobody from outside your network can access the modem's 
management interface and potentially change its settings.

The protection is currently not activated on your system.

In addition, access was gained without providing a password, which
is the default." );
 script_set_attribute(attribute:"solution", value:
"Telnet to this modem and adjust the security settings as follows :

  => ip config firewalling on
  => config save 

In addition, set a strong password on all accounts." );
 script_set_attribute(attribute:"see_also", value:"http://www.alcatel.com/consumer/dsl/security.htm" );
 script_set_attribute(attribute:"risk_factor", value:"High" );

script_end_attributes();

 
   summary["english"] = "Checks Alcatel ADSL modem protection";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2001-2009 Alert4Web.com");
   script_family(english:"Misc.");
   script_require_ports(23);
 
   exit(0);
}

include('global_settings.inc');

if ( ! thorough_tests && ! ereg(pattern:"^10\.0\.0\..*", string:get_host_ip())) exit(0);

port = 23; # alcatel's ADSL modem telnet module can't bind to something else

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv(socket:soc, length:160);
   if("User : " >< r)
   {
     send(socket:soc, data:string("\r\n"));
     r = recv(socket:soc, length:2048);
     if("ALCATEL ADSL" >< r)
     {
       s = string("ip config\r\n");
       send(socket:soc, data:s);
       r = recv(socket:soc, length:2048);
       if("Firewalling off" >< r)security_hole(port);
     }
   }
   close(soc);
 }
}
