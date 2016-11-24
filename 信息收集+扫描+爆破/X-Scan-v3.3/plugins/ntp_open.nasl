#
# This script was written by David Lodge
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - recv() only receives the first two bytes of data (instead of 1024) [RD]
# - replaced ord(result[0]) == 0x1E by ord(result[0]) & 0x1E (binary AND) [RD]
# - updated title (9/8/09)

include("compat.inc");

if(description)
{
 script_id(10884);
 script_version("$Revision: 1.21 $");

 script_name(english:"Network Time Protocol (NTP) Server Detection");

 script_set_attribute(attribute:"synopsis", value:
"An NTP server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"An NTP (Network Time Protocol) server is listening on this port.  It
provides information about the current date and time of the remote
system and may provide system information." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();

 script_summary(english:"NTP allows query of variables");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 David Lodge");
 script_family(english:"Service detection");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

#
# The script code starts here
#
#

function ntp_read_list()
{
    local_var data, p, r, soc;

    data = raw_string(0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00);
    soc = open_sock_udp(123);
    if (!soc)exit(0);
    send(socket:soc, data:data);
    r = recv(socket:soc, length:4096);
    close(soc);

    if (! r) return(NULL);

    p = strstr(r, "version=");
    if (! p) p = strstr(r, "processor=");
    if (! p) p = strstr(r, "system=");
    p = ereg_replace(string:p, pattern:raw_string(0x22), replace:"'");

    if (p) return(p);
    return(NULL);
}


function ntp_installed()
{
local_var data, r, soc;

data = raw_string(0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01,
    		  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA,
		  0x00, 0x00);

soc = open_sock_udp(123);
if (! soc ) exit(0);
send(socket:soc, data:data);
r = recv(socket:soc, length:4096);
close(soc);

if(strlen(r) > 10)
 {
 return(r);
 }
return(NULL);
}



# find out whether we can open the port

if( !(get_udp_port_state(123)) ) exit(0);



r = ntp_installed();
if(r)
   {
      set_kb_item(name:"NTP/Running", value:TRUE);
      register_service(port:123, proto:"ntp", ipproto:"udp");
      list = ntp_read_list();
      if(!list)security_note(port:123, protocol:"udp");
      else
       {
       if ("system" >< list )
        {
         s = egrep(pattern:"system=", string:list);
	 os = ereg_replace(string:s, pattern:".*system='([^']*)'.*", replace:"\1");
         set_kb_item(name:"Host/OS/ntp", value:os);
        }
       if ("processor" >< list )
        {
         s = egrep(pattern:"processor=", string:list);
	 os = ereg_replace(string:s, pattern:".*processor='([^']*)'.*", replace:"\1");
         set_kb_item(name:"Host/processor/ntp", value:os);
        }
       if ("version" >< list )
        {
         s = egrep(pattern:"version=", string:list);
         ver = ereg_replace(string:s, pattern:".*version='([^']*)'.*", replace:"\1");
         set_kb_item(name:"Services/ntp/version", value:ver);
        }

      report = string (
		"It was possible to gather the following information from the remote NTP host :\n\n",
		list
		);

      security_note(port:123, protocol:"udp", extra:report);
    }
  }

 
