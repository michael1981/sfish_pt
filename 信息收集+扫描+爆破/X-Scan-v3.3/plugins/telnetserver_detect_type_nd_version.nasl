#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10281);
 script_version ("$Revision: 1.36 $");

 script_name(english:"Telnet Server Detection");
 script_summary(english:"Telnet Server Detection");

 script_set_attribute(attribute:"synopsis", value:
"A Telnet server is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Telnet server, a remote terminal server." );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 
 exit(0);
}


#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");


# nb: the following defines and two functions resemble those in
#     telnet_func.inc but allow for negotiating a terminal type
#     if the remote requests that.
OPT_WILL 	= 0xfb;
OPT_WONT 	= 0xfc;
OPT_DO   	= 0xfd;
OPT_DONT 	= 0xfe;

OPT_SUBOPT 	= 0xfa;
OPT_ENDSUBOPT 	= 0xf0;

ECHO            = 0x01;
SUPPRESS_GA     = 0x03;
TERMINAL_TYPE   = 0x18;
NEW_ENVIRON     = 0x27;
default_term    = "xterm";


function get_telnet_banner(port)
{
  local_var sb, banner, soc;
  sb = string("Services/telnet/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  soc = open_sock_tcp(port);
  if(!soc) return (0);
  banner = telnet_negotiate(socket:soc);
  close(soc);
  if(strlen(banner)){
	if ( defined_func("replace_kb_item") )
		replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
	else
		set_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
	}
  return(banner);
}


function telnet_negotiate(socket, pattern)
{
 local_var opt, code, s, counter, counter2, buf, prev, subopt, timeout;

 counter = 0;
 timeout = 5;

 send(
  socket:socket, 
  data:raw_string(
    0xff, OPT_DO, SUPPRESS_GA,
    0xff, OPT_WILL, TERMINAL_TYPE,
    0xff, OPT_WILL, NEW_ENVIRON
  )
 );

 while ( TRUE )
 {
  s   = recv(socket:socket, length:1, timeout:timeout);
  if ( !strlen(s) ) break;
  if ( ord(s[0]) != 0xff) {
	 buf += s;
         if ( pattern && egrep(pattern:pattern, string:buf) ) break;
	 }
  else {
   counter ++;
   s  = recv(socket:socket, length:2);

   if ( ord(s[0]) == OPT_DO )
	{
	 # nb: we already said we'd handle terminal type and new environment variables if requested.
	 if ( ord(s[1]) != TERMINAL_TYPE && ord(s[1]) != NEW_ENVIRON ) 
           send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
	}
   else if ( ord(s[0]) == OPT_WILL )
	{
	  # nb: ask the server to echo.
	  if ( ord(s[1]) == ECHO ) send(socket:socket,data:raw_string(0xff, OPT_DO) + s[1]);
	  else if ( ord(s[1]) != SUPPRESS_GA ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
	}
   else if ( ord(s[0]) == OPT_SUBOPT )
	{
	 prev = recv(socket:socket, length:1);
	 subopt = s + prev;
         counter2 = 0;
	 while ( ord(prev) != 0xff && ord(s[0]) != OPT_ENDSUBOPT )
	   {
	    prev = s;
 	    # No timeout - the answer is supposed to be cached.
	    s    = recv(socket:socket, length:1, timeout:0);
	    if ( ! strlen(s) ) return buf;
            subopt += s;
	    counter2++;
	    if ( counter2 >= 100 ) return buf;
	   }
         if (ord(subopt[1]) == TERMINAL_TYPE && ord(subopt[2]) == 1)
           send(socket:socket, data:raw_string(0xff, OPT_SUBOPT, TERMINAL_TYPE, 0)+default_term+raw_string(0xff, OPT_ENDSUBOPT));
         else if (ord(subopt[1]) == NEW_ENVIRON && ord(subopt[2]) == 1)
           send(socket:socket, data:raw_string(0xff, OPT_SUBOPT, NEW_ENVIRON, 0, 0xff, OPT_ENDSUBOPT));
	}
  
   # Not necessary and may introduce endless loops
   #if ( ord(s[0]) == OPT_DONT ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   #if ( ord(s[0]) == OPT_WONT ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
  }
  if ( counter >= 100 || strlen(buf) >= 4096 ) break;
 }

 
 return buf;
}

function test(port)
{
  local_var	banner, trp, b, report;

  if (! get_port_state(port)) return 0;
  if (service_is_unknown(port: port))
  {
    b = get_unknown_banner2(port: port);
    if (isnull(b)) return 0;
    if (b[1] != 'spontaneous') return 0;
    banner = b[0];
    if ( strlen(banner) <= 2 || ord(banner[0]) != 255 ||
       	 ord(banner[1]) < 251 || ord(banner[1]) > 254 )
      return 0;
    register_service(port: port, proto: "telnet");
  }
  else
    if (! verify_service(port: port, proto: "telnet"))
      return 0;

  banner = get_telnet_banner(port: port);
  if(strlen(banner) && "CCProxy Telnet Service" >!< banner)
  {
   if (report_verbosity > 0)
   {
    report = string(
           "Here is the banner from the remote Telnet server :\n",
           "\n",
           crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
           banner, "\n",
           crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
         );
    security_note(port:port, extra:report);
   }
   else security_note(port);
   return 1;
  }
  return 0;
}

l = add_port_in_list(port: 23, list: get_kb_list("Services/telnet"));

foreach port (l)
  test(port: port);
