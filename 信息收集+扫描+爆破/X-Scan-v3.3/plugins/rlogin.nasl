#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10205);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0651");

 script_name(english:"rlogin Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The rlogin service is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the 'rlogin' service.  This service is dangerous in 
the sense that it is not ciphered - that is, everyone can sniff the data that 
passes between the rlogin client and the rloginserver. This includes logins 
and passwords.

Also, it may allow poorly authenticated logins without passwords. If the 
host is vulnerable to TCP sequence number guessing (from any network)
or IP spoofing (including ARP hijacking on a local network) then it may 
be possible to bypass authentication.

Finally, rlogin is an easy way to turn file-write access into full logins 
through the .rhosts or rhosts.equiv files. 

You should disable this service and use ssh instead." );
 script_set_attribute(attribute:"solution", value:
"Comment out the 'login' line in /etc/inetd.conf" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of rlogin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/rlogin", 513);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

function test(port)
{
  local_var	soc, s, c, a, r;

  if (! get_port_state(port)) return 0;
  soc = open_priv_sock_tcp(dport:port);
  if (! soc) return 0;
  s = '\0';
  send(socket:soc, data:s);
  s = 'root\0root\0xterm/38400\0';
  send(socket:soc, data:s);
  c = recv(socket:soc, length: 1);
  if (c != '\0')
  {
    close(soc);
    return 0;
  }
  r = recv(socket:soc, length:1024);
  close(soc);
  a = strcat(c, r);
  set_kb_item(name: "FindService/tcp/"+port+"/rlogin", value: a);
  if ('\0' >< a)
    set_kb_item(name: "FindService/tcp/"+port+"/rloginHex", value: hexstr(a));
  if (strlen(r) < 1) return 0;
  if (port == 513 || 'assword:' >< r)
    return 1;
  else
    return 0;
}

port_l = make_service_list(513, "Services/rlogin");
done = make_list();

foreach p (port_l)
  if (! done[p])
  {
    if (test(port: p))
    {
      security_warning(port: p);
      register_service(port: p, proto: "rlogin");
    }
    done[p] = 1;
  }

if (! get_kb_item("global_settings/disable_service_discovery")
    && thorough_tests)
  foreach p (get_kb_list("Services/unknown"))
    if (! done[p] && service_is_unknown(port: p))
    {
      if (test(port: p))
      {
        security_warning(port: p);
        register_service(port: p, proto: "rlogin");
      }
      done[p] = 1;
    }
