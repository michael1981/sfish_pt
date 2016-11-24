#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11552); 
 script_version("$Revision: 1.12 $");
 script_bugtraq_id(7388, 7393);
 script_xref(name:"OSVDB", value:"55813");
 script_xref(name:"OSVDB", value:"55814");

 script_name(english:"mod_ntlm for Apache Multiple Remote Vulnerabilities");
 script_summary(english:"mod_ntlm overflow / format string");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server module has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host seems to be running mod_ntlm, a NTLM authentication\n",
     "module for Apache.  This version of mod_ntlm has a buffer overflow and\n",
     "a format string vulnerability.  A remote attacker could exploit\n",
     "these issues to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-04/0251.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?9513a21e (vendor patch)"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the vendor patch."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache", "Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

function check(loc)
{
  local_var w, res, soc, r;

  w = http_send_recv3(method:"GET",item:loc, port:port, 
    username: "", password: "");
  if (isnull(w)) exit(1, "the web server did not answer");

  if("WWW-Authenticate: NTLM" >< w[1] )
  {
    w = http_send_recv3(method: "GET ", item: loc, port: port,
      add_headers: make_array("Authorization", "NTLM nnnn"));
    if (isnull(w)) exit(1, "the web server did not answer");
    
    w = http_send_recv3(method:"GET ", item: loc, port: port,
      add_headers: make_array("Authorization", "NTLM %n%n%n%n"));

    if (isnull(w))
    {
      security_hole(port);
      exit(0);
    }
   }
}

pages = get_kb_list(string("www/", port, "/content/auth_required"));
if(isnull(pages)) pages = make_list("/");
else pages = make_list("/", pages);


foreach page (pages)
{
 check(loc:page);
}
