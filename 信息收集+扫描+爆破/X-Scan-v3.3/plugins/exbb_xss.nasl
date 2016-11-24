#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
  script_id(16223);
  script_version("$Revision: 1.7 $");
  script_bugtraq_id(12306);
  script_xref(name:"OSVDB", value:"13056");
  script_xref(name:"Secunia", value:"13877");
  
  script_name(english:"ExBB Netsted BBcode XSS");
  script_summary(english:"Checks ExBB's version");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "A web application running on the remote host has a cross-site\n",
      "scripting vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running ExBB, a bulletin board system written\n",
      "in PHP.\n\n",
      "According to its version number, this install of ExBB has a\n",
      "persistent cross-site scripting vulnerability.  Posting a maliciously\n",
      "crafted forum comment could lead to arbitrary script code execution.\n",
      "A remote attacker could exploit this to steal the authentication\n",
      "cookies of legitimate users."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-01/0526.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"There is no known solution at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

foreach dir ( cgi_dirs() )
{
url = string(dir, "/search.php");
r = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(r)) exit(0);

if( 'class=copyright>ExBB</a>' >< r[2] )
{
  line = egrep(pattern:'Powered by <a href=.* target=_blank class=copyright>ExBB</a> (0\\.|1\\.[0-8][^0-9]|1\\.9[^.]|1\\.9\\.[01][^0-9])', string:r[2]);
  if ( line ) 
  {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
  }
 }
}
