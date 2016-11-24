#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16281);
  script_version ("$Revision: 1.9 $");
  script_bugtraq_id(12405);
  script_xref(name:"OSVDB", value:"13318");

  script_name(english:"SmarterTools SmarterMail Attachment Upload XSS");
  script_summary(english:"Checks for the presence of SmarterMail");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote mail server is vulnerable to a cross-site scripting attack."
  );

  script_set_attribute(
    attribute:'description',
    value:"There are flaws in the remote SmarterMail, a web mail interface.

This version of SmarterMail is affected by a cross-site scripting
issue.  An attacker, exploiting this flaw, would be able to steal user
credentials."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to SmarterMail 2.0.0.1837 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.smartertools.com/SmarterMail/Free-Windows-Mail-Server.aspx"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/About/frmAbout.aspx"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ("<title>About SmarterMail - SmarterMail</title>" >< r)
 {
  if ( egrep(pattern:"SmarterMail Professional Edition v\.([0-1]\.|2\.0\.([0-9]([0-9])?([0-9])?\.|1([0-7][0-9][0-9]\.|8([0-2][0-9]\.|3[0-6]\.))))", string:r))
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   exit(0);
  }
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
