#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40418);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(35783);
  script_xref(name:"OSVDB",   value:"56540");
  script_xref(name:"Secunia", value:"35969");

  script_name(english:"CommuniGate Pro WebMail < 5.2.15 XSS");
  script_summary(english:"Checks for CommuniGate Pro < 5.2.15");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is from a version of
CommuniGate Pro older than 5.2.15.  The webmail component of such
versions fails to correctly parse plain text email messages containing
malicious URL links before displaying the message to the user.  By
sending a specially crafted email message to the victim's email
address, an attacker may be able to leverage this issue to execute
arbitrary JavaScript code within the user's browser session every time
the email message is read." );

  script_set_attribute(attribute:"see_also", value:"http://rawlab.mindcreations.com/codes/exp/xss/communigate-pro-5.2.14-xss.txt" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2009-07/0174.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.communigate.com/cgatepro/History52.html" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to CommuniGate Pro 5.2.15 or later." );

  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

  script_set_attribute(attribute:"vuln_publication_date",   value:"2009/07/23");
  script_set_attribute(attribute:"patch_publication_date",  value:"2009/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/29");
  
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www",8100);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8100);

# Check the version in the banner.
banner = get_http_banner(port:port);

if (!banner || "CommuniGatePro" >!< banner)
  exit(1, "Banner is null or not from CommuniGate Pro.");

if (egrep(pattern:"^Server: CommuniGatePro/([0-4]\.|5\.([0-1][^0-9])|5\.2\.([0-9]|1[0-4])($|[^0-9]))", string:banner)) 
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    serv = strstr(banner, "Server:");
    serv = serv - strstr(serv, '\r\n');

    report = string('\n',
                     'The remote CommuniGatePro server responded with the following banner :','\n\n',
                     serv,'\n');
     security_warning(port:port,extra:report);
  } 
  else security_warning(port);
}
else exit(0, "The installed version of CommuniGate Pro is not affected.");

