#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(14700);
  script_version ("$Revision: 1.6 $"); 
  script_cve_id("CVE-2004-0787");
  script_bugtraq_id(11113);
  script_xref(name:"OSVDB", value:"9749");

  script_name(english:"OpenCA Client System Browser Form Input Field XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running an older version of OpenCA. 

It is reported that OpenCA versions up to and including 0.9.2-RC2 
are prone to a HTML injection vulnerability when processing user
inputs into the web form frontend. This issue may permit an attacker
to execute hostile HTML code in the context of another user." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
  summary["english"] = "Checks for the version of OpenCA";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses : XSS");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

host = get_host_name();
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

res = http_send_recv3(method:"GET", item:"/cgi-bin/pub/pki?cmd=serverInfo", port:port);
if (isnull(res)) exit(1,"Null response to /cgi-bin/pub/pki request.");

str = egrep(pattern:"Server Information for OpenCA Server Version .*", string:res[2]);
if ( str )
{
  version = ereg_replace(pattern:".*Server Information for OpenCA Server Version (.*)\)", string:str, replace:"\1");
  set_kb_item(name:"www/" + port + "/openca/version", value:version);
}

if (egrep(pattern:"Server Information for OpenCA Server Version 0\.([0-8][^0-9]|9\.[0-2][^0-9])", string:str)) 
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  security_warning(port);
}
