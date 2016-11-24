#
# (C) Tenable Network Security
#
#  Date: Fri, 14 Mar 2003 18:42:02 -0800
#  To: bugtraq@securityfocus.com
#  Subject: @(#)Mordred Security Labs - RSA ClearTrust Cross Site Scripting issues 
#  From: sir.mordred@hushmail.com


include("compat.inc");

if(description)
{
 script_id(11399);
 script_bugtraq_id(7108);
 script_xref(name:"OSVDB", value:"50619");
 script_version ("$Revision: 1.21 $");
 
 script_name(english:"RSA ClearTrust ct_logon.asp Multiple Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote ClearTrust server is vulnerable to a cross-site scripting
attack that can be exploited using specially-crafted calls to its
'ct_logon.asp' or 'ct_logon.jsp' scripts." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-03/0224.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Checks for ClearTrust XSS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if ( ! can_host_asp(port:port) ) exit(0);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach dir (make_list(cgi_dirs()))
{
 foreach script (make_list("ct_logon.asp", "ct_logon.jsp"))
 {
  exploit = string(
   dir, "/cleartrust/", script, "?",
   "CTLoginErrorMsg=<script>alert(1)</script>"
  );
  r = http_send_recv3(method:"GET", item:exploit, port:port);
  if (isnull(r)) exit(0);

  if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:r[0]))exit(0);

  if("<script>alert(1)</script>" >< r[2] )
  {
   if (report_verbosity)
   {
    extra = string(
     "\n",
     "Nessus was able to exploit this issue using the following request :\n",
     "\n",
     exploit
    );
    security_warning(port:port, extra:extra);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   }
   else
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   }
   exit(0);
  }
 }
}
