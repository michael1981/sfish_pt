#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");


if(description)
{
 script_id(15626);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-1101");
 script_bugtraq_id(11596);
 script_xref(name:"OSVDB", value:"11412");
 script_xref(name:"Secunia", value:"13093");

 script_name(english:"TIPS MailPost Cross-Site Scripting Vulnerability");
 script_summary(english:"Test the remote mailpost.exe");
 
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
     "The remote host is running TIPS MailPost, a web application used for\n",
     "emailing HTML form data to a third party.\n\n",
     "The version of MailPost running on the remote web server has a\n",
     "cross-site scripting vulnerability in the 'append' variable of\n",
     "mailpost.exe when debug mode is enabled.  Debug mode is enabled by\n",
     "default.  A remote attacker could exploit this to impersonate\n",
     "legitimate users.\n\n",
     "This version of MailPost reportedly has other vulnerabilities, though\n",
     "Nessus has not checked for those issues."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.kb.cert.org/vuls/id/107998"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable debug mode."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

test_cgi_xss(port: port, cgi: "/mailpost.exe", qs: "<script>foo</script>", 
  pass_str: "CGI_QueryString= <script>foo</script>");
