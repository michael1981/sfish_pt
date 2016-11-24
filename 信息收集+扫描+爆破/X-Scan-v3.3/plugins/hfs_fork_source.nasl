#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15927);
 script_cve_id("CVE-2004-1083", "CVE-2004-1084");
 script_bugtraq_id(11802);
 script_xref(name:"OSVDB", value:"12192");
 script_xref(name:"OSVDB", value:"12193");
 script_version ("$Revision: 1.18 $");

 script_name(english:"Apache on Mac OS X HFS+ Arbitrary File Source Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running Mac OS X or Mac OS X Server. 

There is a flaw in the remote web server that allows an attacker to
obtain the source code of any given file on the remote web server by
reading it through its data fork directly.  An attacker may exploit
this flaw to obtain the source code of remote scripts." );
 script_set_attribute(attribute:"solution", value:
"Install the latest Apple Security Patches." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	
script_end_attributes();

 
 summary["english"] = "downloads the source of a remote script";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl");
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
if ( ! port ) exit(0);

if ( get_kb_item("www/no404/" + port  ) ) exit(0);

function check(file, pattern)
{
  local_var	r, u, rep;
  u = strcat(file, "/..namedfork/data");
  r = http_send_recv3(method: 'GET', port: port, item: u);
  if (isnull(r)) exit(0);
  if (r[0] =~ "^HTTP/[01]\.[01] +200 " && (pattern >< r[2] ))
  {
     # Avoid FP
     r = http_send_recv3(method: 'GET', port: port, item: strcat(file, "/..", rand()));
     if (r[0] =~ "^HTTP/[01]\.[01] +200 " && (pattern >< r[2])) return 0;

	  rep = strcat('\nThe output from the following URLs should demonstrate the issue :\n\n - ', build_url(port:port, qs:file), '\n - ', build_url(port:port, qs:u), '\n');
	security_warning (port, extra: rep );
	return 1;
	}

 return 0 ;
}

port = get_http_port(default:80);

 check(file:"/index.php", pattern:"<?");
 files = get_kb_list(string("www/", port, "/content/extensions/php"));
 if(!isnull(files))
 {
 files = make_list(files);
 check(file:files[0], pattern:"<?");
 }
 r = http_send_recv3(method: 'GET', item:"/index.html", port:port);
 if (isnull(r)) exit(0);
 check(file:"/index.html", pattern: r[2]);
