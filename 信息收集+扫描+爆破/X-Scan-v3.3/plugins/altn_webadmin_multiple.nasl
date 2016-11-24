#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16271);
 script_cve_id("CVE-2005-0317", "CVE-2005-0318", "CVE-2005-0319");
 script_bugtraq_id(12395);
 script_xref(name:"OSVDB", value:"13322");
 script_xref(name:"OSVDB", value:"13323");
 script_xref(name:"OSVDB", value:"13324");
 script_version ("$Revision: 1.11 $");
 name["english"] = "Alt-N WebAdmin Multiple Remote Vulnerabilities (XSS, Bypass Access)";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Alt-N WebAdmin, a web interface to MDaemon
mail server.  The remote version of this software is affected by
cross-site scripting vulnerabilities due to a lack of filtering on
user-supplied input in the file 'useredit_account.wdm' and the file
'modalframe.wdm'.  An attacker may exploit this flaw to steal user
credentials. 

This software is also vulnerable to a bypass access attack in the file
'useredit_account.wdm'.  An attacker may exploit this flaw to modify
user account information. 

An attacker needs a valid email account on the server to successfully
exploit either of these issues." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0313.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebAdmin 3.0.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for the version of Alt-N WebAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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

port = get_http_port(default:1000);

function check(url)
{
 local_var r, w;
 global_var port;

 w = http_send_recv3(method:"GET", item:string(url, "/login.wdm"), port:port);
 if (isnull(w)) exit(0);
 r = w[1];
 if ( egrep(pattern:'<A href="http://www\\.altn\\.com/WebAdmin/" target="_blank">WebAdmin</A> v([0-2]\\.|3\\.0\\.[0-2]).*', string:r))
  {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
  }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
