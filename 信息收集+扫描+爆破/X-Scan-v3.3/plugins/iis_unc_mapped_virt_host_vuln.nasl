# 
# tony@libpcap.net
# http://libpcap.net
#
# See the Nessus Scripts License for details


include("compat.inc");

if(description) {
  script_id(11443);
  script_bugtraq_id(1081);
  script_version("$Revision: 1.14 $");
  script_cve_id("CVE-2000-0246");

  script_name(english:"Microsoft IIS ISAPI Virtual Directory UNC Mapping ASP Source Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"It is possible to get the source code of the remote ASP scripts which
are hosted on a mapped network share by appending '%5c' to the end of
the request.  ASP source code usually contains sensitive information
such as logins and passwords." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/MS00-019.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );


script_end_attributes();


  summary["english"] = "Checks IIS for .ASP/.HTR backslash vulnerability.";
  script_summary(english:summary["english"]);
  script_copyright(english:"(C) 2003-2009 tony@libpcap.net");
  script_category(ACT_GATHER_INFO);

  family["english"] = "Web Servers";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl", "www_fingerprinting_hmap.nasl", "translate_f.nasl");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
hf = get_kb_item("Services/www/ms00-058-missing");
if( hf == "installed" ) exit(0);

if ( hf == "missing" )
	{
	 security_warning(port);
	 exit(0);
	}

if ( ! can_host_asp(port:port) ) exit(0);

if(get_port_state(port)) {
  # common ASP files
  f[0] = "/index.asp%5C";
  f[1] = "/default.asp%5C";
  f[2] = "/login.asp%5C";
  
  files = get_kb_list(string("www/", port, "/content/extensions/asp"));
  if(!isnull(files)){
 	files = make_list(files);
	f[3] = files[0] + "%5C";
	}

  for(i = 0; f[i]; i = i + 1) {
    req = http_get(item:f[i], port:port);
    h = http_keepalive_send_recv(port:port, data:req);
    if( h == NULL ) exit(0);
    
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:h) &&
       "Content-Type: application/octet-stream" >< r) {
      security_warning(port);
      exit(0);
    }
  }
}
