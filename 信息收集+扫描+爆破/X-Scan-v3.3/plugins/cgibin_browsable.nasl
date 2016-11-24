#
# (C) Hendrik Scholz <hendrik@scholz.net>
#


include("compat.inc");

if(description)
{
 script_id(10039);
 script_version ("$Revision: 1.28 $");

 script_xref(name:"OSVDB", value:"3268");

 script_name(english:"Directory Browsing Enabled?");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The /cgi-bin directory is browsable.
This will show you the name of the installed common scripts 
and those which are written by the web-master and thus may be 
exploitable." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/913704" );
 script_set_attribute(attribute:"solution", value:
"Make the /cgi-bin non-browsable." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 summary["english"] = "Is /cgi-bin browsable ?";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Hendrik Scholz");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = NULL;
report_head = "The following CGI directories are browsable :";

report_tail = string(
  "This shows an attacker the name of the installed common scripts and \n",
  "those which are written by the web-master and thus may be exploitable."
);

foreach dir (cgi_dirs())
{
 if ( strlen(dir) )
 {
 data = string(dir ,"/");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf))
 {
  buf = tolower(buf);
  if(dir == "") must_see = "index of";
  else must_see = string("<title>", dir);
  if( must_see >< buf ){
  	dirs += '.  ' + dir + '\n';
	set_kb_item( name: 'www/'+port+'/content/directory_index', value: data);
	}
 }
 }
}
report = string(
  "\n",
  report_head, "\n",
  dirs, "\n",
  report_tail
);

if (dirs != NULL )
{
 security_warning(port:port, extra:report);
}


