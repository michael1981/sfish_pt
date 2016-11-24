#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

include("compat.inc");

if(description)
{
 script_id(10056);
 script_version ("$Revision: 1.23 $");

 script_cve_id("CVE-1999-0678");
 script_bugtraq_id(318);
 script_xref(name:"OSVDB", value:"48");

 script_name(english:"/doc Directory Browsable");
 script_summary(english:"Is /doc browsable ?");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The /doc directory is browsable.  /doc shows the contents of the
/usr/doc directory, which reveals not only which programs are
installed but also their versions.");
 script_set_attribute(attribute:"solution", value:
"Use access restrictions for the /doc directory.

If you use Apache you might use this in your access.conf :

 <Directory /usr/doc>
 AllowOverride None
 order deny,allow
 deny from all
 allow from localhost
 </Directory>");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2000/01/03");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Hendrik Scholz");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

data = http_get(item:"/doc/", port:port);
buf = http_keepalive_send_recv(port:port, data:data);
if (isnull(buf)) exit(0);

buf = tolower(buf);
must_see = "index of /doc";

if((ereg(string:buf, pattern:"^http/[0-9]\.[0-9] 200 "))&&(must_see >< buf)){
   	security_warning(port);
	set_kb_item(name:"www/doc_browseable", value:TRUE);
	set_kb_item( name: 'www/'+port+'/content/directory_index',
		     value: '/doc/' );
}

