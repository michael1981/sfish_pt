#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10582);
 script_version ("$Revision: 1.28 $");
 
 script_name(english:"HTTP Protocol Version Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"HTTP protocol version." );
 script_set_attribute(attribute:"description", value:
"This script determines which version of the HTTP protocol the remote
host is speaking" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
 summary["english"] = "HTTP version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("apache_SSL_complain.nasl", "doublecheck_std_services.nasl", "http11_detect.nasl");
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

http_disable_keep_alive();

function mkreq(ua, item)
{
 if ( isnull(item) ) item = "/";
 return string("GET ", item, " HTTP/1.1\r\n",
  	      "Connection: Close\r\n",
  	      "Host: ", get_host_name(), "\r\n",
	      "Pragma: no-cache\r\n",
	      "User-Agent: " + ua + "\r\n",
	      "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n",
	      "Accept-Language: en\r\n",
	      "Accept-Charset: iso-8859-1,*,utf-8\r\n",
	      "\r\n"
	      ); 
}


function check_ips(port)
{
 local_var soc, req;
 local_var r;

 r = http_send_recv3(port: port, item:"/", method:"GET", version: 11,
   add_headers: make_array("User-Agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"));

 if (isnull(r)) exit(0);
  if ( ! ereg(pattern:"^HTTP", string:r[0]) ) return 0;

 r = http_send_recv3(port: port, item:"/", method:"GET", version: 11,
   add_headers: make_array("User-Agent", "Mozilla/4.75 [en] (X11; U; Nessus)"));
 if (isnull(r)) return 1;
 if ( ! ereg(pattern:"^HTTP", string:r[0]) ) return 1;

 return 0;
}

function check_proxy(port)
{
 local_var soc, req;
 local_var r;
 
 req = http_mk_proxy_request(method:"GET", item:"/", scheme: "http", host: "www.google.com");
 r = http_send_recv_req(port: port, req: req);
 if (isnull(r)) return 0;
 if ( egrep(pattern:"^Via: ", string:r[1]) )
  set_kb_item(name:"Services/http_proxy", value:port);
}


  if ( check_ips(port:port) )
  {
   report = 
"The remote port seems to either have network connectivity issues
or seems to be protected by an IPS which prevents Nessus from 
sending HTTP requests to this port.

As a result, the remote web server will not be tested.";
  if (NASL_LEVEL < 3000)
    security_note(port:port, data:report + "

Solution :

Configure your IPS to allow network scanning from " + this_host() + "

Risk Factor : 

None" );
  else
    security_note(port:port, extra:report);
  
  set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
  set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
  exit(0);
  }

w = http_send_recv3(method:"GET", item:"/", version: 11, port: port);
if (! isnull(w) &&
    ereg(string:w[0], pattern:"^HTTP/.* 30[0-9] ") &&
    egrep(pattern:"^Server: EZproxy", string:w[1]) )
{
   report = 
"The remote port seems to be running EZproxy, a proxy server which
opens many HTTP ports to simply to perform HTTP redirections.

Nessus will not perform HTTP tests again the remote port, since they
would consume time and bandwidth for no reason

See also : 

http://www.usefulutilities.com/support/rewrite.html";
		if (NASL_LEVEL < 3000)
  		  security_note(port:port, data:report);
		else
  		  security_note(port:port, extra:report);
		set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
		set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
 		 exit(0);
}

if(! isnull(w) &&
     ereg(string:w[0], pattern:"^HTTP/.* [0-9]*")  &&
   ! ereg(string:w[0], pattern:"^HTTP/.* 50[0-9]") )
{
  	  set_kb_item(name:string("http/", port), value:"11");
	  exit(0);
}
else 
{
  w = http_send_recv3(port: port, method:"GET", item:"/", version: 10);
  if(! isnull(w) && ereg(string:w[0], pattern:"^HTTP/.* [0-9]*") )
  {
	if ( ereg(string:w[0], pattern:"^HTTP/.* 50[0-9]") )
	{
	 set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
  	 set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
 	 set_kb_item(name:"Services/www/" + port + "/broken/reason", value:"50x");
	}
   	else
 	 set_kb_item(name:string("http/", port), value:"10");
	exit(0);
   }
   else
   {
       w = http_send_recv3(method:"GET", port:port, item: "/", version: 9);
       if (! isnull(w) && ("HTML" >< w[0] || "200" >< w[0]))
         {
           set_kb_item(name:string("http/", port), value:"09");
	   exit(0);
         }
   }
}


# The remote server does not speak http at all. We'll mark it as
# 1.0 anyway
if(port == 80)
{
 set_kb_item(name:string("http/", port), value:"10");
}
