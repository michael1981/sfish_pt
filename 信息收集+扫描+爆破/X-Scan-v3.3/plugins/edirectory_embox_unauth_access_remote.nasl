#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(31851);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0926");
  script_bugtraq_id(28441);
  script_xref(name:"OSVDB", value:"43690");
  script_xref(name:"Secunia", value:"29527");

  script_name(english:"eDirectory eMBox Utility Unauthorized Access (uncredentialed check)");
  script_summary(english:"Checks if eDirectory services can be queried remotely.");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host has an application installed that allows unauthorized\n",
      "access to the system."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running eDirectory, a popular directory service\n",
      "software from Novell.\n\n",
      "A vulnerability in the eMBox utility included with the software\n",
      "allows an unauthenticated attacker to access local files or cause a\n",
      "denial-of-service condition.\n\n",
      "Nessus was able to query the list of available eDirectory\n",
      "services on the remote host without using any credentials, see\n",
      "plugin output for more details."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2008-05/0067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.novell.com/support/viewContent.do?externalId=3477912"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to eDirectory 8.8.2 or rename 'embox.nlm' and configure\n",
      "it to start manually."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:C"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports(8008,8028);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port =  get_http_port(default:8008); 	      # Clear text http port on eDirectory 8.8
if (!get_port_state(port)) exit(0);

# POST requests take longer, so check if we are looking 
# at a banner from novell product.

banner = get_http_banner(port: port);
if (!banner || (!egrep(pattern:"DHost/[0-9].[0-9] *HttpStk/[0-9].[0-9]",string:banner) && "NetWare HTTP Stack" >!< banner)) exit(0);

init_cookiejar();
# Request server info and get the Cookie.
postdata =strcat(
'<?xml version="1.0"?>','\n',
'<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">\n',
'<SOAP-ENV:Header/><SOAP-ENV:Body><dispatch><Action>novell.embox.connmgr.serverinfo</Action>',
'<Object/><Parameters/></dispatch></SOAP-ENV:Body></SOAP-ENV:Envelope>\n'
);

# There was "HTTP/1.0" in the old request. I did not force the version
r = http_send_recv3(method: 'POST', item: '/SOAP', data: postdata, port: port,
add_headers: make_array( 'Content-Type', 'text/xml',
	     		 'Accept-Language', 'en-US;q=0.2, en;q=0.1',
			 'Accept-Charset', 'Cp1252',
			 'SOAPAction', '"/novell.embox.connmgr.serverinfo"') );
if (isnull(r)) exit(0);

res = r[0]+r[1]+'\r\n'+r[2];
# If we see serverinfo we can continue.

if ("novell.embox.connmgr.serverinfo" >< res)
{
 if (! egrep(string: r[1], pattern: "^Set-Cookie2?:", icase: 1)) exit(0);
 # Ok for all our efforts we got a Cookie. 
 # Now ask for list of services.

 postdata2 = string(
 
  '<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">',
  '<SOAP-ENV:Header/><SOAP-ENV:Body><dispatch><Action>novell.embox.service.getServiceList</Action>',
  '<Object/><Parameters><params xmlns:EMR="emtoolsmgr.dtd">',
  '<EMR:NamesOnly>0</EMR:NamesOnly></params></Parameters>',
  '</dispatch></SOAP-ENV:Body></SOAP-ENV:Envelope>'
  );

# Same: HTTP/1.0 was forced (but there was a Host field)
 r = http_send_recv3(method: 'POST', item: '/SOAP', data: postdata2, port: port,
add_headers: make_array( 'Content-Type', 'text/xml', 
	     		 'Accept-Language', 'en-US;q=0.2, en;q=0.1',
			 'Accept-Charset', 'Cp1252',
			 'SOAPAction', '"/novell.embox.service.getServiceList"') );
 
 if (isnull(r)) exit(0); # If the embox service is not running, we should exit here.
 res2 = r[0]+r[1]+'\r\n'+r[2];
# Exit if we see an error
if ("</EBX:XError>" >< res2) exit(0); # eDirectory 8.8 sp2

# There is a problem if we see a list of services, with embox.dlm 
# one of them.

found = 0;
service = NULL;

if ("eDirectory Management Tool Box Engine" >< res2)
  {
   line = NULL;
   res3 = NULL;
   res3 = split(res2, sep: ">"); 
   if (isnull(res3)) exit(0);

   foreach line (res3)
   {
    if (ereg(pattern:".*\.[dn]lm</name>$", string:line))
    {
     found++;
     service = ereg_replace(pattern:"^(.+\.[dn]lm)</name>$",string:line ,replace:"\1");
     report += string("+ ",service, "\n");
    }
  }  
  if (found)
  {
   report = string (
   "\nThe following ",found, " services are available on the remote eDirectory install : \n\n",
   report, "\n");

   security_hole(port:port,extra:report);
   }
 } 
}
