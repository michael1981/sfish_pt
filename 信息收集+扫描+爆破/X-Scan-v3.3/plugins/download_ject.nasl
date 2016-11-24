#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12287);
 
 script_version("$Revision: 1.5 $");

 script_name(english:"Microsoft IIS Download.Ject Trojan Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is infected by a Trojan Horse." );
 script_set_attribute(attribute:"description", value:
"Download.Ject is a Trojan that infects Microsoft IIS servers.

The Trojan's dropper sets it as the document footer for all pages 
served by IIS Web sites on the infected computer." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/security/incident/download_ject.mspx" );
 script_set_attribute(attribute:"solution", value:
"Use an Anti-Virus to clean machine." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "IIS Download.Ject Trojan Detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80); 
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig )  exit(0);

r = http_get_cache(item:"/", port:port);
if (isnull(r)) exit(0);

if ( ("function sc088(n24,v8)" >< r) &&
     ("var qxco7=document.cookie" >< r) )
{
	security_hole(port);
	exit(0);
}

