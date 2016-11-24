#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38157);
  script_version("$Revision: 1.2 $");

  script_name(english:"Microsoft SharePoint Server Detection");
  script_summary(english:"Detects a SharePoint Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a document sharing software");

 script_set_attribute(attribute:"description", value:
"The remote web server is running SharePoint,  a web interface for 
document management.

As this interface is likely to contain sensitive information, make sure
only authorized personel can log into this site");
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/Sharepoint/default.mspx");
 script_set_attribute(
   attribute:"solution",
   value:string(
    "Make sure the proper access controls are put in place")
  );

  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );


  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443);
if (!get_port_state(port)) exit(0);

res = http_get_cache(item:"/", port:port);
if (isnull(res)) exit(0);
if ( (line = egrep(pattern:"^MicrosoftSharePointTeamServices: ", string:res)) )
{
 version = ereg_replace(pattern:"^MicrosoftSharePointTeamServices: ([0-9.]+).*", string:line, replace:"\1");
 set_kb_item(name:"www/" + port + "/sharepoint", value:version + " under /");
 security_note(port:port, extra:"Version " + version + " of SharePoint is installed on the remote host"); 
}

