#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10746);
 script_version ("$Revision: 1.19 $");

 script_name(english:"Compaq Web Management Server Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is a web-enabled management service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HP System Management Homepage or Compaq Web
Management, a web-based interface to configure various components of
the remote host. 

It is suggested to not allow anyone to connect to this service." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();

 summary["english"] = "Determines of the remote web server is Compaq Web Management";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www", 2301, 2381);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
 
ports = add_port_in_list(list:get_kb_list("Services/www"), port:2301);
ports = add_port_in_list(list:ports, port:2381);
foreach port (ports)
{
  banner = get_http_banner(port:port);
  if ( ! banner || "Server: CompaqHTTPServer" >!< banner ) continue;
  if ( version = egrep(pattern:"^Server: CompaqHTTPServer/", string: banner ) )
  {
    version = ereg_replace(pattern:"Server: CompaqHTTPServer/(.*)", string:version, replace:"\1");
    version = chomp(version);
    if ("HP System Management Homepage/" >< version)
    {
      prod = "HP System Management Homepage";
      version = strstr(version, prod);
      version = strstr(version, "/") - "/";
    }
    else prod = "Compaq Web Management";

    report = string(
      "\n",
      "According to its banner, ", prod, " version ", version, "\n",
      "is installed on the remote host.\n"
    );
    security_note(port:port, extra:report);

    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
  }
}
