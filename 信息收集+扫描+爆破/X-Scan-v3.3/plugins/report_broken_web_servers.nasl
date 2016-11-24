#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(42799);
 script_version("$Revision: 1.1 $");

 script_name(english: "Broken Web Servers");
 script_summary(english: "Report broken web servers");

 script_set_attribute(attribute:"synopsis", value:
"Tests on this web server have been disabled.");
 script_set_attribute(attribute:"description", value:
"The remote web server seems password protected or misconfigured.  
Further tests on it were disabled so that the whole scan is not 
slowed down." );
 script_set_attribute(attribute:"solution", value: "n/a");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/13");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencies("httpver.nasl", "broken_web_server.nasl");
 script_require_ports("Services/www");
 exit(0);
}

#
port = get_kb_item("Services/www");
if (!port) exit(0);

if (! get_kb_item("Services/www/" +port+ "/broken")) exit(0);

who = get_kb_item("Services/www/"+port+"/declared_broken_by");
why = get_kb_item("Services/www/" +port+ "/broken/reason");

if (who)
{
  report = strcat('\nThis web server was declared broken by ', who, '\n');
  if (why && why != "unknown") 
    report = strcat(report, 'for the following reason :\n\n', why, '\n');
  security_note(port: port, extra: report);
}
else if (why && why != 'unknown')
{
  report = strcat('\nThis web server was declared broken for the following reason :\n\n', why, '\n');
  security_note(port: port, extra: report);
}
else
  security_note(port);
