#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40472);
 script_version("$Revision: 1.3 $");

 script_name(english: "PCI DSS compliance : options settings");
 
 script_set_attribute(attribute:"synopsis", value:
"Sets options for a PCI DSS compliance test." );
 script_set_attribute(attribute:"description", value:
"This plugin configures miscellaneous global variables for Nessus
scripts if the PCI DSS compliance checks are enabled. 

It does not perform any security check but may enable or change the 
behavior of others." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();

 script_summary(english: "Modify global variables for PCI DSS");
 script_category(ACT_SETTINGS);	
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Settings");
 # Make sure we run after these ACT_SETTINGS scripts
 script_dependencies("web_app_test_settings.nasl", "global_settings.nasl");
 exit(0);
}


opt = get_preference("PCI DSS compliance[checkbox]:Check for PCI-DSS compliance");

if ("no" >< opt || "yes" >!< opt) exit(0, "PCI DSS compliance checks are disabled");
set_kb_item(name: "Settings/PCI_DSS", value: TRUE);
set_kb_item(name: "Settings/test_all_accounts", value: TRUE);

report = "";

if (! get_kb_item("Settings/enable_web_app_tests"))
{
  report = strcat(report, 
'Web applications tests were disabled.  They are needed to test
cross-site scripting and SQL injection flaws.\n');
  set_kb_item(name: "Settings/enable_web_app_tests", value: TRUE);
}

t = get_kb_item("Settings/HTTP/max_run_time");
if (int(t) <= 0)
{
  report = strcat(report, 
'The timeout for the web application tests was null.  You should
configure the web application tests properly.\n');
  replace_kb_item(name: "Settings/HTTP/max_run_time", value: 3600);
}

if (get_kb_item("Settings/disable_cgi_scanning"))
{
  report = strcat(report, 
'CGI scanning was disabled.  This is needed to test cross-site
scripting and SQL injection flaws.\n');
  rm_kb_item(name: "Settings/disable_cgi_scanning");
}

if (report) security_note(port: 0, extra: report);
