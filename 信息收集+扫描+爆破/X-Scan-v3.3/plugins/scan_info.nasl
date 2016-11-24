#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if(description)
{
 script_id(19506);
 script_version ("$Revision: 1.32 $");
 script_name(english:"Nessus Scan Information");
 
 script_set_attribute(attribute:"synopsis", value:
"Information about the Nessus scan." );
 script_set_attribute(attribute:"description", value:
"This script displays, for each tested host, information about the scan itself:

 - The version of the plugin set
 - The type of plugin feed (HomeFeed, ProfessionalFeed or GPL)
 - The version of the Nessus Engine
 - The port scanner(s) used
 - The port range scanned
 - The date of the scan
 - The duration of the scan
 - The number of hosts scanned in parallel
 - The number of checks done in parallel" );
 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_end_attributes();

 script_summary(english: "Displays information about the scan");
 
 if ( !isnull(ACT_END2) ) script_category(ACT_END2);
 else script_category(ACT_END);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Settings");
 exit(0);
}

include('plugin_feed_info.inc');
include('global_settings.inc');


old_feed_alert = 0;
NESSUS4 = make_list(4,0,2);

array = split(NESSUS_VERSION, sep:'.', keep:FALSE);
myVersion = make_list(int(array[0]), int(array[1]), int(array[2]));

if ( myVersion[0] < NESSUS4[0] || (myVersion[0] == NESSUS4[0] && (myVersion[1] < NESSUS4[1] || (myVersion[1] == NESSUS4[1] && myVersion[2] < NESSUS4[2]))) )  new_vers = string(NESSUS4[0], ".", NESSUS4[1], ".", NESSUS4[2]);





# 
# If no plugin has shown anything, quietly exit
#
list = get_kb_list("Success/*");
if ( isnull(list) ) exit(0);


if ( ! strlen(NESSUS_VERSION) )
	{
	if ( ! defined_func("pread") && NASL_LEVEL >= 2202 )
		version = "NeWT";
	else
		version = "Unknown (NASL_LEVEL=" + NASL_LEVEL + ")";
	}
 else
	version = NESSUS_VERSION;


if ( new_vers )
 version += " (Nessus " + new_vers + ' is available - consider upgrading)\n';

report = 'Information about this scan : \n\n';
report += 'Nessus version : ' + version + '\n';

if ( PLUGIN_SET )
{
 report += 'Plugin feed version : ' + PLUGIN_SET     + '\n';
 report += 'Type of plugin feed : ' + PLUGIN_FEED    + '\n';
 if ( PLUGIN_SET =~ "^[0-9]*$" )
 {
  rel["year"] = int(substr(PLUGIN_SET, 0, 3));
  rel["mon"] = int(substr(PLUGIN_SET, 4, 5));
  rel["mday"] = int(substr(PLUGIN_SET, 6, 7));
  time = ((rel["year"] - 1970)*(24*3600*365)) + 
	  (rel["year"] - 1970)/4*24*3600;
  time += (rel["mon"]-1)*(12*3600*30+12*3600*31);
  time += rel["mday"]*(24*3600);
  diff = (unixtime() - time)/3600/24;
  if ( diff >= 30 && diff < 10000 )
  {
   old_feed_alert ++;
   report += string("\nERROR: Your plugin feed has not been updated since " , rel["year"] , "/" , rel["mon"] , "/" , rel["mday"], "\n",
"Performing a scan with an older plugin set will yield out of date results and
produce an incomplete audit. Please run nessus-update-plugins to get the
newest vulnerability checks from Nessus.org.\n\n");
  }
 else if ( PLUGIN_FEED == "Release" )
 {
  report += "
This scanner is using the set of plugins bundled with the default
installation, which means that the newest vulnerabilities will not
be checked for and your audit will be incomplete.

If you have not done so already, please obtain an activation code 
at http://www.nessus.org/register/ and update your plugins prior to
running another scan." + '\n\n';
 }
 else if ( "Registered" >< PLUGIN_FEED && "HomeFeed" >!< PLUGIN_FEED )
 {
  report += "
This scanner is using the Registered Feed which has been discontinued on 
July 31st, and will stop working on August 29th.

Please read http://www.nessus.org/products/directfeed/change.php" + '\n\n';
 }
}
}

report += 'Scanner IP : ' + this_host()    + '\n';


list = get_kb_list("Host/scanners/*");
if ( ! isnull(list) )
{
 foreach item ( keys(list) )
 {
  item -= "Host/scanners/";
  scanners += item + ' ';
 }

 report += 'Port scanner(s) : ' + scanners + '\n';
}
else
 report += '\nWARNING : no port scanner was enabled during the scan. This may\nlead to incomplete results\n\n';

if ( get_kb_item("global_settings/disable_service_discovery") ) 
{
 report += '\nWARNING: Service discovery has been disabled. The audit is incomplete\n'; 
}



range = get_preference("port_range");
if ( ! range ) range = "(?)";
report += 'Port range : ' + range + '\n';

report += 'Thorough tests : ';
if ( thorough_tests ) report += 'yes\n';
else report += 'no\n';

report += 'Experimental tests : ';
if ( experimental_scripts ) report += 'yes\n';
else report += 'no\n';

report += 'Paranoia level : ';
report += report_paranoia + '\n';

report += 'Report Verbosity : ';
report += report_verbosity + '\n';

report += 'Safe checks : ';
if ( safe_checks() ) report += 'yes\n';
else report += 'no\n';

report += 'Optimize the test : ';
if ( get_preference("optimize_test") == "yes" ) report += 'yes\n';
else report += 'no\n';

report += 'CGI scanning : ';
if (get_kb_item("Settings/disable_cgi_scanning")) report += 'disabled\n';
else report += 'enabled\n';

report += 'Web application tests : ';
if (get_kb_item("Settings/enable_web_app_tests")) report += 'enabled\n';
else report += 'disabled\n';

report += 'Max hosts : ' + get_preference("max_hosts") + '\n';
report += 'Max checks : ' + get_preference("max_checks") + '\n';
report += 'Recv timeout : ' + get_preference("checks_read_timeout") + '\n';

if ( get_kb_item("general/backported")  )
 report += 'Backports : Detected\n';
else
 report += 'Backports : None\n';
 



start = get_kb_item("/tmp/start_time");



if ( start )
{
 time = localtime(start);
 if ( time["min"] < 10 ) zero = "0";
 else zero = NULL;

 report += 'Scan Start Date : ' + time["year"] + '/' + time["mon"] + '/' + time["mday"] + ' ' + time["hour"] + ':' + zero + time["min"] + '\n';
}



if ( ! start ) scan_duration = 'unknown (ping_host.nasl not launched?)';
else           scan_duration = string (unixtime() - start, " sec");
report += 'Scan duration : ' + scan_duration + '\n';



if ( old_feed_alert )
 security_hole(port:0, data:report);
else
 security_note(port:0, data:report);

