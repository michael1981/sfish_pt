#TRUSTED 4961089c8718bce396992fd11528bd12609a61eeab8669d1c383e82c52aff66cc423af35c3a1eaad6307e27cf74f67c23e7e900a1d6556e02b65e67a2b266d897cbb41f193417678062d08b63d6dbac06a987967f1130609406599e2037a0ca69e3de745bb231c471a90028e1710f0c8e40b5b6a7f8a79605e260810a1cc30527496e0e3c1b0d4596ade89555e5eb5079aa846943ec731246775c52c4e0d42e200ccc94f622ff62f8f401b211c1b33ac536f51cd1c21c2f6d32705b58d548f6c1daa57c5f4544927230e4caa21228d33ee8a4dc56d9bbe0d731d7ef5d31a7960008df244fdaa93aa7ad95d5fa7af0f80ebbc2a028461b94cc654b72ed7eac697cf6379e2603560c461a43dd15058b899e4db5e23369fb7bd025cc1407d8c60c7f30f774e9a8aa5cbc82326f57b9d85d99680a91e57f43fa030a4c4c61b8fc73f3c4fa8a3098254e6c125c6c80f43e8f225c1427878374e69d6a6b0ab4f2a4966e275056d1557af9313cf669ae063e144626d42a03ee158c630e2c0e1cfafcd15a028f3ac6783ff5482cd4f04f2141f50ff0b81abdf97c23b1a0f3a496ba29ef0df81c752e96852d1885df22c9fe16e0b6ded1b320e07fac647cba4ad1573d2945413c0b177bd55bf36a2049557120d5d14471f8cb8776060db495225f43849b3a4b7ae400c51ef31d542efd39f3652cde4af90faf8f7e686f853baaa3a5f628f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12288);
 script_version ("1.22");

 script_name(english:"Global variable settings");
 script_summary(english:"Global variable settings");
 
 script_set_attribute(attribute:"synopsis", value:
"Sets global settings." );
 script_set_attribute(attribute:"description", value:
"This plugin configures miscellaneous global variables for Nessus
plugins.  It does not perform any security checks but may disable or
change the behavior of others.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/29");
 script_end_attributes();

 script_category(ACT_SETTINGS);	
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "Settings");
 
 if ( NASL_LEVEL >= 3200 )
   script_add_preference(name:"Probe services on every port", type:"checkbox", value:"yes");
 script_add_preference(name:"Do not log in with user accounts not specified in the policy", type:"checkbox", value:"no");
 if ( NASL_LEVEL >= 4000 )
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"no");
 else
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"yes");

 script_add_preference(name:"Network type", type:"radio", value:"Mixed (use RFC 1918);Private LAN; Public WAN (Internet)");
 script_add_preference(name:"Enable experimental scripts", type:"checkbox", value:"no");
 script_add_preference(name:"Thorough tests (slow)", type:"checkbox", value:"no");
 script_add_preference(name:"Report verbosity", type:"radio", value:"Normal;Quiet;Verbose");
 script_add_preference(name:"Report paranoia", type:"radio", value:"Normal;Avoid false alarms;Paranoid (more false alarms)");
 script_add_preference(name:"Debug level", type:"entry", value:"0");
 script_add_preference(name:"HTTP User-Agent", type:"entry", value:"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)");
 script_add_preference(name:"SSL certificate to use : ", type:"file", value:"");
 script_add_preference(name:"SSL CA to trust : ", type:"file", value:"");
 script_add_preference(name:"SSL key to use : ", type:"file", value:"");
 script_add_preference(name:"SSL password for SSL key : ", type:"password", value:"");

 exit(0);
}



if ( get_kb_item("global_settings/disable_service_discovery")  ) exit(0);
if ( script_get_preference("SSL certificate to use : ") )
 cert = script_get_preference_file_location("SSL certificate to use : ");

if ( script_get_preference("SSL CA to trust : ") )
 ca = script_get_preference_file_location("SSL CA to trust : ");


if ( script_get_preference("SSL key to use : ") )
 key = script_get_preference_file_location("SSL key to use : ");

pass = script_get_preference("SSL password for SSL key : ");

if ( cert && key )
{
 set_kb_item(name:"SSL/cert", value:cert);
 set_kb_item(name:"SSL/key", value:key);
 if ( ca ) set_kb_item(name:"SSL/CA", value:ca);
 if ( password ) set_kb_item(name:"SSL/password", value:password);
}




opt = script_get_preference("Probe services on every port");
if ( opt && opt == "no" ) set_kb_item(name:"global_settings/disable_service_discovery", value:TRUE);

opt = script_get_preference("Do not log in with user accounts not specified in the policy");
if ( opt && opt == "yes" ) set_kb_item(name:"global_settings/supplied_logins_only", value:TRUE);

if ( !get_preference("lightning_scan_id") )
 {
  opt = script_get_preference("Enable CGI scanning");
  if ( opt == "no" ) set_kb_item(name:"Settings/disable_cgi_scanning", value:TRUE);
 }

opt = script_get_preference("Enable experimental scripts");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/experimental_scripts", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/ExperimentalScripts", value:TRUE);

opt = script_get_preference("Thorough tests (slow)");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/thorough_tests", value:opt);

if ( opt == "yes" ) set_kb_item(name:"Settings/ThoroughTests", value:TRUE);

opt = script_get_preference("Report verbosity");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_verbosity", value:opt);

opt = script_get_preference("Debug level");
if (! opt || ";" >< opt ) opt = "0";
set_kb_item(name:"global_settings/debug_level", value:int(opt));

opt = script_get_preference("Report paranoia");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_paranoia", value:opt);
if (opt == "Paranoid (more false alarms)")
  set_kb_item(name:"Settings/ParanoidReport", value: TRUE);

opt = script_get_preference("Network type");
if (! opt || ";" >< opt ) opt = "Mixed (RFC 1918)";
set_kb_item(name:"global_settings/network_type", value:opt);

opt = script_get_preference("HTTP User-Agent");
if (! opt) opt = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)";
set_kb_item(name:"global_settings/http_user_agent", value:opt);


