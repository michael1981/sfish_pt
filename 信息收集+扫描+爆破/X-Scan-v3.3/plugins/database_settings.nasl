#
# (C) Tenable Network Security, Inc.
#

# @NOSOURCE@
# @PREFERENCES@


include("compat.inc");

if(description)
{
 script_id(33815);
 script_version("$Revision: 1.9 $");
 name["english"] = "Database settings";
 script_set_attribute(attribute:"synopsis", value:
"Database settings" );
 script_set_attribute(attribute:"description", value:
"This script just sets global variables (SID name, ...)
and does not perform any security check" );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 script_name(english:name["english"]);
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 summary["english"] = "set database preferences to perform security checks";
 script_summary(english:summary["english"]);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_category(ACT_SETTINGS);

 script_add_preference(name:"Login : ", type:"entry", value:"");
 script_add_preference(name:"Password : ", type:"password", value:"");

 script_add_preference(name:"DB Type : ", type:"radio", value:"Oracle;SQL Server;MySQL;DB2;Informix/DRDA;PostgreSQL");

 script_add_preference(name:"Database SID : ", type:"entry", value:"");
 script_add_preference(name:"Database port to use : ", type:"entry", value:"");
 script_add_preference(name:"Oracle auth type: ", type:"radio", value:"NORMAL;SYSOPER;SYSDBA");
 script_add_preference(name:"SQL Server auth type: ", type:"radio", value:"Windows;SQL");

 exit(0);
}

login = script_get_preference("Login : ");
if (strlen(login)) set_kb_item(name:"Database/login", value:login);

password = script_get_preference("Password : ");
if (strlen(password)) set_kb_item(name:"/tmp/Database/password", value:password);

type = script_get_preference("DB Type : ");
if ( ";" >< type ) exit(0);
if ("Oracle" >< type)
  type = 0;
else if ("SQL Server" >< type)
  type = 1;
else if ("MySQL" >< type)
  type = 2;
else if ("DB2" >< type)
  type = 3;
else if ("Informix" >< type)
  type = 4;
else if ("PostgreSQL" >< type)
  type = 5;

if ( type ) set_kb_item(name:"Database/type", value:type);

sid = script_get_preference("Database SID : ");
if (strlen(sid)) set_kb_item(name:"Database/SID", value:sid);

port = script_get_preference("Database port to use : ");
if (!isnull(port)) set_kb_item(name:"Database/Port", value:port);


type = script_get_preference("SQL Server auth type: ");
if ("Windows" >< type)
  sspi = TRUE;
else if ("SQL" >< type)
  sspi = FALSE;
if ( sspi ) set_kb_item(name:"Database/sspi", value:sspi);

type = script_get_preference("Oracle auth type: ");
if ("NORMAL" >< type)
  type = TNS_LOGON_NORMAL;
else if ("SYSOPER" >< type)
  type = TNS_LOGON_SYSOPER;
else if ("SYSDBA" >< type)
  type = TNS_LOGON_SYSDBA;
if ( type ) set_kb_item(name:"Database/oracle_atype", value:type);


