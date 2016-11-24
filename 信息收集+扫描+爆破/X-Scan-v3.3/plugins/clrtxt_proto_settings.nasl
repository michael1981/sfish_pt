#TRUSTED 581f05fcfb050ae8305fd139ced1253e9d3c79d2850b2f751901c0634b82308f52660e0d1064cf6234871ac9e4fda52134034bb61137c681487d89145c8eed574679fb37d29c257d1c4c86ebedff4ee11ffc0f3e45e676cfe59cbc7cb864ab6faf1a2a26c7dd308831d5276b224ba98892b83e6093bde26ad20046bcffe0ec4c459edad58f19c046081ff56e692234e8ad858a13d3cc35ec1a89b59a3cca8e19a5d0a4d3e49248ac47a4e4e59147b5d03a433b9161641a564b8d7a0ab71c67f9c2d83dfe683c63fbdbbe379e019212d05db019771b5c7e2a75835404cf327c793ccaad12ca7f55e16836845dfae39623fc9555bfb18a0b189833a1c112b00363753b14abb24ffe4ee1816b8ff74e859403d01ab36c0d1cae2aa2e54cdc834dec078259ce951f9cea32fc28104cfc91893036ccc0f99e7597b6c2263994857f8c4a92117286a9ad668bf43086a2727eaa15c0b1428a0e826729c827fe24882dd49c07cf727e38214033eee9b811e88a49ebcda83b70d32e0bdf4fda374c61a921e67b714f3603bf5d470e2b90db94589c1cff8cefce73bc893691bf348fff2287f7b0a08670da858da6a103edc7c9dc183e8b773f4b36851e0bf74a6d5f6c2e22c282389ff8825fb1f04945c0cf6f16983004064d53f02effe66936e4b75e859445d3f763b2a29c1ef388d64fb21ff641ed8c6eb5244179a36044b97b2904d178
#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(21744);
 script_version ("1.3");

 script_name(english:"Cleartext protocols settings");
 script_summary(english:"Set cleartext credentials to perform local security checks");

 script_set_attribute(
   attribute:"synopsis",
   value:"This script is used to configure Nessus settings."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "This script just sets global variables (telnet/rexec/rsh logins and\n",
     "passwords) that are used to perform host-level patch level checks.\n\n",
     "You should avoid using these cleartext protocols when doing a scan,\n",
     "as Nessus will basically broadcast the password to every tested host."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"n/a"
 );
 script_set_attribute(
   attribute:"risk_factor", 
   value:"None"
 );
 script_end_attributes();

 script_category(ACT_INIT);
 script_family(english:"Settings");

 script_copyright(english:"Copyright (C) 2006-2009 Tenable Network Security, Inc.");

 script_add_preference(name:"User name : ", type:"entry", value:"");
 script_add_preference(name:"Password (unsafe!) : ", type:"password", value:"");
 script_add_preference(name:"Try to perform patch level checks over telnet", type:"checkbox", value:"no");
 #script_add_preference(name:"Try to perform patch level checks over rlogin", type:"checkbox", value:"no");
 script_add_preference(name:"Try to perform patch level checks over rsh", type:"checkbox", value:"no");
 script_add_preference(name:"Try to perform patch level checks over rexec", type:"checkbox", value:"no");

 exit(0);
}

account    = script_get_preference("User name : ");
password   = script_get_preference("Password (unsafe!) : ");

try_telnet = script_get_preference("Try to perform patch level checks over telnet");
#try_rlogin = script_get_preference("Try to perform patch level checks over rlogin");
try_rsh    = script_get_preference("Try to perform patch level checks over rsh");
try_rexec  = script_get_preference("Try to perform patch level checks over rexec");

if ( account  ) set_kb_item(name:"Secret/ClearTextAuth/login", value:account);
if ( password ) set_kb_item(name:"Secret/ClearTextAuth/pass", value:password);

if ( try_telnet == "yes" ) set_kb_item(name:"HostLevelChecks/try_telnet", value:TRUE);
#if ( try_rlogin == "yes" ) set_kb_item(name:"HostLevelChecks/try_rlogin", value:TRUE);
if ( try_rsh    == "yes" ) set_kb_item(name:"HostLevelChecks/try_rsh",    value:TRUE);
if ( try_rexec  == "yes" ) set_kb_item(name:"HostLevelChecks/try_rexec",    value:TRUE);
