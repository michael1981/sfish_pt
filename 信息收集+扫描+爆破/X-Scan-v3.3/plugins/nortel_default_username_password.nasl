#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(15715);
 script_version("$Revision: 1.14 $");
 script_name(english:"Nortel Multiple Default Accounts");
	     
 script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote switch using default
credentials." );
 script_set_attribute(attribute:"description", value:
"It is possible to log into the remote Nortel Accelar routing switch by
using a default set of credentials.  An attacker may use these to gain
access to the remote host." );
 script_set_attribute(attribute:"solution", value:
"Set a strong password for these accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
 script_summary(english:"Logs into the remote switch with a default login/password pair");

 script_category(ACT_GATHER_INFO);

 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_require_keys("Settings/Thorough");
 exit(0);
}

#
# The script code starts here : 
#
include("ssh_func.inc");
include("global_settings.inc");

if ( ! thorough_tests ) exit(0);
if ( supplied_logins_only ) exit(0);


credentials = make_array("12", "12",
			 "13", "13",
			 "ro", "ro",
			 "rw", "rw",
			 "rwa", "rwa");


port = get_kb_item("Services/ssh");
if ( ! port ) port = 22;
if ( ! port || !get_port_state(port) ) exit(0);
if ( ! get_kb_item("SSH/banner/" + port) ) exit(0);

foreach key ( keys(credentials) )
{
 _ssh_socket = open_sock_tcp(port);
 if ( ! _ssh_socket ) exit(0);
 ret = ssh_login(login:key, password:credentials[key]);
 close(_ssh_socket);
 if ( ret == 0 ) working_login += key + '/' + credentials[key] + '\n';
		
}

if ( working_login )
{
 report = '\nThe following credentials have been tested successfully :\n\n' + working_login;
 security_hole(port:port, extra:report); 
}
