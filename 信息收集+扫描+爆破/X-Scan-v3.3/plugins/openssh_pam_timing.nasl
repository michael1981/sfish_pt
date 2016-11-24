#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") || ! defined_func("unixtime") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(11574);
 script_version ("$Revision: 1.32 $");
 script_cve_id("CVE-2003-0190", "CVE-2003-1562");
 script_bugtraq_id(7342, 7467, 7482, 11781);
 script_xref(name:"OSVDB", value:"2109");
 script_xref(name:"OSVDB", value:"2140");
 
 script_name(english:"OpenSSH w/ PAM Multiple Timing Attack Weaknesses");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate valid users on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host seem to be running an SSH server which can allow an
attacker to determine the existence of a given login by comparing the
time the remote sshd daemon takes to refuse a bad password for a
nonexistent login compared to the time it takes to refuse a bad
password for a valid login. 

An attacker may use this flaw to set up a brute force attack against
the remote host." );
 script_set_attribute(attribute:"solution", value:
"Disable PAM support if you do not use it, upgrade to the newest
version of OpenSSH" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	
script_end_attributes();

 
 script_summary(english:"Checks the timing of the remote SSH server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


include("ssh_func.inc");
include("global_settings.inc");

if ( supplied_logins_only ) exit(0);

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);
if ( report_paranoia < 2 ) exit(0);

maxdiff = 3;

if ( ! thorough_tests ) 
  if ( "openssh" >!<  tolower(banner) ) exit(0);





_ssh_socket = open_sock_tcp(port);
if ( ! _ssh_socket ) exit(0);

then = unixtime();
ret = ssh_login(login:"nonexistent" + rand(), password:"n3ssus");
now = unixtime();
close(_ssh_socket);

inval_diff = now - then;

_ssh_socket = open_sock_tcp(port);
if ( ! _ssh_socket ) exit(0);
then = unixtime();
ret = ssh_login(login:"bin", password:"n3ssus");
now = unixtime();
val_diff = now - then;
if ( ( val_diff - inval_diff ) >= maxdiff ) security_warning(port);
close(_ssh_socket);
