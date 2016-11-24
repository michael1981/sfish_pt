#
# (C) Tenable Network Security, Inc.
#

account = "root";
password = "dottie";


include("compat.inc");

if(description)
{
 script_id(31800);
 script_version ("$Revision: 1.5 $");

 script_cve_id("CVE-1999-0502", "CVE-2006-5288");
 script_bugtraq_id(20490);
 script_xref(name:"OSVDB", value:"30913");
 
 script_name(english:"Default Password (dottie) for 'root' Account");
     
 script_set_attribute(attribute:"synopsis", value:
"An administrative account on the remote host uses a weak password." );
 script_set_attribute(attribute:"description", value:
"The account 'root' has the password 'dottie'.  An attacker may use
it to gain further privileges on this system" );
 script_set_attribute(attribute:"solution", value:
"Set a strong password for this account or disable it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


 script_summary(english:"Logs into the remote host");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Default Unix Accounts");
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "ssh_detect.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");

port = check_account(login:account, password:password);
if(port)security_hole(port);
