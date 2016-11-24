#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12513);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-1999-0502");
 
 script_name(english:"Default Password (1234568) for 'root' Account on MacOS X Server");
 script_summary(english:"Logs into the remote host");

 script_set_attribute(
   attribute:"synopsis",
   value:"A default account was detected on the remote host."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "Nessus was able to login to the remote host using the following\n",
     "credentials :\n\n",
     "  Username : root\n",
     "  Password : 12345678\n\n",
     "On older Macintosh computers, Mac OS X server is configured with\n",
     "this default account (on newer computers, the serial number of the\n",
     "system is used instead)."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Set a strong password for the root account."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Default Unix Accounts");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("ssh_detect.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");
include("global_settings.inc");

os = get_kb_item("Host/OS");
if ( os && "Mac OS X" >!< os ) exit(0);

port = check_account(login:"root", password:"12345678");
if(port)security_hole(port);
