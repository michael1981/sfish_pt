#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10166);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0546");
 script_xref(name:"OSVDB", value:"129");
 
 script_name(english:"Windows NT FTP 'guest' Account Present");
 
 script_set_attribute(attribute:"synopsis", value:
"There is a 'guest' account on the remote FTP server." );
 script_set_attribute(attribute:"description", value:
"There is a 'guest' FTP account.
This is usually not a good thing, since very often,
this account will not run in a chrooted environment,
so an attacker will be very likely to use it
to break into this system." );
 script_set_attribute(attribute:"solution", value:
"Disable this FTP account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 script_summary(english: "Checks for guest/guest");
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english: "This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english: "FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

# it the server accepts any login/password, then
# no need to do this check
include('global_settings.inc');
include('ftp_func.inc');

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

if ( get_kb_item('ftp/'+port+'/broken') || 
     get_kb_item('ftp/'+port+'/backdoor') )
  exit(0);

if (get_kb_item("ftp/" + port + "/AnyUser"))exit(0);

# MA 2008-08-23: we used to test "guest"/"" but the summary says that we test 
# guest/guest. Just in case, I added both cases

foreach pass (make_list("", "guest"))
{
  soc = open_sock_tcp(port);
  if (! soc) exit(0);

  if (ftp_authenticate(socket:soc, user:"guest", pass: pass))
  {
   login = get_kb_item("ftp/login");
   if(!login)
   {
    set_kb_item(name:"ftp/login", value: "guest");
    set_kb_item(name:"ftp/password", value: pass);
   }
   if (pass != "")
     rep = strcat('\nguest\'s password is ', pass, '\n');
   else
     rep = '\nThe guest account has no password\n';
   security_hole(port, extra: rep);
   close(soc);
   exit(0);
  }
  close(soc);
}
