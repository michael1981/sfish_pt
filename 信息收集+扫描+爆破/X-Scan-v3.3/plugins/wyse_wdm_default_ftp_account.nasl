#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40332);
 script_version ("$Revision: 1.1 $");
 
 script_name(english:"Wyse Device Manager Default FTP Account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has an account that is protected with default
credentials." );

 script_set_attribute(attribute:"description", value:
"The remote FTP server has an account with a known username / password
combination, possibly created as part of an install of Wyse Device
Manager.  An attacker may be able to use this to gain authenticated
access to the system, which could allow for other attacks against the
affected application and host." );

 script_set_attribute(attribute:"solution", value:
"Change the password associated with the reported username." );

 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/20");

 script_end_attributes();
 
 script_summary(english:"Attempts to log in via FTP using credentials associated with Wyse Device Manager");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
include('ftp_func.inc');

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0, "The port is not open.");

if (get_kb_item('ftp/'+port+'/backdoor')) exit(0, "The FTP server is a backdoor.");
if (get_kb_item('ftp/'+port+'/broken')) exit(0, "The FTP server is not working.");
if (get_kb_item('ftp/'+port+'/AnyUser')) exit(0, "The FTP server accepts arbitrary credentials.");

user   = "rapport";
passwd = "r@p8p0r+";

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket.");

if (ftp_authenticate(socket:soc, user:user, pass:passwd))
{
  ftp_close(socket:soc);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to log into the remote FTP server using the\n",
      "following default credentials :\n",
      "\n",
      "User     : ",user,'\n',
      "Password : ",passwd,'\n'
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

ftp_close(socket:soc);
exit(0, "The FTP server is not affected by this issue.");
