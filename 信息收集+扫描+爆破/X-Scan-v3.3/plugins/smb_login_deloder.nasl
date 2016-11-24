#
# (C) Tenable Network Security
#
#

include("compat.inc");

if(description)
{
 script_id(11454);
 script_version("$Revision: 1.6 $");
 script_name(english: "Windows Administrator Password Known by W32/Deloader");
 script_xref(name: "CERT", value: "CA-2003-08");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to the W32/Deloder worm");
 script_set_attribute(attribute:"description", value:
"W32/Deloder is a worm that tries to connect to a remote share by using
a list of built-in administrator passwords.

Nessus was able to connect to this host with one of these credentials.
The worm W32/Deloder may use it to break into the remote host and upload
infected data in the remote shares.");
 script_set_attribute(attribute: "solution", value: "Change your administrator password to a strong one");
# script_set_attribute(attribute: "see_also", value: "http://www.cert.org/advisories/CA-2003-08.html");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_end_attributes();
 
 script_summary(english: "Attempts to log into the remote host");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_sid2user.nasl", "smb_sid2localuser.nasl", "snmp_lanman_users.nasl");
 script_require_keys("SMB/name");
 script_require_ports(139, 445);
 script_timeout(0);
 exit(0);
}

include("smb_func.inc");
include("global_settings.inc");

if ( supplied_logins_only ) exit(0);

if ( get_kb_item("SMB/any_login") ) exit(0);

port = kb_smb_transport();
if ( ! get_port_state(port) ) exit(0);


function log_in(login, pass)
{
 local_var soc, r;
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 session_init(socket:soc, hostname:kb_smb_name());
 r = NetUseAdd(login:login, password:pass, domain:NULL, share:"IPC$");
 NetUseDel();
 if ( r == 1 ) return TRUE;
 else
  return(FALSE);
}

login = string(get_kb_item("SMB/LocalUsers/0"));
if(!login)login = "administrator";

passwords = make_list("", "0", "000000", "00000000", "007", "1",
		      "110", "111", "111111", "11111111", "12",
		      "121212", "123", "123123", "1234", "12345",
		      "123456", "1234567", "12345678", "123456789",
		      "1234qwer", "123abc", "123asd", "123qwe",
		      "2002", "2003", "2600", "54321", "654321", 
		      "88888888", "Admin", "Internet", "Login",
		      "Password", "a", "aaa", "abc", "abc123", "abcd",
		      "admin", "admin123", "administrator", "alpha",
		      "asdf", "computer", "database", "enable", "foobar",
		      "god", "godblessyou", "home", "ihavenopass", "login",
		      "love", "mypass", "mypass123", "mypc", "mypc123",
		      "oracle", "owner", "pass", "passwd", "password",
		      "pat", "patrick", "pc", "pw", "pw123", "pwd", "qwer",
		      "root", "secret", "server", "sex", "super", "sybase",
		      "temp", "temp123", "test", "test123", "win", "xp",
		      "xxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		      "yxcv", "zxcv");
		      
		      
foreach p (passwords)
{
 if(log_in(login:login, pass:p))
 {
  report = strcat('\nThe account \'', login, '\'/\'',p, '\' is valid.\n');

  security_hole(port:port, extra: report);
  exit(0);
 }
}
