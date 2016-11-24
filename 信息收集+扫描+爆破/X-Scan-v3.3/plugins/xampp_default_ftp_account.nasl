#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18037);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2005-1078");
 script_bugtraq_id(13131);
 script_xref(name:"OSVDB", value:"15636");
 
 script_name(english:"XAMPP Default FTP Account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has an account that is protected with default
credentials." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server has an account with a known username / password
combination, which may have been configured when installing XAMPP.  An
attacker may be able to use this to gain authenticated acccess to the
system, which could allow for other attacks aginst the affected
application and host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-04/0236.html" );
 script_set_attribute(attribute:"solution", value:
"Modify the FTP password of the remote host." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Attempts to log in via FTP using credentials associated with XAMPP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
if (! port) port = 21;
if (!get_port_state(port)) exit(0);
if (get_kb_item('ftp/'+port+'/backdoor') ||
    get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/AnyUser') ) exit(0);

i = 0;
users[i] = "nobody";
passes[i] = "xampp";

i++;
users[i] = "nobody";
passes[i] = "lampp";

# nb: this is the default in 1.4.13.
i++;
users[i] = "newuser";
passes[i] = "wampp";

info = "";
for (j=0; j<=i; j++)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  user = users[j];
  pass = passes[j];
  if (ftp_authenticate(socket:soc, user:user, pass:pass))
  {
    info += '  - ' + user + '/' + pass + '\n';
    if (!thorough_tests) break;
  }
  close(soc);
 }
}


if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report = string(
      "\n",
      "Nessus uncovered the following set", s, " of default credentials :\n",
      "\n",
      info
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
