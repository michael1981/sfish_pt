#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(10933);
  script_version("$Revision: 1.26 $");

  script_bugtraq_id(3333);
  script_cve_id("CVE-2001-1109");
  script_xref(name:"OSVDB", value:"766");

  script_name(english:"EFTP Multiple Command Traversal Arbitrary Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of EFTP installed on the remote host can be used to
determine if a given file exists on the remote host or not, by adding
dot-dot-slashes in front of them. 

For instance, it is possible to determine the presence of
'\autoexec.bat' by using the command SIZE or MDTM with the argument
'../../../../autoexec.bat'

An attacker may leverage this flaw to gain more knowledge about this
host, such as its file layout.  This flaw is especially useful in
combination with other vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-09/0100.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.2 or higher, as it has been reported to fix this
vulnerability." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N" );
script_end_attributes();

 
 script_summary(english:"EFTP directory traversal");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login", "Settings/ThoroughTests");
 exit(0);
}

#
include("ftp_func.inc");
include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

cmd[0] = "SIZE";
cmd[1] = "MDTM";

port = get_kb_item("Services/ftp");
if(!port)port = 21;
login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
# login = "ftp"; pass = "test@test.com";

if(get_port_state(port))
{
 vuln=0; tested=0;
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(login)
  {
   if(ftp_authenticate(socket:soc, user:login, pass:pass))
   {
    tested=tested+1;
    for (i = 0; cmd[i]; i = i + 1)
    {
     req = string(cmd[i], " ../../../../../../autoexec.bat\r\n");
     send(socket:soc, data:req);
     r = ftp_recv_line(socket:soc);
     if("230 " >< r) vuln=vuln+1;
    }
   }
   else
   {
    # We could not log in or could not download autoexec.
    # We'll just attempt to grab the banner and check for version
    # <= 2.0.7
    # I suppose that any version < 2 is vulnerable...
    r = ftp_recv_line(socket:soc);
    if(egrep(string:r, pattern:".*EFTP version ([01]|2\.0\.[0-7])\..*"))
     vuln = 1;
   }
  }
  close(soc);
  if (vuln)
  {
   if (tested)
   {
    security_warning(port);
   }
   else
   {
    rep="
Note that Nessus was not able to test for the presence of
'\autoexec.bat' and solely relied on the version number of your
server, so this may be a false positive.";
    security_warning(port:port, extra:rep);
   }
   exit(0);
  }
 }
}

#
# NB: This server is also vulnerable to another attack.
#
# Date:  Thu, 13 Dec 2001 12:59:43 +0200
# From: "Ertan Kurt" <ertank@olympos.org>
# Affiliation: Olympos Security
# To: bugtraq@securityfocus.com
# Subject: EFTP 2.0.8.346 directory content disclosure
#
# It is possible to see the contents of every drive and directory of
# vulnerable server.
# A valid user account is required to exploit this vulnerability.
# It works both with encryption and w/o encryption.
# Here's how it's done:
# the user is logged in to his home directory (let's say d:\userdir)
# when the user issues a CWD to another directory server returns
# permission denied.
# But, first changing directory to "..." (it will chdir to d:\userdir\...)
# then issuing a CWD to "\" will say permission denied but it will
# successfully change to root directory of the current drive.
# And everytime we want to see a dir's content, we first CWD to our
# home directory and then CWD ...  and then CWD directly to desired
# directory (CWD c:/ or c:/winnt etc)
# 
# So it is possible to see directory contents but i did not test to see
# if there is a possible way to get/put files.
#
