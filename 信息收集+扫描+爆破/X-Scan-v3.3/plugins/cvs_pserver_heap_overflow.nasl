#  
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12240);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0396");
 script_bugtraq_id(10384);
 script_xref(name:"OSVDB", value:"6305"); 
 
 script_name(english:"CVS pserver Line Entry Handling Overflow");
 script_summary(english:"Logs into the remote CVS server and asks the version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote version control service has a remote heap buffer overflow\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its version number, the remote CVS server has a heap\n",
     "buffer overflow vulnerability.  A remote attacker could exploit this\n",
     "to crash the service, or possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?ac6e8d97"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CVS 1.12.8 / 1.11.16 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service1.nasl", "cvs_public_pserver.nasl");

 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

login = get_kb_item(string("cvs/", port, "/login"));
pass  = get_kb_item(string("cvs/", port, "/pass"));
dir   = get_kb_item(string("cvs/", port, "/dir"));

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("BEGIN AUTH REQUEST\n",
dir, "\n",
login,"\n",
"A", pass,"\n",
"END AUTH REQUEST\n");

  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:4096);
  if("I LOVE YOU" >< r)
  {
    send(socket:soc, data:string("version\n"));
    r = recv_line(socket:soc, length:4096);
    if("Concurrent" >< r)
    {
     set_kb_item(name:string("cvs/", port, "/version"), value:r);
     if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-5])|12\.[0-7][^0-9]).*", string:r))
     {
        rep = strcat('\nThe CVS pserver version is : ', r, '\n');
     	security_hole(port, extra: rep);
     }
    }
  }
  close(soc);
 
