#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11112);
 script_bugtraq_id(2618, 2786, 5168, 11159);
 script_cve_id("CVE-2001-0582", "CVE-2001-0680", "CVE-2001-1335", "CVE-2004-1679");
 script_xref(name:"OSVDB", value:"1794");
 script_xref(name:"OSVDB", value:"4050");
 script_xref(name:"OSVDB", value:"8982");
 script_xref(name:"OSVDB", value:"9899");
 script_xref(name:"OSVDB", value:"13892");
 script_version ("$Revision: 1.32 $");
 
 script_name(english:"FTP Server Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server allows any anonymous user to browse the entire
remote disk by issuing commands with traversal style characters. An
attacker could exploit this flaw to gain access to arbitrary files." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-04/0231.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-05/0252.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0106.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-05/0036.html" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for the latest version of the FTP software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
 
script_end_attributes();

 
 script_summary(english:"Attempts to get the listing of the remote root dir");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_exclude_keys("ftp/ncftpd", "ftp/msftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

function dir(loc, soc)
{
 local_var ls, p, r, result, soc2;

 p = ftp_pasv(socket:soc);
 if(!p)exit(0);
 soc2 = open_sock_tcp(p, transport:get_port_transport(port));
 if(!soc2)return NULL;
 
 #display("Ok\n");
 ls = strcat("LIST ", loc, '\r\n');
 send(socket:soc, data:ls);
 r = recv_line(socket:soc, length:4096);
 if(ereg(pattern:"^150 ", string:r))
 {
  result = ftp_recv_listing(socket:soc2);
  close(soc2);
  r = ftp_recv_line(socket:soc);
  return(result);
 }
 close(soc2);
 return NULL;
}


soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", get_host_name())))
 {
  l2 = NULL; l1 = NULL;
  for (i = 0; i < 2 && ! l2; i ++)
    l2 = dir(loc: "/", soc: soc);
  for (i = 0; i < 2 && ! l1; i ++)
    l1 = dir(loc: "/", soc: soc);
  if (l1 != l2) exit(0);

  if (isnull(l1))
	 {
    ftp_close(socket: soc);
	  exit(0);
	 } 
  patterns = 
   make_list(	"../../../../../../../", 
		"..\..\..\..\..\..\..\",
		"..%5c..%5c..%5c..%5c..%5c..%5c..%5c",
		"\..\..\..\..\..\",	# platinum FTP 1.0.7
		"...",
		"/...",
		"/......",
		"\...",
		"...\",
		"..../",
		"\",
		"/");
  foreach pat (patterns)
  {
    l2 = dir(loc: pat, soc: soc);
    
    # ncftpd workaround
    if (strlen(l2) &&
        ! match(string: l2, pattern: "*permission denied*", icase: TRUE) &&
        ! match(string: l2, pattern: "*no such file or directory*", icase: TRUE) &&
	! match(string: l2, pattern: "*total 0*", icase: TRUE) &&
        l1 != l2)
  {
       #display(l1, "\n****\n"); display(l2, "\n");
       report = string("\n", "The command we found to escape the chrooted environment is : ", pat, "\nThe root dir of the remote server contains :\n\n", l2);
	  security_warning(port:port, extra:report);
       ftp_close(socket: soc);
	  exit(0);
  }	 
	  
  }	 
 }
  ftp_close(socket: soc);
}

