#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(11356);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-1999-0170", "CVE-1999-0211", "CVE-1999-0554");
 script_xref(name:"OSVDB", value:"339");
 script_xref(name:"OSVDB", value:"8750");
 script_xref(name:"OSVDB", value:"11516");
 
 script_name(english:"NFS Exported Share Information Disclosure");

 script_set_attribute(
  attribute:"synopsis",
  value:
"It is possible to access NFS shares on the remote host."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"At least one of the NFS shares exported by the remote server could be
mounted by the scanning host.  An attacker may be able to leverage
this to read (and possibly write) files on remote host."
 );
 script_set_attribute(
  attribute:"solution",
  value:
"Configure NFS on the remote host so that only authorized hosts can
mount its remote shares."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2003/03/12"
 );
 script_end_attributes();

 script_summary(english:"Checks for NFS");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 script_dependencie("rpc_portmap.nasl", "showmount.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}



include("misc_func.inc");
include("nfs_func.inc");

mountable = NULL;


list = get_kb_list("nfs/exportlist");
if(isnull(list))exit(0);
shares = make_list(list);


port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
soc = open_priv_sock_udp(dport:port);

port2 = get_rpc_port(program:100003, protocol:IPPROTO_UDP);
if ( ! port2 ) exit(0);
soc2 = open_priv_sock_udp(dport:port2);

if(!soc)exit(0);

foreach share (shares)
{
 fid = nfs_mount(soc:soc, share:share);
 if(fid)
 {
  content = nfs_readdir(soc:soc2, fid:fid);
  mountable += '+ ' + share + '\n' ;
  flag = 0;
  foreach c (content)
  {
   if(flag == 0){
   	mountable += ' + Contents of ' + share + ' : \n';
   	flag = 1;
	}
    mountable += ' - ' + c + '\n'; 
  }
  nfs_umount(soc:soc, share:share);
  mountable += '\n\n';
 }
}

close(soc);

if(mountable)
{
 report = string("\nThe following NFS shares could be mounted :\n\n", mountable);

 security_warning(port:2049, proto:"udp", extra:report);
}		 
