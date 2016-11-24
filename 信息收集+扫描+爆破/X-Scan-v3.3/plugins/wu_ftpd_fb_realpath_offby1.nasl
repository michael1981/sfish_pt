#
# (C) Tenable Network Security, Inc.
#

# Ref:
# 
# Date: Thu, 31 Jul 2003 18:16:03 +0200 (CEST)
# From: Janusz Niewiadomski <funkysh@isec.pl>
# To: vulnwatch@vulnwatch.org, <bugtraq@securityfocus.com>
# Subject: [VulnWatch] wu-ftpd fb_realpath() off-by-one bug



include("compat.inc");

if(description)
{
 script_id(11811);
 script_bugtraq_id(8315);
 script_cve_id("CVE-2003-0466");
 script_xref(name:"OSVDB", value:"2133");
 script_xref(name:"RHSA", value:"RHSA-2003:245-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:032");
 script_version ("$Revision: 1.15 $");
 
 script_name(english:"WU-FTPD fb_realpath() Function Off-by-one Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote WU-FTPD server seems to be vulnerable to an off-by-one
overflow when dealing with huge directory structures. 

An attacker may exploit this flaw to obtain a shell on this host. 

Note that Nessus has solely relied on the banner of the remote server
to issue this warning so it may be a false-positive, especially if the
patch has already been applied." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/unixfocus/5ZP010AAUI.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-08/0042.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9eabbd45" );
 script_set_attribute(attribute:"solution", value:
"Apply the realpath.patch patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
		
script_end_attributes();

		    
 script_summary(english:"Checks the banner of the remote wu-ftpd server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
		  
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
  
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");
include("backport.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (!get_port_state(port)) exit(0);

banner = get_backport_banner(banner:get_ftp_banner(port: port));
if( banner == NULL ) exit(0);
if(egrep(pattern:".*wu-(2\.(5\.|6\.[012])).*", string:banner))security_hole(port);
